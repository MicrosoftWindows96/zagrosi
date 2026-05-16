// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! Per-issuer in-process discovery cache.
//!
//! Wraps `openidconnect::CoreProviderMetadata::discover_async` and
//! caches the resulting metadata + JWKS for [`DEFAULT_TTL`]. Refreshes
//! are rate-limited to at most one HTTP fetch per issuer per
//! [`DEFAULT_REFRESH_RATE_LIMIT`] interval; concurrent refresh
//! attempts coalesce on the per-issuer mutex.
//!
//! ## Why we cache the JWKS document body
//!
//! The optional `expected_jwks_thumbprint` defence-in-depth pin
//! constant-time-compares SHA-256 of the JWKS document JSON against
//! the per-IdP config. The pin is computed at admin-write time over
//! the bytes the IdP served then; recomputing the pin requires the
//! same bytes (after an HTTP round-trip). The cache holds the bytes
//! verbatim alongside the parsed metadata to avoid a second discovery
//! fetch on every callback.
//!
//! ## Shared HTTP client invariant
//!
//! Every discovery refresh uses a shared `reqwest::Client` injected
//! at construction. `IdentityState` and the SAML / breach-list paths
//! consume the same client, so connection pooling and the rustls
//! crypto provider are reused. The test
//! `discovery_uses_shared_reqwest_client` verifies the
//! identity-by-`Arc::ptr_eq` invariant.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use openidconnect::IssuerUrl;
use openidconnect::core::CoreProviderMetadata;
use tokio::sync::{Mutex, RwLock};
use url::Url;

use crate::error::{IdentityError, Result};
use crate::oidc::config::jwks_thumbprint_hex;

/// Default discovery cache TTL. After this window the next refresh
/// attempt re-fetches the discovery document. v0.1 hard-codes the
/// value; section-13's multi-IdP config exposes it.
pub const DEFAULT_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// Minimum elapsed time between refresh HTTP calls per issuer. Even
/// when the cache window expires or a `kid` miss triggers a refresh,
/// this rate-limit prevents a misconfigured IdP from being hammered.
pub const DEFAULT_REFRESH_RATE_LIMIT: Duration = Duration::from_secs(60);

/// Per-issuer cached metadata + JWKS document bytes.
#[derive(Clone)]
struct DiscoveryEntry {
    metadata: CoreProviderMetadata,
    /// Raw JWKS document bytes the discovery fetch produced. Used by
    /// the JWKS thumbprint pin (`expected_jwks_thumbprint`).
    jwks_bytes: Vec<u8>,
    /// Wall-clock time the entry was last (re)populated.
    fetched_at: DateTime<Utc>,
}

/// Per-issuer slot. Holds an optional populated entry plus the last
/// refresh-attempt timestamp + a cold-failure counter. Tracking the
/// attempt outside the entry lets a sustained outage (cold cache +
/// IdP down) still rate-limit the upstream; tracking consecutive
/// cold failures lets us back off exponentially rather than locking
/// every callback out of an attempt for the full warm-cache 60s
/// window. A transient blip recovers on the next request after a
/// 1-2 second back-off; sustained outage caps at 60s.
#[derive(Default)]
struct DiscoverySlot {
    entry: Option<DiscoveryEntry>,
    last_refresh_attempt_at: Option<DateTime<Utc>>,
    consecutive_cold_failures: u32,
}

/// Compute the back-off duration for a cold-cache failure. 1s, 2s,
/// 4s, 8s, ... capped at the per-issuer warm-cache rate limit. A
/// transient blip resolves at the first sub-second back-off; a
/// sustained outage stabilises at the cap.
fn cold_failure_backoff(consecutive_failures: u32, cap: chrono::Duration) -> chrono::Duration {
    if consecutive_failures == 0 {
        return chrono::Duration::zero();
    }
    let shift = consecutive_failures.saturating_sub(1).min(20);
    let secs = 1_i64.checked_shl(shift).unwrap_or(i64::MAX);
    let candidate = chrono::Duration::seconds(secs);
    if candidate < cap { candidate } else { cap }
}

/// Bump the cold-failure counter when an upstream fetch fails and the
/// slot has no warm entry to fall back on. Pure side-effect helper —
/// pulled out of `fetch_or_refresh` so each error arm is one line.
const fn bump_cold_failure_if_no_entry(slot: &mut DiscoverySlot) {
    if slot.entry.is_none() {
        slot.consecutive_cold_failures = slot.consecutive_cold_failures.saturating_add(1);
    }
}

/// Decide whether the current call must short-circuit on the
/// rate-limit gate. Returns:
///
/// - `Ok(Some(snapshot))` when a warm entry exists, the budget is
///   exhausted, AND `force == false`: serve the cached snapshot.
///   The non-force path (`get`) prefers graceful degradation here.
/// - `Err(...)` when (a) no warm entry exists and the cold-failure
///   back-off has not elapsed, OR (b) `force == true` and the rate
///   limit blocks the upstream fetch. The force path (`force_refresh`,
///   used by the kid-miss retry in `OidcClient::exchange_and_verify`)
///   wants the typed `OidcDiscoveryFailed("rate-limited")` so the
///   caller can route the diagnostic instead of re-using the same
///   stale JWKS bytes that triggered the original kid-miss.
/// - `Ok(None)` when the gate allows the upstream fetch.
fn rate_limit_gate(
    slot: &DiscoverySlot,
    now: DateTime<Utc>,
    rate_limit: chrono::Duration,
    force: bool,
) -> Result<Option<DiscoverySnapshot>> {
    let Some(last) = slot.last_refresh_attempt_at else {
        return Ok(None);
    };
    let backoff = if slot.entry.is_some() {
        rate_limit
    } else {
        cold_failure_backoff(slot.consecutive_cold_failures, rate_limit)
    };
    if now - last >= backoff {
        return Ok(None);
    }
    if force {
        return Err(IdentityError::OidcDiscoveryFailed(
            "discovery rate-limited; refresh requested but budget exhausted",
        ));
    }
    if let Some(entry) = slot.entry.as_ref() {
        return Ok(Some(entry.into()));
    }
    Err(IdentityError::OidcDiscoveryFailed(
        "discovery rate-limited; previous attempt failed",
    ))
}

/// Per-issuer in-process discovery cache.
///
/// The shape `Arc<DiscoveryCache>` is the runtime injection target;
/// `IdentityState` holds one such handle and shares it across every
/// OIDC service composition. Internal locks: a single `RwLock` over
/// the per-issuer map for fast read paths, plus a per-issuer `Mutex`
/// for the refresh side so concurrent fetches coalesce.
pub struct DiscoveryCache {
    http: Arc<reqwest::Client>,
    map: RwLock<HashMap<Url, Arc<Mutex<DiscoverySlot>>>>,
    ttl: Duration,
    refresh_rate_limit: Duration,
}

impl DiscoveryCache {
    /// Build a cache wired to the supplied shared `reqwest::Client`.
    /// The cache borrows the `Arc` rather than building its own client
    /// so the `Arc::ptr_eq` invariant holds across `IdentityState`.
    #[must_use]
    pub fn new(http: Arc<reqwest::Client>) -> Self {
        Self::with_settings(http, DEFAULT_TTL, DEFAULT_REFRESH_RATE_LIMIT)
    }

    /// Build with custom TTL + rate-limit. Production callers use
    /// [`DiscoveryCache::new`]; tests use this overload to compress
    /// the rate-limit window.
    #[must_use]
    pub fn with_settings(
        http: Arc<reqwest::Client>,
        ttl: Duration,
        refresh_rate_limit: Duration,
    ) -> Self {
        Self {
            http,
            map: RwLock::new(HashMap::new()),
            ttl,
            refresh_rate_limit,
        }
    }

    /// Borrow the shared HTTP client (used by the OIDC client to
    /// run the token-endpoint exchange against the same connection
    /// pool).
    #[must_use]
    pub const fn http(&self) -> &Arc<reqwest::Client> {
        &self.http
    }

    /// Pre-warm the cache for `issuer`. Used by admin write paths
    /// when an `org_idps` row is created or updated so the first
    /// callback for that IdP does not race a cold cache miss.
    #[tracing::instrument(skip_all, fields(issuer = %issuer, route = "oidc.discovery.prewarm"))]
    pub async fn pre_warm(&self, issuer: &Url) -> Result<()> {
        let _ = self.fetch_or_refresh(issuer, /* force */ true).await?;
        Ok(())
    }

    /// Return cached metadata, re-fetching when the entry is missing,
    /// past TTL, or `force = true`. The returned [`DiscoverySnapshot`]
    /// is `Clone` so callers can hold it across an `await` without
    /// holding the cache lock.
    #[tracing::instrument(skip_all, fields(issuer = %issuer, route = "oidc.discovery.get"))]
    pub async fn get(&self, issuer: &Url) -> Result<DiscoverySnapshot> {
        self.fetch_or_refresh(issuer, /* force */ false).await
    }

    /// Force a refresh for `issuer`, subject to the per-issuer rate
    /// limit. The OIDC client invokes this on `kid` miss; the rate
    /// limit collapses pathological misses to one HTTP call per minute
    /// per issuer.
    #[tracing::instrument(skip_all, fields(issuer = %issuer, route = "oidc.discovery.force_refresh"))]
    pub async fn force_refresh(&self, issuer: &Url) -> Result<DiscoverySnapshot> {
        self.fetch_or_refresh(issuer, /* force */ true).await
    }

    /// Inner refresh path. Fast read path: take the shared lock,
    /// look up the entry, return the snapshot if it is fresh and
    /// `force == false`. Slow path: drop the read lock, take the
    /// per-issuer mutex (creating it under the write lock if absent),
    /// re-check freshness, and run the HTTP fetch under the per-issuer
    /// mutex so concurrent callbacks for the same issuer coalesce
    /// onto a single fetch.
    async fn fetch_or_refresh(&self, issuer: &Url, force: bool) -> Result<DiscoverySnapshot> {
        // Fast path: peek under the shared map lock. Drop the per-
        // issuer guard before acquiring the slow-path write lock so
        // we never hold both at once.
        {
            let map = self.map.read().await;
            if let Some(slot) = map.get(issuer) {
                let guard = slot.lock().await;
                if let Some(entry) = guard.entry.as_ref()
                    && !force
                    && Utc::now() - entry.fetched_at
                        < chrono::Duration::from_std(self.ttl).unwrap_or_default()
                {
                    return Ok(entry.into());
                }
            }
        }

        let slot = self.acquire_slot(issuer).await;
        let mut guard = slot.lock().await;

        let now = Utc::now();
        let rate_limit = chrono::Duration::from_std(self.refresh_rate_limit)
            .unwrap_or_else(|_| chrono::Duration::seconds(60));

        if let Some(entry) = guard.entry.as_ref() {
            let age = now - entry.fetched_at;
            if !force && age < chrono::Duration::from_std(self.ttl).unwrap_or_default() {
                return Ok(entry.into());
            }
        }

        // Rate-limit policy: warm cache enforces the spec's "1 refresh
        // per minute per issuer" budget; cold cache uses exponential
        // back-off (1s/2s/4s/... up to the same cap) so a transient
        // upstream blip doesn't pin every callback for the full 60s
        // window. See `rate_limit_gate` for the decision matrix.
        if let Some(snap) = rate_limit_gate(&guard, now, rate_limit, force)? {
            return Ok(snap);
        }

        // Stamp the attempt BEFORE the HTTP call so a fetch that hangs
        // until the timeout still rate-limits the next caller.
        guard.last_refresh_attempt_at = Some(now);

        let issuer_url = IssuerUrl::from_url(issuer.clone());
        let metadata_fut = CoreProviderMetadata::discover_async(issuer_url, self.http.as_ref());
        let metadata = match tokio::time::timeout(
            crate::oidc::client::PER_CALL_TIMEOUT,
            metadata_fut,
        )
        .await
        {
            Ok(Ok(m)) => m,
            Ok(Err(err)) => {
                tracing::warn!(target: "zagrosi.identity.oidc", %issuer, error = ?err, "discovery fetch failed");
                bump_cold_failure_if_no_entry(&mut guard);
                return Err(IdentityError::OidcDiscoveryFailed(
                    "metadata discovery failed",
                ));
            }
            Err(_elapsed) => {
                bump_cold_failure_if_no_entry(&mut guard);
                return Err(IdentityError::OidcDiscoveryFailed(
                    "metadata discovery timed out",
                ));
            }
        };

        let jwks_uri = metadata.jwks_uri().url().clone();
        let jwks_fetch_fut = async {
            self.http
                .get(jwks_uri.as_str())
                .send()
                .await
                .and_then(reqwest::Response::error_for_status)?
                .bytes()
                .await
        };
        let jwks_bytes = match tokio::time::timeout(
            crate::oidc::client::PER_CALL_TIMEOUT,
            jwks_fetch_fut,
        )
        .await
        {
            Ok(Ok(b)) => b.to_vec(),
            Ok(Err(err)) => {
                tracing::warn!(target: "zagrosi.identity.oidc", %issuer, error = %err, "jwks fetch failed");
                bump_cold_failure_if_no_entry(&mut guard);
                return Err(IdentityError::OidcDiscoveryFailed("jwks fetch failed"));
            }
            Err(_elapsed) => {
                bump_cold_failure_if_no_entry(&mut guard);
                return Err(IdentityError::OidcDiscoveryFailed("jwks fetch timed out"));
            }
        };

        let entry = DiscoveryEntry {
            metadata,
            jwks_bytes,
            fetched_at: Utc::now(),
        };
        let snapshot = DiscoverySnapshot::from(&entry);
        guard.entry = Some(entry);
        // Reset the cold-failure counter on every successful fetch so
        // a future cold-cache transition starts the back-off ladder
        // from 1s again rather than inheriting stale failure history.
        guard.consecutive_cold_failures = 0;
        // Drop the per-issuer mutex before returning to keep the
        // critical section short — concurrent callbacks for distinct
        // issuers should never wait on this guard.
        drop(guard);
        Ok(snapshot)
    }

    /// Acquire (creating if needed) the per-issuer mutex slot.
    async fn acquire_slot(&self, issuer: &Url) -> Arc<Mutex<DiscoverySlot>> {
        {
            let map = self.map.read().await;
            if let Some(slot) = map.get(issuer) {
                return slot.clone();
            }
        }
        let mut map = self.map.write().await;
        // Re-check under the write lock so concurrent inserts
        // coalesce onto a single slot.
        map.entry(issuer.clone())
            .or_insert_with(|| Arc::new(Mutex::new(DiscoverySlot::default())))
            .clone()
    }
}

/// Caller-visible snapshot of a cached discovery entry.
#[derive(Clone)]
pub struct DiscoverySnapshot {
    /// Parsed `openidconnect` metadata, ready to feed into
    /// `CoreClient::from_provider_metadata`.
    pub metadata: CoreProviderMetadata,
    /// Raw JWKS document bytes (used by the optional thumbprint pin).
    pub jwks_bytes: Vec<u8>,
    /// Wall-clock timestamp the entry was populated.
    pub fetched_at: DateTime<Utc>,
}

impl DiscoverySnapshot {
    /// Compute the SHA-256 thumbprint of the cached JWKS document and
    /// constant-time-compare to the configured pin. Returns
    /// [`IdentityError::OidcJwksThumbprintMismatch`] on mismatch.
    pub fn assert_thumbprint(&self, expected_lower_hex: &str) -> Result<()> {
        let actual = jwks_thumbprint_hex(&self.jwks_bytes);
        // Lower-case both sides; `actual` is already lower from
        // `jwks_thumbprint_hex`. The configured value is already
        // validated lower-case by `OidcConfigV1::validate`.
        if subtle::ConstantTimeEq::ct_eq(actual.as_bytes(), expected_lower_hex.as_bytes()).into() {
            Ok(())
        } else {
            Err(IdentityError::OidcJwksThumbprintMismatch)
        }
    }
}

impl From<&DiscoveryEntry> for DiscoverySnapshot {
    fn from(entry: &DiscoveryEntry) -> Self {
        Self {
            metadata: entry.metadata.clone(),
            jwks_bytes: entry.jwks_bytes.clone(),
            fetched_at: entry.fetched_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn make_http() -> Arc<reqwest::Client> {
        Arc::new(
            reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("build reqwest"),
        )
    }

    /// Build a wiremock-backed minimal OIDC discovery surface.
    /// `discovery_hits` and `jwks_hits` count incoming requests so
    /// tests can assert refresh rate-limit behaviour without measuring
    /// wall-clock latency.
    async fn fixture_issuer(
        discovery_hits: Arc<AtomicUsize>,
        jwks_hits: Arc<AtomicUsize>,
    ) -> (MockServer, Url) {
        let server = MockServer::start().await;
        // The lib expects `iss` claim to match the requested
        // `IssuerUrl`. `wiremock` returns `http://host:port` with no
        // trailing slash, but `Url::from_url` canonicalises pathless
        // origins with a trailing `/`. Match the canonical form by
        // stamping a trailing slash on the doc's `issuer` field; the
        // helper returns the same canonical URL so the test code
        // passes the expected shape into the cache.
        let issuer_with_slash = format!("{}/", server.uri());
        let issuer = issuer_with_slash.trim_end_matches('/').to_owned();
        // openidconnect 4.x's `CoreProviderMetadata::discover_async`
        // requires a fairly complete discovery doc; supply the
        // mandatory + most-commonly-required-by-the-lib fields so the
        // tests focus on cache behaviour rather than the discovery
        // document shape.
        let discovery_doc = serde_json::json!({
            "issuer": issuer_with_slash,
            "authorization_endpoint": format!("{issuer}/oauth/authorize"),
            "token_endpoint": format!("{issuer}/oauth/token"),
            "userinfo_endpoint": format!("{issuer}/oauth/userinfo"),
            "jwks_uri": format!("{issuer}/.well-known/jwks.json"),
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "scopes_supported": ["openid", "profile", "email"],
            "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
            "claims_supported": ["sub", "iss", "aud", "exp", "iat", "email", "email_verified", "name"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "response_modes_supported": ["query", "fragment"],
        });
        let jwks_doc = serde_json::json!({"keys": []});

        let dh = discovery_hits.clone();
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(move |_: &wiremock::Request| {
                dh.fetch_add(1, Ordering::SeqCst);
                ResponseTemplate::new(200).set_body_json(discovery_doc.clone())
            })
            .mount(&server)
            .await;

        let jh = jwks_hits.clone();
        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(move |_: &wiremock::Request| {
                jh.fetch_add(1, Ordering::SeqCst);
                ResponseTemplate::new(200).set_body_json(jwks_doc.clone())
            })
            .mount(&server)
            .await;

        let url: Url = issuer_with_slash.parse().expect("parse issuer");
        (server, url)
    }

    #[tokio::test]
    async fn cold_get_fetches_metadata_and_jwks() {
        let dh = Arc::new(AtomicUsize::new(0));
        let jh = Arc::new(AtomicUsize::new(0));
        let (_server, issuer) = fixture_issuer(dh.clone(), jh.clone()).await;
        let cache = DiscoveryCache::new(make_http());
        let snap = cache.get(&issuer).await.expect("discovery");
        assert_eq!(dh.load(Ordering::SeqCst), 1);
        // openidconnect's `discover_async` fetches the JWKS as part of
        // metadata resolution; the cache then performs a second fetch
        // to capture the raw JWKS bytes for the optional thumbprint
        // pin. Two hits total per cold refresh is the intended steady
        // state.
        assert_eq!(jh.load(Ordering::SeqCst), 2);
        assert!(!snap.jwks_bytes.is_empty());
    }

    #[tokio::test]
    async fn warm_get_does_not_refetch_within_ttl() {
        let dh = Arc::new(AtomicUsize::new(0));
        let jh = Arc::new(AtomicUsize::new(0));
        let (_server, issuer) = fixture_issuer(dh.clone(), jh.clone()).await;
        let cache = DiscoveryCache::new(make_http());
        let _ = cache.get(&issuer).await.expect("first");
        let _ = cache.get(&issuer).await.expect("second");
        let _ = cache.get(&issuer).await.expect("third");
        assert_eq!(dh.load(Ordering::SeqCst), 1, "discovery hits once");
        // Same accounting as `cold_get_fetches_metadata_and_jwks`; warm
        // `get`s are served from cache, so the JWKS hit count stays at
        // the single cold-refresh's two hits.
        assert_eq!(
            jh.load(Ordering::SeqCst),
            2,
            "jwks hits twice on cold refresh, not again"
        );
    }

    #[tokio::test]
    async fn force_refresh_within_rate_limit_errors_with_diagnostic() {
        let dh = Arc::new(AtomicUsize::new(0));
        let jh = Arc::new(AtomicUsize::new(0));
        let (_server, issuer) = fixture_issuer(dh.clone(), jh.clone()).await;
        // Compressed TTL + 60s rate-limit so the refresh path is
        // legitimately gated by the rate limit, not the TTL.
        let cache = DiscoveryCache::with_settings(
            make_http(),
            Duration::from_millis(1),
            Duration::from_secs(60),
        );
        let _ = cache.get(&issuer).await.expect("seed");
        // 100 force-refresh attempts must NOT silently serve the
        // cached snapshot. The kid-miss retry path in
        // `OidcClient::exchange_and_verify` calls `force_refresh` on
        // signature-verify failure; if the gate hands back the same
        // bytes that produced the kid-miss, the caller would loop on
        // the same `OidcIdTokenInvalid` instead of surfacing the
        // typed `OidcDiscoveryFailed("rate-limited")` ops signal.
        for _ in 0..100 {
            let result = cache.force_refresh(&issuer).await;
            let outcome = match result {
                Err(IdentityError::OidcDiscoveryFailed(reason)) => Ok(reason),
                Err(other) => Err(format!("wrong error variant: {other:?}")),
                Ok(_) => Err("unexpectedly succeeded with cached snapshot".to_owned()),
            };
            assert!(
                outcome.is_ok(),
                "force_refresh inside rate-limit must fail with OidcDiscoveryFailed: {outcome:?}",
            );
        }
        assert_eq!(
            dh.load(Ordering::SeqCst),
            1,
            "rate-limit collapses force refreshes to the one initial fetch",
        );
    }

    #[tokio::test]
    async fn pre_warm_populates_entry() {
        let dh = Arc::new(AtomicUsize::new(0));
        let jh = Arc::new(AtomicUsize::new(0));
        let (_server, issuer) = fixture_issuer(dh.clone(), jh.clone()).await;
        let cache = DiscoveryCache::new(make_http());
        cache.pre_warm(&issuer).await.expect("pre_warm");
        assert_eq!(dh.load(Ordering::SeqCst), 1);
        // Subsequent `get` is served from cache.
        let _ = cache.get(&issuer).await.expect("warm get");
        assert_eq!(dh.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn shared_http_client_invariant_holds() {
        let http = make_http();
        let cache = DiscoveryCache::new(http.clone());
        assert!(Arc::ptr_eq(cache.http(), &http));
    }

    #[tokio::test]
    async fn assert_thumbprint_matches_jwks_bytes() {
        let dh = Arc::new(AtomicUsize::new(0));
        let jh = Arc::new(AtomicUsize::new(0));
        let (_server, issuer) = fixture_issuer(dh.clone(), jh.clone()).await;
        let cache = DiscoveryCache::new(make_http());
        let snap = cache.get(&issuer).await.expect("discovery");
        let pin = jwks_thumbprint_hex(&snap.jwks_bytes);
        snap.assert_thumbprint(&pin).expect("matching pin verifies");
    }

    #[tokio::test]
    async fn assert_thumbprint_rejects_mismatch() {
        let dh = Arc::new(AtomicUsize::new(0));
        let jh = Arc::new(AtomicUsize::new(0));
        let (_server, issuer) = fixture_issuer(dh.clone(), jh.clone()).await;
        let cache = DiscoveryCache::new(make_http());
        let snap = cache.get(&issuer).await.expect("discovery");
        let bogus = "0".repeat(64);
        let result = snap.assert_thumbprint(&bogus);
        assert!(matches!(
            result,
            Err(IdentityError::OidcJwksThumbprintMismatch)
        ));
    }

    #[tokio::test]
    async fn discovery_failure_propagates_typed_error() {
        let server = MockServer::start().await;
        // No mocks installed → every request 404s.
        let cache = DiscoveryCache::new(make_http());
        let issuer: Url = server.uri().parse().expect("parse");
        let result = cache.get(&issuer).await;
        assert!(matches!(result, Err(IdentityError::OidcDiscoveryFailed(_))));
    }

    /// Spec: `kid_miss_triggers_refresh` — the kid-miss retry path is
    /// the only place the JWKS thumbprint pin gets re-asserted on a
    /// hostile rotation. This test proves the security-load-bearing
    /// piece: post-`force_refresh`, the snapshot's thumbprint reflects
    /// the rotated JWKS bytes, and the pin's `assert_thumbprint` call
    /// returns `OidcJwksThumbprintMismatch` when the rotation is
    /// hostile.
    ///
    /// The full HTTP→client kid-miss-triggers-force-refresh path needs
    /// a real RSA-signed ID token + JWKS fixture; that piece is
    /// deferred to `tests/oidc_negative.rs` in section-16 (per
    /// section-10 spec lines 478-485). What this test asserts is the
    /// security gate that fires AFTER the trigger lands.
    #[tokio::test]
    async fn force_refresh_reasserts_thumbprint_after_jwks_rotation() {
        // Initial JWKS — empty key set, thumbprint pinned for v1.
        let server = MockServer::start().await;
        let issuer_with_slash = format!("{}/", server.uri());
        let issuer_str = issuer_with_slash.trim_end_matches('/').to_owned();
        let issuer: Url = issuer_with_slash.parse().expect("parse issuer");
        let discovery_doc = serde_json::json!({
            "issuer": issuer_with_slash,
            "authorization_endpoint": format!("{issuer_str}/oauth/authorize"),
            "token_endpoint": format!("{issuer_str}/oauth/token"),
            "userinfo_endpoint": format!("{issuer_str}/oauth/userinfo"),
            "jwks_uri": format!("{issuer_str}/.well-known/jwks.json"),
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "scopes_supported": ["openid", "profile", "email"],
            "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
            "claims_supported": ["sub", "iss", "aud", "exp", "iat", "email", "email_verified", "name"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "response_modes_supported": ["query", "fragment"],
        });
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(discovery_doc.clone()))
            .mount(&server)
            .await;

        // Phase 1: serve JWKS-v1.
        let jwks_v1 = serde_json::json!({"keys": []});
        let v1_mock = Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(jwks_v1.clone()))
            .expect(1..)
            .mount_as_scoped(&server)
            .await;

        let cache = DiscoveryCache::with_settings(
            make_http(),
            // Compressed TTL so the next get() is cold; rate limit
            // does NOT gate force_refresh in this scenario because
            // the test's first get() happens at t=0 and we then sleep
            // past the rate-limit boundary by using force_refresh
            // straight away (which respects rate limit but the cold-
            // start fetch counts as the rate-limit anchor).
            Duration::from_millis(1),
            Duration::from_millis(0),
        );
        let snap_v1 = cache.get(&issuer).await.expect("seed v1");
        let pin_v1 = jwks_thumbprint_hex(&snap_v1.jwks_bytes);

        // Phase 2: rotate JWKS to v2 (different `keys` shape so
        // bytes — and therefore the thumbprint — diverge).
        drop(v1_mock);
        let jwks_v2 = serde_json::json!({
            "keys": [{
                "kty": "RSA",
                "use": "sig",
                "kid": "kid-v2-rotated",
                "alg": "RS256",
                // Synthetic; thumbprint is over the JWKS document
                // bytes, not the key contents, so we don't need a
                // real RSA modulus here.
                "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                "e": "AQAB",
            }]
        });
        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(jwks_v2.clone()))
            .mount(&server)
            .await;

        // Force-refresh runs the same code path the kid-miss retry in
        // `OidcClient::exchange_and_verify` invokes (client.rs:243-252).
        let snap_v2 = cache.force_refresh(&issuer).await.expect("force v2");
        let pin_v2 = jwks_thumbprint_hex(&snap_v2.jwks_bytes);
        assert_ne!(
            pin_v1, pin_v2,
            "rotation must produce a distinct JWKS thumbprint",
        );

        // Security gate: re-asserting the v1 pin against v2 must
        // return the typed mismatch. This is the assertion the kid-
        // miss retry path makes immediately before rebuilding the
        // verifier (client.rs:250-252).
        let result = snap_v2.assert_thumbprint(&pin_v1);
        assert!(
            matches!(result, Err(IdentityError::OidcJwksThumbprintMismatch)),
            "rotated JWKS must fail the original pin",
        );

        // Sanity: the rotated pin still verifies against the rotated
        // snapshot (no test artifact pollution).
        snap_v2
            .assert_thumbprint(&pin_v2)
            .expect("rotated pin verifies against rotated snapshot");
    }
}
