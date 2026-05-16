// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! Personal-access-token branch of the gateway-facing introspector.
//!
//! The session introspector
//! ([`crate::session::IdentitySessionIntrospector`]) dispatches by
//! token class: `sid_*` runs the existing session-table path,
//! `pat_*` calls into [`ApiTokenResolver`] here. Both branches share
//! the same return shape (`Result<AuthContext, AuthError>`) so the
//! gateway's bearer middleware does not need to know which kind of
//! token it just resolved.
//!
//! ## Resolve flow
//!
//! 1. **Prefix + body shape**. Re-validates via
//!    [`crate::domain::token_format::parse_raw`]. Cheap defensive
//!    re-check; the dispatcher already validated once.
//! 2. **Hash**. Canonical [`crate::domain::token_format::hash_token`]
//!    chokepoint (prefix included).
//! 3. **Cache probe**. `O(1)` lookup against
//!    [`super::cache::ApiTokenCache`].
//! 4. **DB fallback**. `find_live_by_token_hash` against the
//!    `api_tokens` table. The partial-unique index guarantees ≤ 1
//!    live row per hash so cross-org collision is impossible.
//! 5. **Validate**. `revoked_at IS NULL` and
//!    `(expires_at IS NULL OR expires_at > now())`. Fail-closed on
//!    either invariant.
//! 6. **Per-token rate limit**. `RateLimitKey::PerToken` with the
//!    SHA-256 hash + [`PAT_RESOLVE_SCOPE`]. Trips before
//!    cache-insert / write-behind so a denied resolve does not move
//!    the `last_used_*` counters.
//! 7. **Cache insert + write-behind fire**.
//! 8. **Build `AuthContext`** carrying [`AuthMethod::ApiToken`] and
//!    [`TokenClass::PersonalAccessToken`].

use std::net::IpAddr;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;
use uuid::Uuid;
use zagrosi_core::{
    AuthContext, AuthError, AuthMethod, RateLimitDecision, RateLimitKey, RateLimiter,
    SessionIntrospector, TokenClass,
};

use crate::api_tokens::cache::{ApiTokenCache, CachedApiToken};
use crate::api_tokens::write_behind::{ApiTokenLastUsedSender, ApiTokenLastUsedUpdate};
use crate::domain::token_format::{TokenHash, TokenPrefix, hash_token, parse_raw};
use crate::repo::ApiTokenRepo;

/// Stable bucket scope for per-PAT rate-limit keys.
///
/// Lives as a `&'static str` so the Valkey limiter formats its
/// storage key (`rl:pat_resolve:token:<hex>`) without an extra
/// allocation; same pattern as `crate::service::signin::SIGNIN_SCOPE`.
pub const PAT_RESOLVE_SCOPE: &str = "pat_resolve";

/// Concrete PAT resolver. Cheap to clone; every dependency is an
/// `Arc`-flavoured handle.
#[derive(Clone)]
pub struct ApiTokenResolver {
    repo: ApiTokenRepo,
    cache: ApiTokenCache,
    last_used: Arc<ApiTokenLastUsedSender>,
    rate_limiter: Arc<dyn RateLimiter>,
}

impl ApiTokenResolver {
    /// Wire dependencies. The `last_used` sender is held inside an
    /// `Arc` so the resolver clones cheaply across axum state without
    /// producing a new mpsc producer per clone.
    #[must_use]
    pub fn new(
        repo: ApiTokenRepo,
        cache: ApiTokenCache,
        last_used: ApiTokenLastUsedSender,
        rate_limiter: Arc<dyn RateLimiter>,
    ) -> Self {
        Self {
            repo,
            cache,
            last_used: Arc::new(last_used),
            rate_limiter,
        }
    }

    /// Cache accessor for the NATS subscriber + admin path.
    #[must_use]
    pub const fn cache(&self) -> &ApiTokenCache {
        &self.cache
    }

    /// Resolve a raw `pat_*` token. The caller IP is unknown; the
    /// resolver fires the write-behind with `ip = None` so the
    /// `last_used_ip` column stays unset on this path.
    ///
    /// Most production callers reach the resolver via
    /// [`SessionIntrospector::resolve`] which has no IP context to
    /// surface; the gateway's bearer-IP capture middleware uses
    /// [`Self::resolve_with_observation`] below.
    pub async fn resolve(&self, raw_token: &str) -> Result<AuthContext, AuthError> {
        self.resolve_with_observation(raw_token, None).await
    }

    /// Resolve a raw `pat_*` token, recording the caller IP for the
    /// `last_used_ip` write-behind.
    pub async fn resolve_with_observation(
        &self,
        raw_token: &str,
        ip: Option<IpAddr>,
    ) -> Result<AuthContext, AuthError> {
        // 1 & 2. Prefix validation + hash.
        let (prefix, _body) = parse_raw(raw_token).map_err(|_| AuthError::MalformedPrefix)?;
        if prefix != TokenPrefix::Pat {
            return Err(AuthError::MalformedPrefix);
        }
        let hash = hash_token(raw_token);

        // 3. Cache probe.
        if let Some(entry) = self.cache.get(&hash).await {
            return self.finalise_cached(entry, hash, ip).await;
        }

        // 4. DB fallback.
        let row = self
            .repo
            .find_live_by_token_hash(&hash.0)
            .await
            .map_err(AuthError::internal)?
            .ok_or(AuthError::Unauthorized)?;

        // 5. Defense-in-depth constant-time hash compare. The B-tree
        // probe already narrowed by hash, but a future call site
        // bypassing the index would otherwise leak a non-CT compare;
        // the `subtle::ConstantTimeEq` chokepoint is the documented
        // PAT branch invariant per the section spec.
        let row_hash = TokenHash(row.token_hash);
        if !hash.ct_eq(&row_hash) {
            return Err(AuthError::Unauthorized);
        }

        // 6. Snapshot the revocation generation AFTER the DB read
        //    (we now know `row.id`) but BEFORE rate-limit work and
        //    the cache insert. Any concurrent revoke that beats us
        //    into `insert_with_guard` will bump the generation past
        //    this snapshot, so the would-be stale cache entry gets
        //    dropped. The DB-read-itself race (revoke commits while
        //    we read) is owned by Postgres MVCC: a revoke landing
        //    after our snapshot's read will surface as `revoked_at`
        //    set on the next resolve.
        let post_read_generation = self.cache.current_generation(row.id);

        // 7. Validate.
        if row.revoked_at.is_some() {
            return Err(AuthError::Revoked);
        }
        let now = Utc::now();
        if let Some(exp) = row.expires_at
            && exp <= now
        {
            return Err(AuthError::Expired);
        }

        // 8. Rate limit on first-touch path.
        self.enforce_rate_limit(&hash).await?;

        let cached = CachedApiToken {
            token_id: row.id,
            user_id: row.user_id,
            org_id: row.org_id,
            scopes: row.scopes.clone(),
            expires_at: row.expires_at,
            revoked_at: row.revoked_at,
            created_at: row.created_at,
        };

        // 9. Cache insert (guarded against a concurrent revoke) +
        //    write-behind. If the guard rejects the insert, the
        //    in-flight request still serves the AuthContext we just
        //    validated; future requests miss cache and re-read DB.
        let _ = self
            .cache
            .insert_with_guard(hash, cached.clone(), post_read_generation)
            .await;
        self.fire_last_used(cached.org_id, cached.token_id, ip);

        // 10. Build AuthContext.
        Self::context_from_cached(&cached)
    }

    async fn finalise_cached(
        &self,
        cached: CachedApiToken,
        hash: TokenHash,
        ip: Option<IpAddr>,
    ) -> Result<AuthContext, AuthError> {
        // Re-validate revocation / expiry at every cache hit. The
        // entry could have aged across an expiry boundary since
        // insertion, and the NATS subscriber may not have raced ahead
        // of us with an evict for a freshly-revoked token.
        if cached.revoked_at.is_some() {
            return Err(AuthError::Revoked);
        }
        let now = Utc::now();
        if let Some(exp) = cached.expires_at
            && exp <= now
        {
            return Err(AuthError::Expired);
        }
        // Per-request rate limit. Runs on cache hits too because the
        // budget is per-request, not per-DB-lookup.
        self.enforce_rate_limit(&hash).await?;

        self.fire_last_used(cached.org_id, cached.token_id, ip);
        Self::context_from_cached(&cached)
    }

    fn context_from_cached(cached: &CachedApiToken) -> Result<AuthContext, AuthError> {
        // PATs do not carry the AMR / ACR claim shape sessions do.
        // We tag a single AMR string `pat` so the sign-in audit trail
        // can attribute the call without reaching for the
        // `auth_method` field. RFC 8176 explicitly leaves room for
        // application-defined values.
        let amr = vec!["pat".to_string()];
        // Long-lived PATs may have `expires_at = NULL`. The
        // `AuthContext::new` invariant requires `issued_at < expires_at`,
        // so we synthesise an effective expiry far enough in the
        // future that it is indistinguishable from "no expiry" while
        // still satisfying the constructor. `checked_add_signed`
        // guards against the (otherwise unreachable) overflow at the
        // far end of `DateTime<Utc>`'s range so a fuzz / future
        // migration cannot panic the resolver.
        let effective_expires_at = match cached.expires_at {
            Some(exp) => exp,
            None => cached
                .created_at
                .checked_add_signed(chrono::Duration::days(36_500))
                .ok_or_else(|| {
                    AuthError::internal(std::io::Error::other(
                        "synthesised PAT expiry overflows DateTime<Utc>",
                    ))
                })?,
        };
        let ctx = AuthContext::new(
            cached.user_id,
            cached.token_id,
            cached.org_id,
            AuthMethod::ApiToken,
            TokenClass::PersonalAccessToken,
            amr,
            None,
            cached.created_at,
            effective_expires_at,
            Uuid::now_v7(),
        )
        .map_err(AuthError::internal)?;
        Ok(ctx.with_scopes(cached.scopes.clone()))
    }

    async fn enforce_rate_limit(&self, hash: &TokenHash) -> Result<(), AuthError> {
        let key = RateLimitKey::PerToken {
            token_hash: hash.0,
            scope: PAT_RESOLVE_SCOPE,
        };
        match self.rate_limiter.check(&key).await {
            Ok(RateLimitDecision::Allow { .. }) => Ok(()),
            Ok(
                RateLimitDecision::Deny { retry_after }
                | RateLimitDecision::LockedOut { retry_after, .. },
            ) => Err(AuthError::RateLimited { retry_after }),
            Ok(_) => Err(AuthError::RateLimited {
                retry_after: std::time::Duration::from_secs(60),
            }),
            Err(err) => Err(AuthError::internal(err)),
        }
    }

    fn fire_last_used(&self, org_id: Uuid, token_id: Uuid, ip: Option<IpAddr>) {
        let _ = self.last_used.try_send(ApiTokenLastUsedUpdate {
            org_id,
            token_id,
            ip,
            seen_at: Utc::now(),
        });
    }
}

#[async_trait]
impl SessionIntrospector for ApiTokenResolver {
    async fn resolve(&self, raw_token: &str) -> Result<AuthContext, AuthError> {
        self.resolve_with_observation(raw_token, None).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use static_assertions::assert_impl_all;

    assert_impl_all!(ApiTokenResolver: Send, Sync, Clone);

    #[test]
    fn pat_resolve_scope_constant_is_stable() {
        // The scope string is part of the Valkey storage-key format
        // (`rl:pat_resolve:token:<hex>`). Renaming requires a
        // coordinated migration of in-flight rate-limit state in
        // production; guard against accidental drift.
        assert_eq!(PAT_RESOLVE_SCOPE, "pat_resolve");
    }
}
