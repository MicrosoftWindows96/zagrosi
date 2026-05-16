// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! Domain-verification cache.
//!
//! `(domain, challenge_token)` keys onto the most recent
//! [`VerifyOutcome`] from the dual-resolver path. The cache short-
//! circuits repeated verify attempts inside the configured TTL
//! window so an admin spamming the verify button does not flood
//! the upstream resolvers.
//!
//! Failed outcomes are NOT cached — operators sometimes fix the
//! TXT record between attempts and we want them to see the
//! correction immediately. Verified outcomes ARE cached so a
//! second verify within the TTL completes instantly without a
//! resolver round-trip.

use std::sync::Arc;
use std::time::Duration;

use moka::future::Cache;

use super::dns::VerifyOutcome;

/// Composite cache key. Includes the challenge token so a
/// re-issued challenge for the same domain (e.g. an admin rotated
/// the token before re-publishing TXT) does not hit a stale
/// success entry.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct DomainKey {
    /// Lowercased, IDNA-folded domain. The `lookup_domain` field
    /// of [`super::email_normalise::NormalisedEmail`] feeds this
    /// directly.
    pub domain: String,
    /// `vrf_*`-prefixed challenge token persisted in
    /// `org_idp_domains.challenge_token`.
    pub challenge_token: String,
}

/// Wrapper around a moka cache so callers cannot accidentally
/// cache a [`VerifyOutcome::Failed`] entry. The wrapper is the
/// only path through which the routing handlers read or write the
/// cache.
#[derive(Clone)]
pub struct DomainVerifyCache {
    inner: Cache<DomainKey, VerifyOutcome>,
}

impl DomainVerifyCache {
    /// Build a fresh cache bounded by `capacity` entries with a
    /// `ttl_minutes`-minute TTL on each entry. Both bounds come
    /// from [`crate::config::DnsConfig`].
    #[must_use]
    pub fn new(capacity: u64, ttl_minutes: u32) -> Self {
        let inner = Cache::builder()
            .max_capacity(capacity)
            .time_to_live(Duration::from_secs(
                u64::from(ttl_minutes).saturating_mul(60),
            ))
            .build();
        Self { inner }
    }

    /// Wrap into the `Arc<DomainVerifyCache>` shape consumed by
    /// the routing state.
    #[must_use]
    pub fn into_arc(self) -> Arc<Self> {
        Arc::new(self)
    }

    /// Read a cached entry. Returns `Some` only when the previous
    /// outcome was [`VerifyOutcome::Verified`]; failures are not
    /// cached so the lookup transparently misses.
    pub async fn get(&self, key: &DomainKey) -> Option<VerifyOutcome> {
        self.inner.get(key).await
    }

    /// Insert an outcome. Failures are dropped silently so
    /// operators see the latest resolver state on retry.
    pub async fn insert(&self, key: DomainKey, outcome: VerifyOutcome) {
        if matches!(outcome, VerifyOutcome::Verified { .. }) {
            self.inner.insert(key, outcome).await;
        }
    }

    /// Approximate live-entry count. Used by tests + diagnostics
    /// (the moka counter is best-effort, not authoritative).
    #[must_use]
    pub fn entry_count(&self) -> u64 {
        self.inner.entry_count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(domain: &str, token: &str) -> DomainKey {
        DomainKey {
            domain: domain.to_string(),
            challenge_token: token.to_string(),
        }
    }

    #[tokio::test]
    async fn caches_verified_outcomes() {
        let cache = DomainVerifyCache::new(100, 10);
        let k = key("acme.com", "vrf_abc");
        let outcome = VerifyOutcome::Verified {
            resolver_path: "1.1.1.1+9.9.9.9".to_string(),
        };
        cache.insert(k.clone(), outcome.clone()).await;
        cache.inner.run_pending_tasks().await;
        assert_eq!(cache.get(&k).await, Some(outcome));
    }

    #[tokio::test]
    async fn does_not_cache_failed_outcomes() {
        let cache = DomainVerifyCache::new(100, 10);
        let k = key("acme.com", "vrf_abc");
        let outcome = VerifyOutcome::Failed {
            reason: super::super::dns::VerifyFailure::NxDomain,
            resolver_path: "1.1.1.1+9.9.9.9".to_string(),
        };
        cache.insert(k.clone(), outcome).await;
        cache.inner.run_pending_tasks().await;
        assert!(cache.get(&k).await.is_none());
    }

    #[tokio::test]
    async fn challenge_token_participates_in_key() {
        let cache = DomainVerifyCache::new(100, 10);
        let v_old = VerifyOutcome::Verified {
            resolver_path: "1.1.1.1+9.9.9.9".to_string(),
        };
        cache.insert(key("acme.com", "vrf_old"), v_old).await;
        cache.inner.run_pending_tasks().await;
        // Re-issued challenge with a fresh token MUST miss.
        assert!(cache.get(&key("acme.com", "vrf_new")).await.is_none());
    }
}
