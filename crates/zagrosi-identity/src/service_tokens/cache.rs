// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! In-process LRU cache for the service-token resolver.
//!
//! Structurally identical to [`crate::api_tokens::ApiTokenCache`]
//! (atomic-swap moka backend, reverse `by_token_id` index, healthy /
//! fail-closed TTL flip, per-token revocation-generation guard) but
//! stores [`CachedServiceToken`] keyed by [`TokenHash`]. The caches
//! are deliberately separate per token class so an eviction on one
//! class cannot touch another and the TTL flips move independently.
//!
//! See the `api_tokens::cache` module docs for the stale-write guard
//! rationale; the mechanism here is the same.

use arc_swap::ArcSwap;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use moka::future::Cache;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use uuid::Uuid;

use crate::domain::token_format::TokenHash;

/// Cached fast-path entry: everything
/// [`super::resolver::ServiceTokenResolver`] needs to satisfy a
/// resolve without a DB touch. No `expires_at` — the
/// `service_tokens` schema has no expiry column; revocation +
/// soft-delete are the only terminal states.
#[derive(Debug, Clone)]
pub struct CachedServiceToken {
    /// Row primary key.
    pub token_id: Uuid,
    /// Caller identity (audit / `AuthContext` attribution).
    pub service_name: String,
    /// NATS-subject allowlist surfaced via `AuthContext` scopes.
    pub allowed_subjects: Vec<String>,
    /// Soft revocation timestamp; resolver returns
    /// `AuthError::Revoked` when `Some(_)`.
    pub revoked_at: Option<DateTime<Utc>>,
    /// Issued-at; populates the resolved `AuthContext::issued_at`.
    pub created_at: DateTime<Utc>,
}

/// Two-tier cache (primary + reverse-lookup) plus the active TTL.
/// Cheap to clone; every field wraps an `Arc`.
#[derive(Clone)]
pub struct ServiceTokenCache {
    inner: Arc<ServiceTokenCacheInner>,
}

struct ServiceTokenCacheInner {
    entries: ArcSwap<Cache<TokenHash, CachedServiceToken>>,
    by_token_id: Arc<DashMap<Uuid, TokenHash>>,
    revocations: Arc<DashMap<Uuid, u64>>,
    capacity: u64,
    current_ttl_secs: AtomicU64,
}

impl ServiceTokenCache {
    /// Build a cache sized to `capacity` with initial TTL `ttl`.
    #[must_use]
    pub fn new(capacity: u64, ttl: Duration) -> Self {
        let by_token_id: Arc<DashMap<Uuid, TokenHash>> = Arc::new(DashMap::new());
        let revocations: Arc<DashMap<Uuid, u64>> = Arc::new(DashMap::new());
        let cache = build_cache(capacity, ttl, by_token_id.clone());
        Self {
            inner: Arc::new(ServiceTokenCacheInner {
                entries: ArcSwap::new(Arc::new(cache)),
                by_token_id,
                revocations,
                capacity,
                current_ttl_secs: AtomicU64::new(ttl.as_secs()),
            }),
        }
    }

    /// Snapshot the current revocation generation for `token_id`.
    ///
    /// The resolver takes this snapshot AFTER the DB read (it needs
    /// `row.id` to key the counter) but BEFORE
    /// [`Self::insert_with_guard`]: a concurrent revoke that calls
    /// [`Self::bump_generation`] / [`Self::evict_by_token_id`] in
    /// that window moves the counter past the snapshot, so the
    /// follow-up guarded insert drops the would-be-stale entry. The
    /// service layer additionally bumps BEFORE its revoke `UPDATE`
    /// so a resolver that snapshotted before the bump is also
    /// rejected. (Identical contract to `ApiTokenCache`.)
    #[must_use]
    pub fn current_generation(&self, token_id: Uuid) -> u64 {
        self.inner
            .revocations
            .get(&token_id)
            .map_or(0, |g| *g.value())
    }

    /// Currently active TTL in seconds.
    #[must_use]
    pub fn ttl_secs(&self) -> u64 {
        self.inner.current_ttl_secs.load(Ordering::Relaxed)
    }

    /// Atomically swap the moka cache for one built with `ttl`.
    /// Idempotent when the TTL is unchanged. Clears the reverse
    /// index because the prior cache's entries are unreachable.
    pub fn rebuild_with_ttl(&self, ttl: Duration) {
        let new_secs = ttl.as_secs();
        if self
            .inner
            .current_ttl_secs
            .swap(new_secs, Ordering::Relaxed)
            == new_secs
        {
            return;
        }
        let new_cache = build_cache(self.inner.capacity, ttl, self.inner.by_token_id.clone());
        self.inner.by_token_id.clear();
        self.inner.entries.store(Arc::new(new_cache));
    }

    /// Probe the cache.
    pub async fn get(&self, hash: &TokenHash) -> Option<CachedServiceToken> {
        let cache = self.inner.entries.load_full();
        cache.get(hash).await
    }

    /// Insert without the stale-write guard.
    pub async fn insert(&self, hash: TokenHash, value: CachedServiceToken) {
        let cache = self.inner.entries.load_full();
        let token_id = value.token_id;
        cache.insert(hash, value).await;
        self.inner.by_token_id.insert(token_id, hash);
    }

    /// Insert only when the caller's generation snapshot still
    /// matches the live counter. Returns `false` (entry dropped)
    /// when a concurrent revoke bumped the generation.
    pub async fn insert_with_guard(
        &self,
        hash: TokenHash,
        value: CachedServiceToken,
        snapshot: u64,
    ) -> bool {
        if self.current_generation(value.token_id) != snapshot {
            return false;
        }
        self.insert(hash, value).await;
        true
    }

    /// Evict by token-id. Always bumps the revocation generation
    /// (even with no reverse-index hit) so an in-flight resolve that
    /// snapshotted the prior generation cannot prime a stale entry.
    pub async fn evict_by_token_id(&self, token_id: Uuid) -> bool {
        self.bump_generation(token_id);
        let Some(hash) = self.inner.by_token_id.get(&token_id).map(|r| *r.value()) else {
            return false;
        };
        let cache = self.inner.entries.load_full();
        cache.invalidate(&hash).await;
        self.inner
            .by_token_id
            .remove_if(&token_id, |_, h| *h == hash);
        true
    }

    /// Increment the per-token revocation generation. The service
    /// layer calls this BEFORE the revoke UPDATE so a resolver that
    /// snapshotted the prior value gets its insert rejected.
    pub fn bump_generation(&self, token_id: Uuid) {
        self.inner
            .revocations
            .entry(token_id)
            .and_modify(|g| *g = g.saturating_add(1))
            .or_insert(1);
    }

    /// Evict every entry (healthy → fail-closed drain-in-place).
    pub fn invalidate_all(&self) {
        let cache = self.inner.entries.load_full();
        cache.invalidate_all();
        self.inner.by_token_id.clear();
    }

    /// Approximate live entry count (observability / tests).
    #[must_use]
    pub fn entry_count(&self) -> u64 {
        let cache = self.inner.entries.load_full();
        cache.entry_count()
    }
}

fn build_cache(
    capacity: u64,
    ttl: Duration,
    by_token_id: Arc<DashMap<Uuid, TokenHash>>,
) -> Cache<TokenHash, CachedServiceToken> {
    Cache::builder()
        .max_capacity(capacity)
        .time_to_live(ttl)
        .async_eviction_listener(
            move |_key: Arc<TokenHash>, value: CachedServiceToken, _cause| {
                let by_token_id = by_token_id.clone();
                Box::pin(async move {
                    by_token_id.remove(&value.token_id);
                })
            },
        )
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn fixture(byte: u8) -> (TokenHash, CachedServiceToken) {
        let hash = TokenHash([byte; 32]);
        let value = CachedServiceToken {
            token_id: Uuid::from_bytes([byte; 16]),
            service_name: "email-worker".to_string(),
            allowed_subjects: vec!["email.outbox.queue".to_string()],
            revoked_at: None,
            created_at: Utc.with_ymd_and_hms(2026, 5, 1, 0, 0, 0).unwrap(),
        };
        (hash, value)
    }

    #[tokio::test]
    async fn insert_then_get_round_trips() {
        let cache = ServiceTokenCache::new(8, Duration::from_secs(30));
        let (hash, value) = fixture(1);
        cache.insert(hash, value.clone()).await;
        let got = cache.get(&hash).await.expect("hit");
        assert_eq!(got.token_id, value.token_id);
        assert_eq!(got.allowed_subjects, value.allowed_subjects);
    }

    #[tokio::test]
    async fn evict_by_token_id_removes_and_bumps_generation() {
        let cache = ServiceTokenCache::new(8, Duration::from_secs(30));
        let (hash, value) = fixture(2);
        cache.insert(hash, value.clone()).await;
        let g0 = cache.current_generation(value.token_id);
        assert!(cache.evict_by_token_id(value.token_id).await);
        assert!(cache.get(&hash).await.is_none());
        assert!(cache.current_generation(value.token_id) > g0);
    }

    #[tokio::test]
    async fn insert_with_guard_drops_when_generation_moved() {
        let cache = ServiceTokenCache::new(8, Duration::from_secs(30));
        let (hash, value) = fixture(3);
        let snap = cache.current_generation(value.token_id);
        cache.bump_generation(value.token_id);
        assert!(!cache.insert_with_guard(hash, value.clone(), snap).await);
        assert!(cache.get(&hash).await.is_none());
    }

    #[test]
    fn ttl_round_trips_through_atomic() {
        let cache = ServiceTokenCache::new(8, Duration::from_secs(30));
        assert_eq!(cache.ttl_secs(), 30);
        cache.rebuild_with_ttl(Duration::from_secs(1));
        assert_eq!(cache.ttl_secs(), 1);
    }
}
