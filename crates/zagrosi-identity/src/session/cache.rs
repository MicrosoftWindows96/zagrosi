// SPDX-License-Identifier: AGPL-3.0-or-later

//! In-process LRU cache for the session-resolver fast path.
//!
//! Two-tier structure:
//!
//! - `entries`: an [`arc_swap::ArcSwap`] holding the active
//!   [`moka::future::Cache`] keyed by [`TokenHash`] carrying
//!   [`CachedSession`] values. moka builds the TTL into the cache
//!   instance at construction time, so a healthy → fail-closed
//!   transition swaps the entire cache via [`ArcSwap::store`]; the
//!   atomic swap means in-flight reads still return values from the
//!   pre-swap cache while subsequent reads land on the new one.
//!
//! - `by_session`: a [`dashmap::DashMap`] reverse index keyed by
//!   `session_id` → [`TokenHash`]. NATS-driven evictions arrive
//!   keyed by `session_id` (the broker doesn't see the raw token);
//!   this index lets the eviction handler resolve to the primary
//!   key in O(1) without scanning the cache.
//!
//! Eviction symmetry: the moka cache's eviction listener removes
//! the matching entry from `by_session` so the reverse index does
//! not leak entries when the LRU expires. The TTL-flip rebuild also
//! clears the reverse index so the new cache starts empty.

use arc_swap::ArcSwap;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use moka::future::Cache;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use uuid::Uuid;

use crate::domain::token_format::TokenHash;

/// Cached fast-path entry. Captures every field
/// [`crate::session::introspector::IdentitySessionIntrospector`]
/// needs to satisfy [`zagrosi_core::SessionIntrospector::resolve`]
/// without a DB touch.
#[derive(Debug, Clone)]
pub struct CachedSession {
    /// Session row primary key.
    pub session_id: Uuid,
    /// Owning user.
    pub user_id: Uuid,
    /// Active org at resolve time.
    pub org_id: Uuid,
    /// Hard expiry. Resolver re-checks `> now()` on every cache hit.
    pub expires_at: DateTime<Utc>,
    /// Soft revocation timestamp. Resolver returns
    /// `AuthError::Revoked` when this is `Some(_)`.
    pub revoked_at: Option<DateTime<Utc>>,
    /// Optimistic-lock counter. Frozen at the resolve-time read.
    pub version: i64,
    /// `users.password_updated_at` at resolve time. The resolver
    /// rejects sessions whose `created_at < password_updated_at`,
    /// which is the replica-local password-reset revocation
    /// invariant. Cached value matches the row read on cache miss
    /// so a successful cache hit cannot re-admit a session a
    /// password reset already invalidated.
    pub password_updated_at_at_resolve: DateTime<Utc>,
    /// AMR (RFC 8176) values copied onto the session row at issue
    /// time. The cache holds these so the resolver can hydrate the
    /// `AuthContext` without a second DB round-trip.
    pub amr: Vec<String>,
    /// Optional ACR value.
    pub acr: Option<String>,
    /// Issued-at timestamp; populates [`zagrosi_core::AuthContext`]'s
    /// `issued_at` field on resolve.
    pub created_at: DateTime<Utc>,
}

/// Two-tier cache (primary + reverse-lookup) plus the active TTL.
///
/// Cheap to clone: every field wraps an `Arc` internally.
#[derive(Clone)]
pub struct SessionCache {
    inner: Arc<SessionCacheInner>,
}

struct SessionCacheInner {
    entries: ArcSwap<Cache<TokenHash, CachedSession>>,
    by_session: Arc<DashMap<Uuid, TokenHash>>,
    capacity: u64,
    current_ttl_secs: AtomicU64,
}

impl SessionCache {
    /// Build a cache sized to `capacity` with the initial TTL `ttl`.
    /// Eviction listener mirrors removal into the reverse-lookup
    /// index so it cannot accumulate stale entries.
    #[must_use]
    pub fn new(capacity: u64, ttl: Duration) -> Self {
        let by_session: Arc<DashMap<Uuid, TokenHash>> = Arc::new(DashMap::new());
        let cache = build_cache(capacity, ttl, by_session.clone());
        let inner = Arc::new(SessionCacheInner {
            entries: ArcSwap::new(Arc::new(cache)),
            by_session,
            capacity,
            current_ttl_secs: AtomicU64::new(ttl.as_secs()),
        });
        Self { inner }
    }

    /// Currently active TTL in seconds. The health-tick task reads
    /// this to detect when a flip is required.
    #[must_use]
    pub fn ttl_secs(&self) -> u64 {
        self.inner.current_ttl_secs.load(Ordering::Relaxed)
    }

    /// Atomically swap the underlying moka cache for one built with
    /// `ttl`. Used by the health-probe task to flip between healthy
    /// and fail-closed cache windows. Idempotent — if the requested
    /// TTL already matches the live one this is a no-op.
    ///
    /// The swap also clears the reverse-lookup index because the
    /// previous cache's entries are unreachable through the new
    /// cache.
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
        let new_cache = build_cache(self.inner.capacity, ttl, self.inner.by_session.clone());
        // Drop everything keyed by the old cache before we swap so
        // a concurrent reader cannot pull a value from the swap and
        // then look it up in the freshly empty reverse index.
        self.inner.by_session.clear();
        self.inner.entries.store(Arc::new(new_cache));
    }

    /// Probe the cache. Returns `Some(...)` on hit; `None` on miss.
    pub async fn get(&self, hash: &TokenHash) -> Option<CachedSession> {
        let cache = self.inner.entries.load_full();
        cache.get(hash).await
    }

    /// Insert (or refresh) a cache entry. The primary moka entry
    /// lands first so the moka eviction listener can clean
    /// `by_session` if the reverse-index update races against a
    /// concurrent eviction.
    pub async fn insert(&self, hash: TokenHash, value: CachedSession) {
        let cache = self.inner.entries.load_full();
        let session_id = value.session_id;
        cache.insert(hash, value).await;
        self.inner.by_session.insert(session_id, hash);
    }

    /// Evict by `session_id`. NATS-driven revocations arrive keyed
    /// here; the reverse index resolves to the primary key in O(1).
    /// Returns `true` if a matching entry was found in the reverse
    /// index. The actual moka invalidation happens whether or not
    /// the index hit fired so a concurrent insert race cannot leave
    /// a phantom entry alive.
    pub async fn evict_by_session_id(&self, session_id: Uuid) -> bool {
        // Snapshot the hash without removing the index entry — the
        // moka eviction listener handles the cleanup. Using
        // `remove_if` with an equality check avoids removing a
        // freshly-inserted entry whose hash differs.
        let Some(hash) = self.inner.by_session.get(&session_id).map(|r| *r.value()) else {
            return false;
        };
        let cache = self.inner.entries.load_full();
        cache.invalidate(&hash).await;
        self.inner
            .by_session
            .remove_if(&session_id, |_, h| *h == hash);
        true
    }

    /// Evict every entry. Used during a healthy → fail-closed mode
    /// flip when the caller wants to drain in-place rather than
    /// rebuild the cache (e.g. an explicit `purge_all` admin path).
    pub fn invalidate_all(&self) {
        let cache = self.inner.entries.load_full();
        cache.invalidate_all();
        self.inner.by_session.clear();
    }

    /// Live entry count. Test-only; production code should not need
    /// this metric.
    #[must_use]
    #[cfg(test)]
    pub fn entry_count(&self) -> u64 {
        let cache = self.inner.entries.load_full();
        cache.entry_count()
    }
}

fn build_cache(
    capacity: u64,
    ttl: Duration,
    by_session: Arc<DashMap<Uuid, TokenHash>>,
) -> Cache<TokenHash, CachedSession> {
    Cache::builder()
        .max_capacity(capacity)
        .time_to_live(ttl)
        .async_eviction_listener(move |_key: Arc<TokenHash>, value: CachedSession, _cause| {
            let by_session = by_session.clone();
            Box::pin(async move {
                by_session.remove(&value.session_id);
            })
        })
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn fixture_session(session_id: u8) -> (TokenHash, CachedSession) {
        let hash = TokenHash([session_id; 32]);
        let value = CachedSession {
            session_id: Uuid::from_bytes([session_id; 16]),
            user_id: Uuid::from_bytes([0xAA; 16]),
            org_id: Uuid::from_bytes([0xBB; 16]),
            expires_at: Utc.with_ymd_and_hms(2026, 12, 31, 23, 59, 59).unwrap(),
            revoked_at: None,
            version: 1,
            password_updated_at_at_resolve: Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap(),
            amr: vec!["pwd".to_string()],
            acr: None,
            created_at: Utc.with_ymd_and_hms(2026, 5, 1, 0, 0, 0).unwrap(),
        };
        (hash, value)
    }

    #[tokio::test]
    async fn insert_then_get_round_trips() {
        let cache = SessionCache::new(8, Duration::from_secs(30));
        let (hash, value) = fixture_session(1);
        cache.insert(hash, value.clone()).await;
        let got = cache.get(&hash).await.expect("hit");
        assert_eq!(got.session_id, value.session_id);
    }

    #[tokio::test]
    async fn evict_by_session_id_removes_primary_entry() {
        let cache = SessionCache::new(8, Duration::from_secs(30));
        let (hash, value) = fixture_session(2);
        cache.insert(hash, value.clone()).await;
        let removed = cache.evict_by_session_id(value.session_id).await;
        assert!(removed);
        assert!(cache.get(&hash).await.is_none());
    }

    #[tokio::test]
    async fn invalidate_all_clears_both_tiers() {
        let cache = SessionCache::new(8, Duration::from_secs(30));
        let (hash_a, value_a) = fixture_session(1);
        let (hash_b, value_b) = fixture_session(2);
        cache.insert(hash_a, value_a).await;
        cache.insert(hash_b, value_b).await;
        cache.invalidate_all();
        // Allow moka's async invalidation a moment to settle.
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(cache.get(&hash_a).await.is_none());
        assert!(cache.get(&hash_b).await.is_none());
    }

    #[test]
    fn ttl_round_trips_through_atomic() {
        let cache = SessionCache::new(8, Duration::from_secs(30));
        assert_eq!(cache.ttl_secs(), 30);
        cache.rebuild_with_ttl(Duration::from_secs(1));
        assert_eq!(cache.ttl_secs(), 1);
    }

    #[tokio::test]
    async fn rebuild_with_ttl_clears_existing_entries() {
        let cache = SessionCache::new(8, Duration::from_secs(30));
        let (hash, value) = fixture_session(3);
        cache.insert(hash, value.clone()).await;
        assert!(cache.get(&hash).await.is_some());
        cache.rebuild_with_ttl(Duration::from_secs(1));
        // The new cache built by the rebuild starts empty; the
        // previous entry is unreachable.
        assert!(cache.get(&hash).await.is_none());
    }

    #[tokio::test]
    async fn rebuild_with_ttl_idempotent_when_unchanged() {
        let cache = SessionCache::new(8, Duration::from_secs(30));
        let (hash, value) = fixture_session(4);
        cache.insert(hash, value.clone()).await;
        // Same TTL → no rebuild, entries preserved.
        cache.rebuild_with_ttl(Duration::from_secs(30));
        assert!(cache.get(&hash).await.is_some());
    }

    #[tokio::test]
    async fn evict_with_remove_if_does_not_drop_concurrent_insert() {
        let cache = SessionCache::new(8, Duration::from_secs(30));
        let (hash_a, mut value_a) = fixture_session(5);
        cache.insert(hash_a, value_a.clone()).await;
        // Simulate a concurrent insert that re-bound the same
        // session_id to a different hash. The eviction must NOT
        // drop the new index entry.
        let hash_b = TokenHash([0xEE; 32]);
        let session_id = value_a.session_id;
        value_a.org_id = Uuid::from_bytes([0xFF; 16]);
        cache.insert(hash_b, value_a.clone()).await;
        // Now evict by the old hash via the session id; the
        // remove_if guard should keep the new (hash_b) index entry.
        cache.inner.by_session.insert(session_id, hash_a);
        let _ = cache.evict_by_session_id(session_id).await;
        // The dashmap entry that pointed at hash_a is gone, but the
        // moka entry under hash_b stays alive (the moka invalidate
        // ran against hash_a, not hash_b).
        assert!(cache.get(&hash_b).await.is_some());
    }
}
