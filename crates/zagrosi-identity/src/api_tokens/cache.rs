// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! In-process LRU cache for the personal-access-token resolver.
//!
//! Mirrors the [`crate::session::SessionCache`] shape but stores
//! [`CachedApiToken`] keyed by [`TokenHash`] rather than session
//! entries. The two caches are deliberately separate so a session
//! eviction cannot touch a PAT entry and vice-versa, and so the
//! healthy / fail-closed TTL flips can move at independent cadence
//! per token class.
//!
//! ## Reverse index
//!
//! `by_token_id` resolves a token-id-keyed eviction (administrative
//! revocation, future NATS broadcast) back to the primary
//! [`TokenHash`] in O(1). The moka eviction listener mirrors removal
//! into this index so the reverse lookup never accumulates stale
//! entries.
//!
//! ## TTL flip
//!
//! [`ApiTokenCache::rebuild_with_ttl`] swaps the underlying moka
//! cache atomically; in-flight reads land on the pre-swap cache
//! while subsequent reads see the post-swap one. The reverse index
//! is cleared at the same time because every entry it pointed at is
//! unreachable through the new cache.
//!
//! ## Stale-write guard (revocation generation counter)
//!
//! Concurrent revoke + resolve can leave a stale cache entry: the
//! resolver reads a live row, the revoker bumps `revoked_at` and
//! evicts a (possibly absent) cache slot, then the resolver inserts
//! a `CachedApiToken { revoked_at: None }` snapshot. Subsequent
//! cache hits would serve the stale entry until TTL expiry.
//!
//! [`ApiTokenCache::current_generation`] returns a per-token-id
//! counter that [`ApiTokenCache::evict_by_token_id`] increments on
//! every revoke. Resolvers capture the generation BEFORE the DB
//! read and call [`ApiTokenCache::insert_with_guard`]; the insert
//! is dropped if the live generation no longer matches the snapshot.
//! The caller still serves the in-flight request because the row
//! was observed live at read time, but no stale entry is primed for
//! future hits.

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
/// [`super::resolver::ApiTokenResolver`] needs to satisfy a resolve
/// without a DB touch.
#[derive(Debug, Clone)]
pub struct CachedApiToken {
    /// Token row primary key.
    pub token_id: Uuid,
    /// Owning user.
    pub user_id: Uuid,
    /// Owning org.
    pub org_id: Uuid,
    /// Persisted scope list.
    pub scopes: Vec<String>,
    /// Optional hard expiry. Resolver re-checks `> now()` on every
    /// cache hit because the cached value may have aged past expiry
    /// since insertion.
    pub expires_at: Option<DateTime<Utc>>,
    /// Soft revocation timestamp. Resolver returns
    /// `AuthError::Revoked` when this is `Some(_)`.
    pub revoked_at: Option<DateTime<Utc>>,
    /// Issued-at timestamp; populates the resolved
    /// `AuthContext::issued_at`.
    pub created_at: DateTime<Utc>,
}

/// Two-tier cache (primary + reverse-lookup) plus the active TTL.
///
/// Cheap to clone; every field wraps an `Arc` internally.
#[derive(Clone)]
pub struct ApiTokenCache {
    inner: Arc<ApiTokenCacheInner>,
}

struct ApiTokenCacheInner {
    entries: ArcSwap<Cache<TokenHash, CachedApiToken>>,
    by_token_id: Arc<DashMap<Uuid, TokenHash>>,
    /// Per-token revocation generation counter. Incremented by
    /// every [`ApiTokenCache::evict_by_token_id`] call so an
    /// in-flight resolve that snapshotted the prior value cannot
    /// prime a stale cache entry after revocation.
    revocations: Arc<DashMap<Uuid, u64>>,
    capacity: u64,
    current_ttl_secs: AtomicU64,
}

impl ApiTokenCache {
    /// Build a cache sized to `capacity` with the initial TTL `ttl`.
    /// Eviction listener mirrors removal into the reverse-lookup
    /// index so it cannot accumulate stale entries.
    #[must_use]
    pub fn new(capacity: u64, ttl: Duration) -> Self {
        let by_token_id: Arc<DashMap<Uuid, TokenHash>> = Arc::new(DashMap::new());
        let revocations: Arc<DashMap<Uuid, u64>> = Arc::new(DashMap::new());
        let cache = build_cache(capacity, ttl, by_token_id.clone());
        let inner = Arc::new(ApiTokenCacheInner {
            entries: ArcSwap::new(Arc::new(cache)),
            by_token_id,
            revocations,
            capacity,
            current_ttl_secs: AtomicU64::new(ttl.as_secs()),
        });
        Self { inner }
    }

    /// Snapshot the current revocation generation for `token_id`.
    ///
    /// Resolvers call this BEFORE the DB read so a subsequent
    /// [`Self::evict_by_token_id`] (driven by a concurrent revoke)
    /// will bump the counter past the snapshot, causing the
    /// follow-up [`Self::insert_with_guard`] to drop the would-be
    /// stale entry.
    #[must_use]
    pub fn current_generation(&self, token_id: Uuid) -> u64 {
        self.inner
            .revocations
            .get(&token_id)
            .map_or(0, |g| *g.value())
    }

    /// Currently active TTL in seconds. The health-tick task reads
    /// this to detect when a flip is required.
    #[must_use]
    pub fn ttl_secs(&self) -> u64 {
        self.inner.current_ttl_secs.load(Ordering::Relaxed)
    }

    /// Atomically swap the underlying moka cache for one built with
    /// `ttl`. Idempotent: if the requested TTL already matches the
    /// live one this is a no-op. Clears the reverse-lookup index
    /// because the previous cache's entries are unreachable through
    /// the new cache.
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

    /// Probe the cache. Returns `Some(...)` on hit; `None` on miss.
    pub async fn get(&self, hash: &TokenHash) -> Option<CachedApiToken> {
        let cache = self.inner.entries.load_full();
        cache.get(hash).await
    }

    /// Insert (or refresh) a cache entry without the stale-write
    /// guard. Use [`Self::insert_with_guard`] from any code path
    /// where a concurrent revoke could race the insert.
    pub async fn insert(&self, hash: TokenHash, value: CachedApiToken) {
        let cache = self.inner.entries.load_full();
        let token_id = value.token_id;
        cache.insert(hash, value).await;
        self.inner.by_token_id.insert(token_id, hash);
    }

    /// Insert a cache entry only when the revocation generation
    /// captured by the caller still matches the live counter.
    ///
    /// Returns `true` when the entry landed; `false` when a
    /// concurrent revoke bumped the generation past `snapshot`,
    /// causing the entry to be dropped to prevent stale cache
    /// reads. Callers MUST capture `snapshot` via
    /// [`Self::current_generation`] BEFORE the DB read that
    /// produced `value`.
    pub async fn insert_with_guard(
        &self,
        hash: TokenHash,
        value: CachedApiToken,
        snapshot: u64,
    ) -> bool {
        if self.current_generation(value.token_id) != snapshot {
            return false;
        }
        self.insert(hash, value).await;
        true
    }

    /// Evict by token-id. Returns `true` if a matching reverse-index
    /// entry existed at call time.
    ///
    /// ALWAYS bumps the per-token revocation-generation counter,
    /// even when no reverse-index entry was found, so a concurrent
    /// resolve that has already snapshotted the prior generation
    /// and is about to insert a now-stale entry will be rejected by
    /// [`Self::insert_with_guard`].
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

    /// Increment the per-token revocation generation. Public so the
    /// service layer can flag "this token will be revoked" before
    /// the DB UPDATE lands, closing the race where the UPDATE
    /// returns success but the resolver's snapshot was taken
    /// between the read and the UPDATE.
    pub fn bump_generation(&self, token_id: Uuid) {
        self.inner
            .revocations
            .entry(token_id)
            .and_modify(|g| *g = g.saturating_add(1))
            .or_insert(1);
    }

    /// Evict every entry. Used during a healthy → fail-closed mode
    /// flip when the caller wants to drain in-place rather than
    /// rebuild the cache.
    pub fn invalidate_all(&self) {
        let cache = self.inner.entries.load_full();
        cache.invalidate_all();
        self.inner.by_token_id.clear();
    }

    /// Live entry count.
    ///
    /// Used by integration tests + the admin observability surface
    /// to surface cache pressure. The number is approximate (moka
    /// reports the size after pending eviction work has settled).
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
) -> Cache<TokenHash, CachedApiToken> {
    Cache::builder()
        .max_capacity(capacity)
        .time_to_live(ttl)
        .async_eviction_listener(move |_key: Arc<TokenHash>, value: CachedApiToken, _cause| {
            let by_token_id = by_token_id.clone();
            Box::pin(async move {
                by_token_id.remove(&value.token_id);
            })
        })
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn fixture_token(byte: u8) -> (TokenHash, CachedApiToken) {
        let hash = TokenHash([byte; 32]);
        let value = CachedApiToken {
            token_id: Uuid::from_bytes([byte; 16]),
            user_id: Uuid::from_bytes([0xAA; 16]),
            org_id: Uuid::from_bytes([0xBB; 16]),
            scopes: vec!["tokens:read".to_string()],
            expires_at: Some(Utc.with_ymd_and_hms(2026, 12, 31, 23, 59, 59).unwrap()),
            revoked_at: None,
            created_at: Utc.with_ymd_and_hms(2026, 5, 1, 0, 0, 0).unwrap(),
        };
        (hash, value)
    }

    #[tokio::test]
    async fn insert_then_get_round_trips() {
        let cache = ApiTokenCache::new(8, Duration::from_secs(30));
        let (hash, value) = fixture_token(1);
        cache.insert(hash, value.clone()).await;
        let got = cache.get(&hash).await.expect("hit");
        assert_eq!(got.token_id, value.token_id);
        assert_eq!(got.scopes, vec!["tokens:read".to_string()]);
    }

    #[tokio::test]
    async fn evict_by_token_id_removes_primary_entry() {
        let cache = ApiTokenCache::new(8, Duration::from_secs(30));
        let (hash, value) = fixture_token(2);
        cache.insert(hash, value.clone()).await;
        let removed = cache.evict_by_token_id(value.token_id).await;
        assert!(removed);
        assert!(cache.get(&hash).await.is_none());
    }

    #[tokio::test]
    async fn invalidate_all_clears_both_tiers() {
        let cache = ApiTokenCache::new(8, Duration::from_secs(30));
        let (hash_a, value_a) = fixture_token(1);
        let (hash_b, value_b) = fixture_token(2);
        cache.insert(hash_a, value_a).await;
        cache.insert(hash_b, value_b).await;
        cache.invalidate_all();
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(cache.get(&hash_a).await.is_none());
        assert!(cache.get(&hash_b).await.is_none());
    }

    #[test]
    fn ttl_round_trips_through_atomic() {
        let cache = ApiTokenCache::new(8, Duration::from_secs(30));
        assert_eq!(cache.ttl_secs(), 30);
        cache.rebuild_with_ttl(Duration::from_secs(1));
        assert_eq!(cache.ttl_secs(), 1);
    }

    #[tokio::test]
    async fn rebuild_with_ttl_clears_existing_entries() {
        let cache = ApiTokenCache::new(8, Duration::from_secs(30));
        let (hash, value) = fixture_token(3);
        cache.insert(hash, value.clone()).await;
        assert!(cache.get(&hash).await.is_some());
        cache.rebuild_with_ttl(Duration::from_secs(1));
        assert!(cache.get(&hash).await.is_none());
    }

    #[tokio::test]
    async fn rebuild_with_ttl_idempotent_when_unchanged() {
        let cache = ApiTokenCache::new(8, Duration::from_secs(30));
        let (hash, value) = fixture_token(4);
        cache.insert(hash, value.clone()).await;
        cache.rebuild_with_ttl(Duration::from_secs(30));
        assert!(cache.get(&hash).await.is_some());
    }
}
