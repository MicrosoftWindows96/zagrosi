// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! Bounded write-behind channel for personal-access-token
//! `last_used_*` updates.
//!
//! Mirrors [`crate::session::write_behind`] but for the `api_tokens`
//! table. Each successful resolve emits an
//! [`ApiTokenLastUsedUpdate`] onto the bounded channel; a background
//! drain task batches the updates and issues coalesced
//! `UPDATE api_tokens SET last_used_at = ..., last_used_ip = ...`
//! statements at most once per token per minute.
//!
//! Channel-full silently drops the update; `last_used_*` is
//! best-effort observability, not a security primitive. The dropped
//! update is acceptable because the next resolve produces another
//! event within the cache TTL window.

use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::net::IpAddr;
use tokio::sync::mpsc;
use tracing::{debug, warn};
use uuid::Uuid;

use crate::repo::{ApiTokenRepo, OrgScoped};

/// Coalescing window: at most one DB update per `(org_id, token_id)`
/// per `COALESCE_WINDOW`. Identical cadence to the session
/// write-behind so the two drain tasks share a single timer.
pub const COALESCE_WINDOW: chrono::TimeDelta = chrono::TimeDelta::seconds(60);

/// Single `last_used_*` update event.
#[derive(Debug, Clone, Copy)]
pub struct ApiTokenLastUsedUpdate {
    /// Owning org. The drain task wraps the repo in
    /// [`OrgScoped`] using this id, so a cross-org probe never
    /// reaches the row through this channel.
    pub org_id: Uuid,
    /// Token row whose last-used columns to bump.
    pub token_id: Uuid,
    /// Source IP that introspected the token (when known).
    pub ip: Option<IpAddr>,
    /// Wall-clock time the resolver observed the token.
    pub seen_at: DateTime<Utc>,
}

/// Sender half. Cheap to clone; cloning shares the underlying queue.
#[derive(Debug, Clone)]
pub struct ApiTokenLastUsedSender {
    inner: mpsc::Sender<ApiTokenLastUsedUpdate>,
}

impl ApiTokenLastUsedSender {
    /// Try to enqueue an update without blocking. Channel-full
    /// silently drops the event (best-effort metadata semantic).
    /// Returns `true` if the event landed on the queue.
    pub fn try_send(&self, event: ApiTokenLastUsedUpdate) -> bool {
        match self.inner.try_send(event) {
            Ok(()) => true,
            Err(mpsc::error::TrySendError::Full(_)) => {
                debug!(token_id = %event.token_id, "api-token last_used write-behind queue full; dropping update");
                false
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                warn!("api-token last_used write-behind channel closed");
                false
            }
        }
    }
}

/// Receiver half.
pub struct ApiTokenLastUsedReceiver {
    inner: mpsc::Receiver<ApiTokenLastUsedUpdate>,
    coalesce: HashMap<(Uuid, Uuid), ApiTokenLastUsedUpdate>,
}

impl ApiTokenLastUsedReceiver {
    /// Drain pending events into the coalescing map. Returns the
    /// number of post-coalesce events admitted (≤ events received).
    pub fn drain_pending(&mut self, max: usize) -> usize {
        let mut consumed = 0;
        for _ in 0..max {
            match self.inner.try_recv() {
                Ok(event) => {
                    let key = (event.org_id, event.token_id);
                    let prior = self.coalesce.get(&key).map(|p| p.seen_at);
                    let should_update = prior
                        .is_none_or(|t| event.seen_at.signed_duration_since(t) >= COALESCE_WINDOW);
                    if should_update {
                        self.coalesce.insert(key, event);
                        consumed += 1;
                    }
                }
                Err(mpsc::error::TryRecvError::Empty | mpsc::error::TryRecvError::Disconnected) => {
                    break;
                }
            }
        }
        consumed
    }

    /// Take the coalesced batch, leaving the receiver ready for the
    /// next drain cycle. Drain task calls this then issues per-token
    /// UPDATEs through the org-scoped repo.
    pub fn take_batch(&mut self) -> Vec<ApiTokenLastUsedUpdate> {
        let mut out = Vec::with_capacity(self.coalesce.len());
        for (_, event) in self.coalesce.drain() {
            out.push(event);
        }
        out
    }
}

/// Build a bounded write-behind channel sized to `capacity`.
#[must_use]
pub fn channel(capacity: usize) -> (ApiTokenLastUsedSender, ApiTokenLastUsedReceiver) {
    let (tx, rx) = mpsc::channel(capacity);
    (
        ApiTokenLastUsedSender { inner: tx },
        ApiTokenLastUsedReceiver {
            inner: rx,
            coalesce: HashMap::new(),
        },
    )
}

/// Drain the receiver and apply the coalesced batch through the
/// org-scoped repo. Errors are logged and swallowed so a transient
/// DB hiccup does not crash the drain task.
///
/// Returns the number of UPDATEs issued (post-coalesce). Test
/// hooks rely on the count to assert the coalescing invariant.
pub async fn drain_once(
    rx: &mut ApiTokenLastUsedReceiver,
    repo: &ApiTokenRepo,
    max_events: usize,
) -> usize {
    rx.drain_pending(max_events);
    let batch = rx.take_batch();
    let count = batch.len();
    for event in batch {
        let scoped = OrgScoped::new(repo, event.org_id);
        if let Err(err) = scoped
            .update_last_used(event.token_id, event.seen_at, event.ip)
            .await
        {
            warn!(
                token_id = %event.token_id,
                org_id = %event.org_id,
                error = %err,
                "api-token last_used UPDATE failed; dropping event",
            );
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn fixture_event(token_byte: u8, seen_secs: i64) -> ApiTokenLastUsedUpdate {
        ApiTokenLastUsedUpdate {
            org_id: Uuid::from_bytes([0xCC; 16]),
            token_id: Uuid::from_bytes([token_byte; 16]),
            ip: Some(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
            seen_at: Utc.timestamp_opt(seen_secs, 0).unwrap(),
        }
    }

    #[tokio::test]
    async fn try_send_returns_true_until_queue_fills() {
        let (tx, _rx) = channel(2);
        assert!(tx.try_send(fixture_event(1, 1)));
        assert!(tx.try_send(fixture_event(2, 2)));
        assert!(!tx.try_send(fixture_event(3, 3)));
    }

    #[tokio::test]
    async fn coalesce_collapses_repeats_within_window() {
        let (tx, mut rx) = channel(8);
        tx.try_send(fixture_event(1, 1_700_000_000));
        tx.try_send(fixture_event(1, 1_700_000_030));
        rx.drain_pending(8);
        let batch = rx.take_batch();
        assert_eq!(batch.len(), 1);
    }

    #[tokio::test]
    async fn coalesce_admits_update_after_window_elapses() {
        let (tx, mut rx) = channel(8);
        tx.try_send(fixture_event(1, 1_700_000_000));
        tx.try_send(fixture_event(1, 1_700_000_120));
        rx.drain_pending(8);
        let batch = rx.take_batch();
        assert_eq!(batch.len(), 1);
        assert!(batch[0].seen_at.timestamp() >= 1_700_000_120);
    }

    #[tokio::test]
    async fn distinct_tokens_emit_distinct_batch_entries() {
        let (tx, mut rx) = channel(8);
        tx.try_send(fixture_event(1, 1_700_000_000));
        tx.try_send(fixture_event(2, 1_700_000_001));
        rx.drain_pending(8);
        let batch = rx.take_batch();
        assert_eq!(batch.len(), 2);
    }

    #[tokio::test]
    async fn distinct_orgs_emit_distinct_batch_entries() {
        let (tx, mut rx) = channel(8);
        let mut a = fixture_event(1, 1_700_000_000);
        a.org_id = Uuid::from_bytes([0xCC; 16]);
        let mut b = fixture_event(1, 1_700_000_001);
        b.org_id = Uuid::from_bytes([0xDD; 16]);
        tx.try_send(a);
        tx.try_send(b);
        rx.drain_pending(8);
        let batch = rx.take_batch();
        assert_eq!(batch.len(), 2);
    }

    #[tokio::test]
    async fn closed_channel_silently_drops() {
        let (tx, rx) = channel(4);
        drop(rx);
        assert!(!tx.try_send(fixture_event(1, 1)));
    }
}
