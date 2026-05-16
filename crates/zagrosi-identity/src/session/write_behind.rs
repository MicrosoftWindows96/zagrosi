// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounded write-behind channel for `sessions.last_seen_at`.
//!
//! Updating `last_seen_at` synchronously on every cache-hit
//! introspection would dominate the introspector's latency budget
//! and turn every read into a write. Instead the introspector
//! produces an [`UpdateLastSeen`] event onto a bounded mpsc channel;
//! a background drain task batches them and writes coalesced updates
//! at most once per session per minute.
//!
//! Channel-full means we silently drop the update — `last_seen_at`
//! is best-effort metadata, not a security primitive. The dropped
//! update is acceptable because the next probe will produce a fresh
//! event within the cache TTL window.

use chrono::{DateTime, Utc};
use std::collections::HashMap;
use tokio::sync::mpsc;
use tracing::{debug, warn};
use uuid::Uuid;

/// Coalescing window — at most one DB update per session per
/// `COALESCE_WINDOW`. The cache TTL bounds how often the
/// introspector produces events for a given session in steady state,
/// so a 60-second coalescing window adds only modest write
/// amplification on top of the cache.
pub const COALESCE_WINDOW: chrono::TimeDelta = chrono::TimeDelta::seconds(60);

/// Single `last_seen_at` update event.
#[derive(Debug, Clone, Copy)]
pub struct UpdateLastSeen {
    /// Session whose row should be touched.
    pub session_id: Uuid,
    /// Wall-clock time the introspector observed this session.
    pub seen_at: DateTime<Utc>,
}

/// Sender half. Cheap to clone; cloning shares the underlying queue.
#[derive(Debug, Clone)]
pub struct LastSeenSender {
    inner: mpsc::Sender<UpdateLastSeen>,
}

impl LastSeenSender {
    /// Try to enqueue an update without blocking. Channel-full
    /// silently drops the event (best-effort metadata semantic).
    /// Returns `true` if the event landed on the queue.
    pub fn try_send(&self, event: UpdateLastSeen) -> bool {
        match self.inner.try_send(event) {
            Ok(()) => true,
            Err(mpsc::error::TrySendError::Full(_)) => {
                debug!(session_id = %event.session_id, "last_seen_at write-behind queue full; dropping update");
                false
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                warn!("last_seen_at write-behind channel closed");
                false
            }
        }
    }
}

/// Receiver half.
pub struct LastSeenReceiver {
    inner: mpsc::Receiver<UpdateLastSeen>,
    coalesce: HashMap<Uuid, DateTime<Utc>>,
}

impl LastSeenReceiver {
    /// Drain pending events into the coalescing map. Returns the
    /// number of events consumed (post-coalesce; ≤ events received).
    /// The returned count is purely informational for telemetry.
    pub fn drain_pending(&mut self, max: usize) -> usize {
        let mut consumed = 0;
        for _ in 0..max {
            match self.inner.try_recv() {
                Ok(event) => {
                    let prior = self.coalesce.get(&event.session_id).copied();
                    let should_update = prior
                        .is_none_or(|t| event.seen_at.signed_duration_since(t) >= COALESCE_WINDOW);
                    if should_update {
                        self.coalesce.insert(event.session_id, event.seen_at);
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
    /// next drain cycle. Drain task calls this, then issues a single
    /// `UPDATE ... WHERE id = ANY ($ids) AND last_seen_at < $seen`
    /// per batch.
    pub fn take_batch(&mut self) -> Vec<UpdateLastSeen> {
        let mut out = Vec::with_capacity(self.coalesce.len());
        for (session_id, seen_at) in self.coalesce.drain() {
            out.push(UpdateLastSeen {
                session_id,
                seen_at,
            });
        }
        out
    }
}

/// Build a bounded write-behind channel sized to `capacity`.
#[must_use]
pub fn channel(capacity: usize) -> (LastSeenSender, LastSeenReceiver) {
    let (tx, rx) = mpsc::channel(capacity);
    (
        LastSeenSender { inner: tx },
        LastSeenReceiver {
            inner: rx,
            coalesce: HashMap::new(),
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn fixture_event(session_id_byte: u8, seen_secs: i64) -> UpdateLastSeen {
        UpdateLastSeen {
            session_id: Uuid::from_bytes([session_id_byte; 16]),
            seen_at: Utc.timestamp_opt(seen_secs, 0).unwrap(),
        }
    }

    #[tokio::test]
    async fn try_send_returns_true_until_queue_fills() {
        let (tx, _rx) = channel(2);
        assert!(tx.try_send(fixture_event(1, 1)));
        assert!(tx.try_send(fixture_event(2, 2)));
        assert!(!tx.try_send(fixture_event(3, 3)), "third send must drop");
    }

    #[tokio::test]
    async fn coalesce_collapses_repeats_within_window() {
        let (tx, mut rx) = channel(8);
        // Two updates for same session inside the 60s window
        // collapse to a single coalesced entry.
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
        // Second update fell outside the 60s window so it replaced
        // the first; only one entry remains in the batch but with
        // the later timestamp.
        assert_eq!(batch.len(), 1);
        assert!(batch[0].seen_at.timestamp() >= 1_700_000_120);
    }

    #[tokio::test]
    async fn distinct_sessions_emit_distinct_batch_entries() {
        let (tx, mut rx) = channel(8);
        tx.try_send(fixture_event(1, 1_700_000_000));
        tx.try_send(fixture_event(2, 1_700_000_001));
        rx.drain_pending(8);
        let batch = rx.take_batch();
        assert_eq!(batch.len(), 2);
    }

    #[tokio::test]
    async fn closed_channel_silently_drops() {
        let (tx, rx) = channel(4);
        drop(rx);
        // No panic; just returns false.
        assert!(!tx.try_send(fixture_event(1, 1)));
    }
}
