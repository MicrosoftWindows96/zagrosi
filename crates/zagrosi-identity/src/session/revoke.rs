// SPDX-License-Identifier: AGPL-3.0-or-later

//! Session revocation paths.
//!
//! Three revocation paths land here:
//!
//! 1. **Explicit.** `DELETE /v1/sessions/me` (current session) or
//!    `DELETE /v1/sessions/{id}` (admin / current user) sets
//!    `revoked_at = now()` on the row. A NATS event on
//!    `identity.session.revoked.<session_id>` fans out to peer
//!    replicas so each evicts its in-process cache entry.
//!
//! 2. **Implicit (password reset).** Owned by the password-auth
//!    flow; this module does not need to fire because the
//!    `password_updated_at` invariant rejects pre-reset sessions
//!    on every cache miss.
//!
//! 3. **Implicit (admin sign-out-all / SCIM `active=false`).** Bulk
//!    revoke via [`SessionRevoker::revoke_all_for_user`] in the
//!    same transaction as the upstream flag flip. Each row's
//!    `session_id` would also be published, but the bulk path
//!    instead publishes a single per-user `identity.session.revoked.<user_id>`
//!    fan-out hint so peer replicas can purge their caches without
//!    knowing every individual `session_id`.
//!
//! The 1-second revocation SLA is met by:
//!
//! - The `password_updated_at` invariant for password-reset cascade
//!   (replica-local; ~50 ms latency floor — purely DB write
//!   propagation).
//! - The NATS event for explicit / SCIM revocations under healthy
//!   broker state (sub-second propagation).
//! - The fail-closed cache TTL (1 s default) when the broker is
//!   unreachable, so even a dropped event cannot leave a revoked
//!   session live for longer than that window.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{debug, warn};
use uuid::Uuid;

use crate::error::Result;
use crate::repo::SessionRepo;
use crate::session::cache::SessionCache;
use crate::session::events::SessionEventBus;

/// NATS subject prefix for per-session revocation events.
pub const REVOKE_SUBJECT_PREFIX: &str = "identity.session.revoked";

/// Per-user fan-out subject for bulk revocations driven by SCIM
/// deactivation or admin sign-out-all flows.
pub const REVOKE_USER_SUBJECT_PREFIX: &str = "identity.session.revoked-user";

/// Wire payload for per-session revocation events.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionRevokedEvent {
    /// Session row primary key.
    pub session_id: Uuid,
    /// Owning user.
    pub user_id: Uuid,
    /// Wall-clock revocation time (RFC 3339).
    pub revoked_at: chrono::DateTime<Utc>,
}

/// Wire payload for per-user fan-out revocation hints. Subscribers
/// react by purging every cache entry for the named user; the hint
/// does not enumerate `session_id`s so the broker payload size stays
/// bounded.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserSessionsRevokedEvent {
    /// User whose sessions were bulk-revoked.
    pub user_id: Uuid,
    /// Wall-clock revocation time (RFC 3339).
    pub revoked_at: chrono::DateTime<Utc>,
}

/// Concrete revoker. Cheap to clone — every field wraps an `Arc`.
#[derive(Clone)]
pub struct SessionRevoker {
    sessions: SessionRepo,
    cache: SessionCache,
    bus: Arc<SessionEventBus>,
}

impl SessionRevoker {
    /// Wire the dependencies. `bus` may be backed by a no-op if the
    /// configured NATS URL is empty; the revoker still updates the
    /// DB row + evicts the local cache so the 1-second SLA holds
    /// via the fail-closed cache TTL.
    #[must_use]
    pub const fn new(
        sessions: SessionRepo,
        cache: SessionCache,
        bus: Arc<SessionEventBus>,
    ) -> Self {
        Self {
            sessions,
            cache,
            bus,
        }
    }

    /// Revoke a single session. DB write + local cache eviction +
    /// best-effort NATS publish. Returns the user the session
    /// belonged to so callers can layer audit on top.
    ///
    /// # Errors
    ///
    /// DB failures bubble up as [`crate::error::IdentityError::Database`].
    /// Cache + NATS failures are swallowed (logged at `warn`) — the
    /// canonical revocation lives in the DB row.
    pub async fn revoke(&self, session_id: Uuid, user_id: Uuid) -> Result<()> {
        self.sessions.revoke(session_id).await?;
        self.publish_revoked(session_id, user_id).await;
        Ok(())
    }

    /// Publish-only path: evict the local cache + best-effort NATS
    /// fan-out for a session that was already revoked through a
    /// caller-supplied transaction (e.g. the OIDC refresh-chain
    /// replay handler that needs revoke + chain revoke in one commit
    /// unit before the publish runs). Idempotent; safe to call after
    /// any DB-write path that left `revoked_at` set.
    pub async fn publish_revoked(&self, session_id: Uuid, user_id: Uuid) {
        self.cache.evict_by_session_id(session_id).await;
        let event = SessionRevokedEvent {
            session_id,
            user_id,
            revoked_at: Utc::now(),
        };
        let subject = format!("{REVOKE_SUBJECT_PREFIX}.{session_id}");
        if let Err(err) = self.bus.publish(&subject, &event).await {
            warn!(?err, %session_id, "publish session-revoke event failed");
        } else {
            debug!(%session_id, "session revoke event published");
        }
    }

    /// Revoke every live session belonging to `user_id`. Used by
    /// SCIM `active=false` and the admin sign-out-all flow. Runs as
    /// a single SQL `UPDATE` so the bulk path stays atomic; the
    /// caller is expected to wrap this in the surrounding flag-flip
    /// transaction.
    ///
    /// Publishes a single per-user fan-out event so peer replicas
    /// can purge their caches without enumerating individual session
    /// IDs.
    ///
    /// # Errors
    ///
    /// DB failures bubble up as [`crate::error::IdentityError::Database`].
    pub async fn revoke_all_for_user(&self, user_id: Uuid) -> Result<u64> {
        let revoked_count = self.sessions.revoke_all_for_user(user_id).await?;
        // Per-user evictions are a hint; replicas re-check the
        // `password_updated_at` / `revoked_at` invariants on the
        // next miss and the fail-closed cache TTL bounds the lag.
        let event = UserSessionsRevokedEvent {
            user_id,
            revoked_at: Utc::now(),
        };
        let subject = format!("{REVOKE_USER_SUBJECT_PREFIX}.{user_id}");
        if let Err(err) = self.bus.publish(&subject, &event).await {
            warn!(?err, %user_id, "publish user-bulk-revoke event failed");
        }
        Ok(revoked_count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revoke_subject_prefix_is_namespaced() {
        assert!(REVOKE_SUBJECT_PREFIX.starts_with("identity.session"));
    }

    #[test]
    fn revoke_user_subject_prefix_is_distinct_from_per_session() {
        assert_ne!(REVOKE_SUBJECT_PREFIX, REVOKE_USER_SUBJECT_PREFIX);
    }

    #[test]
    fn session_revoked_event_round_trips_through_serde_json() {
        let event = SessionRevokedEvent {
            session_id: Uuid::from_bytes([1; 16]),
            user_id: Uuid::from_bytes([2; 16]),
            revoked_at: Utc::now(),
        };
        let encoded = serde_json::to_string(&event).expect("encode");
        let decoded: SessionRevokedEvent = serde_json::from_str(&encoded).expect("decode");
        assert_eq!(decoded.session_id, event.session_id);
        assert_eq!(decoded.user_id, event.user_id);
    }

    #[test]
    fn user_revoked_event_round_trips_through_serde_json() {
        let event = UserSessionsRevokedEvent {
            user_id: Uuid::from_bytes([3; 16]),
            revoked_at: Utc::now(),
        };
        let encoded = serde_json::to_string(&event).expect("encode");
        let decoded: UserSessionsRevokedEvent = serde_json::from_str(&encoded).expect("decode");
        assert_eq!(decoded.user_id, event.user_id);
    }
}
