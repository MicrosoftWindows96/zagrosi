// SPDX-License-Identifier: AGPL-3.0-or-later

//! Active-organisation switch for the current session.
//!
//! `PATCH /v1/sessions/me { "org_id": "<uuid>" }` flows here. The
//! switch uses optimistic locking (`UPDATE ... WHERE id = $2 AND
//! version = $3`) so two concurrent tabs / replicas race cleanly:
//! one wins, the other receives `409 Conflict; retry`.
//!
//! Every successful switch:
//!
//! 1. Verifies the user has an active membership in the target org
//!    via [`MembershipRepo`]. Missing / soft-deleted membership →
//!    [`SwitchError::Forbidden`] (mapped to `403`).
//! 2. Issues the optimistic-lock update via
//!    [`SessionRepo::update_active_org`].
//! 3. Evicts the cached entry for this session so the next resolve
//!    sees the new `org_id`.
//! 4. Publishes a `session.updated` NATS event so peer replicas
//!    refetch on their next miss.
//!
//! The session token itself does not change; only `org_id` mutates.
//! Downstream middleware sees the new org on the next request.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{debug, warn};
use uuid::Uuid;

use crate::error::IdentityError;
use crate::repo::{MembershipRepo, SessionRepo};
use crate::session::cache::SessionCache;
use crate::session::events::SessionEventBus;

/// NATS subject prefix for active-org switch events.
pub const SESSION_UPDATED_SUBJECT_PREFIX: &str = "identity.session.updated";

/// Wire payload for active-org switch events.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionUpdatedEvent {
    /// Session row primary key.
    pub session_id: Uuid,
    /// New active org.
    pub org_id: Uuid,
    /// Optimistic-lock counter after the update.
    pub version: i64,
    /// Wall-clock update time (RFC 3339).
    pub updated_at: chrono::DateTime<Utc>,
}

/// Failure modes specific to the switch handler.
#[derive(Debug, thiserror::Error)]
pub enum SwitchError {
    /// The user has no active membership in the target org.
    #[error("forbidden: not a member of target org")]
    Forbidden,
    /// Optimistic-lock conflict — another writer raced ahead.
    #[error("conflict: optimistic-lock version mismatch")]
    Conflict,
    /// Underlying database failure.
    #[error("database: {0}")]
    Database(#[source] Box<IdentityError>),
}

impl From<IdentityError> for SwitchError {
    fn from(err: IdentityError) -> Self {
        match err {
            IdentityError::OptimisticLockConflict => Self::Conflict,
            other => Self::Database(Box::new(other)),
        }
    }
}

/// Switcher composition: the active-org SQL primitive plus the
/// membership check plus the cache eviction plus the NATS publish.
#[derive(Clone)]
pub struct SessionOrgSwitcher {
    sessions: SessionRepo,
    memberships: MembershipRepo,
    cache: SessionCache,
    bus: Arc<SessionEventBus>,
}

/// Outcome of a successful switch.
#[derive(Debug, Clone, Copy)]
pub struct SwitchOutcome {
    /// New active org (echoed back so the handler can serialise).
    pub org_id: Uuid,
    /// Optimistic-lock version after the update.
    pub version: i64,
}

impl SessionOrgSwitcher {
    /// Wire the dependencies.
    #[must_use]
    pub const fn new(
        sessions: SessionRepo,
        memberships: MembershipRepo,
        cache: SessionCache,
        bus: Arc<SessionEventBus>,
    ) -> Self {
        Self {
            sessions,
            memberships,
            cache,
            bus,
        }
    }

    /// Drive the optimistic-lock switch. Returns `Conflict` when the
    /// caller-supplied `expected_version` does not match the live
    /// row.
    ///
    /// # Errors
    ///
    /// - [`SwitchError::Forbidden`] when the user is not an active
    ///   member of `target_org`.
    /// - [`SwitchError::Conflict`] when a concurrent writer raced
    ///   ahead.
    /// - [`SwitchError::Database`] for any other underlying error.
    pub async fn switch(
        &self,
        session_id: Uuid,
        user_id: Uuid,
        target_org: Uuid,
        expected_version: i64,
    ) -> Result<SwitchOutcome, SwitchError> {
        let memberships = self
            .memberships
            .find_for_user(user_id)
            .await
            .map_err(SwitchError::from)?;
        let in_target_org = memberships
            .into_iter()
            .any(|m| m.org_id == target_org && m.deleted_at.is_none());
        if !in_target_org {
            return Err(SwitchError::Forbidden);
        }
        let next_version = self
            .sessions
            .update_active_org(session_id, target_org, expected_version)
            .await
            .map_err(SwitchError::from)?;
        self.cache.evict_by_session_id(session_id).await;
        let event = SessionUpdatedEvent {
            session_id,
            org_id: target_org,
            version: next_version,
            updated_at: Utc::now(),
        };
        let subject = format!("{SESSION_UPDATED_SUBJECT_PREFIX}.{session_id}");
        if let Err(err) = self.bus.publish(&subject, &event).await {
            warn!(?err, %session_id, "publish session-updated event failed");
        } else {
            debug!(%session_id, %target_org, "session active-org switched");
        }
        Ok(SwitchOutcome {
            org_id: target_org,
            version: next_version,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn switch_outcome_serialisable_through_event_payload() {
        let event = SessionUpdatedEvent {
            session_id: Uuid::from_bytes([1; 16]),
            org_id: Uuid::from_bytes([2; 16]),
            version: 7,
            updated_at: Utc::now(),
        };
        let encoded = serde_json::to_string(&event).expect("encode");
        let decoded: SessionUpdatedEvent = serde_json::from_str(&encoded).expect("decode");
        assert_eq!(decoded.session_id, event.session_id);
        assert_eq!(decoded.org_id, event.org_id);
        assert_eq!(decoded.version, event.version);
    }

    #[test]
    fn optimistic_lock_conflict_maps_to_conflict_variant() {
        let mapped: SwitchError = IdentityError::OptimisticLockConflict.into();
        assert!(matches!(mapped, SwitchError::Conflict));
    }
}
