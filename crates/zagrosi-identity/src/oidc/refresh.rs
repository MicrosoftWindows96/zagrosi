// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! Refresh-token chain replay detection.
//!
//! Wraps [`crate::repo::OidcRefreshRepo`] with the chain semantics
//! described in section-10:
//!
//! - **Issue (initial).** The OIDC client mints a fresh refresh token,
//!   inserts a row with `prev_id = NULL`, returns the raw token to the
//!   caller exactly once.
//! - **Refresh.** Lookup by `token_hash`. If `used_at IS NOT NULL`,
//!   replay is detected: revoke the entire chain (every row sharing
//!   the same `session_id`), revoke the parent session, emit
//!   `oidc_refresh_replay` + `suspected_token_replay` audit events.
//!   Otherwise atomically `mark_used` and insert the new row with
//!   `prev_id = current.id`.
//!
//! The OIDC service composes this together with the session revoker
//! and the [`zagrosi_core::Auditor`] port; this module is the SQL
//! discipline only.

use std::sync::Arc;

use chrono::Utc;
use uuid::Uuid;
use zagrosi_core::Auditor;

use crate::domain::OidcRefreshToken;
use crate::error::{IdentityError, Result};
use crate::oidc::cookie::sha256;
use crate::repo::{NewOidcRefresh, OidcRefreshRepo};

/// Outcome of a successful rotation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotatedRefresh {
    /// Persisted child row.
    pub child: OidcRefreshToken,
    /// Raw new refresh token; returned to the OIDC caller exactly once.
    pub raw: String,
}

/// Caller-supplied audit context for replay-detection events. The
/// OIDC service threads its `correlation_id` + `org_id` here so the
/// emitted audit row joins back to the originating callback request.
#[derive(Debug, Default, Clone, Copy)]
pub struct ReplayContext {
    /// Correlation id from the request that triggered replay
    /// detection. When `None`, `RefreshChain` resolves a fresh
    /// `Uuid::now_v7()` (e.g. for internal-only paths that have no
    /// HTTP correlation).
    pub correlation_id: Option<Uuid>,
}

impl ReplayContext {
    /// Resolve the effective correlation id, generating a fresh one
    /// when no caller-supplied value is present.
    #[must_use]
    pub fn resolve_correlation_id(&self) -> Uuid {
        self.correlation_id.unwrap_or_else(Uuid::now_v7)
    }
}

/// Refresh-chain orchestrator. Cheap to clone (every dep is an `Arc`
/// or repo handle).
#[derive(Clone)]
pub struct RefreshChain {
    repo: OidcRefreshRepo,
    sessions: crate::repo::SessionRepo,
    revoker: Arc<crate::session::SessionRevoker>,
    auditor: Arc<dyn Auditor>,
    pool: sqlx::PgPool,
}

impl RefreshChain {
    /// Wire dependencies. The pool backs the chain-revoke + session-
    /// revoke transaction in [`Self::handle_replay`]. The revoker is
    /// invoked AFTER tx commit so peer replicas evict their session
    /// caches via NATS — without it, a refresh-replay would leave
    /// the session live cluster-wide until the cache TTL elapsed.
    #[must_use]
    pub fn new(
        repo: OidcRefreshRepo,
        sessions: crate::repo::SessionRepo,
        revoker: Arc<crate::session::SessionRevoker>,
        auditor: Arc<dyn Auditor>,
        pool: sqlx::PgPool,
    ) -> Self {
        Self {
            repo,
            sessions,
            revoker,
            auditor,
            pool,
        }
    }

    /// Issue the *first* refresh row for a session. The raw token is
    /// returned to the caller exactly once; the row stores only the
    /// SHA-256 hash.
    #[tracing::instrument(skip_all, fields(session_id = %session_id, route = "oidc.refresh.issue"))]
    pub async fn issue_initial(
        &self,
        session_id: Uuid,
        raw_refresh_token: &str,
    ) -> Result<OidcRefreshToken> {
        let hash = sha256(raw_refresh_token.as_bytes());
        let new = NewOidcRefresh {
            id: Uuid::now_v7(),
            session_id,
            token_hash: &hash,
            prev_id: None,
        };
        self.repo.insert(new).await
    }

    /// Rotate a refresh token. On replay, returns
    /// [`IdentityError::RefreshChainReplay`] *after* revoking the whole
    /// chain and the parent session. Callers MUST treat the error as
    /// final: the user re-authenticates from scratch.
    ///
    /// The mark-used flip and the child insert run inside the same
    /// transaction so a torn rotation (parent consumed, child not
    /// inserted) is impossible.
    ///
    /// `replay_ctx` carries the originating request's correlation id
    /// for the replay audit emission. Pass [`ReplayContext::default()`]
    /// from internal-only paths (e.g. background workers) where no
    /// HTTP correlation exists.
    #[tracing::instrument(
        skip_all,
        fields(
            correlation_id = %replay_ctx.resolve_correlation_id(),
            route = "oidc.refresh.rotate",
        )
    )]
    pub async fn rotate(
        &self,
        old_raw_token: &str,
        new_raw_token: &str,
        replay_ctx: ReplayContext,
    ) -> Result<RotatedRefresh> {
        let old_hash = sha256(old_raw_token.as_bytes());
        let Some(parent) = self.repo.find_by_token_hash(&old_hash).await? else {
            // Hash unknown, or the chain was already revoked. We have
            // no parent session to revoke, so surface the typed replay
            // signal and stop.
            return Err(IdentityError::RefreshChainReplay);
        };

        // Replay detection: the lookup no longer filters
        // `used_at IS NULL`. A non-NULL `used_at` means the same hash
        // was redeemed twice, which is the canonical replay scenario.
        // Revoke the chain + the parent session, emit the audit pair,
        // and surface the typed error.
        if parent.used_at.is_some() {
            self.handle_replay(parent.session_id, replay_ctx).await;
            return Err(IdentityError::RefreshChainReplay);
        }

        let mut tx = self.pool.begin().await?;
        if let Err(err) = self
            .repo
            .mark_used_in_tx(&mut tx, parent.id, Utc::now())
            .await
        {
            if matches!(err, IdentityError::RefreshChainReplay) {
                // mark_used_in_tx returns RefreshChainReplay when 0
                // rows match; that closes a TOCTOU race where another
                // rotation consumed the row between our `find` and
                // our `mark_used_in_tx`. Roll back this tx, then
                // revoke the chain + parent session out-of-band.
                let _ = tx.rollback().await;
                self.handle_replay(parent.session_id, replay_ctx).await;
                return Err(IdentityError::RefreshChainReplay);
            }
            return Err(err);
        }

        let new_hash = sha256(new_raw_token.as_bytes());
        let child = self
            .repo
            .insert_in_tx(
                &mut tx,
                NewOidcRefresh {
                    id: Uuid::now_v7(),
                    session_id: parent.session_id,
                    token_hash: &new_hash,
                    prev_id: Some(parent.id),
                },
            )
            .await?;
        tx.commit().await?;

        Ok(RotatedRefresh {
            child,
            raw: new_raw_token.to_owned(),
        })
    }

    /// Revoke the whole chain + parent session inside one transaction,
    /// then publish the per-session NATS event + emit the paired
    /// audit events.
    ///
    /// Sequence:
    ///
    /// 1. Open tx; resolve `(org_id, user_id)` inside the tx so the
    ///    read sees the same horizon as the writes.
    /// 2. `revoke_chain_for_session_in_tx` + `revoke_in_tx` on the
    ///    session row.
    /// 3. Commit.
    /// 4. On commit success: invoke
    ///    [`crate::session::SessionRevoker::publish_revoked`] (cache
    ///    evict + NATS publish) so peer replicas drop their cache
    ///    entry inside the 1-second SLA, AND emit the
    ///    `OidcRefreshReplay` + `SuspectedTokenReplay` audit pair.
    /// 5. On commit failure: emit a single `SigninFailed` audit
    ///    with `sub_reason = "replay_revoke_failed"` so the SIEM can
    ///    spot a half-revoked chain that needs operator follow-up.
    ///
    /// The caller's primary return signal stays
    /// [`IdentityError::RefreshChainReplay`]; this method swallows
    /// errors after logging them.
    #[tracing::instrument(
        skip_all,
        fields(
            session_id = %session_id,
            correlation_id = %replay_ctx.resolve_correlation_id(),
            route = "oidc.refresh.replay",
        )
    )]
    pub async fn handle_replay(&self, session_id: Uuid, replay_ctx: ReplayContext) {
        let correlation_id = replay_ctx.resolve_correlation_id();
        let outcome = self.run_replay_revoke_tx(session_id).await;

        if outcome.committed {
            if let Some(uid) = outcome.user_id {
                self.revoker.publish_revoked(session_id, uid).await;
            } else {
                tracing::trace!(
                    target: "zagrosi.identity.oidc",
                    %session_id,
                    "session row absent during replay; skipping cache evict + NATS publish",
                );
            }
            self.emit_replay_audits(session_id, outcome.org_id, correlation_id)
                .await;
        } else {
            self.emit_replay_revoke_failed_audit(session_id, outcome.org_id, correlation_id)
                .await;
        }
    }

    /// Inner-tx body for [`Self::handle_replay`].
    async fn run_replay_revoke_tx(&self, session_id: Uuid) -> ReplayOutcome {
        let mut tx = match self.pool.begin().await {
            Ok(t) => t,
            Err(err) => {
                tracing::warn!(
                    target: "zagrosi.identity.oidc",
                    %session_id, error = %err,
                    "replay revocation tx begin failed",
                );
                return ReplayOutcome {
                    committed: false,
                    org_id: None,
                    user_id: None,
                };
            }
        };

        let (org_id, user_id_opt) = match self
            .sessions
            .find_org_user_for_session_in_tx(&mut tx, session_id)
            .await
        {
            Ok(Some((org, uid))) => (org, Some(uid)),
            Ok(None) => (None, None),
            Err(err) => {
                tracing::warn!(
                    target: "zagrosi.identity.oidc",
                    %session_id, error = %err,
                    "session lookup during replay handling failed",
                );
                let _ = tx.rollback().await;
                return ReplayOutcome {
                    committed: false,
                    org_id: None,
                    user_id: None,
                };
            }
        };

        if let Err(err) = self
            .repo
            .revoke_chain_for_session_in_tx(&mut tx, session_id)
            .await
        {
            tracing::warn!(
                target: "zagrosi.identity.oidc",
                %session_id, error = %err,
                "refresh chain revoke failed",
            );
            let _ = tx.rollback().await;
            return ReplayOutcome {
                committed: false,
                org_id,
                user_id: user_id_opt,
            };
        }

        if let Err(err) = self.sessions.revoke_in_tx(&mut tx, session_id).await {
            tracing::warn!(
                target: "zagrosi.identity.oidc",
                %session_id, error = %err,
                "session revoke on replay failed",
            );
            let _ = tx.rollback().await;
            return ReplayOutcome {
                committed: false,
                org_id,
                user_id: user_id_opt,
            };
        }

        if let Err(err) = tx.commit().await {
            tracing::warn!(
                target: "zagrosi.identity.oidc",
                %session_id, error = %err,
                "replay revocation tx commit failed",
            );
            return ReplayOutcome {
                committed: false,
                org_id,
                user_id: user_id_opt,
            };
        }

        ReplayOutcome {
            committed: true,
            org_id,
            user_id: user_id_opt,
        }
    }

    async fn emit_replay_audits(
        &self,
        session_id: Uuid,
        org_id: Option<Uuid>,
        correlation_id: Uuid,
    ) {
        let resource = zagrosi_core::AuditResource::Session { session_id };
        self.auditor
            .record(zagrosi_core::AuditEvent::V1(
                zagrosi_core::AuditEventV1::builder(
                    zagrosi_core::AuditEventKind::OidcRefreshReplay,
                    zagrosi_core::AuditActor::System,
                    org_id,
                    correlation_id,
                )
                .resource(resource.clone())
                .metadata(zagrosi_core::AuditPayload::new(serde_json::json!({
                    "session_id": session_id,
                })))
                .build(),
            ))
            .await;
        self.auditor
            .record(zagrosi_core::AuditEvent::V1(
                zagrosi_core::AuditEventV1::builder(
                    zagrosi_core::AuditEventKind::SuspectedTokenReplay,
                    zagrosi_core::AuditActor::System,
                    org_id,
                    correlation_id,
                )
                .resource(resource)
                .metadata(zagrosi_core::AuditPayload::new(serde_json::json!({
                    "session_id": session_id,
                    "kind": "oidc_refresh",
                })))
                .build(),
            ))
            .await;
    }

    async fn emit_replay_revoke_failed_audit(
        &self,
        session_id: Uuid,
        org_id: Option<Uuid>,
        correlation_id: Uuid,
    ) {
        let resource = zagrosi_core::AuditResource::Session { session_id };
        self.auditor
            .record(zagrosi_core::AuditEvent::V1(
                zagrosi_core::AuditEventV1::builder(
                    zagrosi_core::AuditEventKind::SigninFailed,
                    zagrosi_core::AuditActor::System,
                    org_id,
                    correlation_id,
                )
                .resource(resource)
                .metadata(zagrosi_core::AuditPayload::new(serde_json::json!({
                    "sub_reason": "replay_revoke_failed",
                    "session_id": session_id,
                })))
                .build(),
            ))
            .await;
    }
}

/// Inner-tx outcome for [`RefreshChain::run_replay_revoke_tx`].
struct ReplayOutcome {
    committed: bool,
    org_id: Option<Uuid>,
    user_id: Option<Uuid>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotated_refresh_carries_child_row() {
        // Compile-coverage assertion: `RotatedRefresh` is `Debug +
        // Clone` so callers can log + replay it through structured
        // tracing without re-fetching the row.
        fn assert_clone<T: Clone>() {}
        assert_clone::<RotatedRefresh>();
    }
}
