// SPDX-License-Identifier: AGPL-3.0-or-later

//! Admin-only HTTP routes.
//!
//! The current surface is the per-account unlock endpoint; later work
//! will pile additional admin surfaces (impersonation, SCIM-token
//! revocation, etc.) onto the same prefix.
//!
//! ## Authentication
//!
//! Authentication for `/v1/admin/*` is the responsibility of the
//! mounter (the gateway) until a dedicated admin console lands.
//! Direct exposure on a public listener would leak the unlock
//! primitive. The handler accepts no caller-identity proof and
//! relies on its mounter to enforce one.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use uuid::Uuid;
use zagrosi_core::{
    AuditActor, AuditEvent, AuditEventKind, AuditEventV1, AuditPayload, AuditResource, RateLimitKey,
};

use crate::error::Result;
use crate::http::IdentityState;
use crate::service::signin::SIGNIN_SCOPE;

/// `POST /v1/admin/users/{id}/unlock` — clear the per-account
/// exponential-lockout state for one user.
///
/// On success returns `204 No Content`. Emits an
/// [`AuditEventKind::AccountUnlocked`] event so audit can correlate
/// the unlock with the originating admin action recorded by the
/// admin-console mounter.
///
/// # Errors
///
/// - [`crate::error::IdentityError::RateLimiterUnavailable`] when the
///   Valkey-backed limiter cannot acknowledge the unlock. The
///   response uses the standard 503 mapping; the lockout key carries
///   a TTL so a transient outage does not strand the user
///   indefinitely.
pub async fn unlock_user(
    State(state): State<IdentityState>,
    Path(user_id): Path<Uuid>,
) -> Result<StatusCode> {
    let key = RateLimitKey::PerAccount {
        user_id,
        scope: SIGNIN_SCOPE,
    };
    state.service.rate_limiter.unlock(&key).await?;

    state
        .service
        .auditor
        .record(AuditEvent::V1(AuditEventV1::new(
            AuditEventKind::AccountUnlocked,
            // Until a dedicated admin console wires authenticated
            // actors, the actor is the server itself. The mounter
            // is expected to attribute the human-driven action via
            // its own audit row.
            AuditActor::System,
            AuditResource::User { user_id },
            Uuid::now_v7(),
            Uuid::nil(),
            AuditPayload::new(serde_json::json!({
                "scope": SIGNIN_SCOPE,
                "user_id": user_id,
            })),
        )))
        .await;

    Ok(StatusCode::NO_CONTENT)
}
