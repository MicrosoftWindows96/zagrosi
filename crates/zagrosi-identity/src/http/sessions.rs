// SPDX-License-Identifier: AGPL-3.0-or-later

//! Session lifecycle HTTP handlers.
//!
//! These routes assume the gateway has already resolved the bearer
//! / cookie credential and attached an [`AuthContext`] via
//! [`axum::Extension`]. The identity crate itself does not own the
//! gateway middleware; it provides the introspector
//! ([`crate::session::IdentitySessionIntrospector`]) and the CSRF
//! double-submit middleware
//! ([`crate::http::csrf::csrf_middleware`]) the gateway composes.
//!
//! Routes:
//!
//! - `GET /v1/sessions` — list every live session for the current
//!   user (across devices / replicas).
//! - `GET /v1/sessions/me` — inspect the current session (returns
//!   the optimistic-lock `version` so callers can drive
//!   `PATCH /v1/sessions/me` without a separate read).
//! - `DELETE /v1/sessions/me` — sign-out the current session.
//! - `DELETE /v1/sessions/{id}` — sign-out a specific session
//!   belonging to the caller. Cross-user revocation is reserved
//!   for the admin layer.
//! - `PATCH /v1/sessions/me` — switch the active org for the current
//!   session (optimistic-lock; concurrent writers receive 409).

use axum::Extension;
use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zagrosi_core::AuthContext;

use crate::error::{IdentityError, Result};
use crate::http::SessionsState;
use crate::session::switch_org::SwitchError;

/// View of a single session row served by the lifecycle endpoints.
#[derive(Debug, Serialize)]
pub struct SessionView {
    /// Session identifier.
    pub session_id: Uuid,
    /// Owning user.
    pub user_id: Uuid,
    /// Active org (`None` when the user has not yet picked).
    pub org_id: Option<Uuid>,
    /// Optimistic-lock counter. Required as `expected_version` on
    /// `PATCH /v1/sessions/me`.
    pub version: i64,
    /// Hard expiry timestamp.
    pub expires_at: DateTime<Utc>,
    /// Most recent observed activity (`None` when the write-behind
    /// drain has not yet fired against this session).
    pub last_seen_at: DateTime<Utc>,
    /// AMR values from the auth path.
    pub amr: Vec<String>,
    /// Optional ACR claim.
    pub acr: Option<String>,
}

/// Request body for `PATCH /v1/sessions/me`.
#[derive(Debug, Deserialize)]
pub struct SwitchOrgRequest {
    /// Target organisation. The user must have an active membership
    /// in this org.
    pub org_id: Uuid,
    /// Optimistic-lock counter as observed on the most recent
    /// `GET /v1/sessions/me`. Mismatch → `409 Conflict; retry`.
    pub expected_version: i64,
}

/// Response body for a successful `PATCH /v1/sessions/me`.
#[derive(Debug, Serialize)]
pub struct SwitchOrgResponse {
    /// New active org (echoed for SPA convenience).
    pub org_id: Uuid,
    /// Optimistic-lock counter after the update.
    pub version: i64,
}

/// `GET /v1/sessions/me` — inspect the current session.
///
/// Reads the session row through `SessionRepo::find_by_id` so the
/// returned `version` reflects the canonical DB value (the cached
/// `AuthContext` does not carry version). On a miss the caller
/// receives `404 Not Found` so the route does not double as a
/// session-existence oracle.
///
/// # Errors
///
/// - [`IdentityError::TokenNotFound`] when the session row is no
///   longer live.
/// - [`IdentityError::Database`] for any underlying sqlx failure.
pub async fn current_session(
    State(state): State<SessionsState>,
    Extension(ctx): Extension<AuthContext>,
) -> Result<Json<SessionView>> {
    let session = state
        .sessions
        .find_by_id(ctx.session_id())
        .await?
        .ok_or(IdentityError::TokenNotFound)?;
    Ok(Json(SessionView {
        session_id: session.id,
        user_id: session.user_id,
        org_id: session.org_id,
        version: session.version,
        expires_at: session.expires_at,
        last_seen_at: session.last_seen_at,
        amr: session.amr,
        acr: session.acr,
    }))
}

/// `GET /v1/sessions` — list every live session for the current
/// user.
///
/// Useful for the SPA's "active sessions" view that lets users
/// revoke individual remote devices.
///
/// # Errors
///
/// - [`IdentityError::Database`] for any underlying sqlx failure.
pub async fn list_sessions(
    State(state): State<SessionsState>,
    Extension(ctx): Extension<AuthContext>,
) -> Result<Json<Vec<SessionView>>> {
    let rows = state.sessions.list_for_user(ctx.subject_id()).await?;
    let view: Vec<SessionView> = rows
        .into_iter()
        .map(|s| SessionView {
            session_id: s.id,
            user_id: s.user_id,
            org_id: s.org_id,
            version: s.version,
            expires_at: s.expires_at,
            last_seen_at: s.last_seen_at,
            amr: s.amr,
            acr: s.acr,
        })
        .collect();
    Ok(Json(view))
}

/// `DELETE /v1/sessions/me` — sign-out the current session.
///
/// # Errors
///
/// Surfaces [`IdentityError::Database`] if the underlying revoke
/// path fails; the route never returns a body on success.
pub async fn delete_current(
    State(state): State<SessionsState>,
    Extension(ctx): Extension<AuthContext>,
) -> Result<StatusCode> {
    state
        .revoker
        .revoke(ctx.session_id(), ctx.subject_id())
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `DELETE /v1/sessions/{id}` — sign-out a specific session.
///
/// Allows the caller to revoke any of their own active sessions
/// (for example, the "sign me out from another device" flow).
/// Cross-user revocation is reserved for the admin layer; if the
/// looked-up session is owned by a different user, the response
/// masks as `404 Not Found` so the route does not double as a
/// session-existence oracle for unprivileged callers.
///
/// # Errors
///
/// - [`IdentityError::TokenNotFound`] when the session is missing
///   or owned by another user.
/// - [`IdentityError::Database`] for any other underlying failure.
pub async fn delete_specific(
    State(state): State<SessionsState>,
    Extension(ctx): Extension<AuthContext>,
    Path(session_id): Path<Uuid>,
) -> Result<StatusCode> {
    let session = state
        .sessions
        .find_by_id(session_id)
        .await?
        .ok_or(IdentityError::TokenNotFound)?;
    if session.user_id != ctx.subject_id() {
        // Cross-user revocation is admin territory; mask as
        // not-found so the route never confirms existence.
        return Err(IdentityError::TokenNotFound);
    }
    state.revoker.revoke(session_id, session.user_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `PATCH /v1/sessions/me` — switch the active org for the current
/// session.
///
/// # Errors
///
/// - `403 Forbidden` when the user has no active membership in the
///   target org.
/// - `409 Conflict` when the optimistic-lock version does not match.
/// - `500 Internal Server Error` for any underlying database
///   failure.
pub async fn switch_active_org(
    State(state): State<SessionsState>,
    Extension(ctx): Extension<AuthContext>,
    Json(body): Json<SwitchOrgRequest>,
) -> std::result::Result<Json<SwitchOrgResponse>, axum::response::Response> {
    match state
        .switcher
        .switch(
            ctx.session_id(),
            ctx.subject_id(),
            body.org_id,
            body.expected_version,
        )
        .await
    {
        Ok(outcome) => Ok(Json(SwitchOrgResponse {
            org_id: outcome.org_id,
            version: outcome.version,
        })),
        Err(SwitchError::Forbidden) => Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": { "code": "forbidden", "message": "not a member of target org" }
            })),
        )
            .into_response()),
        Err(SwitchError::Conflict) => Err((
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "error": { "code": "conflict", "message": "optimistic-lock retry" }
            })),
        )
            .into_response()),
        Err(SwitchError::Database(err)) => Err((*err).into_response()),
    }
}
