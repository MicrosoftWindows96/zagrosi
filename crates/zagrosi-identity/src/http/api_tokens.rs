// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! Personal-access-token HTTP surface.
//!
//! Routes assume the gateway has already resolved the bearer / cookie
//! credential and attached an [`AuthContext`] via
//! [`axum::Extension`] before reaching these handlers, exactly the
//! same contract as the session-lifecycle routes shipped in
//! `crate::http::sessions`.
//!
//! Routes:
//!
//! - `POST   /v1/api-tokens`        mints a new PAT for the caller.
//! - `GET    /v1/api-tokens`        lists the caller's live PATs.
//! - `GET    /v1/api-tokens/{id}`   fetches one of the caller's PATs.
//! - `DELETE /v1/api-tokens/{id}`   revokes one of the caller's PATs.
//!
//! ## Scope enforcement
//!
//! When the caller authenticated via a PAT
//! ([`AuthMethod::ApiToken`]), the handler enforces the matching
//! scope:
//!
//! - `tokens:read` for `GET /v1/api-tokens[/{id}]`
//! - `tokens:write` for `POST /v1/api-tokens` and
//!   `DELETE /v1/api-tokens/{id}`
//!
//! Session-based auth (browser cookie, OIDC callback, SAML ACS)
//! skips the scope check because sessions derive capabilities from
//! the upcoming RBAC layer rather than scope strings on the token.

use std::sync::Arc;

use axum::Extension;
use axum::Json;
use axum::Router;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{delete, get, post};
use uuid::Uuid;
use zagrosi_core::{AuthContext, AuthMethod};

use crate::api_tokens::{
    ApiTokenService, ApiTokenView, CreateApiTokenRequest, IssueApiTokenInput,
    IssuedApiTokenResponse, SCOPE_TOKENS_READ, SCOPE_TOKENS_WRITE,
};
use crate::error::{IdentityError, Result};

/// Shared application state for the PAT axum handlers. Cheap to
/// clone; every field is an `Arc` handle.
#[derive(Clone)]
pub struct ApiTokensState {
    /// Composed PAT service (CRUD + audit + cache eviction).
    pub service: Arc<ApiTokenService>,
}

impl ApiTokensState {
    /// Construct a fresh state handle.
    #[must_use]
    pub const fn new(service: Arc<ApiTokenService>) -> Self {
        Self { service }
    }
}

/// `POST /v1/api-tokens`: mint a new PAT for the caller.
///
/// # Errors
///
/// - [`IdentityError::InsufficientScope`] when the caller is
///   authenticated via a PAT and lacks `tokens:write`.
/// - [`IdentityError::InvalidApiTokenRequest`] for malformed body.
/// - [`IdentityError::InvalidScope`] for unknown scope strings.
/// - [`IdentityError::Database`] for any underlying sqlx failure.
pub async fn create_api_token(
    State(state): State<ApiTokensState>,
    Extension(ctx): Extension<AuthContext>,
    Json(body): Json<CreateApiTokenRequest>,
) -> Result<(StatusCode, Json<IssuedApiTokenResponse>)> {
    require_scope_for_pat_caller(&ctx, SCOPE_TOKENS_WRITE)?;

    let issued = state
        .service
        .issue(IssueApiTokenInput {
            caller_user_id: ctx.subject_id(),
            caller_org_id: ctx.org_id(),
            request: body,
            correlation_id: ctx.correlation_id(),
        })
        .await?;
    let response = IssuedApiTokenResponse {
        id: issued.token.id,
        display_name: issued.token.display_name,
        scopes: issued.token.scopes,
        expires_at: issued.token.expires_at,
        created_at: issued.token.created_at,
        token: issued.raw_token,
    };
    Ok((StatusCode::CREATED, Json(response)))
}

/// `GET /v1/api-tokens`: list the caller's live PATs.
pub async fn list_api_tokens(
    State(state): State<ApiTokensState>,
    Extension(ctx): Extension<AuthContext>,
) -> Result<Json<Vec<ApiTokenView>>> {
    require_scope_for_pat_caller(&ctx, SCOPE_TOKENS_READ)?;
    let rows = state.service.list(ctx.subject_id(), ctx.org_id()).await?;
    Ok(Json(rows))
}

/// `GET /v1/api-tokens/{id}`: fetch one of the caller's PATs.
pub async fn get_api_token(
    State(state): State<ApiTokensState>,
    Extension(ctx): Extension<AuthContext>,
    Path(token_id): Path<Uuid>,
) -> Result<Json<ApiTokenView>> {
    require_scope_for_pat_caller(&ctx, SCOPE_TOKENS_READ)?;
    let view = state
        .service
        .get(ctx.subject_id(), ctx.org_id(), token_id)
        .await?;
    Ok(Json(view))
}

/// `DELETE /v1/api-tokens/{id}`: revoke a PAT.
///
/// PAT-authenticated callers MUST hold `tokens:write`. Self-revoke
/// (revoking the bearer token itself) succeeds when `tokens:write`
/// is present; the next request with the same token will then
/// resolve to `401` because the row's `revoked_at` is set before
/// the response returns.
pub async fn revoke_api_token(
    State(state): State<ApiTokensState>,
    Extension(ctx): Extension<AuthContext>,
    Path(token_id): Path<Uuid>,
) -> Result<StatusCode> {
    require_scope_for_pat_caller(&ctx, SCOPE_TOKENS_WRITE)?;
    state
        .service
        .revoke(
            ctx.subject_id(),
            ctx.org_id(),
            token_id,
            ctx.correlation_id(),
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Build the api-tokens router.
///
/// Mounted at the root; each route carries its full `/v1/api-tokens`
/// path. The gateway composes this router alongside the session
/// router behind the same bearer-token middleware that produces
/// [`AuthContext`].
pub fn router(state: ApiTokensState) -> Router<()> {
    Router::new()
        .route("/v1/api-tokens", post(create_api_token))
        .route("/v1/api-tokens", get(list_api_tokens))
        .route("/v1/api-tokens/{id}", get(get_api_token))
        .route("/v1/api-tokens/{id}", delete(revoke_api_token))
        .with_state(state)
}

/// Enforce a PAT scope only when the caller authenticated via a PAT.
///
/// Browser sessions, OIDC callbacks, and SAML ACS all leave the
/// scope list empty (capabilities come from RBAC); the
/// `tokens:read` / `tokens:write` chip applies only to PAT-bearer
/// requests.
fn require_scope_for_pat_caller(ctx: &AuthContext, scope: &'static str) -> Result<()> {
    if matches!(ctx.auth_method(), AuthMethod::ApiToken) && !ctx.has_scope(scope) {
        return Err(IdentityError::InsufficientScope { needed: scope });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use static_assertions::assert_impl_all;

    assert_impl_all!(ApiTokensState: Send, Sync, Clone);

    fn build_pat_ctx(scopes: Vec<String>) -> AuthContext {
        let now = chrono::Utc::now();
        let ctx = AuthContext::new(
            Uuid::from_bytes([1; 16]),
            Uuid::from_bytes([2; 16]),
            Uuid::from_bytes([3; 16]),
            AuthMethod::ApiToken,
            zagrosi_core::TokenClass::PersonalAccessToken,
            vec!["pat".into()],
            None,
            now,
            now + chrono::Duration::hours(1),
            Uuid::from_bytes([4; 16]),
        )
        .expect("build pat ctx");
        ctx.with_scopes(scopes)
    }

    fn build_session_ctx() -> AuthContext {
        let now = chrono::Utc::now();
        AuthContext::new(
            Uuid::from_bytes([1; 16]),
            Uuid::from_bytes([2; 16]),
            Uuid::from_bytes([3; 16]),
            AuthMethod::Password,
            zagrosi_core::TokenClass::Session,
            vec!["pwd".into()],
            None,
            now,
            now + chrono::Duration::hours(1),
            Uuid::from_bytes([4; 16]),
        )
        .expect("build session ctx")
    }

    #[test]
    fn pat_with_required_scope_passes() {
        let ctx = build_pat_ctx(vec!["tokens:read".into()]);
        assert!(require_scope_for_pat_caller(&ctx, SCOPE_TOKENS_READ).is_ok());
    }

    #[test]
    fn pat_missing_scope_returns_insufficient_scope() {
        let ctx = build_pat_ctx(vec!["me:read".into()]);
        let err = require_scope_for_pat_caller(&ctx, SCOPE_TOKENS_WRITE)
            .expect_err("should require tokens:write");
        assert!(
            matches!(err, IdentityError::InsufficientScope { needed } if needed == SCOPE_TOKENS_WRITE)
        );
    }

    #[test]
    fn session_caller_skips_scope_check() {
        let ctx = build_session_ctx();
        // No scopes on a session ctx; must still pass the gate.
        assert!(require_scope_for_pat_caller(&ctx, SCOPE_TOKENS_WRITE).is_ok());
    }
}
