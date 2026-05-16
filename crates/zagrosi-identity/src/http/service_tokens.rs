// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! Service-token HTTP surface (`/v1/service-tokens`).
//!
//! Same gateway contract as `crate::http::api_tokens`: the bearer /
//! cookie credential is resolved upstream and an [`AuthContext`] is
//! attached via [`axum::Extension`] before a handler runs (an
//! unauthenticated request never reaches here — the gateway
//! middleware 401s it first).
//!
//! Every route is platform-admin-only. The private
//! `require_platform_admin` helper is the interim
//! [`crate::config::PlatformConfig`] allowlist:
//!
//! - the caller must have authenticated as a human
//!   (`Password` / `Oidc` / `Saml` — not a bearer token managing
//!   bearer tokens), and
//! - `ctx.subject_id()` must be in `platform.admin_user_ids`.
//!
//! Otherwise `403`. The real RBAC role check replaces this when the
//! tenant-isolation layer lands.
// TODO(split-03 RBAC): replace the PlatformConfig allowlist gate with
// a real platform-admin role check.

use std::sync::Arc;

use axum::Extension;
use axum::Json;
use axum::Router;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{delete, get, post};
use uuid::Uuid;
use zagrosi_core::{AuthContext, AuthMethod};

use crate::config::PlatformConfig;
use crate::error::{IdentityError, Result};
use crate::service_tokens::{
    CreateServiceTokenRequest, IssuedServiceTokenResponse, ServiceTokenService, ServiceTokenView,
};

/// Required-scope label surfaced on the 403 envelope when the caller
/// is authenticated but not a platform admin.
const PLATFORM_ADMIN_SCOPE: &str = "platform_admin";

/// Shared state for the service-token handlers. Cheap to clone.
#[derive(Clone)]
pub struct ServiceTokensState {
    /// Composed service-token service (CRUD + audit + cache evict).
    pub service: Arc<ServiceTokenService>,
    /// Interim platform-admin allowlist gate.
    pub platform: Arc<PlatformConfig>,
}

impl ServiceTokensState {
    /// Construct a fresh state handle.
    #[must_use]
    pub const fn new(service: Arc<ServiceTokenService>, platform: Arc<PlatformConfig>) -> Self {
        Self { service, platform }
    }
}

/// `POST /v1/service-tokens` — mint a service token (raw `svc_…`
/// returned once).
pub async fn create_service_token(
    State(state): State<ServiceTokensState>,
    Extension(ctx): Extension<AuthContext>,
    Json(body): Json<CreateServiceTokenRequest>,
) -> Result<(StatusCode, Json<IssuedServiceTokenResponse>)> {
    require_platform_admin(&ctx, &state.platform)?;
    let issued = state
        .service
        .create(ctx.subject_id(), ctx.org_id(), ctx.correlation_id(), body)
        .await?;
    let response = IssuedServiceTokenResponse {
        id: issued.record.id,
        service_name: issued.record.service_name,
        allowed_subjects: issued.record.allowed_subjects,
        display_name: issued.record.display_name,
        created_at: issued.record.created_at,
        // Move the raw token out of the Zeroizing wrapper into the
        // response exactly once; the wrapper still wipes its buffer
        // on drop at the end of this scope.
        token: issued.raw_token.to_string(),
    };
    Ok((StatusCode::CREATED, Json(response)))
}

/// `GET /v1/service-tokens` — list live service tokens.
pub async fn list_service_tokens(
    State(state): State<ServiceTokensState>,
    Extension(ctx): Extension<AuthContext>,
) -> Result<Json<Vec<ServiceTokenView>>> {
    require_platform_admin(&ctx, &state.platform)?;
    Ok(Json(state.service.list().await?))
}

/// `GET /v1/service-tokens/{id}` — fetch one (any revocation state).
pub async fn get_service_token(
    State(state): State<ServiceTokensState>,
    Extension(ctx): Extension<AuthContext>,
    Path(id): Path<Uuid>,
) -> Result<Json<ServiceTokenView>> {
    require_platform_admin(&ctx, &state.platform)?;
    Ok(Json(state.service.get(id).await?))
}

/// `DELETE /v1/service-tokens/{id}` — revoke.
pub async fn revoke_service_token(
    State(state): State<ServiceTokensState>,
    Extension(ctx): Extension<AuthContext>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode> {
    require_platform_admin(&ctx, &state.platform)?;
    state
        .service
        .revoke(ctx.subject_id(), ctx.org_id(), ctx.correlation_id(), id)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Build the service-token router. Mounted at the root; each route
/// carries its full `/v1/service-tokens` path. The gateway composes
/// it behind the same bearer middleware that produces [`AuthContext`].
pub fn router(state: ServiceTokensState) -> Router<()> {
    Router::new()
        .route("/v1/service-tokens", post(create_service_token))
        .route("/v1/service-tokens", get(list_service_tokens))
        .route("/v1/service-tokens/{id}", get(get_service_token))
        .route("/v1/service-tokens/{id}", delete(revoke_service_token))
        .with_state(state)
}

/// Interim platform-admin gate (see module docs). Returns
/// [`IdentityError::InsufficientScope`] (→ `403`) when the
/// authenticated caller is not a configured human platform admin.
fn require_platform_admin(ctx: &AuthContext, platform: &PlatformConfig) -> Result<()> {
    let human = matches!(
        ctx.auth_method(),
        AuthMethod::Password | AuthMethod::Oidc | AuthMethod::Saml
    );
    if human && platform.is_admin(ctx.subject_id()) {
        return Ok(());
    }
    Err(IdentityError::InsufficientScope {
        needed: PLATFORM_ADMIN_SCOPE,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use static_assertions::assert_impl_all;

    assert_impl_all!(ServiceTokensState: Send, Sync, Clone);

    fn ctx(method: AuthMethod, subject: Uuid) -> AuthContext {
        let now = chrono::Utc::now();
        AuthContext::new(
            subject,
            Uuid::from_bytes([2; 16]),
            Uuid::from_bytes([3; 16]),
            method,
            match method {
                AuthMethod::ServiceToken => zagrosi_core::TokenClass::Service,
                _ => zagrosi_core::TokenClass::Session,
            },
            vec!["pwd".into()],
            None,
            now,
            now + chrono::Duration::hours(1),
            Uuid::from_bytes([4; 16]),
        )
        .expect("ctx")
    }

    #[test]
    fn admin_human_session_passes() {
        let admin = Uuid::from_u128(0xA1);
        let platform = PlatformConfig {
            admin_user_ids: vec![admin],
        };
        assert!(require_platform_admin(&ctx(AuthMethod::Password, admin), &platform).is_ok());
    }

    #[test]
    fn non_admin_human_is_forbidden() {
        let platform = PlatformConfig {
            admin_user_ids: vec![Uuid::from_u128(0xA1)],
        };
        let err =
            require_platform_admin(&ctx(AuthMethod::Password, Uuid::from_u128(0xB2)), &platform)
                .expect_err("non-admin must be forbidden");
        assert!(matches!(
            err,
            IdentityError::InsufficientScope { needed } if needed == PLATFORM_ADMIN_SCOPE
        ));
    }

    #[test]
    fn service_token_caller_cannot_manage_service_tokens() {
        let admin = Uuid::from_u128(0xA1);
        // Even if the svc token's sentinel id were in the allowlist,
        // a non-human auth method is refused.
        let platform = PlatformConfig {
            admin_user_ids: vec![admin],
        };
        assert!(require_platform_admin(&ctx(AuthMethod::ServiceToken, admin), &platform).is_err());
    }

    #[test]
    fn empty_allowlist_refuses_everyone() {
        let platform = PlatformConfig::default();
        assert!(
            require_platform_admin(&ctx(AuthMethod::Password, Uuid::from_u128(1)), &platform)
                .is_err()
        );
    }
}
