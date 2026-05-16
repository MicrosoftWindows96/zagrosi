// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! Password-auth HTTP surface.
//!
//! Thin axum handlers that deserialise the request, call the
//! corresponding [`crate::service::IdentityService`] method, and
//! serialise the response. The service layer carries every security
//! invariant; handlers exist for protocol shaping only.
//!
//! Two distinct routers are exposed so the gateway can mount the
//! public auth surface and the admin surface on separately gated
//! listeners (or behind separate middleware stacks):
//!
//! - [`router`] returns the public surface only:
//!   - `POST /v1/auth/sign-up`
//!   - `POST /v1/auth/sign-in`
//!   - `POST /v1/auth/sign-out` (requires an attached `AuthContext`)
//!   - `POST /v1/auth/password-reset/request`
//!   - `POST /v1/auth/password-reset/confirm`
//!   - `GET  /v1/auth/password-reset/landing`
//!   - `GET  /v1/auth/email-verifications/landing`
//!   - `POST /v1/auth/email-verifications/confirm`
//!
//! - [`admin_router`] returns the admin surface in isolation. The
//!   gateway is responsible for mounting it behind authenticated
//!   admin middleware. It is **never** mounted by [`router`] alone,
//!   so a misconfigured gateway cannot accidentally expose admin
//!   primitives like the per-account unlock endpoint:
//!   - `POST /v1/admin/users/{id}/unlock`
//!
//! For test or pre-prod deployments that need both surfaces on a
//! single listener, [`router_with_admin`] composes them.

use std::sync::Arc;

use axum::Router;
use axum::routing::{delete, get, patch, post};

use crate::api_tokens::ApiTokenService;
use crate::oidc::OidcService;
use crate::repo::{OrgRepo, SessionRepo};
use crate::routing::RoutingState;
#[cfg(feature = "saml")]
use crate::saml::SamlService;
use crate::service::IdentityService;
use crate::session::{SessionOrgSwitcher, SessionRevoker};

pub mod admin;
pub mod api_tokens;
pub mod auth;
pub mod csrf;
pub mod email_verify;
pub mod landing;
pub mod oidc;
pub mod password_reset;
#[cfg(feature = "saml")]
pub mod saml;
pub mod scim;
pub mod scim_tokens;
pub mod service_tokens;
pub mod sessions;

/// Shared application state held by every password-auth axum handler.
///
/// `Arc<IdentityService>` keeps the composition cheap to clone for
/// every incoming request while ensuring the service's port impls
/// (rate-limiter, auditor, breach-list, session-issuer) are reused.
///
/// `api_token_service` is opt-in; when supplied via
/// [`IdentityState::with_api_token_service`], [`router`] mounts the
/// `/v1/api-tokens` routes alongside the auth surface so a single
/// composition root produces the full identity HTTP layer.
///
/// `oidc_service` is opt-in; when supplied via
/// [`IdentityState::with_oidc_service`], [`router`] mounts the
/// `/v1/auth/oidc/*` routes through the canonical composition root.
/// A bare `IdentityState::new(...)` keeps the section-08 deployment
/// shape (no PAT or OIDC routes mounted).
#[derive(Clone)]
pub struct IdentityState {
    /// Composed identity service.
    pub service: Arc<IdentityService>,
    /// Composed personal-access-token service. When `Some`, the
    /// public router mounts the PAT CRUD endpoints.
    pub api_token_service: Option<Arc<ApiTokenService>>,
    /// Composed OIDC service. When `Some`, the public router mounts
    /// the OIDC start + callback endpoints. The accompanying
    /// `OrgRepo` is shared between the OIDC handlers (slug → org_id
    /// resolution) and the broader identity surface.
    pub oidc_service: Option<Arc<OidcService>>,
    /// Org lookup wired alongside the OIDC service. Held as an option
    /// so callers that do not enable OIDC do not need to pass one.
    pub org_repo: Option<OrgRepo>,
    /// Composed SAML service. Feature-gated under `saml` so default
    /// builds do not link the samael / xmlsec / openssl C stack.
    /// When `Some`, the public router mounts the SAML start, ACS, and
    /// metadata endpoints.
    #[cfg(feature = "saml")]
    pub saml_service: Option<Arc<SamlService>>,
    /// Composed multi-IdP routing state (section-13). When `Some`,
    /// the public router mounts `POST /v1/auth/discover` and the
    /// admin router mounts the per-org domain-claim CRUD surface.
    /// The mounter MUST gate the admin surface behind authenticated
    /// admin middleware.
    pub routing_state: Option<RoutingState>,
}

impl IdentityState {
    /// Construct a fresh state handle from an `Arc`-wrapped service.
    #[must_use]
    pub const fn new(service: Arc<IdentityService>) -> Self {
        Self {
            service,
            api_token_service: None,
            oidc_service: None,
            org_repo: None,
            #[cfg(feature = "saml")]
            saml_service: None,
            routing_state: None,
        }
    }

    /// Attach a personal-access-token service so [`router`] mounts
    /// the `/v1/api-tokens` routes through the standard public
    /// surface.
    #[must_use]
    pub fn with_api_token_service(mut self, svc: Arc<ApiTokenService>) -> Self {
        self.api_token_service = Some(svc);
        self
    }

    /// Attach an OIDC service + org repo so [`router`] mounts the
    /// `/v1/auth/oidc/*` routes through the canonical composition
    /// root.
    #[must_use]
    pub fn with_oidc_service(mut self, svc: Arc<OidcService>, org_repo: OrgRepo) -> Self {
        self.oidc_service = Some(svc);
        self.org_repo = Some(org_repo);
        self
    }

    /// Attach a SAML service so [`router`] mounts the
    /// `/v1/auth/saml/*` routes (start, ACS, metadata) under the
    /// `saml` feature gate.
    #[cfg(feature = "saml")]
    #[must_use]
    pub fn with_saml_service(mut self, svc: Arc<SamlService>) -> Self {
        self.saml_service = Some(svc);
        self
    }

    /// Attach a multi-IdP routing state so [`router`] mounts
    /// `POST /v1/auth/discover` and [`admin_router`] mounts the
    /// per-org `/v1/orgs/{slug}/idps/{id}/domains/...` CRUD surface.
    #[must_use]
    pub fn with_routing_state(mut self, routing_state: RoutingState) -> Self {
        self.routing_state = Some(routing_state);
        self
    }
}

/// Shared state for the session-lifecycle handlers
/// (`/v1/sessions/*`). Carries the session repo (for ownership
/// checks + version surfacing), the revoker, and the active-org
/// switcher composed against the live cache + NATS bus.
#[derive(Clone)]
pub struct SessionsState {
    /// Repo used to read session rows (ownership, version,
    /// last_seen_at).
    pub sessions: SessionRepo,
    /// Revoker used by `DELETE /v1/sessions/{me,id}`.
    pub revoker: Arc<SessionRevoker>,
    /// Active-org switcher used by `PATCH /v1/sessions/me`.
    pub switcher: Arc<SessionOrgSwitcher>,
}

impl SessionsState {
    /// Compose a fresh state handle from the underlying
    /// dependencies.
    #[must_use]
    pub const fn new(
        sessions: SessionRepo,
        revoker: Arc<SessionRevoker>,
        switcher: Arc<SessionOrgSwitcher>,
    ) -> Self {
        Self {
            sessions,
            revoker,
            switcher,
        }
    }
}

/// Build the public password-auth router.
///
/// Admin routes are intentionally excluded; mount [`admin_router`]
/// behind authenticated middleware separately, or use
/// [`router_with_admin`] for the rare case where a single composed
/// router is acceptable (test harnesses, pre-prod inspection
/// listeners that already gate every request behind admin auth).
pub fn router(state: IdentityState) -> Router<()> {
    let api_tokens_router = state
        .api_token_service
        .as_ref()
        .map(|svc| api_tokens::router(api_tokens::ApiTokensState::new(svc.clone())));

    let oidc_router = match (state.oidc_service.as_ref(), state.org_repo.as_ref()) {
        (Some(svc), Some(org_repo)) => Some(oidc::router(oidc::OidcState::new(
            svc.clone(),
            org_repo.clone(),
        ))),
        _ => None,
    };

    #[cfg(feature = "saml")]
    let saml_router = state
        .saml_service
        .as_ref()
        .map(|svc| saml::router(saml::SamlState::new(svc.clone())));

    // Mount the public discover endpoint when the routing state is
    // present. The admin domain-CRUD endpoints land in `admin_router`
    // and stay behind the gateway's authenticated middleware.
    let routing_router = state
        .routing_state
        .as_ref()
        .map(|rs| crate::routing::router(rs.clone()));

    let auth_routes = Router::new()
        .route("/v1/auth/sign-up", post(auth::sign_up))
        .route("/v1/auth/sign-in", post(auth::sign_in))
        .route("/v1/auth/sign-out", post(auth::sign_out))
        .route(
            "/v1/auth/password-reset/request",
            post(password_reset::request),
        )
        .route(
            "/v1/auth/password-reset/confirm",
            post(password_reset::confirm),
        )
        .route(
            "/v1/auth/password-reset/landing",
            get(password_reset::landing),
        )
        .route(
            "/v1/auth/email-verifications/landing",
            get(email_verify::landing),
        )
        .route(
            "/v1/auth/email-verifications/confirm",
            post(email_verify::confirm),
        )
        .with_state(state);

    let composed = match api_tokens_router {
        Some(pat) => auth_routes.merge(pat),
        None => auth_routes,
    };
    let composed = match oidc_router {
        Some(oidc) => composed.merge(oidc),
        None => composed,
    };
    #[cfg(feature = "saml")]
    let composed = match saml_router {
        Some(saml_r) => composed.merge(saml_r),
        None => composed,
    };
    match routing_router {
        Some(disc) => composed.merge(disc),
        None => composed,
    }
}

/// Build the admin-only router.
///
/// The caller MUST gate this router behind authenticated admin
/// middleware before binding it to a public listener. The handlers
/// themselves accept no caller-identity proof; their security relies
/// on the mounter enforcing one.
pub fn admin_router(state: IdentityState) -> Router<()> {
    let routing_admin = state
        .routing_state
        .as_ref()
        .map(|rs| crate::routing::admin_router(rs.clone()));

    let base = Router::new()
        .route("/v1/admin/users/{id}/unlock", post(admin::unlock_user))
        .with_state(state);

    match routing_admin {
        Some(extras) => base.merge(extras),
        None => base,
    }
}

/// Compose [`router`] + [`admin_router`] for callers that need both
/// surfaces on a single listener (typically test harnesses or
/// pre-prod inspection listeners that already enforce admin auth at
/// every entry point).
pub fn router_with_admin(state: IdentityState) -> Router<()> {
    router(state.clone()).merge(admin_router(state))
}

/// Build the session-lifecycle router.
///
/// Routes assume the gateway has resolved the bearer / cookie
/// credential and attached an [`zagrosi_core::AuthContext`] via
/// [`axum::Extension`] before reaching these handlers. The CSRF
/// middleware exported at [`crate::http::csrf::csrf_middleware`]
/// is intended to layer above this router on browser-facing
/// listeners.
pub fn sessions_router(state: SessionsState) -> Router<()> {
    Router::new()
        .route("/v1/sessions", get(sessions::list_sessions))
        .route("/v1/sessions/me", get(sessions::current_session))
        .route("/v1/sessions/me", delete(sessions::delete_current))
        .route("/v1/sessions/me", patch(sessions::switch_active_org))
        .route("/v1/sessions/{id}", delete(sessions::delete_specific))
        .with_state(state)
}
