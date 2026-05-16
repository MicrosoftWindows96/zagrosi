// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! SCIM 2.0 HTTP surface.
//!
//! Top-level invariants enforced here:
//!
//! - `Content-Type: application/scim+json` on every SCIM response
//!   (success and error). Other identity routes use `application/json`.
//! - SCIM error envelope per RFC 7644 §3.12 — `schemas`, `status`,
//!   `detail`, optional `scimType`. Overrides the project-wide
//!   problem-detail shape on SCIM routes only.
//! - Tenant isolation: every multi-tenant SQL query in this module
//!   anchors on the SCIM bearer token's `org_id`. Cross-org IDs and
//!   missing IDs are indistinguishable from the response surface
//!   (both `404 not found`, both share the same body shape).
//!
//! See the section-12 plan for the routing matrix
//! (`/scim/v2/{Users,Groups,Schemas,ResourceTypes,ServiceProviderConfig}`).

use std::sync::Arc;

use axum::Router;
use axum::http::StatusCode;
use axum::http::header::CONTENT_TYPE;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde::Serialize;
use sqlx::PgPool;

use crate::error::IdentityError;
use crate::repo::{GroupRepo, MembershipRepo, ScimResourceRepo, SessionRepo, UserRepo};
use crate::session::SessionRevoker;
use zagrosi_core::Auditor;

pub mod attrs;
pub mod auth;
pub mod discovery;
pub mod etag;
pub mod filter;
pub mod groups;
pub mod patch;
pub mod translate;
pub mod users;

/// Content-type marker for SCIM 2.0 responses (RFC 7644 §8.1).
pub const SCIM_CONTENT_TYPE: &str = "application/scim+json";

/// SCIM error envelope schema URN (RFC 7644 §3.12).
pub const SCIM_ERROR_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:Error";

/// SCIM list-response envelope schema URN (RFC 7644 §3.4.2).
pub const SCIM_LIST_RESPONSE_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";

/// SCIM PATCH-op envelope schema URN (RFC 7644 §3.5.2).
pub const SCIM_PATCH_OP_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";

/// SCIM core User schema URN (RFC 7643 §4.1).
pub const SCIM_USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";

/// SCIM core Group schema URN (RFC 7643 §4.2).
pub const SCIM_GROUP_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";

/// Server-side cap on `count` per RFC 7644 §3.4.2.4 + the
/// section-12 ServiceProviderConfig advertisement.
pub const SCIM_MAX_COUNT: i64 = 200;

/// Shared application state for every SCIM handler.
///
/// `Arc`-wrapped components match the existing `IdentityState`
/// shape so the gateway can clone the state cheaply for each
/// request.
#[derive(Clone)]
pub struct ScimState {
    /// Connection pool (multi-tenant queries hard-anchor on the
    /// bearer's `org_id`; the pool itself is org-agnostic).
    pub pool: PgPool,
    /// User repo (single-tenant — SCIM Users surface scopes through
    /// `MembershipRepo` to enforce tenancy).
    pub users: UserRepo,
    /// SCIM bearer-token repo for the auth middleware.
    pub scim_tokens: ScimResourceRepo,
    /// Group repo (multi-tenant via `OrgScoped`).
    pub groups: GroupRepo,
    /// Memberships repo for SCIM `groups` mapping.
    pub memberships: MembershipRepo,
    /// Session repo used by the active=false revocation path.
    pub sessions: SessionRepo,
    /// Session revoker so the deactivation flow rides the same
    /// pub/sub channel as interactive sign-out.
    pub revoker: Arc<SessionRevoker>,
    /// Auditor sink. SCIM emits `scim_user_*` / `scim_group_*` /
    /// `scim_unconditional_write` events through this.
    pub auditor: Arc<dyn Auditor>,
    /// Optional public base URL prepended to `meta.location` so
    /// SCIM responses carry absolute URIs (RFC 7643 §3.1
    /// recommends absolute, RFC 7644 §3.3 mandates `Location`
    /// header on `201 Created`). Empty value → relative-path
    /// behaviour (legacy default; production composers should
    /// set this to e.g. `https://app.zagrosi.com`).
    pub base_url: String,
}

impl ScimState {
    /// Compose a SCIM state handle. The new state defaults to a
    /// relative-URI `meta.location` for backwards compatibility;
    /// callers that need absolute URIs (Okta / Entra
    /// integrations) chain [`Self::with_base_url`].
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pool: PgPool,
        users: UserRepo,
        scim_tokens: ScimResourceRepo,
        groups: GroupRepo,
        memberships: MembershipRepo,
        sessions: SessionRepo,
        revoker: Arc<SessionRevoker>,
        auditor: Arc<dyn Auditor>,
    ) -> Self {
        Self {
            pool,
            users,
            scim_tokens,
            groups,
            memberships,
            sessions,
            revoker,
            auditor,
            base_url: String::new(),
        }
    }

    /// Override the `meta.location` base URL. The value is
    /// concatenated verbatim with `/scim/v2/{Resource}/{id}` so
    /// callers should pass a value WITHOUT a trailing slash
    /// (e.g. `https://app.zagrosi.com`).
    #[must_use]
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into();
        self
    }
}

/// SCIM-specific error variants.
///
/// Distinct from [`IdentityError`] so the IntoResponse impl emits
/// the SCIM error envelope (with `Content-Type: application/scim+json`
/// and `scimType` per RFC 7644 §3.12) instead of the project-wide
/// problem-detail JSON.
#[derive(Debug, thiserror::Error)]
pub enum ScimError {
    /// Authorization header missing, malformed, or token unknown /
    /// revoked. Mapped to `401 unauthorized`.
    #[error("scim unauthorized")]
    Unauthorized,
    /// CIDR allowlist rejected the request's peer IP. Mapped to
    /// `403 forbidden`. Distinct from [`Self::Unauthorized`] because
    /// the source-IP check fires *before* the resource lookup; the
    /// status code is intentionally non-tenant-leaking.
    #[error("scim cidr allowlist rejected source ip")]
    Forbidden,
    /// `Content-Type` is not `application/scim+json` on a PATCH/POST/PUT.
    /// Mapped to `415 unsupported media type`.
    #[error("scim unsupported content-type")]
    UnsupportedMediaType,
    /// Resource not found in the caller's org. Cross-org IDs map
    /// here too — never `Forbidden`. Mapped to `404 not found`.
    #[error("scim resource not found")]
    NotFound,
    /// Filter grammar parse failed. `attr` carries the offending
    /// attribute when known. Mapped to `400 invalidFilter`.
    #[error("scim invalid filter: {detail}")]
    InvalidFilter {
        /// Human-readable description of the parse failure.
        detail: String,
    },
    /// PATCH `path` parse failed. Mapped to `400 invalidPath`.
    #[error("scim invalid path: {detail}")]
    InvalidPath {
        /// Human-readable description of the path failure.
        detail: String,
    },
    /// `sortBy` references an attribute outside the whitelist.
    /// Mapped to `400 invalidValue` (RFC 7644 §3.12 documents
    /// `invalidValue` for this case; some validators also accept
    /// `invalidSortBy` — both surface the same scimType here).
    #[error("scim invalid sortBy: {attr}")]
    InvalidSortBy {
        /// The rejected attribute name.
        attr: String,
    },
    /// Request body failed schema validation (missing required
    /// field, wrong type, etc.). Mapped to `400 invalidValue`.
    #[error("scim invalid value: {detail}")]
    InvalidValue {
        /// Human-readable description of the validation failure.
        detail: String,
    },
    /// `userName` (or `displayName` for groups) collides with an
    /// existing live row in the same org. Mapped to `409 uniqueness`.
    #[error("scim uniqueness: {detail}")]
    Uniqueness {
        /// Human-readable description of the collision.
        detail: String,
    },
    /// PUT/PATCH violates a mutability constraint (immutable field,
    /// readOnly field). Mapped to `400 mutability`.
    #[error("scim mutability: {detail}")]
    Mutability {
        /// Human-readable description of the violation.
        detail: String,
    },
    /// `If-Match` precondition mismatch. Mapped to `412 precondition
    /// failed`.
    #[error("scim precondition failed")]
    PreconditionFailed,
    /// Internal failure (DB outage, etc.). Mapped to `500 internal
    /// error`. The detail is `&'static str` so caller-controlled
    /// payloads cannot reach the response body.
    #[error("scim internal error: {0}")]
    Internal(&'static str),
    /// Wrapped persistence error. Mapped to `500 internal error`.
    #[error("scim database: {0}")]
    Database(#[source] Box<sqlx::Error>),
}

impl ScimError {
    /// HTTP status code surfaced to the client. The mapping is
    /// authoritative; the IntoResponse impl is the only consumer.
    #[must_use]
    pub const fn status(&self) -> StatusCode {
        match self {
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::UnsupportedMediaType => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::InvalidFilter { .. }
            | Self::InvalidPath { .. }
            | Self::InvalidSortBy { .. }
            | Self::InvalidValue { .. }
            | Self::Mutability { .. } => StatusCode::BAD_REQUEST,
            Self::Uniqueness { .. } => StatusCode::CONFLICT,
            Self::PreconditionFailed => StatusCode::PRECONDITION_FAILED,
            Self::Internal(_) | Self::Database(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Optional `scimType` per RFC 7644 §3.12.
    #[must_use]
    pub const fn scim_type(&self) -> Option<&'static str> {
        match self {
            Self::InvalidFilter { .. } => Some("invalidFilter"),
            Self::InvalidPath { .. } => Some("invalidPath"),
            Self::InvalidSortBy { .. } | Self::InvalidValue { .. } => Some("invalidValue"),
            Self::Mutability { .. } => Some("mutability"),
            Self::Uniqueness { .. } => Some("uniqueness"),
            _ => None,
        }
    }

    /// Human-readable detail surfaced in the response body.
    /// Caller-controlled fragments are echoed verbatim — handlers
    /// MUST sanitize before constructing variants that embed user
    /// input.
    #[must_use]
    pub fn detail(&self) -> String {
        match self {
            Self::Unauthorized => "authentication required".to_string(),
            Self::Forbidden => "source ip not permitted".to_string(),
            Self::UnsupportedMediaType => {
                format!("Content-Type must be {SCIM_CONTENT_TYPE}")
            }
            Self::NotFound => "resource not found".to_string(),
            Self::InvalidFilter { detail }
            | Self::InvalidPath { detail }
            | Self::InvalidValue { detail }
            | Self::Mutability { detail }
            | Self::Uniqueness { detail } => detail.clone(),
            Self::InvalidSortBy { attr } => format!("unknown sortBy attribute: {attr}"),
            Self::PreconditionFailed => "If-Match precondition failed".to_string(),
            Self::Internal(_) | Self::Database(_) => "internal server error".to_string(),
        }
    }
}

impl From<sqlx::Error> for ScimError {
    fn from(err: sqlx::Error) -> Self {
        Self::Database(Box::new(err))
    }
}

impl From<IdentityError> for ScimError {
    fn from(err: IdentityError) -> Self {
        match err {
            IdentityError::UserNotFound
            | IdentityError::TokenNotFound
            | IdentityError::OrgNotFound
            | IdentityError::OidcIdpNotFound
            | IdentityError::GroupNotFound => Self::NotFound,
            IdentityError::ScimPreconditionFailed => Self::PreconditionFailed,
            IdentityError::EmailAlreadyExists => Self::Uniqueness {
                detail: "userName already in use".to_string(),
            },
            IdentityError::GroupDisplayNameExists => Self::Uniqueness {
                detail: "displayName already in use".to_string(),
            },
            IdentityError::Database(inner) => Self::Database(inner),
            other => {
                tracing::warn!(error = %other, "unmapped identity error in scim path");
                Self::Internal("unmapped identity error")
            }
        }
    }
}

#[derive(Serialize)]
struct ScimErrorBody {
    schemas: [&'static str; 1],
    status: String,
    detail: String,
    #[serde(rename = "scimType", skip_serializing_if = "Option::is_none")]
    scim_type: Option<&'static str>,
}

impl IntoResponse for ScimError {
    fn into_response(self) -> Response {
        let status = self.status();
        if matches!(self, Self::Database(_) | Self::Internal(_)) {
            tracing::warn!(error = %self, "scim handler emitted internal error");
        }
        let body = ScimErrorBody {
            schemas: [SCIM_ERROR_SCHEMA],
            status: status.as_u16().to_string(),
            detail: self.detail(),
            scim_type: self.scim_type(),
        };
        let json = serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec());
        let mut resp = (status, json).into_response();
        resp.headers_mut().insert(
            CONTENT_TYPE,
            axum::http::HeaderValue::from_static(SCIM_CONTENT_TYPE),
        );
        resp
    }
}

/// Build the SCIM 2.0 router (`/scim/v2/*`).
///
/// The bearer + CIDR layer is applied uniformly so a missing or
/// rejected token never reaches the resource handlers. The discovery
/// endpoints (`/Schemas`, `/ResourceTypes`, `/ServiceProviderConfig`)
/// share the layer because some validators authenticate even those
/// reads and we follow their stricter convention.
pub fn router(state: ScimState) -> Router<()> {
    Router::new()
        .route(
            "/scim/v2/Users",
            get(users::list_users).post(users::create_user),
        )
        .route(
            "/scim/v2/Users/{id}",
            get(users::get_user)
                .patch(users::patch_user)
                .put(users::put_user)
                .delete(users::delete_user),
        )
        .route(
            "/scim/v2/Groups",
            get(groups::list_groups).post(groups::create_group),
        )
        .route(
            "/scim/v2/Groups/{id}",
            get(groups::get_group)
                .patch(groups::patch_group)
                .put(groups::put_group)
                .delete(groups::delete_group),
        )
        .route("/scim/v2/ResourceTypes", get(discovery::resource_types))
        .route("/scim/v2/Schemas", get(discovery::schemas))
        .route(
            "/scim/v2/ServiceProviderConfig",
            get(discovery::service_provider_config),
        )
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth::scim_bearer_layer,
        ))
        .with_state(state)
}

/// Serialise `body` as the SCIM `application/scim+json` content
/// type with the given status code.
pub(crate) fn scim_json<T: Serialize>(status: StatusCode, body: &T) -> Response {
    scim_json_with_headers(status, body, None, None)
}

/// Serialise `body` and attach optional `ETag` + `Location`
/// headers. RFC 7643 §3.1 mandates `ETag` mirror `meta.version`
/// on every mutation response; RFC 7644 §3.3 mandates a
/// `Location` header on `201 Created` for resource creation.
pub(crate) fn scim_json_with_headers<T: Serialize>(
    status: StatusCode,
    body: &T,
    etag: Option<&str>,
    location: Option<&str>,
) -> Response {
    let Ok(bytes) = serde_json::to_vec(body) else {
        return ScimError::Internal("response serialisation failed").into_response();
    };
    let mut resp = (status, bytes).into_response();
    let headers = resp.headers_mut();
    headers.insert(
        CONTENT_TYPE,
        axum::http::HeaderValue::from_static(SCIM_CONTENT_TYPE),
    );
    if let Some(tag) = etag
        && let Ok(value) = axum::http::HeaderValue::from_str(tag)
    {
        headers.insert(axum::http::header::ETAG, value);
    }
    if let Some(loc) = location
        && let Ok(value) = axum::http::HeaderValue::from_str(loc)
    {
        headers.insert(axum::http::header::LOCATION, value);
    }
    resp
}

// Helper aliases used by tests.
pub use auth::ScimAuth;
