// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! SCIM bearer + CIDR allowlist middleware.
//!
//! Order of operations on every SCIM request:
//!
//! 1. `Authorization: Bearer scim_<43>` → reject with `401` if
//!    missing or malformed prefix.
//! 2. SHA-256 hash with the `scim_` prefix included → look up live
//!    row in `scim_tokens` (global, not org-scoped — see the
//!    `ScimResourceRepo::find_global_by_token_hash` rationale).
//! 3. Constant-time-equal the row's stored hash against the
//!    computed hash via `subtle::ConstantTimeEq`.
//! 4. CIDR allowlist (`allowed_cidrs`): reject with `403` if
//!    populated and the peer IP is outside the listed networks.
//!    Empty array = unrestricted.
//! 5. Attach [`ScimAuth`] to the request extensions so handlers can
//!    `Extension<ScimAuth>` it.
//! 6. Best-effort `last_used_at` update.
//!
//! The CIDR check fires BEFORE any resource lookup so token-scoped
//! source-IP restriction is the auth contract, not a resource
//! attribute. Failed CIDR returns `403`, not `404`, because the
//! source IP is not subject to the tenant-isolation status-code
//! parity rule.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::HeaderMap;
use axum::http::header::AUTHORIZATION;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use sha2::{Digest, Sha256};
use sqlx::types::ipnetwork::IpNetwork;
use subtle::ConstantTimeEq;
use tracing::warn;
use uuid::Uuid;

use super::{ScimError, ScimState};

/// Bearer-credentials view attached to every authenticated SCIM
/// request via `Extension<ScimAuth>`.
#[derive(Debug, Clone)]
pub struct ScimAuth {
    /// Primary key of the `scim_tokens` row.
    pub token_id: Uuid,
    /// Owning org. Every multi-tenant SCIM query MUST hard-anchor
    /// on this value.
    pub org_id: Uuid,
    /// Scope set granted by the token (`users:read`, etc.). For
    /// v0.1 the scopes are advisory — the SCIM router exposes the
    /// full surface to every authenticated bearer; per-scope
    /// gating arrives with the admin layer.
    pub scopes: Vec<String>,
    /// Whether `tolerant_mode` is enabled (Entra ID PATCH workarounds).
    pub tolerant_mode: bool,
}

/// Required prefix for SCIM bearers.
const SCIM_PREFIX: &str = "scim_";
/// Length of the random body of a SCIM bearer (43 base64url chars).
const SCIM_BODY_LEN: usize = 43;

/// SCIM bearer + CIDR layer.
///
/// Mounted via `route_layer(axum::middleware::from_fn_with_state(...))`
/// so every SCIM route inherits the same authentication contract.
///
/// # Errors
///
/// Returns [`ScimError`] for any auth failure. The error is rendered
/// through the SCIM error envelope (the standard `IdentityError`
/// envelope is bypassed — SCIM uses `application/scim+json` for
/// errors too).
pub async fn scim_bearer_layer(
    State(state): State<ScimState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    mut req: Request<Body>,
    next: Next,
) -> Result<Response, ScimError> {
    let raw = parse_bearer(&headers).ok_or(ScimError::Unauthorized)?;
    if !raw.starts_with(SCIM_PREFIX) || raw.len() != SCIM_PREFIX.len() + SCIM_BODY_LEN {
        return Err(ScimError::Unauthorized);
    }

    let mut hasher = Sha256::new();
    hasher.update(raw.as_bytes());
    let computed: [u8; 32] = hasher.finalize().into();

    let row = state
        .scim_tokens
        .find_global_by_token_hash(&computed)
        .await
        .map_err(super::ScimError::from)?
        .ok_or(ScimError::Unauthorized)?;

    if !bool::from(row.token_hash.ct_eq(&computed)) {
        return Err(ScimError::Unauthorized);
    }

    if !row.allowed_cidrs.is_empty() && !cidr_contains(&row.allowed_cidrs, peer.ip()) {
        warn!(token_id = %row.id, "scim cidr allowlist rejected source ip");
        return Err(ScimError::Forbidden);
    }

    let auth = ScimAuth {
        token_id: row.id,
        org_id: row.org_id,
        scopes: row.scopes.clone(),
        tolerant_mode: row.tolerant_mode,
    };
    req.extensions_mut().insert(auth);

    // The touch is a tenant WRITE: it rides the APP pool with the
    // resolved row's org as context (state.scim_tokens is the
    // SELECT-only auth-pool repo).
    let touch_repo = crate::repo::ScimResourceRepo::new(state.pool.clone());
    if let Err(err) = crate::repo::OrgScoped::new(&touch_repo, row.org_id)
        .touch_last_used(row.id, Some(peer.ip()))
        .await
    {
        warn!(error = %err, token_id = %row.id, "scim last_used_at update failed");
    }

    Ok(next.run(req).await)
}

fn parse_bearer(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(AUTHORIZATION)?.to_str().ok()?;
    let trimmed = raw.trim();
    let body = trimmed
        .strip_prefix("Bearer ")
        .or_else(|| trimmed.strip_prefix("bearer "))?;
    Some(body.trim().to_string())
}

fn cidr_contains(networks: &[IpNetwork], ip: std::net::IpAddr) -> bool {
    networks.iter().any(|net| net.contains(ip))
}

impl IntoResponse for ScimAuth {
    /// Defensive impl for misuse — middleware sets the value on
    /// extensions, never returns it as a body. Render an empty
    /// 200 OK to avoid panics.
    fn into_response(self) -> Response {
        Response::builder()
            .status(axum::http::StatusCode::NO_CONTENT)
            .body(Body::empty())
            .unwrap_or_else(|_| {
                Response::builder()
                    .status(axum::http::StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::empty())
                    .unwrap_or_default()
            })
    }
}

/// Helper used by tests + the token issuance UX.
///
/// Hashes the raw token (with prefix) into the 32-byte storage
/// form. Mirrors the SCIM auth path so test fixtures populate
/// `token_hash` correctly.
#[must_use]
pub fn hash_scim_token_raw(raw: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(raw.as_bytes());
    hasher.finalize().into()
}

#[allow(dead_code)] // re-exported by ScimState constructor for clarity
type ScimAuthArc = Arc<ScimAuth>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn cidr_empty_means_unrestricted() {
        let _peer: IpAddr = "10.0.0.1".parse().unwrap();
        // The middleware short-circuits on `is_empty()`; here we
        // just exercise `cidr_contains` against a populated list.
        let nets: Vec<IpNetwork> = vec!["10.0.0.0/8".parse().unwrap()];
        assert!(cidr_contains(&nets, "10.255.0.5".parse().unwrap()));
        assert!(!cidr_contains(&nets, "11.0.0.1".parse().unwrap()));
    }

    #[test]
    fn parse_bearer_strips_prefix() {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            axum::http::HeaderValue::from_static("Bearer scim_abc"),
        );
        assert_eq!(parse_bearer(&headers).as_deref(), Some("scim_abc"));
    }

    #[test]
    fn parse_bearer_case_insensitive_scheme() {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            axum::http::HeaderValue::from_static("bearer scim_abc"),
        );
        assert_eq!(parse_bearer(&headers).as_deref(), Some("scim_abc"));
    }
}
