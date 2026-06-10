// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! SCIM bearer-token issuance UX.
//!
//! Surfaces the admin-facing CRUD on `scim_tokens` so an org admin
//! can mint, list, fetch, and revoke per-org SCIM bearers from the
//! SPA. Authentication for these routes is the standard
//! session / PAT path (NOT a SCIM bearer), so callers reach this
//! handler through the same `AuthContext`-extension contract as
//! the password-auth surface.
//!
//! Wire shape (mirrors RFC 7642 §3 + Okta / OneLogin / Entra
//! conventions):
//!
//! - `POST   /v1/orgs/{org_slug}/scim-tokens`             → mint
//! - `GET    /v1/orgs/{org_slug}/scim-tokens`             → list
//! - `GET    /v1/orgs/{org_slug}/scim-tokens/{token_id}`  → metadata
//! - `DELETE /v1/orgs/{org_slug}/scim-tokens/{token_id}`  → revoke
//!
//! Mint returns the raw `scim_<43>` exactly **once**; subsequent
//! reads expose only metadata. The split-25 admin SPA copies the
//! raw bytes into a clipboard prompt and never re-fetches them.

use std::str::FromStr;
use std::sync::Arc;

use axum::Extension;
use axum::Json;
use axum::Router;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{delete, get, post};
use base64::Engine;
use chrono::{DateTime, Utc};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::types::ipnetwork::IpNetwork;
use uuid::Uuid;
use zagrosi_core::{
    AuditActor, AuditEvent, AuditEventKind, AuditEventV1, AuditResource, Auditor, AuthContext,
};

use crate::error::{IdentityError, Result};
use crate::repo::{NewScimResource, OrgRepo, OrgScoped, ScimResourceRepo};

/// Shared application state for the SCIM-token-issuance handlers.
#[derive(Clone)]
pub struct ScimTokensState {
    /// Org repo (resolves `org_slug` → `org_id`).
    pub orgs: OrgRepo,
    /// SCIM bearer-token repo (issuance + revoke).
    pub scim_tokens: ScimResourceRepo,
    /// Auditor sink (`scim_authenticated` is emitted by the SCIM
    /// path; this surface emits create / revoke events on the
    /// general identity audit feed once split-03 lands).
    pub auditor: Arc<dyn Auditor>,
}

impl ScimTokensState {
    /// Compose a state handle.
    #[must_use]
    pub fn new(orgs: OrgRepo, scim_tokens: ScimResourceRepo, auditor: Arc<dyn Auditor>) -> Self {
        Self {
            orgs,
            scim_tokens,
            auditor,
        }
    }
}

/// Mint request body.
#[derive(Debug, Deserialize)]
pub struct CreateScimTokenRequest {
    /// Display name shown in the admin UI.
    pub name: String,
    /// Scope set. Defaults to the v0.1 catalogue when omitted.
    #[serde(default)]
    pub scopes: Option<Vec<String>>,
    /// Optional source-IP allow-list. Empty / omitted → unrestricted.
    #[serde(default, rename = "allowedCidrs")]
    pub allowed_cidrs: Option<Vec<String>>,
    /// Optional `tolerant_mode` flag (Entra ID PATCH workarounds).
    #[serde(default, rename = "tolerantMode")]
    pub tolerant_mode: Option<bool>,
    /// Optional hard expiry timestamp.
    #[serde(default, rename = "expiresAt")]
    pub expires_at: Option<DateTime<Utc>>,
}

/// Issued SCIM bearer (raw token surfaced exactly once).
#[derive(Debug, Serialize)]
pub struct IssuedScimToken {
    /// Row ID.
    pub id: Uuid,
    /// Display name.
    pub name: String,
    /// Scope set.
    pub scopes: Vec<String>,
    /// CIDR allowlist (string form for wire stability).
    #[serde(rename = "allowedCidrs")]
    pub allowed_cidrs: Vec<String>,
    /// `tolerant_mode` flag.
    #[serde(rename = "tolerantMode")]
    pub tolerant_mode: bool,
    /// Creation timestamp.
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
    /// Optional hard expiry.
    #[serde(rename = "expiresAt", skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    /// Raw `scim_<43>` token. Returned exactly once at mint.
    pub token: String,
}

/// SCIM-token metadata view (no raw bytes).
#[derive(Debug, Serialize)]
pub struct ScimTokenView {
    /// Row ID.
    pub id: Uuid,
    /// Display name.
    pub name: String,
    /// Scope set.
    pub scopes: Vec<String>,
    /// CIDR allowlist.
    #[serde(rename = "allowedCidrs")]
    pub allowed_cidrs: Vec<String>,
    /// `tolerant_mode` flag.
    #[serde(rename = "tolerantMode")]
    pub tolerant_mode: bool,
    /// Last-used timestamp.
    #[serde(rename = "lastUsedAt", skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<DateTime<Utc>>,
    /// Last-used source IP.
    #[serde(rename = "lastUsedIp", skip_serializing_if = "Option::is_none")]
    pub last_used_ip: Option<String>,
    /// Creation timestamp.
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
    /// Optional hard expiry.
    #[serde(rename = "expiresAt", skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    /// Optional revoked timestamp (set when `DELETE` was called).
    #[serde(rename = "revokedAt", skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
}

/// Default v0.1 scope catalogue when the caller does not supply one.
const DEFAULT_SCOPES: &[&str] = &["users:read", "users:write", "groups:read", "groups:write"];

/// `POST /v1/orgs/{org_slug}/scim-tokens` — mint a new bearer.
pub async fn create_scim_token(
    State(state): State<ScimTokensState>,
    Extension(ctx): Extension<AuthContext>,
    Path(org_slug): Path<String>,
    Json(req): Json<CreateScimTokenRequest>,
) -> Result<(StatusCode, Json<IssuedScimToken>)> {
    let org = state
        .orgs
        .find_by_slug(&org_slug)
        .await?
        .ok_or(IdentityError::OrgNotFound)?;
    if ctx.org_id() != org.id {
        return Err(IdentityError::OrgNotFound);
    }
    let scopes_owned: Vec<String> = req
        .scopes
        .clone()
        .unwrap_or_else(|| DEFAULT_SCOPES.iter().map(|s| (*s).to_string()).collect());
    let scopes_borrow: Vec<&str> = scopes_owned.iter().map(String::as_str).collect();
    let allowed_cidrs: Vec<IpNetwork> = req
        .allowed_cidrs
        .as_deref()
        .unwrap_or_default()
        .iter()
        .map(|s| {
            IpNetwork::from_str(s).map_err(|err| IdentityError::InvalidApiTokenRequest {
                reason: format!("malformed CIDR '{s}': {err}"),
            })
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;

    let raw = mint_raw_token();
    let mut hasher = Sha256::new();
    hasher.update(raw.as_bytes());
    let hash: [u8; 32] = hasher.finalize().into();

    let scoped = OrgScoped::new(&state.scim_tokens, org.id);
    let row = scoped
        .create(NewScimResource {
            id: Uuid::now_v7(),
            display_name: &req.name,
            token_hash: &hash[..],
            scopes: &scopes_borrow,
            allowed_cidrs: &allowed_cidrs,
            tolerant_mode: req.tolerant_mode.unwrap_or(false),
            expires_at: req.expires_at,
        })
        .await?;

    record_create(
        &state.auditor,
        org.id,
        ctx.subject_id(),
        row.id,
        ctx.correlation_id(),
    )
    .await;
    Ok((
        StatusCode::CREATED,
        Json(IssuedScimToken {
            id: row.id,
            name: row.display_name,
            scopes: row.scopes,
            allowed_cidrs: row.allowed_cidrs.iter().map(ToString::to_string).collect(),
            tolerant_mode: row.tolerant_mode,
            created_at: row.created_at,
            expires_at: row.expires_at,
            token: raw,
        }),
    ))
}

/// `GET /v1/orgs/{org_slug}/scim-tokens` — list metadata for the
/// caller's org. v0.1 returns the live + revoked rows together; the
/// SPA filters by `revokedAt is null` for the active set.
pub async fn list_scim_tokens(
    State(state): State<ScimTokensState>,
    Extension(ctx): Extension<AuthContext>,
    Path(org_slug): Path<String>,
) -> Result<Json<Vec<ScimTokenView>>> {
    let org = state
        .orgs
        .find_by_slug(&org_slug)
        .await?
        .ok_or(IdentityError::OrgNotFound)?;
    if ctx.org_id() != org.id {
        return Err(IdentityError::OrgNotFound);
    }
    let rows = sqlx::query!(
        r#"
        SELECT id, display_name, scopes, allowed_cidrs, tolerant_mode,
               last_used_at, last_used_ip, created_at, expires_at,
               revoked_at, deleted_at
        FROM scim_tokens
        WHERE org_id = $1 AND deleted_at IS NULL
        ORDER BY created_at DESC
        "#,
        org.id,
    )
    .fetch_all(state.scim_tokens.pool())
    .await?;
    let views = rows
        .into_iter()
        .map(|r| ScimTokenView {
            id: r.id,
            name: r.display_name,
            scopes: r.scopes,
            allowed_cidrs: r.allowed_cidrs.iter().map(ToString::to_string).collect(),
            tolerant_mode: r.tolerant_mode,
            last_used_at: r.last_used_at,
            last_used_ip: r.last_used_ip.map(|n| n.ip().to_string()),
            created_at: r.created_at,
            expires_at: r.expires_at,
            revoked_at: r.revoked_at,
        })
        .collect();
    Ok(Json(views))
}

/// `GET /v1/orgs/{org_slug}/scim-tokens/{id}` — metadata only.
pub async fn get_scim_token(
    State(state): State<ScimTokensState>,
    Extension(ctx): Extension<AuthContext>,
    Path((org_slug, token_id)): Path<(String, Uuid)>,
) -> Result<Json<ScimTokenView>> {
    let org = state
        .orgs
        .find_by_slug(&org_slug)
        .await?
        .ok_or(IdentityError::OrgNotFound)?;
    if ctx.org_id() != org.id {
        return Err(IdentityError::OrgNotFound);
    }
    let row = sqlx::query!(
        r#"
        SELECT id, display_name, scopes, allowed_cidrs, tolerant_mode,
               last_used_at, last_used_ip, created_at, expires_at,
               revoked_at, deleted_at
        FROM scim_tokens
        WHERE org_id = $1 AND id = $2 AND deleted_at IS NULL
        "#,
        org.id,
        token_id,
    )
    .fetch_optional(state.scim_tokens.pool())
    .await?
    .ok_or(IdentityError::TokenNotFound)?;
    Ok(Json(ScimTokenView {
        id: row.id,
        name: row.display_name,
        scopes: row.scopes,
        allowed_cidrs: row.allowed_cidrs.iter().map(ToString::to_string).collect(),
        tolerant_mode: row.tolerant_mode,
        last_used_at: row.last_used_at,
        last_used_ip: row.last_used_ip.map(|n| n.ip().to_string()),
        created_at: row.created_at,
        expires_at: row.expires_at,
        revoked_at: row.revoked_at,
    }))
}

/// `DELETE /v1/orgs/{org_slug}/scim-tokens/{id}` — revoke.
pub async fn revoke_scim_token(
    State(state): State<ScimTokensState>,
    Extension(ctx): Extension<AuthContext>,
    Path((org_slug, token_id)): Path<(String, Uuid)>,
) -> Result<impl IntoResponse> {
    let org = state
        .orgs
        .find_by_slug(&org_slug)
        .await?
        .ok_or(IdentityError::OrgNotFound)?;
    if ctx.org_id() != org.id {
        return Err(IdentityError::OrgNotFound);
    }
    let scoped = OrgScoped::new(&state.scim_tokens, org.id);
    scoped.revoke(token_id).await?;
    record_revoke(
        &state.auditor,
        org.id,
        ctx.subject_id(),
        token_id,
        ctx.correlation_id(),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

/// Build the SCIM-token-issuance router.
pub fn router(state: ScimTokensState) -> Router<()> {
    Router::new()
        .route("/v1/orgs/{org_slug}/scim-tokens", post(create_scim_token))
        .route("/v1/orgs/{org_slug}/scim-tokens", get(list_scim_tokens))
        .route("/v1/orgs/{org_slug}/scim-tokens/{id}", get(get_scim_token))
        .route(
            "/v1/orgs/{org_slug}/scim-tokens/{id}",
            delete(revoke_scim_token),
        )
        .with_state(state)
}

/// Mint a fresh SCIM bearer in the canonical
/// `scim_<43 base64url no-pad>` form. 32 random bytes are
/// base64url-encoded without padding (32 → 43 chars).
fn mint_raw_token() -> String {
    let mut buf = [0u8; 32];
    OsRng.fill_bytes(&mut buf);
    let body = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf);
    assert_eq!(
        body.len(),
        43,
        "base64url-no-pad of 32 bytes must be 43 chars; encoder change broke the auth contract"
    );
    format!("scim_{body}")
}

async fn record_create(
    auditor: &Arc<dyn Auditor>,
    org_id: Uuid,
    actor_id: Uuid,
    token_id: Uuid,
    correlation: Uuid,
) {
    let event = AuditEventV1::builder(
        AuditEventKind::ServiceTokenCreated,
        AuditActor::User {
            user_id: actor_id,
            ip: None,
        },
        Some(org_id),
        correlation,
    )
    .resource(AuditResource::ScimToken { token_id })
    .build();
    auditor.record(AuditEvent::V1(event)).await;
}

async fn record_revoke(
    auditor: &Arc<dyn Auditor>,
    org_id: Uuid,
    actor_id: Uuid,
    token_id: Uuid,
    correlation: Uuid,
) {
    let event = AuditEventV1::builder(
        AuditEventKind::ServiceTokenRevoked,
        AuditActor::User {
            user_id: actor_id,
            ip: None,
        },
        Some(org_id),
        correlation,
    )
    .resource(AuditResource::ScimToken { token_id })
    .build();
    auditor.record(AuditEvent::V1(event)).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mint_raw_format() {
        let raw = mint_raw_token();
        assert!(raw.starts_with("scim_"));
        assert_eq!(raw.len(), "scim_".len() + 43);
        let body = &raw[5..];
        assert!(
            body.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        );
    }
}
