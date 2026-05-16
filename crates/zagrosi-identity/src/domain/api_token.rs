// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! `ApiToken` (personal access token) aggregate.

use chrono::{DateTime, Utc};
use std::net::IpAddr;
use uuid::Uuid;

/// Personal access token (`pat_*`). `token_hash` is SHA-256 over the
/// full raw token (prefix included). `(token_hash, revoked_at IS NULL)`
/// is partially unique. `last_used_*` columns are best-effort
/// observability — concurrent updates may lose without consequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiToken {
    /// Application-generated UUID v7 primary key.
    pub id: Uuid,
    /// SHA-256 of the raw token (`pat_<43>`). 32 bytes.
    pub token_hash: [u8; 32],
    /// Owning user.
    pub user_id: Uuid,
    /// Owning org. PAT scope is always (user, org) — see
    /// the API-token surface for the broader policy model.
    pub org_id: Uuid,
    /// Human-set display name shown on the token-management UI.
    pub display_name: String,
    /// Authorisation scopes. Free-form strings consumed by future
    /// policy code (the service-token surface).
    pub scopes: Vec<String>,
    /// Last-used timestamp; updated by the API-token introspector.
    pub last_used_at: Option<DateTime<Utc>>,
    /// Last source IP that introspected the token.
    pub last_used_ip: Option<IpAddr>,
    /// Row creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Optional hard expiry timestamp; `None` means never.
    pub expires_at: Option<DateTime<Utc>>,
    /// Revocation timestamp; `None` for live tokens.
    pub revoked_at: Option<DateTime<Utc>>,
}
