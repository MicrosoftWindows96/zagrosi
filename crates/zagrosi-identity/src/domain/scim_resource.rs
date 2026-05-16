// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! `ScimResource` (SCIM bearer token) aggregate.

use chrono::{DateTime, Utc};
use sqlx::types::ipnetwork::IpNetwork;
use std::net::IpAddr;
use uuid::Uuid;

/// Per-org SCIM bearer token (`scim_*`). Each row is keyed by the
/// SHA-256 hash of the raw token. `scopes` is the SCIM scope set;
/// `allowed_cidrs` constrains the IPs that may present the token —
/// an empty array means unrestricted. `tolerant_mode` toggles
/// SCIM-server workarounds for Entra ID PATCH deviations.
///
/// Naming nuance: the table is `scim_tokens` (a SCIM bearer token
/// IS the SCIM "service-credential" resource); the in-crate name
/// `ScimResource` matches the persistence-layer naming to keep the
/// SCIM vocabulary distinct from the broader `*Token` family. The
/// SCIM server retains this naming.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScimResource {
    /// Application-generated UUID v7 primary key.
    pub id: Uuid,
    /// Owning org.
    pub org_id: Uuid,
    /// Display name shown in admin UI.
    pub display_name: String,
    /// SHA-256 of the raw `scim_*` token.
    pub token_hash: [u8; 32],
    /// SCIM scope set, e.g. `users:read`, `groups:write`.
    pub scopes: Vec<String>,
    /// Source-IP allow-list. Empty means unrestricted.
    pub allowed_cidrs: Vec<IpNetwork>,
    /// Toggles SCIM-server Entra ID workarounds.
    pub tolerant_mode: bool,
    /// Last-used timestamp.
    pub last_used_at: Option<DateTime<Utc>>,
    /// Last source IP that introspected the token.
    pub last_used_ip: Option<IpAddr>,
    /// Row creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Optional hard expiry timestamp.
    pub expires_at: Option<DateTime<Utc>>,
    /// Revocation timestamp.
    pub revoked_at: Option<DateTime<Utc>>,
    /// Soft-delete tombstone.
    pub deleted_at: Option<DateTime<Utc>>,
}
