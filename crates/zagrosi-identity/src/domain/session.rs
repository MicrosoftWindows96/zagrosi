// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! `Session` aggregate (browser / bearer session cookie).

use chrono::{DateTime, Utc};
use std::net::IpAddr;
use uuid::Uuid;

/// Browser session record. The `token_hash` column persists the
/// SHA-256 of the raw `sid_*` cookie value; the raw value never lands
/// in the database. `version` is the optimistic-locking counter that
/// `update_active_org` increments. `amr` (RFC 8176) and
/// `acr` (RFC 6711) record the authentication methods + assurance
/// level for downstream policy evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    /// Application-generated UUID v7 primary key.
    pub id: Uuid,
    /// SHA-256 digest of the raw cookie value. Bound to the
    /// `BYTEA token_hash` column.
    pub token_hash: [u8; 32],
    /// Owning user.
    pub user_id: Uuid,
    /// Currently-selected org for this session; `None` for newly
    /// authenticated sessions before the first org is picked.
    pub org_id: Option<Uuid>,
    /// User agent string at issue time. Best-effort observability.
    pub user_agent: Option<String>,
    /// Source IP at issue time. Best-effort observability.
    pub ip_addr: Option<IpAddr>,
    /// Optimistic-lock counter; the session module increments on
    /// `update_active_org`.
    pub version: i64,
    /// Authentication Method Reference values per RFC 8176.
    pub amr: Vec<String>,
    /// Authentication Context Class Reference per RFC 6711 / OIDC Core.
    pub acr: Option<String>,
    /// Row creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Last-seen timestamp; updated on cookie introspection.
    pub last_seen_at: DateTime<Utc>,
    /// Hard expiry timestamp; the session is rejected past this point
    /// regardless of `revoked_at`.
    pub expires_at: DateTime<Utc>,
    /// Revocation timestamp; `None` for live sessions.
    pub revoked_at: Option<DateTime<Utc>>,
    /// Soft-delete tombstone; `None` for live rows.
    pub deleted_at: Option<DateTime<Utc>>,
}
