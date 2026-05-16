// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! `OidcRefreshToken` aggregate (refresh-rotation chain).

use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Refresh-token chain entry. `prev_id` self-references the row that
/// minted this one so the OIDC client can revoke the entire chain when a
/// re-use is detected. `token_hash` is SHA-256 over the raw refresh
/// token (the prefix is implementation-private to the OIDC client).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcRefreshToken {
    /// Application-generated UUID v7 primary key.
    pub id: Uuid,
    /// Owning session.
    pub session_id: Uuid,
    /// SHA-256 of the raw refresh-token value.
    pub token_hash: [u8; 32],
    /// Previous link in the chain; `None` for the first refresh of a
    /// session.
    pub prev_id: Option<Uuid>,
    /// Issue timestamp.
    pub issued_at: DateTime<Utc>,
    /// Single-use seal; `Some(now)` after rotation.
    pub used_at: Option<DateTime<Utc>>,
    /// Revocation timestamp; `None` while live.
    pub revoked_at: Option<DateTime<Utc>>,
}
