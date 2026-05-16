// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! `Org` (organisation / tenant root) aggregate.

use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Tenant root record. `slug` is unique among live (`deleted_at IS NULL`)
/// rows via a partial unique index in migration `002_orgs.sql`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Org {
    /// Application-generated UUID v7 primary key.
    pub id: Uuid,
    /// URL-safe identifier (lowercased; whitespace-free).
    pub slug: String,
    /// Human-readable display name.
    pub display_name: String,
    /// Optional primary email-domain claim. The multi-IdP routing layer keys
    /// off `org_idp_domains` rather than this column for IdP routing.
    pub primary_domain: Option<String>,
    /// Row creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Last-mutation timestamp.
    pub updated_at: DateTime<Utc>,
    /// Soft-delete tombstone; `None` for live rows.
    pub deleted_at: Option<DateTime<Utc>>,
}
