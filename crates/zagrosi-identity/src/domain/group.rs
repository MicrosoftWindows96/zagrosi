// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! `Group` + `GroupMembership` aggregates for the SCIM 2.0 `Groups`
//! resource. Persisted via `repo::group_repo::GroupRepo` (multi-tenant
//! through `OrgScoped`).

use chrono::{DateTime, Utc};
use uuid::Uuid;

/// SCIM 2.0 `Group` resource (RFC 7643 §4.2).
///
/// Multi-tenant — every group belongs to exactly one org. The
/// `display_name` is unique per `(org_id, lower(display_name))`
/// while the row is live. `external_id` mirrors SCIM `externalId`
/// (IdP-assigned identifier). `row_version` is the per-row
/// monotonic mutation counter consumed by the SCIM ETag derivation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    /// Application-generated UUID v7 primary key.
    pub id: Uuid,
    /// Owning org.
    pub org_id: Uuid,
    /// SCIM `displayName`.
    pub display_name: String,
    /// SCIM `externalId` (opaque IdP-assigned identifier).
    pub external_id: Option<String>,
    /// Per-row monotonic mutation counter.
    pub row_version: i64,
    /// Row creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Last-mutation timestamp.
    pub updated_at: DateTime<Utc>,
    /// Soft-delete tombstone; `None` for live rows.
    pub deleted_at: Option<DateTime<Utc>>,
}

/// Membership join row between a [`Group`] and a `User`.
///
/// `(group_id, user_id)` is unique while live. Soft-deletion
/// tombstones the row so audit queries can walk historical
/// membership; the partial unique index allows the same pair to be
/// re-added once the prior row is tombstoned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupMembership {
    /// Application-generated UUID v7 primary key.
    pub id: Uuid,
    /// Group side of the join.
    pub group_id: Uuid,
    /// User side of the join.
    pub user_id: Uuid,
    /// Row creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Soft-delete tombstone; `None` for live rows.
    pub deleted_at: Option<DateTime<Utc>>,
}
