// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! `Membership` (user ↔ org link) aggregate.

use chrono::{DateTime, Utc};
use uuid::Uuid;

/// One per `(user_id, org_id)` live row. The `(user_id, org_id)`
/// uniqueness is enforced by a partial unique index over
/// `deleted_at IS NULL` so a user can re-join after leaving.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Membership {
    /// Application-generated UUID v7 primary key.
    pub id: Uuid,
    /// Linked user.
    pub user_id: Uuid,
    /// Linked org.
    pub org_id: Uuid,
    /// Coarse role placeholder until the tenant-isolation layer's RBAC lands. Defaults to `member`.
    pub basic_role: String,
    /// Auth path that minted the membership: one of
    /// `password`, `oidc`, `saml`, `scim`, `manual`.
    pub joined_via: String,
    /// Timestamp the membership was JIT-provisioned via SSO/SCIM;
    /// `None` for password / manual joins.
    pub jit_provisioned_at: Option<DateTime<Utc>>,
    /// Row creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Soft-delete tombstone; `None` for live rows.
    pub deleted_at: Option<DateTime<Utc>>,
}
