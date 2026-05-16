// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! `User` aggregate. Persisted via `repo::user_repo::UserRepo`.

use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Canonical user record.
///
/// `email` is stored case-preserving for display; `email_lower` mirrors
/// the database generated column (`lower(email)`) and is the column
/// every uniqueness / lookup index targets. `password_hash` is `None`
/// for SSO-only accounts. `password_updated_at` is the password-reset
/// revocation invariant consumed by sessions (sessions issued before
/// this timestamp are rejected). `password_hash_version` tracks the
/// Argon2id profile version. `active` mirrors SCIM `active`; SCIM
/// `active=false` flips this and revokes every live session for the
/// user in the same DB transaction. `external_id` mirrors SCIM
/// `externalId` (IdP-assigned opaque identifier). `row_version` is
/// the per-row monotonic mutation counter consumed by the SCIM ETag
/// derivation (`http::scim::etag::meta_version`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    /// Application-generated UUID v7 primary key.
    pub id: Uuid,
    /// Display-case email address.
    pub email: String,
    /// `lower(email)` mirror of the DB generated column.
    pub email_lower: String,
    /// Display name shown in chrome / member rosters. Distinct from
    /// `email` so renames are cheap.
    pub display_name: String,
    /// Timestamp the user verified their email; `None` until the
    /// `vrf_*` flow completes.
    pub email_verified_at: Option<DateTime<Utc>>,
    /// PHC-format password hash; `None` for SSO-only users.
    pub password_hash: Option<String>,
    /// Timestamp the password was last set / rotated. The session module
    /// rejects sessions whose `created_at` precedes this value.
    pub password_updated_at: Option<DateTime<Utc>>,
    /// Argon2id profile version; bumped by password-auth rotation.
    pub password_hash_version: i16,
    /// Timestamp the user enrolled an MFA factor; `None` until enrolled.
    pub mfa_enrolled_at: Option<DateTime<Utc>>,
    /// SCIM `active` flag. Flipping to `false` revokes every live
    /// session for the user in the same DB transaction.
    pub active: bool,
    /// SCIM `externalId` (opaque IdP-assigned identifier). `None`
    /// for users provisioned outside SCIM.
    pub external_id: Option<String>,
    /// Per-row monotonic mutation counter; bumped on every PATCH/PUT
    /// to disambiguate ETags within the same `updated_at` granularity.
    pub row_version: i64,
    /// Row creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Last-mutation timestamp.
    pub updated_at: DateTime<Utc>,
    /// Soft-delete tombstone; `None` for live rows.
    pub deleted_at: Option<DateTime<Utc>>,
}
