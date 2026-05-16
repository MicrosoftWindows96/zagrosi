// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! `FederatedIdentity` (canonical SSO anchor) aggregate.

use chrono::{DateTime, Utc};
use uuid::Uuid;

/// SSO anchor row. The composite uniqueness on
/// `(protocol, issuer_or_entity_id, subject_or_nameid)` is the
/// project-wide invariant; see `documentation/identity.md`, section "SSO
/// canonical user lookup". `user_id` is `None` for tombstones; the
/// row still occupies the unique slot to prevent silent
/// re-attachment after soft-delete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FederatedIdentity {
    /// Application-generated UUID v7 primary key.
    pub id: Uuid,
    /// `oidc` or `saml`.
    pub protocol: String,
    /// OIDC `iss` or SAML `EntityID`.
    pub issuer_or_entity_id: String,
    /// OIDC `sub` or SAML `NameID`.
    pub subject_or_nameid: String,
    /// IdP that produced this anchor.
    pub org_idp_id: Uuid,
    /// Linked user; `None` for tombstones.
    pub user_id: Option<Uuid>,
    /// Row creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Last successful login through this anchor.
    pub last_login_at: Option<DateTime<Utc>>,
}
