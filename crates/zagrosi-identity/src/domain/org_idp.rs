// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! `OrgIdp` (per-org SSO IdP configuration) aggregate.

use chrono::{DateTime, Utc};
use serde_json::Value as JsonValue;
use uuid::Uuid;

/// Per-org IdP configuration. `protocol` is one of `oidc` / `saml`.
/// `config` is a versioned JSONB blob whose schema is described by
/// `OidcConfigV1` / `SamlConfigV1` ports in `zagrosi-core`. The
/// secret material inside `config` (e.g. OIDC `client_secret`, SAML SP
/// signing key) is wrapped via the `crypto::Secrets` shim
/// before reaching the repository.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrgIdp {
    /// Application-generated UUID v7 primary key.
    pub id: Uuid,
    /// Owning org.
    pub org_id: Uuid,
    /// `oidc` or `saml`.
    pub protocol: String,
    /// Display name shown in admin UI / IdP picker.
    pub display_name: String,
    /// Versioned JSONB configuration blob (encrypted secrets included).
    pub config: JsonValue,
    /// Schema version for `config`. Bumped when a new field becomes
    /// non-optional.
    pub config_version: i16,
    /// Whether SCIM/SSO Just-in-Time provisioning is allowed.
    pub jit_provisioning: bool,
    /// Whether this IdP handles unrouted traffic for the org.
    pub is_default: bool,
    /// Kill-switch; flipping to `false` rejects new sign-ins.
    pub enabled: bool,
    /// Row creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Last-mutation timestamp.
    pub updated_at: DateTime<Utc>,
    /// Soft-delete tombstone; `None` for live rows.
    pub deleted_at: Option<DateTime<Utc>>,
}
