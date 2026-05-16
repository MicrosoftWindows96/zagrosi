// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! `OrgIdpDomain` — verified-domain → IdP mapping aggregate.
//!
//! Each row claims one DNS domain for one IdP. The pair
//! `(lower(domain), org_idp_id)` is partial-unique on verified live
//! rows so an unverified placeholder cannot block a competing claim,
//! but a verified row excludes any other verified claim of the same
//! `(lower(domain), org_idp_id)` tuple.
//!
//! `challenge_token` is a `vrf_*`-prefixed base64url string published
//! to DNS as `_zagrosi-verify.<domain> IN TXT "<token>"`. The verify
//! endpoint resolves the TXT record through the dual-resolver DNSSEC
//! path and matches against the persisted token.
//!
//! `priority` orders multiple verified claims for the same domain in
//! the routing-decision picker (lower wins).

use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Per-IdP domain claim. Tied to an [`crate::domain::OrgIdp`] via
/// `org_idp_id`; that IdP is in turn tied to the owning org. Domain
/// strings are stored as entered (preserving display case); routing
/// lookups always normalise to `lower(domain)` first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrgIdpDomain {
    /// Application-generated UUID v7 primary key.
    pub id: Uuid,
    /// Owning IdP. Joins to `org_idps.id`.
    pub org_idp_id: Uuid,
    /// Domain as entered. The partial unique index is on
    /// `lower(domain)` so case differences cannot fan out into
    /// duplicate verified rows.
    pub domain: String,
    /// `vrf_*`-prefixed challenge token published as the TXT record.
    /// Empty for legacy rows created before migration 020.
    pub challenge_token: String,
    /// Wall-clock when DNS verification last succeeded. `None` for
    /// pending rows.
    pub verified_at: Option<DateTime<Utc>>,
    /// Resolver path that produced the last successful verification
    /// (e.g. `"1.1.1.1+9.9.9.9"`). `None` until the first verify.
    pub last_verified_via: Option<String>,
    /// Picker tie-breaker. Lower priority wins. Defaults to `100`.
    pub priority: i32,
    /// Row creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Soft-delete tombstone; `None` for live rows.
    pub deleted_at: Option<DateTime<Utc>>,
}

/// One row of the routing-decision lookup. Joins
/// [`OrgIdpDomain`] against the underlying IdP so the discover
/// handler has every field needed to build a picker entry without
/// chasing additional repos.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainRouteHit {
    /// IdP id; the discover response carries this.
    pub org_idp_id: Uuid,
    /// Owning org id. Routing does not gate on org but downstream
    /// audit emits this in the event payload.
    pub org_id: Uuid,
    /// `oidc` or `saml`. Discriminator the discover handler maps
    /// onto its `method` field.
    pub protocol: String,
    /// Display name shown in the picker.
    pub display_name: String,
    /// Domain priority (lower wins). Carried so the handler can
    /// sort the picker entries.
    pub priority: i32,
}
