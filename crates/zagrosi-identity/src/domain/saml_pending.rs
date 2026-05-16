// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! `SamlPendingAuth` aggregate. State held between the SP-initiated
//! AuthnRequest and the IdP's POST to the ACS endpoint.

use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Pending SAML AuthnRequest record. Mirrors the contract of
/// [`crate::domain::OidcPendingAuth`]: the row pins the request to a
/// specific `org_idps` row, persists the IdP-bound request id and the
/// 256-bit `RelayState` so the ACS handler can correlate the IdP's
/// response back to the originating start request, and runs against a
/// hard 10-minute expiry. The partial unique index
/// `saml_pending_auth_request_id_unused` guarantees the request id is
/// single-use; representation of a used id is rejected at the SQL
/// layer before the ACS strict-order validation pipeline fires.
///
/// `request_id` is stored verbatim (NOT hashed) because the IdP
/// responds with the value in `Response/@InResponseTo`, and samael's
/// `parse_xml_response_with_mode` requires the original ASCII id to
/// validate the response correlation. The id is generated server-side
/// from a 256-bit CSPRNG draw (see `crate::saml::authn`), so it is
/// unguessable in practice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SamlPendingAuth {
    /// Application-generated UUID v7 primary key.
    pub id: Uuid,
    /// SAML AuthnRequest id (`saml:AuthnRequest/@ID`). 256 bits of
    /// CSPRNG entropy rendered as a stable ASCII id token; the IdP
    /// echoes this verbatim in `Response/@InResponseTo`.
    pub request_id: String,
    /// 256-bit base64url RelayState. A signed envelope is overkill for
    /// a one-shot per-org SP; the value is opaque to the IdP and the
    /// ACS handler matches against the persisted row.
    pub relay_state: String,
    /// IdP this request targets. Resolves the org via
    /// `org_idps.org_id`.
    pub org_idp_id: Uuid,
    /// Row creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Hard expiry (~10 minutes after creation).
    pub expires_at: DateTime<Utc>,
    /// Single-use seal; `Some(now)` after the ACS handler consumes the
    /// row.
    pub used_at: Option<DateTime<Utc>>,
}
