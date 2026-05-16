// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! `SamlAssertionRecord` aggregate (assertion replay ledger).

use chrono::{DateTime, Utc};
use uuid::Uuid;

/// One row per `(org_idp_id, assertion_id)`. The composite primary key
/// IS the replay-rejection mechanism. A duplicate insert raises a
/// unique violation, which the SAML SP layer translates into an
/// authentication failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SamlAssertionRecord {
    /// Owning IdP. Composite PK part 1.
    pub org_idp_id: Uuid,
    /// `<Assertion ID>` attribute from the SAML response. Composite
    /// PK part 2.
    pub assertion_id: String,
    /// `<Conditions NotOnOrAfter>` attribute. Cleanup sweeps prune
    /// rows past this timestamp.
    pub not_on_or_after: DateTime<Utc>,
    /// Row insert timestamp.
    pub created_at: DateTime<Utc>,
}
