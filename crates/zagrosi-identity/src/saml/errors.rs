// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! Audit-grade SAML error variants.
//!
//! Every variant maps to a distinct `sub_reason` on the
//! `signin_failed` / `saml_acs_*` audit event family. The HTTP layer
//! collapses every variant onto a uniform `401 Unauthorized` (or
//! `409 Conflict` for the cross-org email collision) so the public
//! surface does not leak which step failed; the audit dashboards
//! distinguish via `sub_reason`.

use thiserror::Error;

/// SAML SP failure surface. See section-11 spec lines 200-225.
#[derive(Debug, Error)]
pub enum SamlError {
    /// IdP-initiated callback (no `InResponseTo`) arrived but the
    /// per-IdP `allow_idp_initiated` flag is false.
    #[error("idp_initiated_disallowed")]
    IdpInitiatedDisallowed,

    /// XML parsing failed (samael decoder error). Captures malformed
    /// input that didn't trip a more specific guard.
    #[error("xml_parse_failed")]
    XmlParseFailed,

    /// XML payload contained a DOCTYPE declaration. The SP rejects
    /// any DTD to eliminate XXE.
    #[error("dtd_rejected")]
    DtdRejected,

    /// XML payload referenced an external entity. Hardened parser
    /// disables resolution; the SP still flags the attempt for audit.
    #[error("external_entity_rejected")]
    ExternalEntityRejected,

    /// `Signature` failed cryptographic verification against the
    /// pinned IdP `idp_x509_cert_pem`.
    #[error("signature_invalid")]
    SignatureInvalid,

    /// Multiple elements share the same `xml:id`. This is one of the
    /// XSW pre-conditions; the SP rejects before reduction so the
    /// reducer cannot pick the wrong subtree.
    #[error("xml_id_duplicate")]
    XmlIdDuplicate,

    /// Validated `Signature/Reference/@URI` did not refer to the
    /// node samael then surfaced as the assertion. samael's reducer
    /// guards this; the SP layer re-asserts for defence in depth.
    #[error("signed_node_mismatch")]
    SignedNodeMismatch,

    /// `SubjectConfirmation/@Method` is not `bearer`, or
    /// `SubjectConfirmationData` is missing.
    #[error("subject_confirmation_invalid")]
    SubjectConfirmationInvalid,

    /// `SubjectConfirmationData/@Recipient` does not match the SP's
    /// computed ACS URL.
    #[error("recipient_mismatch")]
    RecipientMismatch,

    /// `SubjectConfirmationData/@NotOnOrAfter` already elapsed.
    #[error("not_on_or_after_expired")]
    NotOnOrAfterExpired,

    /// `SubjectConfirmationData/@InResponseTo` does not match any
    /// persisted `saml_pending_auth.request_id` for this org_idp.
    #[error("in_response_to_mismatch")]
    InResponseToMismatch,

    /// `Conditions/AudienceRestriction` does not include the SP
    /// entity ID.
    #[error("audience_mismatch")]
    AudienceMismatch,

    /// `Conditions/@NotBefore` or `@NotOnOrAfter` puts the assertion
    /// outside its validity window.
    #[error("conditions_window_invalid")]
    ConditionsWindowInvalid,

    /// `saml_assertion_replay` UNIQUE caught a re-presentation of
    /// the same `(org_idp_id, assertion_id)` tuple.
    #[error("assertion_replay")]
    AssertionReplay,

    /// `RelayState` did not match any persisted
    /// `saml_pending_auth.relay_state`, or the row was already
    /// consumed.
    #[error("relay_state_mismatch")]
    RelayStateMismatch,

    /// Encrypted assertion arrived but the assertion-decrypt key
    /// algorithm is not implemented (e.g. AES-256-GCM key wrap is
    /// not supported by the current samael release).
    #[error("encryption_method_unsupported")]
    EncryptionMethodUnsupported,

    /// `SubjectConfirmationData/@NotBefore`-equivalent clock-skew
    /// guard tripped before the assertion's validity window opened.
    #[error("not_before_in_future")]
    NotBeforeInFuture,

    /// JIT trust gate: the ID assertion's email claim cannot bind a
    /// new user without `trust_email_assertion = true` on the IdP.
    #[error("email_not_trusted")]
    EmailNotTrusted,

    /// JIT cross-org email collision: the email already binds a live
    /// user in another tenant. Rejected with `409 use_admin_link`.
    #[error("account_already_exists")]
    AccountAlreadyExists,

    /// Anchor-hit path: the resolved `federated_identities` row was
    /// minted under a DIFFERENT IdP that happens to share the
    /// `(protocol, iss, sub)` triple with the resolving IdP. Distinct
    /// from `AccountAlreadyExists` so dashboards can triage
    /// cross-tenant-anchor probes vs email-collision probes.
    #[error("cross_tenant_anchor")]
    CrossTenantAnchor,

    /// IdP-supplied entity_id in `Response/Issuer` did not match the
    /// pinned `idp_entity_id` on the resolving `org_idps` row.
    #[error("issuer_mismatch")]
    IssuerMismatch,

    /// Resolving the `(org_slug, protocol = 'saml')` row failed: no
    /// enabled SAML IdP for the org.
    #[error("idp_not_found")]
    IdpNotFound,

    /// Multiple SAML IdPs are enabled for the resolved org and the
    /// caller did not narrow the choice. Section-13 introduces the
    /// disambiguation API; section-11 surfaces the ambiguity verbatim.
    #[error("ambiguous_idp")]
    AmbiguousIdp,

    /// The org slug did not resolve to a live `orgs` row.
    #[error("org_not_found")]
    OrgNotFound,

    /// `org_idps.config` JSONB failed re-validation against
    /// [`super::config::SamlConfigV1`].
    #[error("config_invalid: {reason}")]
    ConfigInvalid {
        /// Stable rendering of the underlying parse error.
        reason: String,
    },

    /// SP signing-key generation, envelope-encrypt, or persist failed.
    #[error("metadata_key_provisioning_failed")]
    MetadataKeyProvisioningFailed,

    /// Underlying repo / DB error. The HTTP layer renders this as a
    /// uniform 401 so internal-fault timing isn't a probe vector;
    /// audit captures the inner sqlx error chain via `tracing::error`.
    #[error("internal_error")]
    Internal,
}

impl SamlError {
    /// Stable `sub_reason` token for audit emission. The token names
    /// are the variant `#[error]` strings except where two variants
    /// share a public surface (e.g. `internal_error`); using the
    /// `#[error]` derives directly keeps the audit dashboard glossary
    /// in sync with the Rust enum.
    #[must_use]
    pub const fn sub_reason(&self) -> &'static str {
        match self {
            Self::IdpInitiatedDisallowed => "idp_initiated_disallowed",
            Self::XmlParseFailed => "xml_parse_failed",
            Self::DtdRejected => "dtd_rejected",
            Self::ExternalEntityRejected => "external_entity_rejected",
            Self::SignatureInvalid => "signature_invalid",
            Self::XmlIdDuplicate => "xml_id_duplicate",
            Self::SignedNodeMismatch => "signed_node_mismatch",
            Self::SubjectConfirmationInvalid => "subject_confirmation_invalid",
            Self::RecipientMismatch => "recipient_mismatch",
            Self::NotOnOrAfterExpired => "not_on_or_after_expired",
            Self::InResponseToMismatch => "in_response_to_mismatch",
            Self::AudienceMismatch => "audience_mismatch",
            Self::ConditionsWindowInvalid => "conditions_window_invalid",
            Self::AssertionReplay => "assertion_replay",
            Self::RelayStateMismatch => "relay_state_mismatch",
            Self::EncryptionMethodUnsupported => "encryption_method_unsupported",
            Self::NotBeforeInFuture => "not_before_in_future",
            Self::EmailNotTrusted => "email_not_trusted",
            Self::AccountAlreadyExists => "account_already_exists",
            Self::CrossTenantAnchor => "cross_tenant_anchor",
            Self::IssuerMismatch => "issuer_mismatch",
            Self::IdpNotFound => "idp_not_found",
            Self::AmbiguousIdp => "ambiguous_idp",
            Self::OrgNotFound => "org_not_found",
            Self::ConfigInvalid { .. } => "config_invalid",
            Self::MetadataKeyProvisioningFailed => "metadata_key_provisioning_failed",
            Self::Internal => "internal_error",
        }
    }
}
