// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! `SamlService` — start + ACS + metadata orchestrator.
//!
//! Composes [`super::acs::AcsDeps`], [`super::authn::AuthnDeps`], and
//! [`super::metadata::MetadataDeps`]. Three entry points:
//! [`SamlService::start`], [`SamlService::acs`], and
//! [`SamlService::metadata`].
//!
//! ## Audit emission
//!
//! Every public method emits a single audit-class `tracing::warn!` /
//! `tracing::info!` event tagged with the structured `audit = ...`
//! field so the SIEM-side ingestion pipeline can route on it. The
//! `zagrosi-audit` crate's [`zagrosi_core::Auditor`] port is wired
//! via a thin wrapper at the gateway composition root; see the OIDC
//! service for the analogous pattern. The granular SAML audit-kind
//! taxonomy (`saml_acs_replay`, `saml_xsw_rejected`, etc. — section-11
//! spec line 225) is encoded in the structured `audit` field, not
//! in [`zagrosi_core::AuditEventKind`] (which today carries only
//! coarse-grained discriminators that the gateway lifts into the
//! granular taxonomy).

use std::net::IpAddr;

use uuid::Uuid;

use crate::session::SessionAttachment;

use super::acs::{self, AcsDeps, AcsRequest};
use super::authn::{self, AuthnDeps};
use super::errors::SamlError;
use super::metadata::{self, MetadataDeps, MetadataResponse};

/// Outcome of [`SamlService::start`].
#[derive(Debug)]
pub struct StartOutcome {
    /// IdP authorization URL the caller redirects the browser to.
    pub redirect_url: url::Url,
    /// AuthnRequest id persisted to `saml_pending_auth.request_id`.
    /// Surfaced for tracing.
    pub request_id: String,
}

/// Input to [`SamlService::acs`].
#[derive(Debug, Clone)]
pub struct AcsCallbackInput<'a> {
    /// Org slug from the URL path. Resolved to `org_id` inside the
    /// service.
    pub org_slug: &'a str,
    /// Form-posted `SAMLResponse` field (base64-encoded XML).
    pub saml_response_b64: &'a str,
    /// Form-posted `RelayState` field.
    pub relay_state: &'a str,
    /// Caller IP (resolved by the gateway middleware), if available.
    pub client_ip: Option<IpAddr>,
    /// Per-request correlation id (UUID v7) for log + audit cross-ref.
    pub correlation_id: Uuid,
}

/// Outcome of [`SamlService::acs`].
#[derive(Debug, Clone)]
pub struct AcsCallbackOutcome {
    /// User id of the issued session subject.
    pub user_id: Uuid,
    /// Org id of the issued session subject.
    pub org_id: Uuid,
    /// Session id of the issued session.
    pub session_id: Uuid,
    /// Session cookie pair (`__Host-zagrosi_sid` + `__Host-zagrosi_csrf`).
    pub attachment: SessionAttachment,
    /// Where to redirect the browser after success. Defaults to `/`.
    pub redirect_to: String,
}

/// Outcome of [`SamlService::metadata`].
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct MetadataOutcome {
    /// `EntityDescriptor` XML (UTF-8).
    pub xml: String,
    /// Whether the metadata document carries a `<ds:Signature>`.
    pub signed: bool,
}

/// Composed SAML orchestrator. Cheap to clone (every dep is an `Arc`
/// or a repo handle).
#[derive(Clone)]
pub struct SamlService {
    authn: AuthnDeps,
    acs: AcsDeps,
    metadata: MetadataDeps,
}

/// Build-args bundle for [`SamlService::new`]. Keeps the constructor
/// readable as the dep list grows.
pub struct SamlServiceDeps {
    /// Start-handler dependencies.
    pub authn: AuthnDeps,
    /// ACS-handler dependencies.
    pub acs: AcsDeps,
    /// Metadata-handler dependencies.
    pub metadata: MetadataDeps,
}

impl SamlService {
    /// Wire dependencies.
    #[must_use]
    pub fn new(deps: SamlServiceDeps) -> Self {
        Self {
            authn: deps.authn,
            acs: deps.acs,
            metadata: deps.metadata,
        }
    }

    /// Borrow the underlying [`AcsDeps`] for tests.
    #[must_use]
    pub const fn acs_deps(&self) -> &AcsDeps {
        &self.acs
    }

    /// Borrow the underlying [`AuthnDeps`] for tests.
    #[must_use]
    pub const fn authn_deps(&self) -> &AuthnDeps {
        &self.authn
    }

    /// Borrow the underlying [`MetadataDeps`] for tests.
    #[must_use]
    pub const fn metadata_deps(&self) -> &MetadataDeps {
        &self.metadata
    }

    /// Start an SP-initiated SAML sign-in. Returns the IdP
    /// authorization URL (HTTP-Redirect binding).
    ///
    /// # Errors
    ///
    /// - [`SamlError::OrgNotFound`] when the slug does not resolve.
    /// - [`SamlError::IdpNotFound`] when no enabled SAML IdP exists.
    /// - [`SamlError::AmbiguousIdp`] when multiple enabled SAML IdPs
    ///   exist.
    /// - [`SamlError::ConfigInvalid`] when the stored config fails
    ///   revalidation.
    /// - [`SamlError::Internal`] for any database error.
    #[tracing::instrument(
        skip_all,
        fields(
            org_slug = %org_slug,
            route = "saml.start",
        )
    )]
    pub async fn start(&self, org_slug: &str) -> Result<StartOutcome, SamlError> {
        let outcome = authn::start(&self.authn, org_slug)
            .await
            .inspect_err(|err| {
                tracing::warn!(
                    target: "zagrosi.identity.saml",
                    audit = "saml_start_failed",
                    sub_reason = err.sub_reason(),
                    "saml start failed"
                );
            })?;
        tracing::info!(
            target: "zagrosi.identity.saml",
            audit = "saml_start_success",
            request_id = %outcome.request_id,
            "saml start succeeded"
        );
        Ok(StartOutcome {
            redirect_url: outcome.redirect_url,
            request_id: outcome.request_id,
        })
    }

    /// Run the ACS path. Emits a single audit-class trace per outcome
    /// (success or failure).
    ///
    /// # Errors
    ///
    /// Every variant of [`SamlError`] reachable from [`acs::handler`]
    /// is re-raised verbatim after the audit emission.
    #[tracing::instrument(
        skip_all,
        fields(
            org_slug = %input.org_slug,
            correlation_id = %input.correlation_id,
            route = "saml.acs",
        )
    )]
    pub async fn acs(&self, input: AcsCallbackInput<'_>) -> Result<AcsCallbackOutcome, SamlError> {
        let request = AcsRequest {
            saml_response_b64: input.saml_response_b64.to_owned(),
            relay_state: input.relay_state.to_owned(),
        };

        match acs::handler(&self.acs, input.org_slug, &request).await {
            Ok(outcome) => {
                tracing::info!(
                    target: "zagrosi.identity.saml",
                    audit = "signin_success",
                    auth_method = "saml",
                    user_id = %outcome.user_id,
                    session_id = %outcome.session_id,
                    "saml acs succeeded"
                );
                Ok(AcsCallbackOutcome {
                    user_id: outcome.user_id,
                    org_id: outcome.org_id,
                    session_id: outcome.session_id,
                    attachment: outcome.attachment,
                    redirect_to: "/".to_owned(),
                })
            }
            Err(err) => {
                let audit_kind = saml_audit_kind(&err);
                tracing::warn!(
                    target: "zagrosi.identity.saml",
                    audit = audit_kind,
                    sub_reason = err.sub_reason(),
                    auth_method = "saml",
                    "saml acs failed"
                );
                Err(err)
            }
        }
    }

    /// Return the SP metadata XML, generating + persisting the SP
    /// signing key on first call. Idempotent on subsequent calls.
    ///
    /// # Errors
    ///
    /// - [`SamlError::OrgNotFound`] when the slug does not resolve.
    /// - [`SamlError::IdpNotFound`] when no enabled SAML IdP exists.
    /// - [`SamlError::ConfigInvalid`] when stored config fails
    ///   revalidation.
    /// - [`SamlError::MetadataKeyProvisioningFailed`] on key-gen,
    ///   envelope, or persistence failure.
    #[tracing::instrument(
        skip_all,
        fields(
            org_slug = %org_slug,
            route = "saml.metadata",
        )
    )]
    pub async fn metadata(&self, org_slug: &str) -> Result<MetadataOutcome, SamlError> {
        let response: MetadataResponse = metadata::handler(&self.metadata, org_slug).await?;
        Ok(MetadataOutcome {
            xml: response.xml,
            signed: response.signed,
        })
    }
}

/// Map a [`SamlError`] onto the granular SAML audit-class token (per
/// section-11 spec line 225). The token carries finer detail than the
/// upstream [`zagrosi_core::AuditEventKind`] enum so the SIEM-side
/// ingestion pipeline can route on it.
const fn saml_audit_kind(err: &SamlError) -> &'static str {
    match err {
        SamlError::AssertionReplay => "saml_acs_replay",
        SamlError::SignatureInvalid => "saml_signature_invalid",
        SamlError::SignedNodeMismatch | SamlError::XmlIdDuplicate => "saml_xsw_rejected",
        SamlError::DtdRejected | SamlError::ExternalEntityRejected => "saml_xxe_rejected",
        SamlError::EncryptionMethodUnsupported => "saml_encryption_unsupported",
        SamlError::IdpInitiatedDisallowed => "saml_idp_initiated_disallowed",
        SamlError::CrossTenantAnchor => "saml_acs_anchor_cross_tenant",
        SamlError::Internal => "saml_internal_error",
        _ => "signin_failed",
    }
}
