// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! SP-initiated AuthnRequest start handler.

use std::sync::Arc;

use chrono::{Duration, Utc};
use samael::service_provider::ServiceProvider;
use uuid::Uuid;

use crate::repo::{NewSamlPending, OrgIdpRepo, OrgRepo, OrgScoped, SamlPendingRepo};

use super::config::SamlConfigV1;
use super::errors::SamlError;
use super::{relay_state, request_id};

/// Hard ceiling on pending-row TTL. Mirrors the OIDC pending TTL
/// (`crate::oidc::pending::DEFAULT_PENDING_TTL`); the SAML SP shares
/// the 10-minute window so a stalled authn does not pin a row past
/// admin-tolerable bounds.
pub const DEFAULT_PENDING_TTL: Duration = Duration::minutes(10);

/// Composed dependency bundle for [`start`]. Identity-State exposes a
/// pre-wired instance.
#[derive(Clone)]
pub struct AuthnDeps {
    /// Org lookup (slug → row).
    pub orgs: OrgRepo,
    /// IdP lookup (org_id → SAML row).
    pub idps: OrgIdpRepo,
    /// Pending-auth ledger persistence.
    pub pending: SamlPendingRepo,
    /// Public base URL (`ZAGROSI_BASE_URL`); the ACS URL derives from
    /// this when the per-IdP override is `None`.
    pub base_url: Arc<str>,
}

/// Outcome of a successful [`start`]. The HTTP layer emits a 302
/// redirect to `redirect_url` (HTTP-Redirect binding) and stamps the
/// `__Host-zagrosi_saml_relay` cookie clear-on-callback contract per
/// section-08.
#[derive(Debug)]
pub struct StartOutcome {
    /// IdP authorization URL the caller redirects the browser to.
    pub redirect_url: url::Url,
    /// AuthnRequest id persisted to `saml_pending_auth.request_id`.
    /// Surfaced for tracing.
    pub request_id: String,
    /// Resolved `org_idps.id` row id.
    pub org_idp_id: Uuid,
}

/// Run the SP-initiated SAML start path.
///
/// Steps:
///   1. Resolve `org_slug` → live `orgs` row.
///   2. Load enabled `org_idps` row with `protocol = 'saml'` for the
///      org. Reject when 0 (`IdpNotFound`) or > 1 (`AmbiguousIdp`).
///   3. Validate the IdP's stored config via [`SamlConfigV1::from_jsonb`].
///   4. Mint a 256-bit RelayState + `xs:ID`-safe request id.
///   5. Persist a `saml_pending_auth` row carrying both, scoped to
///      `org_idp_id` with a 10-minute hard expiry.
///   6. Build the AuthnRequest via samael, override the request id
///      with our high-entropy value, and serialise into the
///      HTTP-Redirect-binding URL (DEFLATE + base64 + query).
///
/// # Errors
///
/// - [`SamlError::OrgNotFound`]: slug does not resolve.
/// - [`SamlError::IdpNotFound`]: no enabled SAML IdP for the org.
/// - [`SamlError::AmbiguousIdp`]: multiple enabled SAML IdPs.
/// - [`SamlError::ConfigInvalid`]: stored config failed re-validation.
/// - [`SamlError::Internal`]: repo failure / samael XML serialise
///   failure.
pub async fn start(deps: &AuthnDeps, org_slug: &str) -> Result<StartOutcome, SamlError> {
    let org = deps
        .orgs
        .find_by_slug(org_slug)
        .await
        .map_err(|e| internal_error(&e))?
        .ok_or(SamlError::OrgNotFound)?;

    let scoped = OrgScoped::new(&deps.idps, org.id);
    let mut saml_idps: Vec<_> = scoped
        .list_for_org()
        .await
        .map_err(|e| internal_error(&e))?
        .into_iter()
        .filter(|idp| idp.enabled && idp.protocol == "saml")
        .collect();
    if saml_idps.is_empty() {
        return Err(SamlError::IdpNotFound);
    }
    if saml_idps.len() > 1 {
        return Err(SamlError::AmbiguousIdp);
    }
    let idp = saml_idps.remove(0);
    let cfg = SamlConfigV1::from_jsonb(&idp.config)?;

    let acs_url = derive_acs_url(&deps.base_url, org_slug);
    let entity_id = derive_entity_id(&deps.base_url);

    let sp = build_sp_for_start(&cfg, &acs_url, &entity_id);
    let mut authn_request = sp
        .make_authentication_request(&cfg.idp_sso_url)
        .map_err(|err| {
            tracing::warn!(target: "zagrosi.identity.saml", error = %err, "samael make_authentication_request failed");
            SamlError::Internal
        })?;

    // Override samael's 32-bit `rand::random::<u32>()` default with a
    // 256-bit CSPRNG draw — the pending-row correlation is part of
    // the security claim.
    let high_entropy_id = request_id::new_random();
    authn_request.id.clone_from(&high_entropy_id);
    authn_request.issue_instant = Utc::now();

    let relay = relay_state::new_random();
    let now = Utc::now();
    deps.pending
        .insert(NewSamlPending {
            id: Uuid::now_v7(),
            request_id: &high_entropy_id,
            relay_state: &relay,
            org_idp_id: idp.id,
            expires_at: now + DEFAULT_PENDING_TTL,
        })
        .await
        .map_err(|e| internal_error(&e))?;

    let redirect_url = authn_request
        .redirect(&relay)
        .map_err(|err| {
            tracing::warn!(target: "zagrosi.identity.saml", error = %err, "samael redirect failed");
            SamlError::Internal
        })?
        .ok_or_else(|| {
            tracing::warn!(target: "zagrosi.identity.saml", "samael redirect produced no destination");
            SamlError::Internal
        })?;

    Ok(StartOutcome {
        redirect_url,
        request_id: high_entropy_id,
        org_idp_id: idp.id,
    })
}

/// SP entity id derivation. The metadata URL is the canonical entity
/// id when no per-org override exists; sharing the derivation rule
/// across `start` + `metadata` keeps the IdP's `Audience` validation
/// stable across both code paths.
#[must_use]
pub fn derive_entity_id(base_url: &str) -> String {
    format!("{}/v1/auth/saml/metadata", base_url.trim_end_matches('/'))
}

/// ACS URL derivation. Used by both the start path (registered as the
/// `AssertionConsumerServiceURL` in the AuthnRequest) and the ACS
/// path (compared against the IdP-supplied
/// `SubjectConfirmationData/@Recipient`). Both sides MUST agree, so
/// derivation lives in one place.
#[must_use]
pub fn derive_acs_url(base_url: &str, org_slug: &str) -> String {
    format!(
        "{}/v1/auth/saml/{}/acs",
        base_url.trim_end_matches('/'),
        org_slug,
    )
}

/// Build a samael [`ServiceProvider`] sufficient for AuthnRequest
/// construction. Signature verification on the ACS path uses a
/// separate constructor (see `acs::build_sp_for_acs`) since it needs
/// the IdP cert and the request-id correlation list.
fn build_sp_for_start(cfg: &SamlConfigV1, acs_url: &str, entity_id: &str) -> ServiceProvider {
    ServiceProvider {
        entity_id: Some(entity_id.to_owned()),
        acs_url: Some(acs_url.to_owned()),
        slo_url: None,
        // No IdP-cert wiring needed for start (samael accesses
        // `idp_metadata.idp_sso_descriptors[].key_descriptors` only on
        // the ACS path).
        idp_metadata: samael::metadata::EntityDescriptor {
            entity_id: Some(cfg.idp_entity_id.clone()),
            ..samael::metadata::EntityDescriptor::default()
        },
        allow_idp_initiated: cfg.allow_idp_initiated,
        ..ServiceProvider::default()
    }
}

fn internal_error(err: &crate::error::IdentityError) -> SamlError {
    tracing::warn!(
        target: "zagrosi.identity.saml",
        error = %err,
        "saml authn start: repo error",
    );
    SamlError::Internal
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_entity_id_strips_trailing_slash() {
        assert_eq!(
            derive_entity_id("https://example.com/"),
            "https://example.com/v1/auth/saml/metadata",
        );
        assert_eq!(
            derive_entity_id("https://example.com"),
            "https://example.com/v1/auth/saml/metadata",
        );
    }

    #[test]
    fn derive_acs_url_inlines_org_slug() {
        assert_eq!(
            derive_acs_url("https://example.com/", "acme"),
            "https://example.com/v1/auth/saml/acme/acs",
        );
    }
}
