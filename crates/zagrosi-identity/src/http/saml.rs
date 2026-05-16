// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! SAML 2.0 HTTP surface.
//!
//! Three thin axum handlers wire [`crate::saml::SamlService`] into
//! the `/v1/auth/saml/{org_slug}` URL space:
//!
//! - `GET  /v1/auth/saml/{org_slug}/start`
//! - `POST /v1/auth/saml/{org_slug}/acs`
//! - `GET  /v1/auth/saml/{org_slug}/metadata.xml`
//!
//! The handlers exist purely for protocol shaping (`Set-Cookie`
//! headers, form parsing, redirect responses); every security
//! invariant is enforced inside the service layer.
//!
//! ACS is the security cliff. The handler is wired through
//! [`SamlService::acs`] which audits + maps every error variant onto
//! a uniform `401 Unauthorized` (or `409 Conflict` for the cross-org
//! email collision). Failure responses do not leak which check
//! rejected the assertion. The org-not-found / IdP-not-found surface
//! collapses onto the same `401` so an attacker cannot enumerate
//! which org slugs (or which IdPs) exist by status alone.

use std::net::IpAddr;
use std::sync::Arc;

use axum::Router;
use axum::extract::{DefaultBodyLimit, Extension, Form, Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde::Deserialize;
use uuid::Uuid;

use crate::oidc::build_clear_cookie as build_clear_oidc_cookie;
use crate::saml::{AcsCallbackInput, SamlError, SamlService};

/// Hard ceiling on the SAML `SAMLResponse` form payload (256 KiB).
/// SAML responses in the wild rarely exceed 32 KiB even with rich
/// AttributeStatements + signatures; 256 KiB carries an 8× margin
/// while bounding the libxml2 parse + xmlsec signature-verify CPU
/// cost an attacker can force per request.
pub const ACS_BODY_LIMIT_BYTES: usize = 256 * 1024;

/// Content type advertised by the metadata endpoint per
/// SAML 2.0 metadata profile (sstc-saml-metadata-2.0-os §1.5).
pub const SAML_METADATA_CONTENT_TYPE: &str = "application/samlmetadata+xml";

/// Trusted client-IP extension. Mirrors
/// [`crate::http::oidc::ClientIp`]; both surfaces share the same
/// gateway middleware contract.
#[derive(Debug, Clone, Copy)]
pub struct ClientIp(pub IpAddr);

/// Shared application state held by the SAML handlers.
#[derive(Clone)]
pub struct SamlState {
    /// Composed SAML service.
    pub service: Arc<SamlService>,
}

impl SamlState {
    /// Wire dependencies.
    #[must_use]
    pub const fn new(service: Arc<SamlService>) -> Self {
        Self { service }
    }
}

/// Build the SAML router. The ACS POST route carries an explicit
/// `DefaultBodyLimit` ceiling so a malicious IdP / spoofed POST
/// cannot force a multi-megabyte parse.
pub fn router(state: SamlState) -> Router<()> {
    Router::new()
        .route("/v1/auth/saml/{org_slug}/start", get(start_handler))
        .route(
            "/v1/auth/saml/{org_slug}/acs",
            post(acs_handler).layer(DefaultBodyLimit::max(ACS_BODY_LIMIT_BYTES)),
        )
        .route(
            "/v1/auth/saml/{org_slug}/metadata.xml",
            get(metadata_handler),
        )
        .with_state(state)
}

/// `GET /v1/auth/saml/{org_slug}/start`
///
/// Returns a 302 redirect to the IdP authorization URL (HTTP-Redirect
/// binding). The pending row carrying RelayState + AuthnRequest id is
/// persisted before the redirect so the IdP's POST cannot beat the row
/// to the database.
async fn start_handler(State(state): State<SamlState>, Path(org_slug): Path<String>) -> Response {
    match state.service.start(&org_slug).await {
        Ok(outcome) => {
            let mut headers = HeaderMap::new();
            let Some(loc) = header_value(outcome.redirect_url.as_str()) else {
                return failure_response(&SamlError::Internal);
            };
            headers.insert(header::LOCATION, loc);
            (StatusCode::FOUND, headers).into_response()
        }
        Err(err) => failure_response(&err),
    }
}

/// `POST /v1/auth/saml/{org_slug}/acs`
///
/// Form fields: `SAMLResponse` (base64-encoded XML) and `RelayState`.
/// On success, returns a 302 to `/` with the `__Host-zagrosi_sid` +
/// `__Host-zagrosi_csrf` Set-Cookie pair plus a clear-cookie for any
/// stale `__Host-zagrosi_oidc` left behind by an interrupted OIDC
/// flow. Failure paths return 401 / 409 with no body.
async fn acs_handler(
    State(state): State<SamlState>,
    Path(org_slug): Path<String>,
    extension_ip: Option<Extension<ClientIp>>,
    Form(form): Form<AcsForm>,
) -> Response {
    let client_ip = extension_ip.map(|Extension(ClientIp(ip))| ip);
    let correlation_id = Uuid::now_v7();

    let input = AcsCallbackInput {
        org_slug: &org_slug,
        saml_response_b64: &form.saml_response,
        relay_state: &form.relay_state,
        client_ip,
        correlation_id,
    };

    let outcome = match state.service.acs(input).await {
        Ok(o) => o,
        Err(err) => return failure_response(&err),
    };

    let mut headers = HeaderMap::new();
    let session_cookie = outcome.attachment.session_set_cookie();
    let csrf_cookie = outcome.attachment.csrf_set_cookie();
    let (Some(session_value), Some(csrf_value), Some(clear_oidc), Some(location)) = (
        header_value(&session_cookie),
        header_value(&csrf_cookie),
        header_value(&build_clear_oidc_cookie()),
        header_value(&outcome.redirect_to),
    ) else {
        return failure_response(&SamlError::Internal);
    };
    headers.append(header::SET_COOKIE, session_value);
    headers.append(header::SET_COOKIE, csrf_value);
    // Clear any stale OIDC pending cookie left behind by a cancelled
    // OIDC sign-in. Without this, a user who started OIDC then
    // completed SAML keeps the OIDC cookie in their jar — a later
    // OIDC start path could attempt to open it under the new
    // session's secrets.
    headers.append(header::SET_COOKIE, clear_oidc);
    headers.insert(header::LOCATION, location);
    (StatusCode::FOUND, headers).into_response()
}

/// `GET /v1/auth/saml/{org_slug}/metadata.xml`
///
/// Returns the SP `EntityDescriptor` XML. First call mints +
/// persists the SP signing key + cert; subsequent calls return
/// idempotently.
async fn metadata_handler(
    State(state): State<SamlState>,
    Path(org_slug): Path<String>,
) -> Response {
    match state.service.metadata(&org_slug).await {
        Ok(outcome) => {
            let mut headers = HeaderMap::new();
            headers.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static(SAML_METADATA_CONTENT_TYPE),
            );
            (StatusCode::OK, headers, outcome.xml).into_response()
        }
        Err(err) => failure_response(&err),
    }
}

/// Map every [`SamlError`] onto a uniform HTTP envelope. The match
/// is exhaustive (no `_` arm) so adding a new `SamlError` variant
/// fails compilation rather than silently classifying as `401`.
///
/// `OrgNotFound` and `IdpNotFound` collapse onto `401` rather than
/// `404` so an attacker cannot enumerate which org slugs (or which
/// IdPs) exist by status alone — the same anti-enumeration posture
/// the OIDC service uses.
fn failure_response(err: &SamlError) -> Response {
    let status = match err {
        SamlError::AccountAlreadyExists => StatusCode::CONFLICT,
        SamlError::Internal
        | SamlError::MetadataKeyProvisioningFailed
        | SamlError::ConfigInvalid { .. } => StatusCode::INTERNAL_SERVER_ERROR,
        SamlError::IdpInitiatedDisallowed
        | SamlError::XmlParseFailed
        | SamlError::DtdRejected
        | SamlError::ExternalEntityRejected
        | SamlError::SignatureInvalid
        | SamlError::XmlIdDuplicate
        | SamlError::SignedNodeMismatch
        | SamlError::SubjectConfirmationInvalid
        | SamlError::RecipientMismatch
        | SamlError::NotOnOrAfterExpired
        | SamlError::InResponseToMismatch
        | SamlError::AudienceMismatch
        | SamlError::ConditionsWindowInvalid
        | SamlError::AssertionReplay
        | SamlError::RelayStateMismatch
        | SamlError::EncryptionMethodUnsupported
        | SamlError::NotBeforeInFuture
        | SamlError::EmailNotTrusted
        | SamlError::IssuerMismatch
        | SamlError::IdpNotFound
        | SamlError::AmbiguousIdp
        | SamlError::OrgNotFound
        | SamlError::CrossTenantAnchor => StatusCode::UNAUTHORIZED,
    };
    // `info!` for failed-auth so the SIEM correlation pipeline picks
    // it up at default log levels. `trace!` would have been silent
    // under any standard production filter.
    tracing::info!(
        target: "zagrosi.identity.saml",
        sub_reason = err.sub_reason(),
        status = %status,
        "saml http error envelope"
    );
    (status, ()).into_response()
}

/// Convert a `&str` into a `HeaderValue`, returning `None` on
/// non-ASCII / control-character inputs. Centralises the
/// `HeaderValue::from_str` failure handling so every handler maps
/// the failure to a single `SamlError::Internal` surface.
fn header_value(s: &str) -> Option<HeaderValue> {
    HeaderValue::from_str(s).ok()
}

/// Form payload posted by the IdP to the ACS endpoint per the
/// SAML 2.0 HTTP-POST binding.
///
/// `Debug` is implemented manually to redact `saml_response` —
/// signed assertions carry user PII (email, given name, family
/// name, group memberships) + opaque attribute statements that
/// must not surface in tracing logs.
#[derive(Deserialize)]
pub struct AcsForm {
    /// `SAMLResponse` form field — base64-encoded `<saml:Response>`
    /// XML.
    #[serde(rename = "SAMLResponse")]
    pub saml_response: String,
    /// `RelayState` form field — opaque value the SP minted on the
    /// AuthnRequest start path.
    #[serde(rename = "RelayState", default)]
    pub relay_state: String,
}

impl std::fmt::Debug for AcsForm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AcsForm")
            .field(
                "saml_response",
                &format_args!("<redacted {} bytes>", self.saml_response.len()),
            )
            .field("relay_state", &self.relay_state)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failure_response_account_collision_returns_409() {
        let resp = failure_response(&SamlError::AccountAlreadyExists);
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }

    #[test]
    fn failure_response_signature_returns_401() {
        let resp = failure_response(&SamlError::SignatureInvalid);
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn failure_response_internal_returns_500() {
        let resp = failure_response(&SamlError::Internal);
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn failure_response_metadata_provisioning_returns_500() {
        let resp = failure_response(&SamlError::MetadataKeyProvisioningFailed);
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn failure_response_config_invalid_returns_500() {
        let resp = failure_response(&SamlError::ConfigInvalid {
            reason: "bad pem".to_owned(),
        });
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn failure_response_cross_tenant_anchor_returns_401() {
        let resp = failure_response(&SamlError::CrossTenantAnchor);
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn failure_response_org_not_found_collapses_to_401() {
        let resp = failure_response(&SamlError::OrgNotFound);
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn failure_response_idp_not_found_collapses_to_401() {
        let resp = failure_response(&SamlError::IdpNotFound);
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn acs_form_debug_redacts_saml_response() {
        let form = AcsForm {
            saml_response: "leaky-pii-bearing-xml".to_owned(),
            relay_state: "rs".to_owned(),
        };
        let rendered = format!("{form:?}");
        assert!(!rendered.contains("leaky-pii-bearing-xml"));
        assert!(rendered.contains("redacted"));
        assert!(rendered.contains("rs"));
    }
}
