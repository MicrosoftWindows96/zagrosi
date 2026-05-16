// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! OIDC HTTP surface.
//!
//! Two thin axum handlers wire [`crate::oidc::OidcService`] into the
//! `/v1/auth/oidc/{org_slug}` URL space. The handlers exist purely
//! for protocol shaping (`Set-Cookie` headers, query-parameter
//! parsing, redirect responses); every security invariant is enforced
//! inside the service layer.
//!
//! Every callback path attaches a `Set-Cookie` clearing the OIDC
//! cookie, regardless of outcome. Failure responses go out as
//! `oidc_callback_failed` after the service-level audit emission. The
//! handler converts every `Err` into an explicit response (instead of
//! relying on `?` propagation) so the cookie-clear header survives.

use std::net::IpAddr;
use std::sync::Arc;

use axum::Router;
use axum::extract::{Extension, Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use cookie::Cookie;
use serde::Deserialize;
use uuid::Uuid;

use crate::error::{IdentityError, Result};
use crate::oidc::{COOKIE_NAME, CallbackInput, OidcService, build_clear_cookie};
use crate::repo::OrgRepo;

/// Trusted client-IP extension. Gateway middleware that resolves the
/// caller IP (axum `ConnectInfo`, forwarded-for normalisation, or a
/// static-ip mock under tests) wraps the value in this newtype before
/// inserting it into the request extensions.
#[derive(Debug, Clone, Copy)]
pub struct ClientIp(pub IpAddr);

/// Shared application state held by the OIDC handlers.
#[derive(Clone)]
pub struct OidcState {
    /// Composed OIDC service.
    pub service: Arc<OidcService>,
    /// Org lookup used to resolve `org_slug → org_id` before invoking
    /// the callback service. Section-13's multi-IdP routing layer
    /// will replace the slug with a domain-routed lookup; today the
    /// slug is the only public anchor.
    pub org_repo: OrgRepo,
}

impl OidcState {
    /// Wire dependencies.
    #[must_use]
    pub const fn new(service: Arc<OidcService>, org_repo: OrgRepo) -> Self {
        Self { service, org_repo }
    }
}

/// Build the OIDC router.
pub fn router(state: OidcState) -> Router<()> {
    Router::new()
        .route("/v1/auth/oidc/{org_slug}/start", get(start_handler))
        .route("/v1/auth/oidc/{org_slug}/callback", get(callback_handler))
        .with_state(state)
}

/// `GET /v1/auth/oidc/{org_slug}/start[?domain=<email_domain>]`
async fn start_handler(
    State(state): State<OidcState>,
    Path(org_slug): Path<String>,
    Query(_query): Query<StartQuery>,
) -> Result<Response> {
    let outcome = state.service.start(&org_slug).await?;
    let mut headers = HeaderMap::new();
    headers.insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&outcome.set_cookie_value).map_err(|_| {
            IdentityError::OidcConfigInvalid {
                reason: "set-cookie header value contains illegal byte".into(),
            }
        })?,
    );
    headers.insert(
        header::LOCATION,
        HeaderValue::from_str(outcome.redirect_url.as_str()).map_err(|_| {
            IdentityError::OidcConfigInvalid {
                reason: "authorize URL is not a valid header value".into(),
            }
        })?,
    );
    Ok((StatusCode::FOUND, headers).into_response())
}

/// `GET /v1/auth/oidc/{org_slug}/callback?code=<>&state=<>&iss=<>`
///
/// Three failure paths short-circuit before the service runs:
/// `OrgNotFound`, IdP-emitted `?error=...`, and missing `code`/`state`.
/// Each routes through `OidcService::audit_handler_failure` so the
/// SIEM sees one event per failure regardless of where the
/// short-circuit fired. The handler always converts the outcome (Ok or
/// Err) into a response explicitly so the cookie-clear `Set-Cookie`
/// header survives — `?` propagation would discard the headers.
async fn callback_handler(
    State(state): State<OidcState>,
    Path(org_slug): Path<String>,
    Query(query): Query<CallbackQuery>,
    headers: HeaderMap,
    extension_ip: Option<Extension<ClientIp>>,
) -> Response {
    let cookie_value = read_oidc_cookie(&headers);
    let client_ip = extension_ip.map(|Extension(ClientIp(ip))| ip);
    let correlation_id = Uuid::now_v7();

    // Step 1: resolve org_slug -> org. Failure here cannot be audited
    // through `OidcService` because the service expects an `org_id`;
    // we still need to emit a failure event so the audit envelope
    // covers org-enumeration probes. Use a nil org_id placeholder; the
    // sub_reason payload distinguishes.
    let org = match state.org_repo.find_by_slug(&org_slug).await {
        Ok(Some(o)) => o,
        Ok(None) => {
            let err = IdentityError::OrgNotFound;
            let stub = CallbackInput {
                expected_org_id: Uuid::nil(),
                expected_org_slug: Some(&org_slug),
                code: "",
                state: "",
                iss_query: query.iss.as_deref(),
                cookie_value: cookie_value.as_deref(),
                correlation_id,
                client_ip,
            };
            state.service.audit_handler_failure(stub, &err).await;
            return failure_response(err);
        }
        Err(err) => {
            tracing::warn!(target: "zagrosi.identity.oidc", error = %err, "org_repo lookup failed");
            let stub = CallbackInput {
                expected_org_id: Uuid::nil(),
                expected_org_slug: Some(&org_slug),
                code: "",
                state: "",
                iss_query: query.iss.as_deref(),
                cookie_value: cookie_value.as_deref(),
                correlation_id,
                client_ip,
            };
            state.service.audit_handler_failure(stub, &err).await;
            return failure_response(err);
        }
    };

    let stub_input = CallbackInput {
        expected_org_id: org.id,
        expected_org_slug: Some(&org_slug),
        code: "",
        state: "",
        iss_query: query.iss.as_deref(),
        cookie_value: cookie_value.as_deref(),
        correlation_id,
        client_ip,
    };

    // Step 2: IdP-emitted error short-circuit.
    if let Some(error_code) = query.error_code.as_deref() {
        if let Some(desc) = query.error_description.as_deref() {
            tracing::trace!(
                target: "zagrosi.identity.oidc",
                %error_code,
                %desc,
                "idp redirected with error",
            );
        } else {
            tracing::trace!(
                target: "zagrosi.identity.oidc",
                %error_code,
                "idp redirected with error",
            );
        }
        let err = IdentityError::OidcDiscoveryFailed("idp returned error");
        state.service.audit_handler_failure(stub_input, &err).await;
        return failure_response(err);
    }

    // Step 3: required-parameter check.
    let code = query.code.as_deref().unwrap_or("");
    let state_param = query.state.as_deref().unwrap_or("");
    if code.is_empty() || state_param.is_empty() {
        let err = IdentityError::OidcStateMismatch;
        state.service.audit_handler_failure(stub_input, &err).await;
        return failure_response(err);
    }

    // Step 4: full service callback path. The service emits its own
    // success/failure audit; we only need to shape the response.
    let outcome = match state
        .service
        .callback(CallbackInput {
            expected_org_id: org.id,
            expected_org_slug: Some(&org_slug),
            code,
            state: state_param,
            iss_query: query.iss.as_deref(),
            cookie_value: cookie_value.as_deref(),
            correlation_id,
            client_ip,
        })
        .await
    {
        Ok(o) => o,
        Err(err) => return failure_response(err),
    };

    success_response(&outcome).unwrap_or_else(failure_response)
}

/// Build the success-redirect response with the issued session cookies
/// + the OIDC cookie clear.
fn success_response(outcome: &crate::oidc::CallbackOutcome) -> Result<Response> {
    let mut response_headers = HeaderMap::new();
    response_headers.append(
        header::SET_COOKIE,
        HeaderValue::from_str(&outcome.clear_oidc_cookie).map_err(|_| {
            IdentityError::OidcConfigInvalid {
                reason: "clear cookie header malformed".into(),
            }
        })?,
    );
    let session_cookie = outcome.attachment.session_set_cookie();
    let csrf_cookie = outcome.attachment.csrf_set_cookie();
    response_headers.append(
        header::SET_COOKIE,
        HeaderValue::from_str(&session_cookie).map_err(|_| IdentityError::OidcConfigInvalid {
            reason: "session cookie header malformed".into(),
        })?,
    );
    response_headers.append(
        header::SET_COOKIE,
        HeaderValue::from_str(&csrf_cookie).map_err(|_| IdentityError::OidcConfigInvalid {
            reason: "csrf cookie header malformed".into(),
        })?,
    );
    response_headers.insert(
        header::LOCATION,
        HeaderValue::from_str(&outcome.redirect_to).map_err(|_| {
            IdentityError::OidcConfigInvalid {
                reason: "post-login redirect malformed".into(),
            }
        })?,
    );
    Ok((StatusCode::FOUND, response_headers).into_response())
}

/// Build the failure response from any error and stamp the OIDC clear
/// cookie. `err.into_response()` produces the JSON envelope; we then
/// merge the cookie-clear header on top.
fn failure_response(err: IdentityError) -> Response {
    let mut response = err.into_response();
    let Ok(header_value) = HeaderValue::from_str(&build_clear_cookie()) else {
        // Fallback: malformed clear-cookie value is impossible given
        // `build_clear_cookie` returns a constant ASCII string. Log
        // loudly and return the bare error response.
        tracing::warn!(
            target: "zagrosi.identity.oidc",
            "build_clear_cookie produced an invalid header value"
        );
        return response;
    };
    response
        .headers_mut()
        .append(header::SET_COOKIE, header_value);
    response
}

/// Read the `__Host-zagrosi_oidc` cookie from the request headers.
fn read_oidc_cookie(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    Cookie::split_parse(raw)
        .flatten()
        .find(|cookie| cookie.name() == COOKIE_NAME)
        .map(|cookie| cookie.value().to_owned())
}

/// Query parameters accepted by the start handler.
#[derive(Debug, Deserialize)]
pub struct StartQuery {
    /// Optional email-domain hint. Section-13 narrows the IdP picker
    /// using this; v0.1 ignores it (and rejects ambiguous orgs early).
    #[serde(default)]
    pub domain: Option<String>,
}

/// Query parameters accepted by the callback handler.
#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    /// Authorization code returned by the IdP.
    #[serde(default)]
    pub code: Option<String>,
    /// `state` parameter the IdP echoes back; matched against the
    /// pending row.
    #[serde(default)]
    pub state: Option<String>,
    /// RFC 9207 `iss` parameter; constant-time-compared to the pinned
    /// issuer when present.
    #[serde(default)]
    pub iss: Option<String>,
    /// IdPs route OAuth errors back via the redirect URI; when present
    /// the handler short-circuits before the service runs.
    #[serde(default, rename = "error")]
    pub error_code: Option<String>,
    /// Human-readable description that some IdPs include alongside
    /// `error`. Logged at trace level only — never reflected back to
    /// the caller.
    #[serde(default)]
    pub error_description: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_oidc_cookie_extracts_named_cookie() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("foo=bar; __Host-zagrosi_oidc=abc123; baz=qux"),
        );
        assert_eq!(read_oidc_cookie(&headers).as_deref(), Some("abc123"));
    }

    #[test]
    fn read_oidc_cookie_returns_none_without_header() {
        let headers = HeaderMap::new();
        assert!(read_oidc_cookie(&headers).is_none());
    }

    #[test]
    fn read_oidc_cookie_returns_none_when_absent() {
        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, HeaderValue::from_static("foo=bar"));
        assert!(read_oidc_cookie(&headers).is_none());
    }

    #[test]
    fn read_oidc_cookie_skips_malformed_predecessor() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("garbage=\"unclosed; __Host-zagrosi_oidc=abc123"),
        );
        assert_eq!(read_oidc_cookie(&headers).as_deref(), Some("abc123"));
    }

    #[test]
    fn failure_response_attaches_clear_cookie() {
        let response = failure_response(IdentityError::OidcStateMismatch);
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let set_cookies: Vec<&HeaderValue> = response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .collect();
        assert!(
            set_cookies.iter().any(|v| v
                .to_str()
                .is_ok_and(|s| s.contains(COOKIE_NAME) && s.contains("Max-Age=0"))),
            "failure response must clear the OIDC cookie"
        );
    }

    #[test]
    fn failure_response_attaches_clear_cookie_for_idp_error() {
        let response = failure_response(IdentityError::OidcDiscoveryFailed("idp returned error"));
        let set_cookies: Vec<&HeaderValue> = response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .collect();
        assert!(set_cookies.iter().any(|v| {
            v.to_str()
                .is_ok_and(|s| s.contains(COOKIE_NAME) && s.contains("Max-Age=0"))
        }));
    }
}
