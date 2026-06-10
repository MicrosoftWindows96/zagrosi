// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! `POST /v1/auth/discover` — IdP routing decision for an email.
//!
//! Public endpoint. The handler:
//!
//! 1. Validates + normalises the email (plus-tag strip, IDNA fold).
//! 2. Hard-rejects public-domain emails (PSL + curated catch-all)
//!    onto password auth so an attacker cannot smuggle a public
//!    domain past a misconfigured org_idp_domains row.
//! 3. Looks up verified, enabled, non-soft-deleted IdP claims for
//!    `lower(domain)` via [`crate::repo::OrgIdpDomainRepo`].
//! 4. Returns one of four `method` shapes per the spec contract:
//!    `password`, `oidc`, `saml`, or `picker` (multi-IdP choice).
//!
//! The handler MUST NOT leak whether the underlying email exists
//! in the `users` table — every response is identical for known
//! and unknown users with the same domain. The single signal an
//! attacker can extract is "this domain is configured for SSO via
//! IdP X" which is already public knowledge (the IdP itself
//! advertises the same routing).

use axum::Json;
use axum::extract::State;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{IdentityError, Result};

use super::blocklist::is_public_domain;
use super::email_normalise::{NormalisedEmail, normalise};
use super::state::RoutingState;

/// Request body for `POST /v1/auth/discover`.
#[derive(Debug, Clone, Deserialize)]
pub struct DiscoverRequest {
    /// Email address to route.
    pub email: String,
    /// Optional same-origin path the SPA wants the IdP to redirect
    /// back to after sign-in. Validated as a path-only string by
    /// `safe_return_to`; cross-origin or scheme-bearing values
    /// are silently dropped.
    #[serde(default)]
    pub return_to: Option<String>,
}

/// Response shape for `POST /v1/auth/discover`.
///
/// Internally tagged on `method` so the SPA can branch on a single
/// discriminator. The picker variant carries a sorted slice of
/// options; the `oidc` / `saml` variants carry one start URL each.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(tag = "method", rename_all = "snake_case")]
pub enum DiscoverResponse {
    /// No verified IdP claims for this domain (or the domain is
    /// public). The SPA falls back to the password / passkey
    /// surface.
    Password,
    /// Single OIDC IdP matched. `start_url` is the URL the SPA
    /// should navigate to so the IdP-redirect chain begins.
    Oidc {
        /// Start-flow URL with `return_to` + `login_hint` query
        /// parameters already wired.
        start_url: String,
    },
    /// Single SAML IdP matched. Same `start_url` semantics as
    /// the OIDC variant.
    Saml {
        /// Start-flow URL.
        start_url: String,
    },
    /// Multiple verified IdPs matched. The SPA renders a picker
    /// using the supplied options; selecting one navigates the
    /// browser to that option's `start_url`.
    Picker {
        /// One entry per matched IdP. Sorted by
        /// `(priority ASC, display_name ASC)` per the spec
        /// contract; the SPA can render the slice without
        /// re-sorting.
        options: Vec<PickerOption>,
    },
}

/// One choice in the multi-IdP picker.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PickerOption {
    /// Discriminator that names the protocol family for this
    /// option. Stable values: `oidc` / `saml`.
    pub method: PickerMethod,
    /// IdP id. The SPA echoes this in analytics; the start URL
    /// also carries it so the start handler can resolve the IdP
    /// directly.
    pub org_idp_id: Uuid,
    /// Display name shown next to the picker entry.
    pub display_name: String,
    /// Pre-built start URL for this option.
    pub start_url: String,
}

/// Picker-option protocol discriminator. Distinct from the
/// outer `method` field on [`DiscoverResponse`] so the picker
/// payload uses lowercase variants without leaking the
/// `password` / `picker` outer values.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PickerMethod {
    /// OIDC option.
    Oidc,
    /// SAML option.
    Saml,
}

/// Axum handler for `POST /v1/auth/discover`.
///
/// # Errors
///
/// Returns [`IdentityError::InvalidEmail`] when the request body's
/// email fails normalisation. Other failure modes (database
/// outage, etc.) propagate as the relevant
/// `IdentityError::Database` / `IdentityError::Config` shape.
pub async fn handle_discover(
    State(state): State<RoutingState>,
    Json(req): Json<DiscoverRequest>,
) -> Result<Json<DiscoverResponse>> {
    let normalised = normalise(&req.email)?;
    let response = decide(&state, &normalised, req.return_to.as_deref()).await?;
    Ok(Json(response))
}

/// Pure-decision helper extracted from the handler so the
/// integration tests can drive the routing logic without spinning
/// the axum runtime.
///
/// Increments the spec-mandated
/// `zagrosi_identity_discover_total{decision=...}` counter on
/// every successful decision so ops dashboards can break SSO
/// adoption out by routing class. Errors short-circuit before the
/// counter increment so bookkeeping does not double-count failed
/// lookups.
///
/// # Errors
///
/// Propagates [`IdentityError::Database`] from the underlying
/// repo lookup. Returns [`IdentityError::OidcConfigInvalid`] only
/// when an `org_idps.protocol` row carries a value outside the
/// `oidc` / `saml` CHECK constraint (which would indicate
/// schema drift).
pub async fn decide(
    state: &RoutingState,
    normalised: &NormalisedEmail<'_>,
    return_to: Option<&str>,
) -> Result<DiscoverResponse> {
    if is_public_domain(&normalised.lookup_domain) {
        record_decision_metric(DecisionLabel::Password);
        return Ok(DiscoverResponse::Password);
    }

    let safe_path = safe_return_to(return_to);
    let hits = state
        .discovery_domain_repo
        .lookup_routes_by_domain_lower(&normalised.lookup_domain)
        .await?;

    if hits.is_empty() {
        record_decision_metric(DecisionLabel::Password);
        return Ok(DiscoverResponse::Password);
    }

    if hits.len() == 1 {
        let hit = &hits[0];
        let start_url = build_start_url(
            &hit.protocol,
            hit.org_idp_id,
            normalised.original,
            safe_path.as_deref(),
        );
        return Ok(match hit.protocol.as_str() {
            "oidc" => {
                record_decision_metric(DecisionLabel::Oidc);
                DiscoverResponse::Oidc { start_url }
            }
            "saml" => {
                record_decision_metric(DecisionLabel::Saml);
                DiscoverResponse::Saml { start_url }
            }
            // Defensive: the `org_idps.protocol` CHECK constraint
            // restricts values to `oidc` / `saml`. Anything else
            // is corruption — surface as a typed internal error.
            other => {
                return Err(IdentityError::OidcConfigInvalid {
                    reason: format!("unknown protocol `{other}` in org_idps row"),
                });
            }
        });
    }

    let mut options = Vec::with_capacity(hits.len());
    for hit in hits {
        let method = match hit.protocol.as_str() {
            "oidc" => PickerMethod::Oidc,
            "saml" => PickerMethod::Saml,
            other => {
                return Err(IdentityError::OidcConfigInvalid {
                    reason: format!("unknown protocol `{other}` in org_idps row"),
                });
            }
        };
        let start_url = build_start_url(
            &hit.protocol,
            hit.org_idp_id,
            normalised.original,
            safe_path.as_deref(),
        );
        options.push(PickerOption {
            method,
            org_idp_id: hit.org_idp_id,
            display_name: hit.display_name,
            start_url,
        });
    }
    record_decision_metric(DecisionLabel::Picker);
    Ok(DiscoverResponse::Picker { options })
}

/// Spec-mandated discover-decision counter name.
///
/// Pulled into a `const` so tests can assert against the same
/// string the prometheus exporter sees.
pub const DISCOVER_TOTAL_METRIC: &str = "zagrosi_identity_discover_total";

/// Stable label values for the `decision` dimension of
/// [`DISCOVER_TOTAL_METRIC`]. Pulled into an enum so the spec
/// labelling stays in lockstep with the response taxonomy.
#[derive(Debug, Clone, Copy)]
enum DecisionLabel {
    Password,
    Oidc,
    Saml,
    Picker,
}

impl DecisionLabel {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::Oidc => "oidc",
            Self::Saml => "saml",
            Self::Picker => "picker",
        }
    }
}

fn record_decision_metric(label: DecisionLabel) {
    metrics::counter!(DISCOVER_TOTAL_METRIC, "decision" => label.as_str()).increment(1);
}

/// Build the IdP start URL.
///
/// URL shape: `/v1/auth/{protocol}/by-idp/{org_idp_id}/start?return_to=...&login_hint=...`.
/// The `by-idp` infix lets the start handler resolve the IdP
/// directly from the URL without re-running the routing decision.
/// Section-16's full-stack integration tests wire the `by-idp`
/// route handler; the unit tests in this crate assert the URL
/// shape only.
fn build_start_url(
    protocol: &str,
    org_idp_id: Uuid,
    login_hint: &str,
    return_to: Option<&str>,
) -> String {
    let mut url = format!("/v1/auth/{protocol}/by-idp/{org_idp_id}/start");

    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    if let Some(rt) = return_to {
        serializer.append_pair("return_to", rt);
    }
    serializer.append_pair("login_hint", login_hint);
    let qs = serializer.finish();
    if !qs.is_empty() {
        url.push('?');
        url.push_str(&qs);
    }
    url
}

/// Same-origin guard for the caller-supplied `return_to`.
///
/// Drops any value that contains a scheme (`://`), a backslash
/// (Windows-path smuggling), or that does not start with `/`. The
/// SPA may pass `/dashboard`, `/projects/42`, or similar; cross-
/// origin URLs are silently ignored to prevent open-redirect
/// abuse via the SSO redirect chain.
///
/// Also rejects ASCII C0 control bytes (CR, LF, NUL, tab, etc.) so
/// downstream code that ever surfaces the value in a header or log
/// line cannot trigger response-splitting / log-injection.
#[must_use]
fn safe_return_to(input: Option<&str>) -> Option<String> {
    let raw = input?.trim();
    if raw.is_empty() {
        return None;
    }
    if raw.contains("://") || raw.contains('\\') {
        return None;
    }
    if !raw.starts_with('/') {
        return None;
    }
    // Reject `//foo` (protocol-relative URL — same SOP smuggle).
    if raw.starts_with("//") {
        return None;
    }
    // Reject ASCII C0 control bytes (< 0x20) and DEL (0x7F).
    // CRLF in particular enables HTTP response-splitting if the
    // value is later inserted into a `Location:` header without
    // re-encoding; NUL trips C-string boundaries downstream.
    if raw.bytes().any(|b| b < 0x20 || b == 0x7F) {
        return None;
    }
    Some(raw.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_start_url_includes_login_hint_and_org_idp_id() {
        let id = Uuid::nil();
        let url = build_start_url("oidc", id, "alice@acme.com", Some("/dashboard"));
        assert!(url.starts_with(&format!("/v1/auth/oidc/by-idp/{id}/start?")));
        assert!(url.contains("login_hint=alice%40acme.com"));
        assert!(url.contains("return_to=%2Fdashboard"));
    }

    #[test]
    fn build_start_url_omits_return_to_when_absent() {
        let id = Uuid::nil();
        let url = build_start_url("saml", id, "alice@acme.com", None);
        assert!(url.contains("login_hint="));
        assert!(!url.contains("return_to="));
    }

    #[test]
    fn safe_return_to_keeps_root_relative_path() {
        assert_eq!(
            safe_return_to(Some("/dashboard")).as_deref(),
            Some("/dashboard")
        );
    }

    #[test]
    fn safe_return_to_drops_absolute_url() {
        assert!(safe_return_to(Some("https://evil.example/")).is_none());
    }

    #[test]
    fn safe_return_to_drops_protocol_relative() {
        assert!(safe_return_to(Some("//evil.example/")).is_none());
    }

    #[test]
    fn safe_return_to_drops_relative() {
        assert!(safe_return_to(Some("dashboard")).is_none());
    }

    #[test]
    fn safe_return_to_drops_backslash_smuggle() {
        assert!(safe_return_to(Some("/path\\to")).is_none());
    }

    #[test]
    fn safe_return_to_passes_through_none() {
        assert!(safe_return_to(None).is_none());
        assert!(safe_return_to(Some("")).is_none());
        assert!(safe_return_to(Some("   ")).is_none());
    }

    #[test]
    fn picker_method_serialises_lowercase() {
        let json = serde_json::to_string(&PickerMethod::Oidc)
            .unwrap_or_else(|e| panic!("serialise oidc: {e}"));
        assert_eq!(json, "\"oidc\"");
        let json = serde_json::to_string(&PickerMethod::Saml)
            .unwrap_or_else(|e| panic!("serialise saml: {e}"));
        assert_eq!(json, "\"saml\"");
    }

    #[test]
    fn discover_response_password_serialises_with_method_tag() {
        let v: serde_json::Value = serde_json::to_value(DiscoverResponse::Password)
            .unwrap_or_else(|e| panic!("serialise password: {e}"));
        assert_eq!(v, serde_json::json!({"method": "password"}));
    }

    #[test]
    fn discover_response_oidc_serialises_with_start_url() {
        let v: serde_json::Value = serde_json::to_value(DiscoverResponse::Oidc {
            start_url: "/v1/auth/oidc/by-idp/x/start?login_hint=a%40b".to_string(),
        })
        .unwrap_or_else(|e| panic!("serialise oidc: {e}"));
        assert_eq!(v["method"], serde_json::json!("oidc"));
        assert!(
            v["start_url"]
                .as_str()
                .is_some_and(|s| s.contains("login_hint"))
        );
    }

    #[test]
    fn discover_response_picker_serialises_with_options_array() {
        let v: serde_json::Value = serde_json::to_value(DiscoverResponse::Picker {
            options: vec![PickerOption {
                method: PickerMethod::Oidc,
                org_idp_id: Uuid::nil(),
                display_name: "Acme".to_string(),
                start_url: "/v1/auth/oidc/by-idp/x/start".to_string(),
            }],
        })
        .unwrap_or_else(|e| panic!("serialise picker: {e}"));
        assert_eq!(v["method"], serde_json::json!("picker"));
        assert!(v["options"].as_array().is_some_and(|a| a.len() == 1));
    }
}
