// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::missing_panics_doc,
    clippy::missing_errors_doc,
    clippy::missing_const_for_fn
)]
//! `SimpleSAMLphp` (kristophjunge/test-saml-idp) helpers for the
//! section-16 stack.
//!
//! The container ships a fixed `IdP` with a seeded test user (see
//! `infra/simplesaml/`). The `tests/saml_flow.rs` suite fetches the
//! `IdP` metadata here and drives the built-in login form to obtain a
//! `SAMLResponse`. All calls are fail-soft reqwest requests.

use super::TestResult;

/// Default `SimpleSAMLphp` base (mapped to `127.0.0.1:8081` by
/// `compose.test.yaml`). Overridable via
/// `ZAGROSI_TEST_SIMPLESAML_URL`.
#[must_use]
pub fn base_url() -> String {
    std::env::var("ZAGROSI_TEST_SIMPLESAML_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:8081".to_string())
}

/// Seeded test-user credentials baked into
/// `infra/simplesaml/authsources.php`.
pub const TEST_USER: &str = "user@example.com";
/// Seeded test-user password (mirrors the upstream image default;
/// not a secret — a throwaway local `IdP`).
pub const TEST_USER_PASSWORD: &str = "user";

/// `GET /simplesaml/saml2/idp/metadata.php` — the `IdP`
/// `EntityDescriptor`. Returned verbatim so the SP-side metadata
/// trust bootstrap can pin the signing certificate.
pub async fn idp_metadata(http: &reqwest::Client) -> TestResult<String> {
    let url = format!("{}/simplesaml/saml2/idp/metadata.php", base_url());
    let xml = http
        .get(&url)
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;
    Ok(xml)
}

/// Liveness probe mirroring the compose healthcheck
/// (`/simplesaml/module.php/core/frontpage_welcome.php`).
pub async fn healthy(http: &reqwest::Client) -> bool {
    let url = format!(
        "{}/simplesaml/module.php/core/frontpage_welcome.php",
        base_url()
    );
    http.get(&url)
        .send()
        .await
        .map(|r| r.status().is_success())
        .unwrap_or(false)
}
