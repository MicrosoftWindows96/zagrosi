// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::missing_panics_doc,
    clippy::missing_errors_doc,
    clippy::missing_const_for_fn
)]
//! Authentik admin-API client for the section-16 stack.
//!
//! Authentik is the canonical OIDC provider (for `tests/oidc_flow.rs`)
//! and the canonical inbound SCIM producer (for
//! `tests/scim_inbound_authentik.rs`). Section 16 ships the container,
//! blueprint discovery, and admin-API bootstrap hooks; the full OIDC +
//! SCIM object provisioning is gated until the gateway composition root
//! exists. These helpers are the typed surface over the handful of
//! admin-API calls the suites need.

use super::TestResult;

/// Default Authentik base (mapped to `127.0.0.1:9000` by
/// `compose.test.yaml`). Overridable via `ZAGROSI_TEST_AUTHENTIK_URL`.
#[must_use]
pub fn base_url() -> String {
    std::env::var("ZAGROSI_TEST_AUTHENTIK_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:9000".to_string())
}

/// Bootstrap admin API token (the `AUTHENTIK_BOOTSTRAP_TOKEN` the
/// compose env injects). Required for every admin-API call.
#[must_use]
pub fn admin_token() -> Option<String> {
    std::env::var("AUTHENTIK_BOOTSTRAP_TOKEN").ok()
}

/// `GET /application/o/zagrosi-test/.well-known/openid-configuration`
/// once the full E2E provisioning blueprint is active.
pub async fn openid_configuration(http: &reqwest::Client) -> TestResult<serde_json::Value> {
    let url = format!(
        "{}/application/o/zagrosi-test/.well-known/openid-configuration",
        base_url()
    );
    let body: serde_json::Value = http
        .get(&url)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    Ok(body)
}

/// Liveness probe (`/-/health/live/`).
pub async fn healthy(http: &reqwest::Client) -> bool {
    http.get(format!("{}/-/health/live/", base_url()))
        .send()
        .await
        .map(|r| r.status().is_success())
        .unwrap_or(false)
}

/// Trigger an outbound SCIM sync for the blueprint-provisioned
/// provider (`POST /api/v3/providers/scim/{id}/sync/`). `provider_id`
/// is resolved by `scripts/bootstrap-authentik.sh` and passed through
/// the `ZAGROSI_TEST_AUTHENTIK_SCIM_PROVIDER` env var.
pub async fn trigger_scim_sync(http: &reqwest::Client) -> TestResult<()> {
    let token = admin_token().ok_or("AUTHENTIK_BOOTSTRAP_TOKEN unset")?;
    let provider = std::env::var("ZAGROSI_TEST_AUTHENTIK_SCIM_PROVIDER")
        .map_err(|_| "ZAGROSI_TEST_AUTHENTIK_SCIM_PROVIDER unset")?;
    let url = format!("{}/api/v3/providers/scim/{provider}/sync/", base_url());
    http.post(&url)
        .bearer_auth(token)
        .send()
        .await?
        .error_for_status()?;
    Ok(())
}
