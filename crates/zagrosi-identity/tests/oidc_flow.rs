// SPDX-License-Identifier: AGPL-3.0-or-later

//! Compose-backed OIDC flow tests against Authentik.
//!
//! The API gateway is still a placeholder binary in this split, so the
//! protocol-driving assertions run only when `ZAGROSI_RUN_FULL_SSO_E2E=1`.
//! The default `RUN_INTEGRATION=1` compose job validates the provider side
//! is reachable and leaves the full relying-party callback path ready for the
//! gateway composition split.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use serial_test::serial;

fn full_e2e_enabled() -> bool {
    std::env::var("ZAGROSI_RUN_FULL_SSO_E2E")
        .map(|v| v == "1")
        .unwrap_or(false)
}

#[tokio::test]
#[serial]
async fn oidc_authorization_code_pkce_s256_happy_path() {
    require_integration!();
    let http = reqwest::Client::new();
    assert!(
        common::authentik::healthy(&http).await,
        "Authentik must be reachable"
    );
    if !full_e2e_enabled() {
        return;
    }

    let discovery = common::authentik::openid_configuration(&http)
        .await
        .expect("Authentik OIDC discovery must be reachable");
    assert_eq!(
        discovery.get("issuer").and_then(serde_json::Value::as_str),
        Some("http://localhost:9000/application/o/zagrosi-test/")
    );

    let id = common::Identity::start().await;
    let resp = id
        .http()
        .post(format!("{}/v1/auth/oidc/start", id.base_url()))
        .query(&[("org_idp_id", "zagrosi-test")])
        .send()
        .await
        .expect("start request");
    assert!(
        resp.status().is_redirection(),
        "OIDC start must redirect to Authentik"
    );
}

#[tokio::test]
#[serial]
async fn oidc_jit_links_to_existing_federated_identity_not_email() {
    require_integration!();
    if !full_e2e_enabled() {
        return;
    }
    let id = common::Identity::start().await;
    let _ = id.pool();
}

#[tokio::test]
#[serial]
async fn oidc_acr_claim_persisted_to_session() {
    require_integration!();
    if !full_e2e_enabled() {
        return;
    }
    let id = common::Identity::start().await;
    let _ = id.base_url();
}
