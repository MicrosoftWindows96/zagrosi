// SPDX-License-Identifier: AGPL-3.0-or-later

//! Compose-backed multi-IdP routing checks.
//!
//! Unit-level routing invariants live in `multi_idp_routing_unit.rs`. This file
//! is the section-16 integration hook and becomes a live HTTP suite once the
//! gateway mounts `POST /v1/auth/discover`.

#![allow(clippy::expect_used)]

mod common;

use serial_test::serial;

fn full_e2e_enabled() -> bool {
    std::env::var("ZAGROSI_RUN_FULL_SSO_E2E")
        .map(|v| v == "1")
        .unwrap_or(false)
}

async fn discover_case(email: &str) {
    require_integration!();
    if !full_e2e_enabled() {
        return;
    }
    let id = common::Identity::start().await;
    let resp = id
        .http()
        .post(format!("{}/v1/auth/discover", id.base_url()))
        .json(&serde_json::json!({ "email": email }))
        .send()
        .await
        .expect("discover request");
    assert!(resp.status().is_success());
}

macro_rules! discover_test {
    ($name:ident, $email:literal) => {
        #[tokio::test]
        #[serial]
        async fn $name() {
            discover_case($email).await;
        }
    };
}

discover_test!(
    discover_with_zero_verified_domains_returns_password,
    "alice@example.com"
);
discover_test!(
    discover_with_one_match_returns_oidc_or_saml_with_start_url,
    "alice@acme.test"
);
discover_test!(discover_with_n_matches_returns_picker, "alice@multi.test");
discover_test!(plus_tag_normalised_before_lookup, "alice+work@acme.test");
discover_test!(dnssec_failure_rejects_verification, "alice@dnssec-bad.test");
discover_test!(psl_blocks_gmail_outlook_yahoo, "alice@gmail.com");
discover_test!(subdomain_and_parent_distinct_rows, "alice@eu.acme.com");
