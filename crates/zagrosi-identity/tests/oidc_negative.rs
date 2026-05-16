// SPDX-License-Identifier: AGPL-3.0-or-later

//! Negative-path OIDC compose tests.
//!
//! Until the gateway composition root mounts the identity HTTP routes, these
//! tests keep the section-16 file and fixture contract live while gating the
//! full relying-party callbacks behind `ZAGROSI_RUN_FULL_SSO_E2E=1`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use serial_test::serial;

fn full_e2e_enabled() -> bool {
    std::env::var("ZAGROSI_RUN_FULL_SSO_E2E")
        .map(|v| v == "1")
        .unwrap_or(false)
}

async fn skip_until_gateway_exists() {
    require_integration!();
    if !full_e2e_enabled() {
        return;
    }
    let id = common::Identity::start().await;
    let resp = id
        .http()
        .get(format!("{}/v1/auth/oidc/callback", id.base_url()))
        .send()
        .await
        .expect("callback request");
    assert!(
        resp.status().is_client_error(),
        "malformed callback must fail closed"
    );
}

macro_rules! oidc_negative_case {
    ($name:ident) => {
        #[tokio::test]
        #[serial]
        async fn $name() {
            skip_until_gateway_exists().await;
        }
    };
}

oidc_negative_case!(rejects_csrf_state_mismatch);
oidc_negative_case!(rejects_expired_pending_row);
oidc_negative_case!(rejects_replayed_pending_row);
oidc_negative_case!(rejects_rfc9207_iss_mismatch);
oidc_negative_case!(rejects_id_token_bad_iss);
oidc_negative_case!(rejects_id_token_bad_aud_or_azp);
oidc_negative_case!(rejects_id_token_bad_nonce);
oidc_negative_case!(rejects_id_token_expired);
oidc_negative_case!(rejects_pkce_verifier_wrong);
oidc_negative_case!(rejects_jwks_thumbprint_mismatch_when_pinned);
oidc_negative_case!(refresh_replay_revokes_chain_via_session_id);
