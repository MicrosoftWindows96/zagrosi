// SPDX-License-Identifier: AGPL-3.0-or-later

//! SAML negative corpus tests.
//!
//! The corpus files are committed fixtures and are also used as seeds for the
//! `saml_assertion` fuzz target. The full ACS HTTP callback path is enabled
//! with `RUN_INTEGRATION=1 ZAGROSI_RUN_FULL_SSO_E2E=1`.

#![cfg(feature = "saml")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use serial_test::serial;

fn full_e2e_enabled() -> bool {
    std::env::var("ZAGROSI_RUN_FULL_SSO_E2E")
        .map(|v| v == "1")
        .unwrap_or(false)
}

async fn reject_fixture(fixture: &str, expected_code: &str) {
    let bytes = common::fixtures::read_negative_saml(fixture);
    assert!(!bytes.is_empty(), "{fixture} must not be empty");
    require_integration!();
    if !full_e2e_enabled() {
        return;
    }

    let id = common::Identity::start().await;
    let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, bytes);
    let resp = id
        .http()
        .post(format!("{}/v1/auth/saml/acs", id.base_url()))
        .form(&[("SAMLResponse", encoded), ("RelayState", "x".to_string())])
        .send()
        .await
        .expect("ACS request");
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let body: serde_json::Value = resp.json().await.expect("error body");
    assert_eq!(body["code"], expected_code);
}

macro_rules! reject_corpus_case {
    ($name:ident, $fixture:literal, $expected_err:literal) => {
        #[tokio::test]
        #[serial]
        async fn $name() {
            reject_fixture($fixture, $expected_err).await;
        }
    };
}

reject_corpus_case!(rejects_xsw_a, "xsw_a.xml", "saml_signature_invalid");
reject_corpus_case!(rejects_xsw_b, "xsw_b.xml", "saml_signature_invalid");
reject_corpus_case!(rejects_xsw_c, "xsw_c.xml", "saml_signature_invalid");
reject_corpus_case!(rejects_xsw_d, "xsw_d.xml", "saml_signature_invalid");
reject_corpus_case!(rejects_xsw_e, "xsw_e.xml", "saml_signature_invalid");
reject_corpus_case!(rejects_xsw_f, "xsw_f.xml", "saml_signature_invalid");
reject_corpus_case!(rejects_xsw_g, "xsw_g.xml", "saml_signature_invalid");
reject_corpus_case!(rejects_xsw_h, "xsw_h.xml", "saml_signature_invalid");
reject_corpus_case!(rejects_xxe_dtd, "xxe_dtd.xml", "saml_xml_parse");
reject_corpus_case!(
    rejects_xxe_external_entity,
    "xxe_external_entity.xml",
    "saml_xml_parse"
);
reject_corpus_case!(rejects_duplicate_id, "duplicate_id.xml", "saml_xml_parse");
reject_corpus_case!(
    rejects_bad_recipient,
    "bad_recipient.xml",
    "saml_recipient_mismatch"
);
reject_corpus_case!(
    rejects_expired_notonorafter,
    "expired_notonorafter.xml",
    "saml_expired"
);
reject_corpus_case!(rejects_replay, "replay_assertion.xml", "saml_replay");
reject_corpus_case!(
    rejects_idp_initiated_when_disabled,
    "idp_initiated.xml",
    "saml_idp_initiated_disabled"
);
