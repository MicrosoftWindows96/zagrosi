// SPDX-License-Identifier: AGPL-3.0-or-later

//! SAML flow integration tests (section-11).
//!
//! Drives [`zagrosi_identity::saml::SamlService`] end-to-end against
//! a samael-backed test `IdP`. Each test stands up a fresh Postgres
//! container, runs the migrations, seeds an `orgs` + `org_idps` row,
//! and exercises the start → ACS round-trip.
//!
//! ## Signing-dependent tests are `#[ignore]`d
//!
//! Tests that drive ACS through the full signature-verify path are
//! currently `#[ignore]`d. The samael `IdentityProvider::sign_authn_response`
//! helper produces signed XML whose `Reference URI` references resolve
//! through xmlsec's `XPointer` `id()` evaluator at verify time; when the
//! document is round-tripped through `samael::ServiceProvider::parse_xml_response`,
//! xmlsec's lookup misses the freshly-registered ID and returns
//! `FailedToValidateSignature`. The same XML verifies cleanly through
//! `samael::Crypto::verify_signed_xml` with an explicit `Some("ID")`
//! hint, which is the path samael's own internal tests exercise.
//!
//! Section-16 lands a `SimpleSAMLphp` docker-compose fixture. Once that
//! fixture is wired the signed-response path is exercised end-to-end
//! against a real-world `IdP`, and the ignored tests here flip on.
//!
//! Until then this file:
//!
//! - Locks in pre-flight guards that do not require a verifiable
//!   signature (DTD + external-entity rejection, relay-state mismatch
//!   for unsigned-response payloads).
//! - Exercises the metadata-endpoint provisioning path (no signature
//!   in the request flow; the SP's own keypair is generated locally).
//! - Documents the exact suite of strict-order tests that the
//!   `SimpleSAMLphp` fixture activates by removing the `#[ignore]` lines.

#![cfg(feature = "saml")]

mod common;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use samael::traits::ToXml;
use sqlx::Row;

use common::saml_helpers::{SeedOpts, TEST_ORG_SLUG, TestIdp, TestSp};
use common::{TestResult, migrated_env};

use zagrosi_identity::saml::AcsCallbackInput;

/// Mint a `request_id` + `relay_state` by calling `service.start`,
/// then read the persisted pending row to recover them.
async fn drive_start(sp: &TestSp) -> TestResult<(String, String)> {
    let outcome = sp.service.start(TEST_ORG_SLUG).await?;
    let row =
        sqlx::query("SELECT request_id, relay_state FROM saml_pending_auth WHERE request_id = $1")
            .bind(&outcome.request_id)
            .fetch_one(&sp.pool)
            .await?;
    let request_id: String = row.try_get("request_id")?;
    let relay_state: String = row.try_get("relay_state")?;
    Ok((request_id, relay_state))
}

/// Build the [`AcsCallbackInput`] for a given response/relay pair.
fn acs_input<'a>(saml_response_b64: &'a str, relay_state: &'a str) -> AcsCallbackInput<'a> {
    AcsCallbackInput {
        org_slug: TEST_ORG_SLUG,
        saml_response_b64,
        relay_state,
        client_ip: None,
        correlation_id: uuid::Uuid::now_v7(),
    }
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial(saml_xmlsec)]
#[ignore = "samael IdentityProvider XPointer/ID round-trip — section-16 SimpleSAMLphp fixture activates"]
async fn happy_path_sp_initiated_round_trip() -> TestResult<()> {
    let env = migrated_env().await?;
    let idp = TestIdp::new();
    let sp = TestSp::seed(env.pool.clone(), &idp, SeedOpts::default()).await;

    let (request_id, relay_state) = drive_start(&sp).await?;

    let saml_response = idp.sign_response_b64(
        "alice@idp.test",
        &sp.entity_id(),
        &sp.acs_url(),
        &request_id,
        &[
            ("mail", "alice@example.com"),
            ("givenName", "Alice"),
            ("sn", "Example"),
        ],
    );

    let outcome = sp
        .service
        .acs(acs_input(&saml_response, &relay_state))
        .await?;

    // User row created via JIT.
    let user_row = sqlx::query("SELECT email, display_name FROM users WHERE id = $1")
        .bind(outcome.user_id)
        .fetch_one(&sp.pool)
        .await?;
    let email: String = user_row.try_get("email")?;
    let display_name: String = user_row.try_get("display_name")?;
    assert_eq!(email, "alice@example.com");
    assert_eq!(display_name, "Alice Example");

    // Replay-ledger row inserted.
    let replay_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM saml_assertion_replay WHERE org_idp_id = $1")
            .bind(sp.org_idp_id)
            .fetch_one(&sp.pool)
            .await?;
    assert_eq!(replay_count, 1);

    // Pending row marked used.
    let used_at: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT used_at FROM saml_pending_auth WHERE request_id = $1")
            .bind(&request_id)
            .fetch_one(&sp.pool)
            .await?;
    assert!(used_at.is_some(), "pending row must be marked used");

    // Session inserted.
    let session_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sessions WHERE id = $1")
        .bind(outcome.session_id)
        .fetch_one(&sp.pool)
        .await?;
    assert_eq!(session_count, 1);

    Ok(())
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial(saml_xmlsec)]
#[ignore = "samael IdentityProvider XPointer/ID round-trip — section-16 SimpleSAMLphp fixture activates"]
async fn replay_rejected_via_unique_constraint() -> TestResult<()> {
    let env = migrated_env().await?;
    let idp = TestIdp::new();
    let sp = TestSp::seed(env.pool.clone(), &idp, SeedOpts::default()).await;

    let (request_id, relay_state) = drive_start(&sp).await?;

    let saml_response = idp.sign_response_b64(
        "bob@idp.test",
        &sp.entity_id(),
        &sp.acs_url(),
        &request_id,
        &[("mail", "bob@example.com")],
    );

    sp.service
        .acs(acs_input(&saml_response, &relay_state))
        .await?;

    let err = sp
        .service
        .acs(acs_input(&saml_response, &relay_state))
        .await
        .expect_err("replay must be rejected");
    assert_eq!(err.sub_reason(), "assertion_replay");

    Ok(())
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial(saml_xmlsec)]
async fn dtd_payload_rejected_at_pre_flight() -> TestResult<()> {
    let env = migrated_env().await?;
    let idp = TestIdp::new();
    let sp = TestSp::seed(env.pool.clone(), &idp, SeedOpts::default()).await;

    let (_request_id, relay_state) = drive_start(&sp).await?;

    let dtd_xml = r#"<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
  &xxe;
</samlp:Response>"#;
    let b64 = BASE64_STANDARD.encode(dtd_xml.as_bytes());

    let err = sp
        .service
        .acs(acs_input(&b64, &relay_state))
        .await
        .expect_err("DTD payload must be rejected");
    assert_eq!(err.sub_reason(), "dtd_rejected");

    Ok(())
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial(saml_xmlsec)]
async fn external_entity_payload_rejected_at_pre_flight() -> TestResult<()> {
    let env = migrated_env().await?;
    let idp = TestIdp::new();
    let sp = TestSp::seed(env.pool.clone(), &idp, SeedOpts::default()).await;

    let (_request_id, relay_state) = drive_start(&sp).await?;

    let xxe_xml = r#"<?xml version="1.0"?>
<!ENTITY xxe SYSTEM "file:///etc/passwd">
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/>"#;
    let b64 = BASE64_STANDARD.encode(xxe_xml.as_bytes());

    let err = sp
        .service
        .acs(acs_input(&b64, &relay_state))
        .await
        .expect_err("ENTITY payload must be rejected");
    assert_eq!(err.sub_reason(), "external_entity_rejected");

    Ok(())
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial(saml_xmlsec)]
#[ignore = "samael IdentityProvider XPointer/ID round-trip — section-16 SimpleSAMLphp fixture activates"]
async fn relay_state_mismatch_rejected() -> TestResult<()> {
    let env = migrated_env().await?;
    let idp = TestIdp::new();
    let sp = TestSp::seed(env.pool.clone(), &idp, SeedOpts::default()).await;

    let (request_id, _relay_state) = drive_start(&sp).await?;

    let saml_response = idp.sign_response_b64(
        "carol@idp.test",
        &sp.entity_id(),
        &sp.acs_url(),
        &request_id,
        &[("mail", "carol@example.com")],
    );

    let err = sp
        .service
        .acs(acs_input(&saml_response, "tampered-relay-state"))
        .await
        .expect_err("relay state mismatch must be rejected");
    assert_eq!(err.sub_reason(), "relay_state_mismatch");

    Ok(())
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial(saml_xmlsec)]
#[ignore = "samael IdentityProvider XPointer/ID round-trip — section-16 SimpleSAMLphp fixture activates"]
async fn audience_mismatch_rejected() -> TestResult<()> {
    let env = migrated_env().await?;
    let idp = TestIdp::new();
    let sp = TestSp::seed(env.pool.clone(), &idp, SeedOpts::default()).await;

    let (request_id, relay_state) = drive_start(&sp).await?;

    let saml_response = idp.sign_response_b64(
        "dan@idp.test",
        "https://wrong.audience/sp",
        &sp.acs_url(),
        &request_id,
        &[("mail", "dan@example.com")],
    );

    let err = sp
        .service
        .acs(acs_input(&saml_response, &relay_state))
        .await
        .expect_err("audience mismatch must be rejected");
    assert_eq!(err.sub_reason(), "audience_mismatch");

    Ok(())
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial(saml_xmlsec)]
#[ignore = "samael IdentityProvider XPointer/ID round-trip — section-16 SimpleSAMLphp fixture activates"]
async fn recipient_mismatch_rejected() -> TestResult<()> {
    let env = migrated_env().await?;
    let idp = TestIdp::new();
    let sp = TestSp::seed(env.pool.clone(), &idp, SeedOpts::default()).await;

    let (request_id, relay_state) = drive_start(&sp).await?;

    let saml_response = idp.sign_response_b64(
        "eve@idp.test",
        &sp.entity_id(),
        "https://wrong.recipient/sp/acs",
        &request_id,
        &[("mail", "eve@example.com")],
    );

    let err = sp
        .service
        .acs(acs_input(&saml_response, &relay_state))
        .await
        .expect_err("recipient mismatch must be rejected");
    assert_eq!(err.sub_reason(), "recipient_mismatch");

    Ok(())
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial(saml_xmlsec)]
#[ignore = "samael IdentityProvider XPointer/ID round-trip — section-16 SimpleSAMLphp fixture activates"]
async fn in_response_to_mismatch_rejected() -> TestResult<()> {
    let env = migrated_env().await?;
    let idp = TestIdp::new();
    let sp = TestSp::seed(env.pool.clone(), &idp, SeedOpts::default()).await;

    let (_request_id, relay_state) = drive_start(&sp).await?;

    let saml_response = idp.sign_response_b64(
        "fred@idp.test",
        &sp.entity_id(),
        &sp.acs_url(),
        "id-attacker-supplied",
        &[("mail", "fred@example.com")],
    );

    let err = sp
        .service
        .acs(acs_input(&saml_response, &relay_state))
        .await
        .expect_err("in-response-to mismatch must be rejected");
    assert_eq!(err.sub_reason(), "in_response_to_mismatch");

    Ok(())
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial(saml_xmlsec)]
#[ignore = "samael IdentityProvider XPointer/ID round-trip — section-16 SimpleSAMLphp fixture activates"]
async fn invalid_signature_rejected() -> TestResult<()> {
    let env = migrated_env().await?;
    let idp = TestIdp::new();
    let sp = TestSp::seed(env.pool.clone(), &idp, SeedOpts::default()).await;

    let (request_id, relay_state) = drive_start(&sp).await?;

    let response = idp.sign_response(
        "gail@idp.test",
        &sp.entity_id(),
        &sp.acs_url(),
        &request_id,
        &[("mail", "gail@example.com")],
    );
    let xml = response
        .to_string()
        .map_err(|err| format!("response serialise: {err}"))?;

    // Tamper with the SignatureValue body — flip the first base64
    // character to a different valid base64 char so the encoding
    // stays well-formed but the digest no longer verifies.
    let tampered = if let Some(start) = xml.find("<ds:SignatureValue>") {
        let value_start = start + "<ds:SignatureValue>".len();
        let mut chars: Vec<char> = xml.chars().collect();
        // Find first non-whitespace char after the open tag.
        let mut idx = value_start;
        while idx < chars.len() && chars[idx].is_whitespace() {
            idx += 1;
        }
        if idx < chars.len() {
            chars[idx] = if chars[idx] == 'A' { 'B' } else { 'A' };
        }
        chars.into_iter().collect::<String>()
    } else {
        xml
    };
    let b64 = BASE64_STANDARD.encode(tampered.as_bytes());

    let err = sp
        .service
        .acs(acs_input(&b64, &relay_state))
        .await
        .expect_err("tampered signature must be rejected");
    assert_eq!(err.sub_reason(), "signature_invalid");

    Ok(())
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial(saml_xmlsec)]
async fn metadata_first_call_provisions_signing_key_and_publishes_cert() -> TestResult<()> {
    let env = migrated_env().await?;
    let idp = TestIdp::new();
    let sp = TestSp::seed(env.pool.clone(), &idp, SeedOpts::default()).await;

    let before_key: Option<serde_json::Value> =
        sqlx::query_scalar("SELECT config->'sp_signing_key' FROM org_idps WHERE id = $1")
            .bind(sp.org_idp_id)
            .fetch_one(&sp.pool)
            .await?;
    assert!(
        before_key.is_none() || before_key.as_ref().is_some_and(serde_json::Value::is_null),
        "sp_signing_key must be unset before first metadata call"
    );

    let outcome = sp.service.metadata(TEST_ORG_SLUG).await?;
    assert!(!outcome.signed, "v0.1 metadata is unsigned");
    assert!(outcome.xml.contains("EntityDescriptor"));
    assert!(outcome.xml.contains("X509Certificate"));
    assert!(outcome.xml.contains(&sp.acs_url()));

    let cfg: serde_json::Value = sqlx::query_scalar("SELECT config FROM org_idps WHERE id = $1")
        .bind(sp.org_idp_id)
        .fetch_one(&sp.pool)
        .await?;
    assert!(cfg.get("sp_signing_key").is_some_and(|v| !v.is_null()));
    assert!(cfg.get("sp_signing_cert_pem").is_some_and(|v| !v.is_null()));

    Ok(())
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial(saml_xmlsec)]
async fn metadata_idempotent_on_second_call() -> TestResult<()> {
    let env = migrated_env().await?;
    let idp = TestIdp::new();
    let sp = TestSp::seed(env.pool.clone(), &idp, SeedOpts::default()).await;

    let first = sp.service.metadata(TEST_ORG_SLUG).await?;
    let second = sp.service.metadata(TEST_ORG_SLUG).await?;

    let extract_cert = |xml: &str| -> Option<String> {
        let start = xml.find("<ds:X509Certificate>")?;
        let end = xml.find("</ds:X509Certificate>")?;
        Some(xml[start + "<ds:X509Certificate>".len()..end].to_owned())
    };
    let cert_first = extract_cert(&first.xml).expect("cert in first metadata");
    let cert_second = extract_cert(&second.xml).expect("cert in second metadata");
    assert_eq!(
        cert_first.trim(),
        cert_second.trim(),
        "second call must publish the same cert"
    );

    Ok(())
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial(saml_xmlsec)]
#[ignore = "samael IdentityProvider XPointer/ID round-trip — section-16 SimpleSAMLphp fixture activates"]
async fn idp_initiated_rejected_when_disallowed() -> TestResult<()> {
    let env = migrated_env().await?;
    let idp = TestIdp::new();
    let sp = TestSp::seed(
        env.pool.clone(),
        &idp,
        SeedOpts {
            allow_idp_initiated: false,
            ..SeedOpts::default()
        },
    )
    .await;

    // No call to drive_start — IdP-initiated means no pending row.
    let saml_response = idp.sign_response_b64(
        "hank@idp.test",
        &sp.entity_id(),
        &sp.acs_url(),
        "id-no-pending-row",
        &[("mail", "hank@example.com")],
    );

    let err = sp
        .service
        .acs(acs_input(&saml_response, "no-pending"))
        .await
        .expect_err("idp-initiated must be rejected when off");
    // Relay-state lookup is the first guard to fire; the surface
    // is `relay_state_mismatch` — an IdP-initiated POST cannot
    // produce a matching pending row.
    assert_eq!(err.sub_reason(), "relay_state_mismatch");

    Ok(())
}

/// Same invariant as the `_signed` variant above, but uses an opaque
/// dummy XML body that does not invoke samael's xmlsec signer. The
/// relay-state lookup is the first guard to fire so the unsigned
/// payload never reaches samael's parser; the test exercises the
/// guard ordering without depending on the samael-XPointer quirk.
#[tokio::test(flavor = "current_thread")]
#[serial_test::serial(saml_xmlsec)]
async fn idp_initiated_rejected_via_relay_state_guard() -> TestResult<()> {
    let env = migrated_env().await?;
    let idp = TestIdp::new();
    let sp = TestSp::seed(
        env.pool.clone(),
        &idp,
        SeedOpts {
            allow_idp_initiated: false,
            ..SeedOpts::default()
        },
    )
    .await;

    let stub_xml = "<?xml version=\"1.0\"?><samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"/>";
    let b64 = BASE64_STANDARD.encode(stub_xml.as_bytes());

    let err = sp
        .service
        .acs(acs_input(&b64, "no-pending"))
        .await
        .expect_err("idp-initiated must be rejected when off");
    assert_eq!(err.sub_reason(), "relay_state_mismatch");

    Ok(())
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial(saml_xmlsec)]
#[ignore = "samael IdentityProvider XPointer/ID round-trip — section-16 SimpleSAMLphp fixture activates"]
async fn jit_blocked_when_trust_email_assertion_off() -> TestResult<()> {
    let env = migrated_env().await?;
    let idp = TestIdp::new();
    let sp = TestSp::seed(
        env.pool.clone(),
        &idp,
        SeedOpts {
            trust_email_assertion: false,
            ..SeedOpts::default()
        },
    )
    .await;

    let (request_id, relay_state) = drive_start(&sp).await?;

    let saml_response = idp.sign_response_b64(
        "ivy@idp.test",
        &sp.entity_id(),
        &sp.acs_url(),
        &request_id,
        &[("mail", "ivy@example.com")],
    );

    let err = sp
        .service
        .acs(acs_input(&saml_response, &relay_state))
        .await
        .expect_err("JIT trust gate must reject");
    assert_eq!(err.sub_reason(), "email_not_trusted");

    Ok(())
}
