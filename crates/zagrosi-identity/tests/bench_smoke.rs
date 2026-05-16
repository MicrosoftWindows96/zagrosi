// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(
    clippy::expect_used,
    clippy::missing_const_for_fn,
    clippy::unwrap_used,
    missing_docs
)]

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use chrono::{TimeZone, Utc};
use serde_json::Value;
use tempfile::tempdir;
use uuid::Uuid;
use zagrosi_identity::config::Argon2Config;
use zagrosi_identity::domain::token_format::TokenHash;
use zagrosi_identity::password::{Argon2idHasher, calibrate};
use zagrosi_identity::session::{CachedSession, SessionCache};

const OIDC_FIXTURE: &[u8] = include_bytes!("fixtures/bench/oidc_id_token.json");
const SAML_FIXTURE: &[u8] = include_bytes!("fixtures/bench/saml_assertion.xml");

fn bench_argon2_config() -> Argon2Config {
    Argon2Config {
        m_cost: 8,
        t_cost: 1,
        p_cost: 1,
        max_concurrency: 1,
    }
}

fn cached_session(seed: u8) -> (TokenHash, CachedSession) {
    let created_at = Utc.with_ymd_and_hms(2026, 5, 1, 0, 0, 0).unwrap();
    (
        TokenHash([seed; 32]),
        CachedSession {
            session_id: Uuid::from_bytes([seed; 16]),
            user_id: Uuid::from_bytes([seed.wrapping_add(1); 16]),
            org_id: Uuid::from_bytes([seed.wrapping_add(2); 16]),
            expires_at: Utc.with_ymd_and_hms(2027, 1, 1, 0, 0, 0).unwrap(),
            revoked_at: None,
            version: 1,
            password_updated_at_at_resolve: created_at,
            amr: vec!["pwd".to_string()],
            acr: None,
            created_at,
        },
    )
}

#[tokio::test]
async fn argon2_calibration_runs_one_iteration() {
    let hasher = Argon2idHasher::new(&bench_argon2_config()).unwrap();
    calibrate(&hasher).await.unwrap();
}

#[tokio::test]
async fn session_resolve_cache_hit_preserves_identity_fields() {
    let cache = SessionCache::new(16, Duration::from_secs(30));
    let mut hashes = Vec::new();
    let mut values = Vec::new();

    for seed in 1..=8 {
        let (hash, value) = cached_session(seed);
        cache.insert(hash, value.clone()).await;
        hashes.push(hash);
        values.push(value);
    }

    for (hash, expected) in hashes.iter().zip(values.iter()) {
        let got = cache.get(hash).await.expect("prewarmed cache hit");
        assert_eq!(got.session_id, expected.session_id);
        assert_eq!(got.user_id, expected.user_id);
        assert_eq!(got.org_id, expected.org_id);
    }
}

#[test]
fn oidc_bench_fixture_decodes_and_matches_jwks() {
    let fixture: Value = serde_json::from_slice(OIDC_FIXTURE).unwrap();
    let id_token = fixture.get("id_token").and_then(Value::as_str).unwrap();
    assert_eq!(id_token.split('.').count(), 3);
    assert_eq!(
        fixture.pointer("/claims/iss").and_then(Value::as_str),
        Some("https://authentik.test/application/o/zagrosi/")
    );
    assert_eq!(
        fixture.pointer("/jwks/keys/0/kid").and_then(Value::as_str),
        Some("bench-key")
    );
}

#[test]
fn saml_bench_fixture_has_expected_response_shape() {
    let xml = std::str::from_utf8(SAML_FIXTURE).unwrap();
    assert!(xml.contains("<saml2p:Response"));
    assert!(xml.contains("<saml2:Assertion ID=\"bench-assertion-001\""));
    assert!(xml.contains("Recipient=\"https://zagrosi.test/v1/saml/acs\""));
}

#[test]
fn bench_gate_script_fails_and_passes_on_fixture_estimates() {
    let tmp = tempdir().unwrap();
    let script = repo_root().join("scripts/check-bench-gate.sh");
    write_estimate(tmp.path(), "session_resolve_bench", 200_000.0);
    let fail = Command::new(&script)
        .env("CRITERION_DIR", tmp.path())
        .args(["session_resolve_bench", "10000"])
        .status()
        .unwrap();
    assert!(!fail.success());

    write_estimate(tmp.path(), "session_resolve_bench", 50_000.0);
    let pass = Command::new(&script)
        .env("CRITERION_DIR", tmp.path())
        .args(["session_resolve_bench", "10000"])
        .status()
        .unwrap();
    assert!(pass.success());
}

fn write_estimate(root: &std::path::Path, bench: &str, mean_ns: f64) {
    let dir = root.join(bench).join("new");
    fs::create_dir_all(&dir).unwrap();
    fs::write(
        dir.join("estimates.json"),
        format!(
            r#"{{
  "mean": {{
    "confidence_interval": {{ "confidence_level": 0.95, "lower_bound": {mean_ns}, "upper_bound": {mean_ns} }},
    "point_estimate": {mean_ns},
    "standard_error": 0.0
  }}
}}"#
        ),
    )
    .unwrap();
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("crate must live under crates/zagrosi-identity")
        .to_path_buf()
}
