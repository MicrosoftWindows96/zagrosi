// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(
    clippy::expect_used,
    clippy::redundant_pub_crate,
    clippy::unwrap_used,
    dead_code
)]

use std::env;
use std::time::Duration;

use chrono::{TimeZone, Utc};
use serde_json::Value;
use tokio::runtime::Runtime;
use uuid::Uuid;
use zagrosi_identity::config::Argon2Config;
use zagrosi_identity::domain::token_format::TokenHash;
use zagrosi_identity::session::{CachedSession, SessionCache};

pub(super) const BENCH_PASSWORD: &str = "bench-password-32-bytes-long-0001";

pub(super) fn criterion_runtime() -> Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .expect("build benchmark runtime")
}

pub(super) fn bench_argon2_config() -> Argon2Config {
    Argon2Config {
        m_cost: env_u32("ZAGROSI_ARGON2_M_COST", 8),
        t_cost: env_u32("ZAGROSI_ARGON2_T_COST", 1),
        p_cost: env_u32("ZAGROSI_ARGON2_P_COST", 1),
        max_concurrency: env_usize("ZAGROSI_ARGON2_MAX_CONCURRENCY", 1),
    }
}

pub(super) fn production_argon2_config() -> Argon2Config {
    Argon2Config {
        m_cost: env_u32("ZAGROSI_ARGON2_M_COST", 19_456),
        t_cost: env_u32("ZAGROSI_ARGON2_T_COST", 2),
        p_cost: env_u32("ZAGROSI_ARGON2_P_COST", 1),
        max_concurrency: env_usize("ZAGROSI_ARGON2_MAX_CONCURRENCY", num_cpus::get()),
    }
}

pub(super) fn cached_session(seed: u8) -> (TokenHash, CachedSession) {
    let mut hash = [seed; 32];
    hash[31] = hash[31].wrapping_add(17);
    let created_at = Utc.with_ymd_and_hms(2026, 5, 1, 0, 0, 0).unwrap();
    (
        TokenHash(hash),
        CachedSession {
            session_id: Uuid::from_bytes([seed; 16]),
            user_id: Uuid::from_bytes([seed.wrapping_add(1); 16]),
            org_id: Uuid::from_bytes([seed.wrapping_add(2); 16]),
            expires_at: Utc.with_ymd_and_hms(2027, 1, 1, 0, 0, 0).unwrap(),
            revoked_at: None,
            version: i64::from(seed.max(1)),
            password_updated_at_at_resolve: created_at,
            amr: vec!["pwd".to_string()],
            acr: Some("urn:zagrosi:bench".to_string()),
            created_at,
        },
    )
}

pub(super) async fn warm_session_cache(size: usize) -> (SessionCache, Vec<TokenHash>) {
    let capacity = u64::try_from(size)
        .unwrap_or(u64::MAX - 16)
        .saturating_add(16);
    let cache = SessionCache::new(capacity, Duration::from_secs(300));
    let mut hashes = Vec::with_capacity(size);
    for i in 0..size {
        let seed = u8::try_from((i % 250) + 1).unwrap_or(1);
        let (hash, value) = cached_session(seed);
        cache.insert(hash, value).await;
        hashes.push(hash);
    }
    (cache, hashes)
}

pub(super) fn decode_oidc_fixture(bytes: &[u8]) -> Value {
    let fixture: Value = serde_json::from_slice(bytes).expect("OIDC bench fixture must be JSON");
    let token = fixture
        .get("id_token")
        .and_then(Value::as_str)
        .expect("OIDC bench fixture must carry id_token");
    let claims = fixture
        .get("claims")
        .and_then(Value::as_object)
        .expect("OIDC bench fixture must carry claims");
    assert!(
        token.split('.').count() == 3,
        "id_token must be compact JWS"
    );
    assert_eq!(
        claims.get("iss").and_then(Value::as_str),
        Some("https://authentik.test/application/o/zagrosi/")
    );
    assert_eq!(
        claims.get("aud").and_then(Value::as_str),
        Some("zagrosi-bench")
    );
    fixture
}

pub(super) fn decode_saml_fixture(bytes: &[u8]) -> String {
    let xml = std::str::from_utf8(bytes).expect("SAML bench fixture must be UTF-8");
    assert!(
        xml.contains("<saml2:Assertion"),
        "SAML fixture must include Assertion"
    );
    assert!(
        xml.contains("ID=\"bench-assertion-001\""),
        "SAML fixture assertion id changed"
    );
    xml.to_owned()
}

fn env_u32(name: &str, default: u32) -> u32 {
    env::var(name)
        .ok()
        .and_then(|raw| raw.parse().ok())
        .unwrap_or(default)
}

fn env_usize(name: &str, default: usize) -> usize {
    env::var(name)
        .ok()
        .and_then(|raw| raw.parse().ok())
        .unwrap_or(default)
}
