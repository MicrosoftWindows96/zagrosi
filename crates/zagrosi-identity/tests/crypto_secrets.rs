// SPDX-License-Identifier: AGPL-3.0-or-later

//! Integration tests for the secrets shim.
//!
//! Mirrors the design notes (round-trip, tamper rejection, wire-shape
//! forward-compat to the KMS layer's rewrap, env-var validation through
//! `IdentityConfig::load`). Tests touch process-level env state via
//! `figment::Jail::expect_with` so the workspace `unsafe_code = forbid`
//! lint stays satisfied.

#![allow(missing_docs)]

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use figment::Jail;
use static_assertions::assert_impl_all;
use zagrosi_identity::{
    Envelope, IdentityConfig, IdentityError, KEY_ID_V0_1_STATIC, LoadOptions, Secrets,
};

// The design notes demanded module-scope assertions; integration scope
// keeps the same guarantee even if the crate's unit-test module is
// stripped.
assert_impl_all!(Secrets: Send, Sync);
assert_impl_all!(Envelope: Send, Sync, Clone, std::fmt::Debug);

/// 32-byte zero key encoded as base64. Suitable only for tests.
const ZERO_KEY_B64: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

/// Test-only fixed master key.
const TEST_KEY: [u8; 32] = [0x42; 32];

#[test]
fn secrets_seal_open_roundtrip() {
    let secrets = Secrets::from_key(Box::new(TEST_KEY));
    let plaintext = b"client_secret-shhh";
    let env = secrets
        .seal(plaintext)
        .unwrap_or_else(|e| panic!("seal: {e}"));
    let decrypted = secrets.open(&env).unwrap_or_else(|e| panic!("open: {e}"));
    assert_eq!(decrypted, plaintext);
}

#[test]
fn secrets_open_rejects_tampered() {
    let secrets = Secrets::from_key(Box::new(TEST_KEY));
    let mut env = secrets
        .seal(b"plaintext")
        .unwrap_or_else(|e| panic!("seal: {e}"));
    let mut bytes = BASE64_STANDARD
        .decode(&env.ciphertext)
        .unwrap_or_else(|e| panic!("decode: {e}"));
    bytes[0] ^= 0x01;
    env.ciphertext = BASE64_STANDARD.encode(&bytes);
    let result = secrets.open(&env);
    assert!(matches!(result, Err(IdentityError::IntegrityError)));
}

#[test]
fn envelope_forward_compat_v0_2_kms_placeholder() {
    // Round-trip an envelope JSON that carries the future KMS layer's key_id.
    // The shim must:
    //   - deserialise the JSON cleanly (wire shape is forward-compatible),
    //   - return UnknownKeyId when v0.1 tries to open it (the documented
    //     routing point for the KMS layer's KMS provider).
    let secrets = Secrets::from_key(Box::new(TEST_KEY));
    let mut env = secrets
        .seal(b"plaintext")
        .unwrap_or_else(|e| panic!("seal: {e}"));
    env.key_id = "v0.2-kms-rotation-1".into();
    let json = serde_json::to_string(&env).unwrap_or_else(|e| panic!("serialise: {e}"));
    let parsed: Envelope =
        serde_json::from_str(&json).unwrap_or_else(|e| panic!("deserialise: {e}"));
    assert_eq!(parsed.key_id, "v0.2-kms-rotation-1");
    let result = secrets.open(&parsed);
    match result {
        Err(IdentityError::UnknownKeyId(id)) => assert_eq!(id, "v0.2-kms-rotation-1"),
        other => panic!("expected UnknownKeyId, got {other:?}"),
    }
}

#[test]
fn config_missing_secrets_key() {
    Jail::expect_with(|jail| {
        // figment's `Jail` does not clear pre-existing env vars on entry —
        // only those set via `set_env` are restored on drop. A developer
        // running with `direnv` / `.envrc` would otherwise see this test
        // fail because `ZAGROSI_SECRETS_KEY` is already exported.
        jail.clear_env();
        let result = IdentityConfig::load(LoadOptions {
            env_prefix: "ZAGROSI_",
            file_path: None,
        });
        match result {
            Err(IdentityError::MissingSecretsKey) => Ok(()),
            other => Err(figment::Error::from(format!(
                "expected MissingSecretsKey, got {other:?}"
            ))),
        }
    });
}

#[test]
fn config_malformed_secrets_key_non_base64() {
    Jail::expect_with(|jail| {
        jail.clear_env();
        jail.set_env("ZAGROSI_SECRETS_KEY", "!!!not-base64!!!");
        jail.set_env("ZAGROSI_VALKEY_URL", "redis://valkey:6379");
        let result = IdentityConfig::load(LoadOptions {
            env_prefix: "ZAGROSI_",
            file_path: None,
        });
        match result {
            Err(IdentityError::MalformedSecretsKey { reason }) => {
                assert!(
                    reason.contains("base64"),
                    "reason mentions base64: {reason}"
                );
                Ok(())
            }
            other => Err(figment::Error::from(format!(
                "expected MalformedSecretsKey, got {other:?}"
            ))),
        }
    });
}

#[test]
fn config_malformed_secrets_key_wrong_length() {
    Jail::expect_with(|jail| {
        jail.clear_env();
        // 16 zero bytes encoded as base64 — valid base64, wrong length.
        jail.set_env("ZAGROSI_SECRETS_KEY", "AAAAAAAAAAAAAAAAAAAAAA==");
        jail.set_env("ZAGROSI_VALKEY_URL", "redis://valkey:6379");
        let result = IdentityConfig::load(LoadOptions {
            env_prefix: "ZAGROSI_",
            file_path: None,
        });
        match result {
            Err(IdentityError::MalformedSecretsKey { reason }) => {
                assert!(
                    reason.contains("16 bytes"),
                    "reason mentions actual length: {reason}"
                );
                Ok(())
            }
            other => Err(figment::Error::from(format!(
                "expected MalformedSecretsKey, got {other:?}"
            ))),
        }
    });
}

#[test]
fn config_secrets_key_round_trips_via_secrets_from_config() {
    Jail::expect_with(|jail| {
        jail.clear_env();
        jail.set_env("ZAGROSI_SECRETS_KEY", ZERO_KEY_B64);
        jail.set_env("ZAGROSI_VALKEY_URL", "redis://valkey:6379");
        let mut cfg = IdentityConfig::load(LoadOptions {
            env_prefix: "ZAGROSI_",
            file_path: None,
        })
        .map_err(|e| figment::Error::from(e.to_string()))?;
        let secrets =
            Secrets::from_config(&mut cfg).map_err(|e| figment::Error::from(e.to_string()))?;
        let env = secrets
            .seal(b"end-to-end")
            .map_err(|e| figment::Error::from(e.to_string()))?;
        assert_eq!(env.key_id, KEY_ID_V0_1_STATIC);
        let decrypted = secrets
            .open(&env)
            .map_err(|e| figment::Error::from(e.to_string()))?;
        assert_eq!(decrypted, b"end-to-end");
        Ok(())
    });
}

#[test]
fn default_identity_config_secrets_key_returns_missing() {
    let cfg = IdentityConfig::default();
    match cfg.secrets_key() {
        Err(IdentityError::MissingSecretsKey) => {}
        other => panic!("expected MissingSecretsKey from Default config, got {other:?}"),
    }
}
