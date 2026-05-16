// SPDX-License-Identifier: AGPL-3.0-or-later

//! AES-256-GCM envelope encryption for persisted secrets.
//!
//! v0.1 wraps every stored secret under the static key sourced from
//! `ZAGROSI_SECRETS_KEY` (32-byte base64). The wire envelope
//! `{key_id, nonce, ciphertext, tag}` is forward-compatible with
//! the KMS layer's KMS-backed envelope rewrap: future `key_id` values
//! (`v0.2-kms-<rotation>`) route through the new provider, while the
//! static `v0.1-static` envelopes keep decrypting under this shim.

use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce, Tag};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use rand_core::{OsRng, RngCore};
use secrecy::{ExposeSecret, SecretBox};
use serde::{Deserialize, Serialize};

use crate::config::{IdentityConfig, SECRETS_KEY_LEN};
use crate::error::IdentityError;

/// Static `key_id` for the v0.1 single-key shim.
///
/// The KMS layer introduces additional KMS-backed `key_id` values; today the
/// shim only decrypts envelopes carrying this exact discriminator.
///
/// **Production code MUST NOT hard-code this constant for routing
/// decisions.** Use [`IdentityError::UnknownKeyId`] from
/// [`Secrets::open`] as the routing signal so the KMS layer's KMS provider
/// can claim envelopes it owns. This constant is exposed for tests +
/// rare authoring of v0.1 envelopes (e.g. seed corpora) only.
pub const KEY_ID_V0_1_STATIC: &str = "v0.1-static";

/// AES-GCM nonce length in bytes (96-bit per `RustCrypto` guidance).
pub const NONCE_LEN: usize = 12;

/// AES-GCM authentication tag length in bytes.
pub const TAG_LEN: usize = 16;

/// Wire envelope persisted to the DB.
///
/// Stored verbatim in columns like `oidc_idps.client_secret_ref` and
/// `org_idps.config.sp_signing_key`. Forward-compatible with KMS rewrap
/// because every field of the next envelope generation is also expressible
/// in this shape; only `key_id` needs to widen.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    /// Discriminator the decryption-side uses to route to the correct
    /// key provider. v0.1 always emits [`KEY_ID_V0_1_STATIC`].
    pub key_id: String,
    /// Base64-encoded 12-byte nonce. Each [`Secrets::seal`] call mints a
    /// fresh nonce via [`OsRng`]; nonce reuse under the same key is a
    /// catastrophic AES-GCM failure mode and is intentionally not
    /// reachable from the public API.
    pub nonce: String,
    /// Base64-encoded ciphertext (excludes the GCM tag).
    pub ciphertext: String,
    /// Base64-encoded 16-byte GCM authentication tag. Stored separately
    /// from `ciphertext` so envelopes are human-inspectable in the DB
    /// without losing AEAD semantics.
    pub tag: String,
}

/// AES-256-GCM secrets shim.
///
/// Construct via [`Secrets::from_key`] (caller-supplied 32-byte key) or
/// [`Secrets::from_config`] (reads `ZAGROSI_SECRETS_KEY` via
/// [`IdentityConfig`]). [`Secrets`] is `Send + Sync`; production wiring
/// shares it via `Arc` inside `IdentityState` (lands with the OIDC client).
pub struct Secrets {
    /// Master key. Wrapped in [`SecretBox`] so [`Drop`] zeroes the bytes.
    key: SecretBox<[u8; SECRETS_KEY_LEN]>,
    /// Discriminator written into every [`Envelope::key_id`].
    key_id: String,
}

impl Secrets {
    /// Build from a heap-resident 32-byte raw key, using
    /// [`KEY_ID_V0_1_STATIC`] as the envelope discriminator.
    ///
    /// Accepting `Box<[u8; 32]>` (rather than `[u8; 32]` by value) keeps
    /// the master key on the heap throughout construction — there is no
    /// stack-frame slot that ends up holding the raw bytes after
    /// [`Box::new`] is moved into [`SecretBox`]. The bytes are then
    /// zeroized by [`SecretBox`]'s `Drop` impl.
    ///
    /// Test code typically writes `Secrets::from_key(Box::new([0x42; 32]))`.
    #[must_use]
    pub fn from_key(key: Box<[u8; SECRETS_KEY_LEN]>) -> Self {
        Self {
            key: SecretBox::new(key),
            key_id: KEY_ID_V0_1_STATIC.to_owned(),
        }
    }

    /// Build from a validated [`IdentityConfig`], moving the master key
    /// out of the config without producing an intermediate stack copy.
    ///
    /// The config's `decoded_secrets_key` field is left as `None` after
    /// the call returns; subsequent `cfg.secrets_key()` calls would
    /// surface [`IdentityError::MissingSecretsKey`]. Callers that need
    /// to build multiple `Secrets` from one config should `Arc<Secrets>`
    /// after the first construction.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::MissingSecretsKey`] when the config was
    /// not constructed via [`IdentityConfig::load`] (i.e. the decoded
    /// master key has not been populated).
    pub fn from_config(cfg: &mut IdentityConfig) -> Result<Self, IdentityError> {
        let boxed = cfg.take_secrets_key()?;
        Ok(Self::from_key(boxed))
    }

    /// AEAD-seal a plaintext, returning the wire [`Envelope`] ready to
    /// persist. Generates a fresh 96-bit nonce per call via [`OsRng`].
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::IntegrityError`] when the underlying AEAD
    /// primitive fails to produce a tag (`RustCrypto`'s `aes-gcm` documents
    /// this as practically unreachable on supported architectures, but
    /// the error is surfaced typed rather than via panic to satisfy the
    /// workspace `unwrap_used = deny` lint).
    pub fn seal(&self, plaintext: &[u8]) -> Result<Envelope, IdentityError> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(self.key.expose_secret()));
        let mut nonce_bytes = [0_u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let mut buffer = plaintext.to_vec();
        let tag = cipher
            .encrypt_in_place_detached(nonce, &[], &mut buffer)
            .map_err(|_| IdentityError::IntegrityError)?;
        Ok(Envelope {
            key_id: self.key_id.clone(),
            nonce: BASE64_STANDARD.encode(nonce_bytes),
            ciphertext: BASE64_STANDARD.encode(&buffer),
            tag: BASE64_STANDARD.encode(tag.as_slice()),
        })
    }

    /// AEAD-open an envelope, returning plaintext bytes.
    ///
    /// # Errors
    ///
    /// - [`IdentityError::UnknownKeyId`] when `env.key_id` is anything
    ///   other than this provider's configured `key_id`. The KMS layer routes
    ///   on this error so its KMS provider can claim the envelope.
    /// - [`IdentityError::MalformedEnvelope`] when one of the base64
    ///   fields fails to decode or has the wrong byte length.
    /// - [`IdentityError::IntegrityError`] when the AEAD authentication
    ///   check fails. Constant-time: never disclose which check failed.
    pub fn open(&self, env: &Envelope) -> Result<Vec<u8>, IdentityError> {
        if env.key_id != self.key_id {
            return Err(IdentityError::UnknownKeyId(env.key_id.clone()));
        }
        let nonce_bytes = BASE64_STANDARD
            .decode(&env.nonce)
            .map_err(|_| IdentityError::MalformedEnvelope("nonce: not valid base64"))?;
        if nonce_bytes.len() != NONCE_LEN {
            return Err(IdentityError::MalformedEnvelope("nonce: wrong byte length"));
        }
        let tag_bytes = BASE64_STANDARD
            .decode(&env.tag)
            .map_err(|_| IdentityError::MalformedEnvelope("tag: not valid base64"))?;
        if tag_bytes.len() != TAG_LEN {
            return Err(IdentityError::MalformedEnvelope("tag: wrong byte length"));
        }
        let mut buffer = BASE64_STANDARD
            .decode(&env.ciphertext)
            .map_err(|_| IdentityError::MalformedEnvelope("ciphertext: not valid base64"))?;
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(self.key.expose_secret()));
        let nonce = Nonce::from_slice(&nonce_bytes);
        let tag = Tag::from_slice(&tag_bytes);
        cipher
            .decrypt_in_place_detached(nonce, &[], &mut buffer, tag)
            .map_err(|_| IdentityError::IntegrityError)?;
        Ok(buffer)
    }
}

impl std::fmt::Debug for Secrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Secrets")
            .field("key_id", &self.key_id)
            .field("key", &"<redacted>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use static_assertions::assert_impl_all;

    assert_impl_all!(Secrets: Send, Sync);
    assert_impl_all!(Envelope: Send, Sync, Clone, std::fmt::Debug);

    /// Fixed 32-byte test key. Never used outside `#[cfg(test)]`.
    const TEST_KEY: [u8; SECRETS_KEY_LEN] = [0x42; SECRETS_KEY_LEN];

    #[test]
    fn seal_open_roundtrip() {
        let secrets = Secrets::from_key(Box::new(TEST_KEY));
        let plaintext = b"top-secret plaintext";
        let envelope = secrets
            .seal(plaintext)
            .unwrap_or_else(|e| panic!("seal: {e}"));
        let decrypted = secrets
            .open(&envelope)
            .unwrap_or_else(|e| panic!("open: {e}"));
        assert_eq!(decrypted, plaintext);
        assert_eq!(envelope.key_id, KEY_ID_V0_1_STATIC);
    }

    #[test]
    fn seal_open_empty_plaintext() {
        let secrets = Secrets::from_key(Box::new(TEST_KEY));
        let envelope = secrets.seal(&[]).unwrap_or_else(|e| panic!("seal: {e}"));
        let decrypted = secrets
            .open(&envelope)
            .unwrap_or_else(|e| panic!("open: {e}"));
        assert!(decrypted.is_empty());
    }

    #[test]
    fn seal_uses_unique_nonce_per_call() {
        let secrets = Secrets::from_key(Box::new(TEST_KEY));
        let plaintext = b"identical plaintext";
        let env_a = secrets
            .seal(plaintext)
            .unwrap_or_else(|e| panic!("seal a: {e}"));
        let env_b = secrets
            .seal(plaintext)
            .unwrap_or_else(|e| panic!("seal b: {e}"));
        assert_ne!(env_a.nonce, env_b.nonce, "nonces must be unique per call");
        assert_ne!(
            env_a.ciphertext, env_b.ciphertext,
            "fresh nonce must produce different ciphertext"
        );
    }

    #[test]
    fn open_rejects_tampered_ciphertext() {
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
    fn open_rejects_tampered_tag() {
        let secrets = Secrets::from_key(Box::new(TEST_KEY));
        let mut env = secrets
            .seal(b"plaintext")
            .unwrap_or_else(|e| panic!("seal: {e}"));
        let mut tag = BASE64_STANDARD
            .decode(&env.tag)
            .unwrap_or_else(|e| panic!("decode: {e}"));
        tag[0] ^= 0x01;
        env.tag = BASE64_STANDARD.encode(&tag);
        let result = secrets.open(&env);
        assert!(matches!(result, Err(IdentityError::IntegrityError)));
    }

    #[test]
    fn open_rejects_tampered_nonce() {
        let secrets = Secrets::from_key(Box::new(TEST_KEY));
        let mut env = secrets
            .seal(b"plaintext")
            .unwrap_or_else(|e| panic!("seal: {e}"));
        let mut nonce = BASE64_STANDARD
            .decode(&env.nonce)
            .unwrap_or_else(|e| panic!("decode: {e}"));
        nonce[0] ^= 0x01;
        env.nonce = BASE64_STANDARD.encode(&nonce);
        let result = secrets.open(&env);
        assert!(matches!(result, Err(IdentityError::IntegrityError)));
    }

    #[test]
    fn envelope_wire_format_stable() {
        let secrets = Secrets::from_key(Box::new(TEST_KEY));
        let env = secrets.seal(b"x").unwrap_or_else(|e| panic!("seal: {e}"));
        let json: serde_json::Value =
            serde_json::to_value(&env).unwrap_or_else(|e| panic!("serialise: {e}"));
        let object = json
            .as_object()
            .unwrap_or_else(|| panic!("envelope must serialise to object"));
        let keys: std::collections::BTreeSet<_> = object.keys().map(String::as_str).collect();
        let expected: std::collections::BTreeSet<_> = ["key_id", "nonce", "ciphertext", "tag"]
            .into_iter()
            .collect();
        assert_eq!(keys, expected, "envelope wire keys must not drift");
    }

    #[test]
    fn open_unknown_key_id_returns_unknown_key_id() {
        let secrets = Secrets::from_key(Box::new(TEST_KEY));
        let mut env = secrets
            .seal(b"plaintext")
            .unwrap_or_else(|e| panic!("seal: {e}"));
        env.key_id = "v0.2-kms-rotation-1".into();
        let result = secrets.open(&env);
        match result {
            Err(IdentityError::UnknownKeyId(id)) => assert_eq!(id, "v0.2-kms-rotation-1"),
            other => panic!("expected UnknownKeyId, got {other:?}"),
        }
    }

    #[test]
    fn open_rejects_non_base64_nonce() {
        let secrets = Secrets::from_key(Box::new(TEST_KEY));
        let mut env = secrets.seal(b"x").unwrap_or_else(|e| panic!("seal: {e}"));
        env.nonce = "!!!not-base64!!!".into();
        let result = secrets.open(&env);
        assert!(matches!(
            result,
            Err(IdentityError::MalformedEnvelope("nonce: not valid base64"))
        ));
    }

    #[test]
    fn open_rejects_non_base64_tag() {
        let secrets = Secrets::from_key(Box::new(TEST_KEY));
        let mut env = secrets.seal(b"x").unwrap_or_else(|e| panic!("seal: {e}"));
        env.tag = "!!!not-base64!!!".into();
        let result = secrets.open(&env);
        assert!(matches!(
            result,
            Err(IdentityError::MalformedEnvelope("tag: not valid base64"))
        ));
    }

    #[test]
    fn open_rejects_non_base64_ciphertext() {
        let secrets = Secrets::from_key(Box::new(TEST_KEY));
        let mut env = secrets.seal(b"x").unwrap_or_else(|e| panic!("seal: {e}"));
        env.ciphertext = "!!!not-base64!!!".into();
        let result = secrets.open(&env);
        assert!(matches!(
            result,
            Err(IdentityError::MalformedEnvelope(
                "ciphertext: not valid base64"
            ))
        ));
    }

    #[test]
    fn open_rejects_wrong_nonce_length() {
        let secrets = Secrets::from_key(Box::new(TEST_KEY));
        let mut env = secrets.seal(b"x").unwrap_or_else(|e| panic!("seal: {e}"));
        // Encode 8 zero bytes instead of 12.
        env.nonce = BASE64_STANDARD.encode([0_u8; 8]);
        let result = secrets.open(&env);
        assert!(matches!(
            result,
            Err(IdentityError::MalformedEnvelope("nonce: wrong byte length"))
        ));
    }

    #[test]
    fn open_rejects_wrong_tag_length() {
        let secrets = Secrets::from_key(Box::new(TEST_KEY));
        let mut env = secrets.seal(b"x").unwrap_or_else(|e| panic!("seal: {e}"));
        env.tag = BASE64_STANDARD.encode([0_u8; 8]);
        let result = secrets.open(&env);
        assert!(matches!(
            result,
            Err(IdentityError::MalformedEnvelope("tag: wrong byte length"))
        ));
    }

    #[test]
    fn debug_does_not_leak_key_bytes() {
        let secrets = Secrets::from_key(Box::new(TEST_KEY));
        let rendered = format!("{secrets:?}");
        assert!(rendered.contains("redacted"));
        // 0x42 == 'B' — the rendered string would contain a literal 'B'
        // ASCII run if the inner bytes were ever formatted. Spot-check
        // that the entire 32-byte run does not appear verbatim.
        let key_ascii: String = (0..SECRETS_KEY_LEN).map(|_| 'B').collect();
        assert!(!rendered.contains(&key_ascii));
    }
}
