// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! Sealed callback cookie carrying raw CSRF / nonce / PKCE verifier.
//!
//! ## Why a cookie carries the secrets, not the database
//!
//! Section-03's `oidc_pending_auth` migration stores SHA-256 hashes only —
//! `state_hash`, `nonce_hash`, `verifier_hash`, and `csrf_cookie_hash`.
//! The raw values never reach the database. That keeps a database
//! compromise from leaking in-flight OIDC verifiers / nonces / CSRF
//! tokens, but it also means the OIDC callback handler cannot recover
//! the raw values from Postgres alone.
//!
//! The handler still needs raw values for two security-critical
//! operations:
//!
//! 1. The PKCE token-exchange (`set_pkce_verifier`) which sends the
//!    raw verifier upstream.
//! 2. The ID-token nonce check inside `openidconnect`'s
//!    `IdToken::claims(&verifier, &nonce)` call.
//!
//! Solution: the start handler attaches a single signed cookie
//! (`__Host-zagrosi_oidc`) whose payload is an AES-256-GCM-sealed
//! [`CallbackPayload`]. The cookie carries raw `csrf` / `nonce` /
//! `pkce_verifier` between the redirect and the callback. On the
//! callback the handler opens the envelope, hashes each field, and
//! constant-time-compares against the row's `*_hash` columns. Tampering
//! breaks both the AEAD tag (envelope refuses to open) and the per-field
//! hash (mismatched bytes); both surface as `OidcStateMismatch`.
//!
//! ## Threat model
//!
//! - **DB compromise alone:** attacker reads only hashes; cannot replay
//!   the OIDC callback because they cannot mint a matching cookie
//!   without the AEAD key.
//! - **Cookie theft:** attacker steals the cookie before the callback
//!   completes; this is equivalent to today's session-cookie theft (the
//!   `__Host-` prefix already enforces `Secure` + same-origin), but the
//!   pending row is single-use so the attack window is the 10-minute
//!   `expires_at`.
//! - **DB compromise + cookie theft:** attacker has both; the row's
//!   `used_at` flip in step 6 of the callback collapses the race window.
//!
//! ## Wire format
//!
//! Cookie value is base64url-no-pad of the JSON-serialised
//! [`crate::crypto::Envelope`]. The envelope is reused unchanged from
//! the secrets shim (the KMS layer's KMS rewrap path covers this cookie too).
//! Inner plaintext is the JSON-serialised [`CallbackPayload`] struct.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::{Envelope, Secrets};
use crate::error::{IdentityError, Result};

/// HTTP cookie name used by the start handler / callback handler.
///
/// `__Host-` prefix forbids any `Domain` attribute and forces
/// `Secure` + `Path=/`, which closes the cross-subdomain attack
/// surface that a session-fixation forgery would otherwise rely on.
pub const COOKIE_NAME: &str = "__Host-zagrosi_oidc";

/// Number of bytes minted by the start handler for the CSRF and
/// nonce values. 32 bytes → 256 bits of entropy each. Section-08 uses
/// the same budget for its CSRF cookie.
pub const RANDOM_BYTES: usize = 32;

/// PKCE code-verifier RFC 7636 §4.1 minimum length. We always mint at
/// the maximum length so timing-side-channel observers cannot
/// distinguish runs.
pub const PKCE_VERIFIER_LEN: usize = 128;

/// Plaintext payload sealed inside [`COOKIE_NAME`].
///
/// Every field is a base64url-no-pad string so the inner JSON stays
/// ASCII-only and the seal output stays cookie-safe after a second
/// base64 pass. `csrf` / `nonce` are the raw 32-byte randoms; `verifier`
/// is the 128-char PKCE code verifier (URL-safe charset by construction).
/// The Debug impl redacts every field so a stray `tracing::debug!(?payload)`
/// cannot leak PKCE / nonce material into log surfaces.
///
/// `Zeroize` + `ZeroizeOnDrop` derives ensure the raw csrf / nonce /
/// verifier heap buffers are scrubbed when the payload drops at the
/// end of the start handler (post-seal) and the callback handler
/// (post-cookie-open). Without the wrappers, plaintext PKCE + nonce
/// material lingers in heap memory until allocator reuse — the same
/// hardening discipline the saml issuer applies to its raw session
/// token + CSRF value.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct CallbackPayload {
    /// Raw CSRF value. Hash compared against `oidc_pending_auth.csrf_cookie_hash`.
    pub csrf: String,
    /// Raw OIDC `nonce` value. Hash compared against `oidc_pending_auth.nonce_hash`;
    /// raw value passed to `openidconnect::IdToken::claims(verifier, &Nonce)`.
    pub nonce: String,
    /// Raw PKCE code verifier. Hash compared against `oidc_pending_auth.verifier_hash`;
    /// raw value passed to `set_pkce_verifier(PkceCodeVerifier::new(verifier))`.
    pub verifier: String,
}

impl std::fmt::Debug for CallbackPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CallbackPayload")
            .field("csrf", &"<redacted>")
            .field("nonce", &"<redacted>")
            .field("verifier_len", &self.verifier.len())
            .finish()
    }
}

impl CallbackPayload {
    /// Mint a fresh payload using `OsRng`. Each field draws from a
    /// distinct entropy budget; the start handler stores hashes of
    /// each value on the pending row.
    #[must_use]
    pub fn new_random() -> Self {
        Self {
            csrf: random_b64url(RANDOM_BYTES),
            nonce: random_b64url(RANDOM_BYTES),
            verifier: random_b64url(PKCE_VERIFIER_LEN * 3 / 4 + 1)
                .chars()
                .take(PKCE_VERIFIER_LEN)
                .collect(),
        }
    }

    /// SHA-256 of the raw `csrf` value, used to seed the pending row's
    /// `csrf_cookie_hash` column.
    #[must_use]
    pub fn csrf_hash(&self) -> [u8; 32] {
        sha256(self.csrf.as_bytes())
    }

    /// SHA-256 of the raw nonce, used to seed the pending row's
    /// `nonce_hash` column.
    #[must_use]
    pub fn nonce_hash(&self) -> [u8; 32] {
        sha256(self.nonce.as_bytes())
    }

    /// SHA-256 of the raw PKCE verifier, used to seed the pending row's
    /// `verifier_hash` column.
    #[must_use]
    pub fn verifier_hash(&self) -> [u8; 32] {
        sha256(self.verifier.as_bytes())
    }
}

/// Mint a base64url-no-pad string of `byte_count` random bytes.
///
/// Used for the raw CSRF / nonce values; the PKCE verifier construction
/// in [`CallbackPayload::new_random`] also uses this and then truncates
/// to the RFC 7636 verifier length.
#[must_use]
pub fn random_b64url(byte_count: usize) -> String {
    let mut bytes = vec![0_u8; byte_count];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Compute SHA-256 of `bytes` as a fixed-size array. Stable shape for
/// constant-time comparisons against `[u8; 32]` columns.
#[must_use]
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

/// Seal a [`CallbackPayload`] into the cookie value (base64url-no-pad
/// of the JSON-serialised [`Envelope`]).
///
/// # Errors
///
/// - [`IdentityError::IntegrityError`] when the AES-GCM primitive
///   refuses to seal (practically unreachable).
/// - [`IdentityError::Database`] is not produced — the surface is pure
///   crypto.
pub fn seal(secrets: &Secrets, payload: &CallbackPayload) -> Result<String> {
    let plaintext = serde_json::to_vec(payload)
        .map_err(|_| IdentityError::OidcCookieMalformed("serialise payload"))?;
    let envelope = secrets.seal(&plaintext)?;
    let envelope_json = serde_json::to_vec(&envelope)
        .map_err(|_| IdentityError::OidcCookieMalformed("serialise envelope"))?;
    Ok(URL_SAFE_NO_PAD.encode(envelope_json))
}

/// Open a cookie value (base64url-no-pad of [`Envelope`] JSON) into
/// the inner [`CallbackPayload`].
///
/// # Errors
///
/// - [`IdentityError::OidcCookieMalformed`] when the cookie is not
///   valid base64url, the inner JSON is not a valid [`Envelope`], the
///   envelope opens but the inner JSON is not a valid
///   [`CallbackPayload`], or any wire-format / length invariant is
///   violated.
/// - [`IdentityError::IntegrityError`] when the AEAD authentication
///   check fails (tampered cookie value).
/// - [`IdentityError::UnknownKeyId`] when the envelope's `key_id` is
///   unknown to this provider — the future KMS layer's KMS provider routes on
///   this signal.
pub fn open(secrets: &Secrets, cookie_value: &str) -> Result<CallbackPayload> {
    let envelope_json = URL_SAFE_NO_PAD
        .decode(cookie_value.as_bytes())
        .map_err(|_| IdentityError::OidcCookieMalformed("cookie not base64url"))?;
    let envelope: Envelope = serde_json::from_slice(&envelope_json)
        .map_err(|_| IdentityError::OidcCookieMalformed("cookie envelope JSON malformed"))?;
    let plaintext = secrets.open(&envelope)?;
    let payload: CallbackPayload = serde_json::from_slice(&plaintext)
        .map_err(|_| IdentityError::OidcCookieMalformed("payload JSON malformed"))?;
    if payload.csrf.is_empty() || payload.nonce.is_empty() || payload.verifier.is_empty() {
        return Err(IdentityError::OidcCookieMalformed("payload field empty"));
    }
    if payload.verifier.len() < 43 || payload.verifier.len() > 128 {
        // RFC 7636 §4.1: code_verifier length [43, 128].
        return Err(IdentityError::OidcCookieMalformed(
            "verifier length out of RFC 7636 range",
        ));
    }
    Ok(payload)
}

/// Render the `Set-Cookie` header value for [`COOKIE_NAME`] sealed
/// against `secrets`. The cookie is marked `Secure; HttpOnly;
/// SameSite=Lax; Path=/` and carries `Max-Age` = the supplied
/// `pending_ttl_seconds`. The `__Host-` prefix forbids `Domain`.
///
/// # Errors
///
/// Propagates [`seal`]'s error variants.
pub fn build_set_cookie_header(
    secrets: &Secrets,
    payload: &CallbackPayload,
    pending_ttl_seconds: u32,
) -> Result<String> {
    let value = seal(secrets, payload)?;
    Ok(format!(
        "{COOKIE_NAME}={value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={pending_ttl_seconds}",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_secrets() -> Secrets {
        Secrets::from_key(Box::new([0x42; 32]))
    }

    #[test]
    fn payload_random_fields_are_distinct() {
        let p = CallbackPayload::new_random();
        assert!(!p.csrf.is_empty());
        assert!(!p.nonce.is_empty());
        assert!(p.verifier.len() == PKCE_VERIFIER_LEN);
        assert_ne!(p.csrf, p.nonce);
        assert_ne!(p.csrf, p.verifier);
        assert_ne!(p.nonce, p.verifier);
    }

    #[test]
    fn payload_random_is_high_entropy() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..1_000 {
            let p = CallbackPayload::new_random();
            // `CallbackPayload` is `ZeroizeOnDrop`, so its fields cannot
            // be moved out — clone the csrf value into the set instead.
            assert!(seen.insert(p.csrf.clone()), "csrf collision under 1k draws");
        }
    }

    #[test]
    fn seal_open_round_trips() {
        let s = fixture_secrets();
        let payload = CallbackPayload::new_random();
        let cookie = seal(&s, &payload).expect("seal");
        let opened = open(&s, &cookie).expect("open");
        assert_eq!(opened, payload);
    }

    #[test]
    fn open_rejects_tampered_envelope() {
        let s = fixture_secrets();
        let payload = CallbackPayload::new_random();
        let cookie = seal(&s, &payload).expect("seal");
        let mut bytes = cookie.into_bytes();
        // Flip a single byte in the encoded envelope.
        let last = bytes.len().saturating_sub(2);
        bytes[last] ^= 0x01;
        let tampered = String::from_utf8(bytes).expect("ascii");
        let result = open(&s, &tampered);
        // Either the base64url decode breaks or the AEAD tag breaks;
        // both surface through the `Cookie` family or `IntegrityError`.
        assert!(matches!(
            result,
            Err(IdentityError::IntegrityError | IdentityError::OidcCookieMalformed(_))
        ));
    }

    #[test]
    fn open_rejects_bogus_base64() {
        let s = fixture_secrets();
        let result = open(&s, "!!!not-base64url!!!");
        assert!(matches!(
            result,
            Err(IdentityError::OidcCookieMalformed("cookie not base64url"))
        ));
    }

    #[test]
    fn open_rejects_short_verifier() {
        let s = fixture_secrets();
        let payload = CallbackPayload {
            csrf: "abcdef".into(),
            nonce: "ghijkl".into(),
            // 42 chars — below RFC 7636 minimum of 43.
            verifier: "a".repeat(42),
        };
        let cookie = seal(&s, &payload).expect("seal");
        let result = open(&s, &cookie);
        assert!(matches!(
            result,
            Err(IdentityError::OidcCookieMalformed(
                "verifier length out of RFC 7636 range"
            ))
        ));
    }

    #[test]
    fn payload_hashes_are_deterministic() {
        let payload = CallbackPayload {
            csrf: "fixed-csrf".into(),
            nonce: "fixed-nonce".into(),
            verifier: "v".repeat(64),
        };
        assert_eq!(payload.csrf_hash(), sha256(b"fixed-csrf"));
        assert_eq!(payload.nonce_hash(), sha256(b"fixed-nonce"));
        assert_eq!(payload.verifier_hash(), sha256(&[b'v'; 64]));
    }

    #[test]
    fn build_set_cookie_header_carries_required_attributes() {
        let s = fixture_secrets();
        let payload = CallbackPayload::new_random();
        let header = build_set_cookie_header(&s, &payload, 600).expect("header");
        assert!(header.starts_with(&format!("{COOKIE_NAME}=")));
        assert!(header.contains("Path=/"));
        assert!(header.contains("Secure"));
        assert!(header.contains("HttpOnly"));
        assert!(header.contains("SameSite=Lax"));
        assert!(header.contains("Max-Age=600"));
        assert!(!header.contains("Domain="));
    }

    #[test]
    fn random_b64url_length_matches_byte_count() {
        let s = random_b64url(RANDOM_BYTES);
        // 32 bytes encoded base64url-no-pad = 43 chars.
        assert_eq!(s.len(), 43);
        assert!(
            s.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        );
    }
}
