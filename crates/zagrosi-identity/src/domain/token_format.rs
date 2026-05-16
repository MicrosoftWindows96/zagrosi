// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! Canonical token-format chokepoint for the identity crate.
//!
//! Every persisted secret token in the identity surface
//! (sessions, PATs, SCIM bearers, service tokens, password resets,
//! email verifications) is represented on the wire as
//! `<prefix><43 base64url chars>`. This module is the **single
//! source of truth** for the prefix set, the body length, the wire-
//! format parser, and the SHA-256 hash function whose digest is
//! persisted in `BYTEA token_hash` columns.
//!
//! ## Invariants
//!
//! 1. The prefix is part of the SHA-256 input. Two raw tokens that
//!    differ only by prefix (e.g. `sid_<body>` vs `pat_<body>`) hash
//!    to different digests — preventing a session token from being
//!    accepted at a PAT lookup site even if an attacker reused the
//!    body. This is asserted by the `prefix_changes_hash` test.
//! 2. The body is exactly [`TOKEN_BODY_LEN`] base64url characters;
//!    `parse_raw` rejects anything else.
//! 3. Prefix-aware parsing is the *first* gate any consumer applies
//!    to a raw bearer token, BEFORE any database lookup. This keeps
//!    obviously-malformed input from costing a round-trip.
//!
//! ## Cross-crate handover
//!
//! `zagrosi_core::TokenClass` (the cross-crate ports) carries the *gateway-facing*
//! subset of prefixes (`sid_/pat_/scim_/svc_`). The internal flow
//! tokens (`vrf_/rst_`) never reach the gateway introspector and are
//! intentionally absent from `TokenClass`. The two enums are kept
//! separate so that adding a new internal-only prefix does not force
//! a change to the cross-crate port surface; conversion is
//! one-directional via [`TokenPrefix::as_token_class`] when an
//! identity-side caller needs to bridge to the gateway port.
//!
//! ## Constant-time compare
//!
//! Repo-layer `find_by_token_hash` paths perform `WHERE token_hash = $1`
//! against a partial-unique index, which is already constant-time at
//! the storage layer. Application-layer comparisons of the resulting
//! [`TokenHash`] (e.g. inside test fixtures) MUST go through
//! [`TokenHash::ct_eq`] — re-exported from `subtle` — to defend the
//! invariant against future call sites that compare hashes outside a
//! SQL predicate.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand_core::{OsRng, RngCore as _};
use sha2::Digest as _;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zagrosi_core::TokenClass;

use crate::error::IdentityError;

/// Body length in characters for every raw token (`sid_<43>`, `pat_<43>`,
/// `scim_<43>`, `svc_<43>`, `vrf_<43>`, `rst_<43>`). 43 base64url chars
/// encode 32 bytes via the standard length formula `ceil(32 * 4 / 3)`
/// minus the `=` padding character that base64url omits.
pub const TOKEN_BODY_LEN: usize = 43;

/// Number of random bytes drawn from the OS RNG per [`mint`] call.
/// 32 bytes is 256 bits of entropy, well above the 128-bit floor the
/// project plan asserts for state / nonce values.
pub const TOKEN_RANDOM_BYTES: usize = 32;

/// SHA-256 digest length in bytes. Re-exported as a named constant so
/// repo layers can declare `[u8; HASH_LEN]` without a magic number.
pub const HASH_LEN: usize = 32;

/// Token class prefix.
///
/// Identity-internal flow tokens (`vrf_`, `rst_`) join the four
/// gateway-facing prefixes from `zagrosi_core::TokenClass`. The
/// numeric ordering of the variants is documented as stable ONLY
/// within this enum; downstream code MUST match exhaustively rather
/// than relying on a discriminant order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TokenPrefix {
    /// `sid_` — browser session cookie or bearer.
    Session,
    /// `pat_` — personal access token.
    Pat,
    /// `scim_` — SCIM 2.0 bearer.
    Scim,
    /// `svc_` — internal service-to-service token.
    Service,
    /// `vrf_` — single-use email-verification token.
    Verification,
    /// `rst_` — single-use password-reset token.
    Reset,
}

impl TokenPrefix {
    /// Prefix string as it appears on the wire (trailing underscore
    /// included). The returned string is always in the form `xxx_`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Session => "sid_",
            Self::Pat => "pat_",
            Self::Scim => "scim_",
            Self::Service => "svc_",
            Self::Verification => "vrf_",
            Self::Reset => "rst_",
        }
    }

    /// Match a raw prefix string back to a [`TokenPrefix`].
    ///
    /// Accepts only exact matches against the five-character forms
    /// (`scim_` is the only five-char prefix; the rest are four). Used
    /// internally by [`parse_raw`].
    #[must_use]
    pub fn from_prefix_str(prefix: &str) -> Option<Self> {
        match prefix {
            "sid_" => Some(Self::Session),
            "pat_" => Some(Self::Pat),
            "scim_" => Some(Self::Scim),
            "svc_" => Some(Self::Service),
            "vrf_" => Some(Self::Verification),
            "rst_" => Some(Self::Reset),
            _ => None,
        }
    }

    /// Convert this internal prefix into the gateway-facing
    /// `zagrosi_core::TokenClass`. Returns `None` for the
    /// identity-internal prefixes (`Verification`, `Reset`) which
    /// never reach the gateway introspector.
    #[must_use]
    pub const fn as_token_class(self) -> Option<TokenClass> {
        match self {
            Self::Session => Some(TokenClass::Session),
            Self::Pat => Some(TokenClass::PersonalAccessToken),
            Self::Scim => Some(TokenClass::Scim),
            Self::Service => Some(TokenClass::Service),
            Self::Verification | Self::Reset => None,
        }
    }
}

/// SHA-256 digest of a raw token. Carrier type for
/// `BYTEA token_hash` column reads / writes.
///
/// Wraps `[u8; HASH_LEN]` to give the type system a hook for
/// constant-time comparison via [`ConstantTimeEq`] and to make
/// the sqlx `BYTEA` round-trip explicit at the repo boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TokenHash(pub [u8; HASH_LEN]);

impl TokenHash {
    /// Borrow the raw digest as a byte slice for sqlx `BYTEA` binds.
    #[must_use]
    pub const fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Constant-time equality. Repo layers prefer SQL predicates
    /// (`WHERE token_hash = $1`) which are already storage-engine
    /// constant-time; this helper is reserved for non-DB call sites
    /// (test fixtures, future in-memory caches).
    #[must_use]
    pub fn ct_eq(&self, other: &Self) -> bool {
        bool::from(ConstantTimeEq::ct_eq(&self.0[..], &other.0[..]))
    }
}

impl From<[u8; HASH_LEN]> for TokenHash {
    fn from(bytes: [u8; HASH_LEN]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for TokenHash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Parse a raw token string into `(prefix, body)`.
///
/// Validation rejects:
/// - any prefix outside the documented six-prefix set
/// - body length other than [`TOKEN_BODY_LEN`]
/// - any byte outside the base64url alphabet (`A-Z`, `a-z`, `0-9`,
///   `-`, `_`)
///
/// # Errors
///
/// Returns [`IdentityError::MalformedToken`] with a `&'static str`
/// reason that callers MUST NOT surface verbatim into log lines that
/// land in user-visible error pages — the reason is a routing aid for
/// internal logs only.
pub fn parse_raw(raw: &str) -> Result<(TokenPrefix, &str), IdentityError> {
    let underscore = raw
        .find('_')
        .ok_or(IdentityError::MalformedToken("missing prefix delimiter"))?;
    let prefix_end = underscore
        .checked_add(1)
        .ok_or(IdentityError::MalformedToken("prefix length overflow"))?;
    let prefix_str = raw
        .get(..prefix_end)
        .ok_or(IdentityError::MalformedToken("prefix slice failed"))?;
    let prefix = TokenPrefix::from_prefix_str(prefix_str)
        .ok_or(IdentityError::MalformedToken("unknown prefix"))?;
    let body = raw
        .get(prefix_end..)
        .ok_or(IdentityError::MalformedToken("missing body"))?;
    if body.len() != TOKEN_BODY_LEN {
        return Err(IdentityError::MalformedToken("body length is not 43"));
    }
    if !body
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(IdentityError::MalformedToken("body contains non-base64url"));
    }
    Ok((prefix, body))
}

/// SHA-256 over the entire raw token (prefix + body included).
///
/// Hashing the prefix is part of the [crate-level invariant](self):
/// `sid_<body>` and `pat_<body>` MUST hash to different digests so
/// that a session token can never be accepted at a PAT lookup site
/// (and vice versa) even if an attacker reuses the body. This
/// behaviour is asserted by `prefix_changes_hash` below.
#[must_use]
pub fn hash_token(raw: &str) -> TokenHash {
    let mut hasher = Sha256::new();
    hasher.update(raw.as_bytes());
    let digest = hasher.finalize();
    let mut out = [0_u8; HASH_LEN];
    out.copy_from_slice(&digest);
    TokenHash(out)
}

/// Mint a fresh token of the given class.
///
/// Reads [`TOKEN_RANDOM_BYTES`] (32) bytes from the OS RNG,
/// base64url-encodes (no padding, [`TOKEN_BODY_LEN`] = 43 chars),
/// and prepends the prefix. Returns the raw token string —
/// `mint` is the **only** sanctioned mint path; callers that need
/// the digest should hash the returned value via [`hash_token`].
#[must_use]
pub fn mint(prefix: TokenPrefix) -> String {
    let mut bytes = [0_u8; TOKEN_RANDOM_BYTES];
    OsRng.fill_bytes(&mut bytes);
    let body = URL_SAFE_NO_PAD.encode(bytes);
    debug_assert_eq!(body.len(), TOKEN_BODY_LEN);
    let mut out = String::with_capacity(prefix.as_str().len() + body.len());
    out.push_str(prefix.as_str());
    out.push_str(&body);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use static_assertions::assert_impl_all;
    use std::collections::HashSet;

    assert_impl_all!(TokenPrefix: Send, Sync, Copy);
    assert_impl_all!(TokenHash: Send, Sync, Copy);

    #[test]
    fn parse_raw_accepts_session_token() {
        let raw = mint(TokenPrefix::Session);
        let (prefix, body) = parse_raw(&raw).expect("session parse");
        assert_eq!(prefix, TokenPrefix::Session);
        assert_eq!(body.len(), TOKEN_BODY_LEN);
    }

    #[test]
    fn parse_raw_accepts_all_six_prefixes() {
        for prefix in [
            TokenPrefix::Session,
            TokenPrefix::Pat,
            TokenPrefix::Scim,
            TokenPrefix::Service,
            TokenPrefix::Verification,
            TokenPrefix::Reset,
        ] {
            let raw = mint(prefix);
            let (parsed, _) = parse_raw(&raw).expect("parse");
            assert_eq!(parsed, prefix);
        }
    }

    #[test]
    fn parse_raw_rejects_unknown_prefix() {
        assert!(matches!(
            parse_raw("abc_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            Err(IdentityError::MalformedToken(_))
        ));
    }

    #[test]
    fn parse_raw_rejects_missing_underscore() {
        assert!(matches!(
            parse_raw("sidaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            Err(IdentityError::MalformedToken(_))
        ));
    }

    #[test]
    fn parse_raw_rejects_short_body() {
        assert!(matches!(
            parse_raw("sid_short"),
            Err(IdentityError::MalformedToken(_))
        ));
    }

    #[test]
    fn parse_raw_rejects_long_body() {
        // 44 char body
        let body = "a".repeat(TOKEN_BODY_LEN + 1);
        let raw = format!("sid_{body}");
        assert!(matches!(
            parse_raw(&raw),
            Err(IdentityError::MalformedToken(_))
        ));
    }

    #[test]
    fn parse_raw_rejects_non_base64url() {
        let body_with_plus: String = "a".repeat(TOKEN_BODY_LEN - 1) + "+";
        let raw = format!("sid_{body_with_plus}");
        assert!(matches!(
            parse_raw(&raw),
            Err(IdentityError::MalformedToken(_))
        ));
    }

    #[test]
    fn prefix_changes_hash() {
        let body = "a".repeat(TOKEN_BODY_LEN);
        let h1 = hash_token(&format!("sid_{body}"));
        let h2 = hash_token(&format!("pat_{body}"));
        assert_ne!(h1, h2, "prefix MUST be part of hash input");
    }

    #[test]
    fn mint_session_starts_with_prefix() {
        let raw = mint(TokenPrefix::Session);
        assert!(raw.starts_with("sid_"));
        assert_eq!(raw.len(), 4 + TOKEN_BODY_LEN);
    }

    #[test]
    fn mint_scim_includes_five_char_prefix() {
        let raw = mint(TokenPrefix::Scim);
        assert!(raw.starts_with("scim_"));
        assert_eq!(raw.len(), 5 + TOKEN_BODY_LEN);
    }

    #[test]
    fn mint_emits_unique_tokens() {
        let mut seen: HashSet<String> = HashSet::with_capacity(1000);
        for _ in 0..1000 {
            let token = mint(TokenPrefix::Session);
            assert!(seen.insert(token), "mint produced collision");
        }
    }

    #[test]
    fn token_class_bridge_for_gateway_prefixes() {
        assert_eq!(
            TokenPrefix::Session.as_token_class(),
            Some(TokenClass::Session)
        );
        assert_eq!(
            TokenPrefix::Pat.as_token_class(),
            Some(TokenClass::PersonalAccessToken)
        );
        assert_eq!(TokenPrefix::Scim.as_token_class(), Some(TokenClass::Scim));
        assert_eq!(
            TokenPrefix::Service.as_token_class(),
            Some(TokenClass::Service)
        );
    }

    #[test]
    fn token_class_bridge_blocks_internal_prefixes() {
        assert_eq!(TokenPrefix::Verification.as_token_class(), None);
        assert_eq!(TokenPrefix::Reset.as_token_class(), None);
    }

    #[test]
    fn token_hash_ct_eq_matches() {
        let hash = hash_token("sid_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let same = hash_token("sid_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let diff = hash_token("sid_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        assert!(hash.ct_eq(&same));
        assert!(!hash.ct_eq(&diff));
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1000))]

        #[test]
        fn parse_raw_rejects_arbitrary_wrong_lengths(
            len in 0_usize..200_usize,
            body_seed in any::<u64>(),
        ) {
            prop_assume!(len != TOKEN_BODY_LEN);
            let body: String = (0..len)
                .map(|i| {
                    let alphabet = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_";
                    let idx = usize::try_from(body_seed.wrapping_add(i as u64) % alphabet.len() as u64).unwrap_or(0);
                    alphabet[idx] as char
                })
                .collect();
            let raw = format!("sid_{body}");
            prop_assert!(parse_raw(&raw).is_err());
        }

        #[test]
        fn prefix_aware_hash_collision_resistant(seed in any::<u64>()) {
            // Build a body deterministically so the prefix delta is the only differentiator.
            let body: String = (0..TOKEN_BODY_LEN)
                .map(|i| {
                    let alphabet = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_";
                    let idx = usize::try_from(seed.wrapping_add(i as u64) % alphabet.len() as u64).unwrap_or(0);
                    alphabet[idx] as char
                })
                .collect();
            let h_sid = hash_token(&format!("sid_{body}"));
            let h_pat = hash_token(&format!("pat_{body}"));
            let h_scim = hash_token(&format!("scim_{body}"));
            prop_assert_ne!(h_sid, h_pat);
            prop_assert_ne!(h_sid, h_scim);
            prop_assert_ne!(h_pat, h_scim);
        }
    }
}
