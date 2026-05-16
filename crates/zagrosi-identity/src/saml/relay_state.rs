// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! 256-bit `RelayState` minting + constant-time compare.
//!
//! `RelayState` is opaque to the IdP — the SP echoes it on the
//! AuthnRequest start and validates the IdP's POST against the
//! persisted row at ACS time. A signed envelope is overkill for a
//! one-shot per-org SP since the persisted row already binds the
//! state to the originating org_idp + a 10-minute TTL; the value
//! only needs unguessable entropy + collision-resistance over the
//! pending-row lifetime.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand_core::{OsRng, RngCore};
use subtle::ConstantTimeEq;

/// Number of CSPRNG bytes drawn for each `RelayState` value. 256 bits
/// → birthday collision below 2^-100 for any practical session count.
pub const RELAY_STATE_BYTES: usize = 32;

/// Mint a fresh `RelayState`. The output is base64url-encoded
/// (URL-safe, no padding) so it survives the HTTP-Redirect query
/// string and the IdP-form-POST round-trip without re-encoding.
#[must_use]
pub fn new_random() -> String {
    let mut buf = [0_u8; RELAY_STATE_BYTES];
    OsRng.fill_bytes(&mut buf);
    URL_SAFE_NO_PAD.encode(buf)
}

/// Constant-time compare of two `RelayState` values. The ACS handler
/// uses this when validating the IdP-supplied `RelayState` against
/// the persisted row's value.
#[must_use]
pub fn constant_time_eq(left: &str, right: &str) -> bool {
    left.as_bytes().ct_eq(right.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_is_unique_under_1k_draws() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..1_000 {
            let s = new_random();
            assert!(seen.insert(s), "relay-state collision under 1k draws");
        }
    }

    #[test]
    fn random_round_trips_base64url() {
        let s = new_random();
        let bytes = URL_SAFE_NO_PAD.decode(s.as_bytes()).expect("decode");
        assert_eq!(bytes.len(), RELAY_STATE_BYTES);
    }

    #[test]
    fn constant_time_eq_matches_naive_eq() {
        let a = new_random();
        let b = a.clone();
        let c = new_random();
        assert!(constant_time_eq(&a, &b));
        assert!(!constant_time_eq(&a, &c));
    }

    #[test]
    fn constant_time_eq_handles_length_mismatch() {
        // `subtle::ConstantTimeEq` requires equal-length operands; a
        // mismatched-length compare must return false rather than
        // panic.
        assert!(!constant_time_eq("short", "much-longer-value"));
    }
}
