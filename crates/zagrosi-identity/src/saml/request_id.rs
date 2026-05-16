// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! `xs:ID`-safe AuthnRequest id minting.
//!
//! samael's [`samael::service_provider::ServiceProvider::make_authentication_request`]
//! defaults to `format!("id-{}", rand::random::<u32>())` — only 32
//! bits of entropy. The pending-row correlation in the SP is part of
//! the security claim (a guessed id lets an attacker correlate to a
//! victim's start request), so we override with a 256-bit CSPRNG draw
//! rendered as a hex string with the `id-` prefix XML's `xs:ID` type
//! requires (must start with a letter or underscore; not begin with a
//! digit).

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand_core::{OsRng, RngCore};

/// Number of CSPRNG bytes drawn for each AuthnRequest id. 256 bits.
pub const REQUEST_ID_BYTES: usize = 32;

/// Mint a fresh AuthnRequest id. Format: `id-{base64url}`. The leading
/// `id-` literal satisfies `xs:ID`'s "must start with a letter or
/// underscore" constraint; base64url's character set (`[A-Za-z0-9_-]`)
/// is `xs:ID`-safe for the body.
#[must_use]
pub fn new_random() -> String {
    let mut buf = [0_u8; REQUEST_ID_BYTES];
    OsRng.fill_bytes(&mut buf);
    format!("id-{}", URL_SAFE_NO_PAD.encode(buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_starts_with_id_prefix() {
        for _ in 0..16 {
            assert!(new_random().starts_with("id-"));
        }
    }

    #[test]
    fn random_is_unique_under_1k_draws() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..1_000 {
            let s = new_random();
            assert!(seen.insert(s), "request-id collision under 1k draws");
        }
    }

    #[test]
    fn random_body_is_base64url() {
        let s = new_random();
        let body = s.strip_prefix("id-").expect("prefix");
        // base64url no-pad of 32 bytes = ceil(32 * 4 / 3) = 43 chars.
        assert_eq!(body.len(), 43, "encoded length stable");
        URL_SAFE_NO_PAD
            .decode(body.as_bytes())
            .expect("decodes back to bytes");
    }
}
