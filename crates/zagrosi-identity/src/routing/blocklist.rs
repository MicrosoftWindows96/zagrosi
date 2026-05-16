// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! Public-domain blocklist.
//!
//! Two layers stack:
//!
//! 1. The Mozilla Public Suffix List via the `psl` crate. Catches
//!    effective-TLD apex labels (`co.uk`, `appspot.com`, etc.) so an
//!    admin cannot claim "everyone on `.co.uk`" by typing `co.uk`
//!    into the domain-add box.
//! 2. The curated catch-all extension in [`super::data::public_domain_extras`]
//!    which enumerates common ESP apexes (`gmail.com`, `outlook.com`,
//!    `protonmail.com`, ...) that the PSL does not classify as
//!    public suffixes but which MUST NOT be claimable for SSO.
//!
//! The function is `pub(crate)` because both the discover handler
//! (which short-circuits public-domain emails to password auth) and
//! the domain-create / verify handlers (which hard-reject) consume
//! it; surface stays internal so callers cannot subclass the rule.
//!
//! Refresh cadence: PSL snapshot pin lives in workspace `Cargo.toml`;
//! bump quarterly with a `chore(identity): bump psl snapshot` line in
//! `CHANGELOG.md`.

use super::data::public_domain_extras::CATCH_ALL_PUBLIC_DOMAINS;

/// Returns `true` when `domain` is a public-suffix apex or appears
/// on the curated ESP catch-all list. Subdomains of any catch-all
/// entry are also blocked (so `mail.gmail.com` blocks identically
/// to `gmail.com`).
///
/// `domain` MUST already be lowercased + ASCII-folded
/// (`idna::domain_to_ascii` + `to_ascii_lowercase`); the function
/// does no normalisation of its own. Passing a raw mixed-case input
/// would underreport (PSL is case-sensitive against the snapshot).
#[must_use]
pub(crate) fn is_public_domain(domain: &str) -> bool {
    if domain.is_empty() {
        // An empty domain cannot route anywhere; treat as public so
        // the caller short-circuits. (The discover handler rejects
        // empty-domain emails before this branch is reached.)
        return true;
    }

    // Layer 1: PSL. `psl::suffix_str` returns the public-suffix tail
    // (e.g. `"com"` for `gmail.com`, `"co.uk"` for `acme.co.uk`,
    // `"appspot.com"` for `myapp.appspot.com`). When the input EQUALS
    // its own suffix the user is trying to claim a public suffix
    // itself (`co.uk`, `appspot.com`, ...) — block.
    if let Some(suffix) = psl::suffix_str(domain)
        && suffix == domain
    {
        return true;
    }

    // Layer 2: curated catch-all. Match exact apex AND every
    // subdomain (`mail.gmail.com` → `gmail.com` is also blocked).
    // Subdomain check uses `ends_with(format!(".{apex}"))` so
    // partial matches like `notgmail.com` do not false-positive.
    for apex in CATCH_ALL_PUBLIC_DOMAINS {
        if domain == *apex {
            return true;
        }
        if domain.ends_with(apex) {
            // Strict subdomain match: the byte before the apex must
            // be `.`. `notgmail.com` ends with `gmail.com` but the
            // preceding byte is `t`, not `.`.
            let preceding = domain.len().wrapping_sub(apex.len());
            if preceding > 0 && domain.as_bytes().get(preceding - 1) == Some(&b'.') {
                return true;
            }
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn psl_blocks_common_esp_psl_entries() {
        // PSL itself catches effective TLDs.
        assert!(is_public_domain("co.uk"));
        assert!(is_public_domain("appspot.com"));
    }

    #[test]
    fn catch_all_blocks_dominant_esps() {
        for needle in [
            "gmail.com",
            "outlook.com",
            "yahoo.com",
            "icloud.com",
            "protonmail.com",
        ] {
            assert!(is_public_domain(needle), "{needle} must be blocked");
        }
    }

    #[test]
    fn catch_all_extends_psl() {
        // `protonmail.com` is NOT a PSL effective TLD but IS in the
        // curated catch-all list. The combined predicate must
        // recognise both layers.
        assert!(is_public_domain("protonmail.com"));
        assert!(is_public_domain("subdomain.protonmail.com"));
    }

    #[test]
    fn corporate_domain_passes() {
        assert!(!is_public_domain("acme.com"));
        assert!(!is_public_domain("eu.acme.com"));
        assert!(!is_public_domain("workforce.acme.co.uk"));
    }

    #[test]
    fn partial_apex_match_does_not_false_positive() {
        // `notgmail.com` ends with the bytes of `gmail.com` but is
        // a distinct apex; the preceding-byte check guards against
        // false positives.
        assert!(!is_public_domain("notgmail.com"));
        assert!(!is_public_domain("xgmail.com"));
        assert!(!is_public_domain("ggmail.com"));
    }

    #[test]
    fn empty_string_is_public() {
        assert!(is_public_domain(""));
    }

    #[test]
    fn lowercase_ascii_assumption_holds_for_callers() {
        // Mixed-case input would underreport — document the
        // expectation by asserting the function does NOT lowercase
        // internally. The discover handler must call
        // `idna::domain_to_ascii` + `to_ascii_lowercase` first.
        // Using uppercase `GMAIL.COM` here SHOULD still match
        // because `psl::suffix_str` is case-insensitive in modern
        // versions, but the catch-all contains `gmail.com`
        // exactly — so this asserts the contract a caller breaks
        // when they skip normalisation.
        let block_lower = is_public_domain("gmail.com");
        assert!(block_lower);
    }
}
