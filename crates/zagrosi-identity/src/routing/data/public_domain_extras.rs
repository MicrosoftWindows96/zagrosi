// SPDX-License-Identifier: AGPL-3.0-or-later

//! Curated catch-all extension to the Mozilla Public Suffix List.
//!
//! The PSL classifies effective TLDs (`co.uk`, `appspot.com`,
//! `compute.amazonaws.com`, etc.) but does not enumerate the apex
//! domains of common email service providers. An admin who claims
//! `gmail.com` would otherwise route every Google Mail user through
//! their tenant's IdP — a catastrophic SSO confused-deputy. This
//! catch-all covers the gap.
//!
//! Rules of the road for adding entries:
//!
//! - Lowercase, ASCII-only.
//! - One apex per line; subdomains of every entry are also blocked
//!   (e.g. `*.gmail.com` blocks `mail.gmail.com`).
//! - Add only via PR review with the `security` label.
//! - Quarterly audit alongside the PSL bump (see workspace
//!   `CHANGELOG.md` `[Unreleased]`).

/// Curated catch-all list of public ESP / mail-provider domains
/// that the PSL does not classify as public suffixes but which MUST
/// NOT be claimable for SSO routing.
pub static CATCH_ALL_PUBLIC_DOMAINS: &[&str] = &[
    // Google.
    "gmail.com",
    "googlemail.com",
    // Microsoft consumer mail family.
    "outlook.com",
    "hotmail.com",
    "live.com",
    "msn.com",
    // Yahoo family.
    "yahoo.com",
    "yahoo.co.uk",
    "yahoo.co.jp",
    "ymail.com",
    "rocketmail.com",
    // Proton.
    "protonmail.com",
    "proton.me",
    "pm.me",
    // Apple.
    "icloud.com",
    "me.com",
    "mac.com",
    // AOL / 1&1 / Mail.com legacy family.
    "aol.com",
    "gmx.com",
    "gmx.net",
    "mail.com",
    // Other widely used consumer mail providers.
    "zoho.com",
    "fastmail.com",
    "fastmail.fm",
    "tutanota.com",
    "tuta.io",
    "yandex.ru",
    "yandex.com",
    "ya.ru",
    "qq.com",
    "163.com",
    "126.com",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catch_all_entries_are_lowercase_ascii() {
        for entry in CATCH_ALL_PUBLIC_DOMAINS {
            assert!(
                entry
                    .chars()
                    .all(|c| c.is_ascii() && !c.is_ascii_uppercase()),
                "{entry:?} must be lowercase ASCII (mixed case fans out into duplicate evaluations)"
            );
        }
    }

    #[test]
    fn catch_all_entries_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for entry in CATCH_ALL_PUBLIC_DOMAINS {
            assert!(
                seen.insert(*entry),
                "duplicate catch-all entry {entry:?}; remove the second occurrence"
            );
        }
    }

    #[test]
    fn catch_all_includes_dominant_providers() {
        let required = ["gmail.com", "outlook.com", "yahoo.com", "icloud.com"];
        for needle in required {
            assert!(
                CATCH_ALL_PUBLIC_DOMAINS.contains(&needle),
                "{needle} must remain on the catch-all list"
            );
        }
    }
}
