// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! Email normalisation for the SSO routing decision.
//!
//! Plus-tag stripping (`alice+work@acme.com` → `alice@acme.com`)
//! prevents an attacker from defeating the routing layer by adding
//! a tag the IdP does not honour. The original email is preserved
//! for downstream session / audit / `login_hint` propagation.
//!
//! Domain-side normalisation runs `idna::domain_to_ascii` to
//! punycode IDNs followed by lowercase. The combined output keys
//! the routing-lookup partial unique index (`lower(domain)`).
//!
//! Plus-tag stripping operates on the local part only — characters
//! after the FIRST `+` are dropped. `alice++@acme.com` and
//! `alice+a+b@acme.com` both reduce to `alice`. `+@acme.com`
//! reduces to an empty local part and is rejected.

use crate::error::{IdentityError, Result};

/// Result of normalising an email for SSO routing lookup.
///
/// `original` borrows the input so the caller can propagate the
/// as-entered email into the IdP `login_hint` parameter without
/// allocating. `lookup_local` and `lookup_domain` own their bytes
/// because plus-tag stripping and IDNA punycoding both produce new
/// strings.
#[derive(Debug, Clone)]
pub struct NormalisedEmail<'a> {
    /// The email exactly as the caller entered it. Used for
    /// downstream session metadata and IdP `login_hint`.
    pub original: &'a str,
    /// Local part with any plus-tag stripped. Preserves the
    /// supplied case (RFC 5321 §2.4 — local parts are technically
    /// case-sensitive; routing only cares about the domain).
    pub lookup_local: String,
    /// Punycoded, lowercased domain. Suitable for direct use as
    /// the SQL key against the `lower(domain)` partial index.
    pub lookup_domain: String,
}

/// Normalise an email for routing lookup.
///
/// # Errors
///
/// - [`IdentityError::InvalidEmail`] when the input is missing an
///   `@`, has more than one `@` not separating local from domain,
///   has an empty local part (after plus-tag strip), or has an
///   empty domain.
/// - [`IdentityError::InvalidDomain`] when the domain fails
///   IDNA-to-ASCII normalisation (catastrophic Unicode escape, dot
///   in punycode prefix, etc.).
pub fn normalise(email: &str) -> Result<NormalisedEmail<'_>> {
    // Reject obvious DoS up front. RFC 5321 §4.5.3 caps email
    // addresses at 254 octets; we cap at 320 to give the local
    // part the legacy SMTP 64-char ceiling room. A 320-byte
    // address through every downstream is not free; rejecting
    // here keeps later passes cheap.
    if email.is_empty() || email.len() > 320 {
        return Err(IdentityError::InvalidEmail);
    }

    // Split on the LAST `@`. RFC 5321 forbids `@` inside the
    // domain literal so the rightmost `@` is canonical.
    let Some((local_raw, domain_raw)) = email.rsplit_once('@') else {
        return Err(IdentityError::InvalidEmail);
    };

    if local_raw.is_empty() || domain_raw.is_empty() {
        return Err(IdentityError::InvalidEmail);
    }

    // Strip plus-tag. Everything after the first `+` is the tag
    // — including subsequent `+` literals.
    let lookup_local = local_raw.split_once('+').map_or_else(
        || local_raw.to_string(),
        |(before_plus, _tag)| before_plus.to_string(),
    );
    if lookup_local.is_empty() {
        return Err(IdentityError::InvalidEmail);
    }

    // IDNA-to-ASCII the domain via `domain_to_ascii_strict` so the
    // call enforces UTS46 + DNS label / total-length limits AND
    // rejects ASCII control bytes (CR, LF, NUL, tab). Lowercase
    // last so punycode prefixes (`xn--`) emerge in their canonical
    // lowercase form. The lax `domain_to_ascii` would silently
    // accept embedded NUL or per-label > 63 octets — feeding either
    // into the `_zagrosi-verify.<domain>` FQDN construction or any
    // downstream log line would corrupt the wire format / open
    // log-injection.
    let domain_ascii =
        idna::domain_to_ascii_strict(domain_raw).map_err(|err| IdentityError::InvalidDomain {
            reason: format!("idna strict failure: {err}"),
        })?;
    let lookup_domain = domain_ascii.to_ascii_lowercase();
    if lookup_domain.is_empty() {
        return Err(IdentityError::InvalidEmail);
    }

    Ok(NormalisedEmail {
        original: email,
        lookup_local,
        lookup_domain,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_plus_tag_from_local_part() {
        let n = normalise("alice+work@acme.com").unwrap_or_else(|e| panic!("normalise: {e}"));
        assert_eq!(n.lookup_local, "alice");
        assert_eq!(n.lookup_domain, "acme.com");
        assert_eq!(n.original, "alice+work@acme.com");
    }

    #[test]
    fn strips_at_first_plus_only() {
        let n = normalise("alice+a+b@acme.com").unwrap_or_else(|e| panic!("normalise: {e}"));
        // Everything after the first `+` is the tag, including
        // additional `+` literals.
        assert_eq!(n.lookup_local, "alice");
    }

    #[test]
    fn lowercases_domain_only() {
        let n = normalise("Alice@ACME.COM").unwrap_or_else(|e| panic!("normalise: {e}"));
        // Local part case is preserved — RFC 5321 §2.4 advisory.
        assert_eq!(n.lookup_local, "Alice");
        // Domain is canonicalised lowercase.
        assert_eq!(n.lookup_domain, "acme.com");
    }

    #[test]
    fn idn_punycoded() {
        // Cyrillic-looking domain `bücher.example` punycodes to
        // `xn--bcher-kva.example`.
        let n = normalise("admin@bücher.example").unwrap_or_else(|e| panic!("normalise: {e}"));
        assert_eq!(n.lookup_domain, "xn--bcher-kva.example");
    }

    #[test]
    fn plus_in_domain_is_left_alone() {
        // `+` in the domain part is invalid per DNS but the test
        // documents that the local-part stripper does not interfere
        // with whatever the domain parser raises.
        let result = normalise("alice@plus+host.com");
        // idna may accept or reject; the only guarantee is that
        // when accepted, the local part stays `alice`.
        if let Ok(n) = result {
            assert_eq!(n.lookup_local, "alice");
        }
    }

    #[test]
    fn rejects_empty_local_after_plus_strip() {
        // `+anything@acme.com` strips to empty local part — must
        // reject rather than route.
        let err = normalise("+work@acme.com").expect_err("empty local must reject");
        assert!(matches!(err, IdentityError::InvalidEmail));
    }

    #[test]
    fn rejects_missing_at() {
        assert!(matches!(
            normalise("noseparator").unwrap_err(),
            IdentityError::InvalidEmail
        ));
    }

    #[test]
    fn rejects_empty() {
        assert!(matches!(
            normalise("").unwrap_err(),
            IdentityError::InvalidEmail
        ));
    }

    #[test]
    fn rejects_oversized_input() {
        let long = format!("{}@acme.com", "x".repeat(400));
        assert!(matches!(
            normalise(&long).unwrap_err(),
            IdentityError::InvalidEmail
        ));
    }

    #[test]
    fn rejects_empty_local() {
        assert!(matches!(
            normalise("@acme.com").unwrap_err(),
            IdentityError::InvalidEmail
        ));
    }

    #[test]
    fn rejects_empty_domain() {
        assert!(matches!(
            normalise("alice@").unwrap_err(),
            IdentityError::InvalidEmail
        ));
    }
}
