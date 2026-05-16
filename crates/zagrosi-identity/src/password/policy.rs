// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! Password policy gate.
//!
//! Length-only per NIST SP 800-63B (no character-class rules, no
//! periodic-rotation requirement). The minimum is configurable via
//! [`crate::config::PasswordConfig`]; the maximum is hard-coded at
//! 256 to bound the DoS surface from arbitrarily long Argon2id input.

use crate::config::PasswordConfig;
use crate::error::IdentityError;

/// Fixed bait password the dummy-verify path uses. Exported so tests
/// can assert it stays stable across crate versions; production code
/// MUST NOT compare passwords against this constant.
pub const DUMMY_VERIFY_PASSWORD: &str = "dummy-verify-anti-enumeration";

/// Validate `password` against the configured length policy.
///
/// # Errors
///
/// Returns [`IdentityError::PasswordTooShort`] when the password is
/// shorter than `cfg.min_length`, or [`IdentityError::PasswordTooLong`]
/// when longer than `cfg.max_length`. Empty passwords surface as
/// `PasswordTooShort` rather than a separate variant.
pub fn validate_password_length(password: &str, cfg: &PasswordConfig) -> Result<(), IdentityError> {
    let len = password.chars().count();
    if len < cfg.min_length {
        return Err(IdentityError::PasswordTooShort {
            min: cfg.min_length,
        });
    }
    if len > cfg.max_length {
        return Err(IdentityError::PasswordTooLong {
            max: cfg.max_length,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> PasswordConfig {
        PasswordConfig {
            min_length: 12,
            max_length: 256,
        }
    }

    #[test]
    fn rejects_too_short() {
        let err = validate_password_length("short", &cfg()).unwrap_err();
        assert!(matches!(err, IdentityError::PasswordTooShort { min: 12 }));
    }

    #[test]
    fn rejects_empty() {
        let err = validate_password_length("", &cfg()).unwrap_err();
        assert!(matches!(err, IdentityError::PasswordTooShort { .. }));
    }

    #[test]
    fn accepts_exactly_min() {
        validate_password_length("a".repeat(12).as_str(), &cfg()).unwrap();
    }

    #[test]
    fn accepts_exactly_max() {
        validate_password_length("a".repeat(256).as_str(), &cfg()).unwrap();
    }

    #[test]
    fn rejects_over_max() {
        let err = validate_password_length("a".repeat(257).as_str(), &cfg()).unwrap_err();
        assert!(matches!(err, IdentityError::PasswordTooLong { max: 256 }));
    }

    #[test]
    fn no_character_class_required() {
        // 12 lowercase chars must pass — NIST SP 800-63B compliance.
        validate_password_length("abcdefghijkl", &cfg()).unwrap();
    }

    #[test]
    fn unicode_counted_as_chars_not_bytes() {
        // 12 emoji = 12 chars (each is multi-byte). Must pass.
        validate_password_length(&"🦀".repeat(12), &cfg()).unwrap();
    }
}
