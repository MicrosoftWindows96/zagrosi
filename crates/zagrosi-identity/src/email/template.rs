// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! Catalogue of email templates the password-auth producer hands to
//! the email-outbox worker.
//!
//! The actual `.ftl` files live under `crates/zagrosi-identity/templates/`.
//! The email-outbox worker resolves [`TemplateName`] to a fluent-templates
//! key + locale and renders against the payload JSON the producer
//! attached to the outbox row.

/// Templates this crate writes into `email_outbox`.
///
/// Wire-format value is the snake_case stringification (used by the
/// email-outbox worker as the lookup key into the embedded fluent
/// loader).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum TemplateName {
    /// Sign-up verification email. Carries a `vrf_*` token URL.
    VerifyEmail,
    /// Password reset email. Carries a `rst_*` token URL.
    PasswordReset,
    /// Anti-enumeration sign-up collision: the email already
    /// belongs to a known user. Instructs the recipient to sign in
    /// or use the password-reset flow.
    AccountAlreadyExists,
    /// Org-invite email. The invite-issuance code path lives in
    /// the admin layer; the template ships here so the embedded fluent
    /// loader is complete from password-auth onward.
    OrgInvite,
}

impl TemplateName {
    /// Wire-format key written to `email_outbox.template_key`.
    #[must_use]
    pub const fn as_key(self) -> &'static str {
        match self {
            Self::VerifyEmail => "verify_email",
            Self::PasswordReset => "password_reset",
            Self::AccountAlreadyExists => "account_already_exists",
            Self::OrgInvite => "org_invite",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_stable() {
        assert_eq!(TemplateName::VerifyEmail.as_key(), "verify_email");
        assert_eq!(TemplateName::PasswordReset.as_key(), "password_reset");
        assert_eq!(
            TemplateName::AccountAlreadyExists.as_key(),
            "account_already_exists",
        );
        assert_eq!(TemplateName::OrgInvite.as_key(), "org_invite");
    }
}
