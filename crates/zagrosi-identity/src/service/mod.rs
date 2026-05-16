// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! Password-auth `IdentityService`.
//!
//! `IdentityService` is the single concrete entry point for the
//! identity surface. Every password flow is a method on this struct;
//! later layers add OIDC / SAML / SCIM methods to the same type.
//!
//! Construction is via [`IdentityService::new`], which:
//!
//! - decodes the [`IdentityConfig`] env load,
//! - constructs the [`Argon2idHasher`],
//! - runs the [`crate::password::calibrate`] startup verify-bench,
//! - wires repos against a shared `sqlx::PgPool`,
//! - holds `Arc<dyn ...>` ports for the [`Auditor`], [`RateLimiter`],
//!   [`BreachListClient`], and the session-module-supplied
//!   [`crate::session::SessionIssuer`].
//!
//! Public methods live in the sub-modules
//! [`signup`], [`signin`], [`signout`], [`password_reset`],
//! [`email_verify`] — each is wired via `impl IdentityService`.

use std::sync::Arc;

use zagrosi_core::{Auditor, BreachListClient, RateLimiter};

use crate::config::IdentityConfig;
use crate::email::EmailOutboxWriter;
use crate::error::{IdentityError, Result};
use crate::password::Argon2idHasher;
use crate::repo::{
    EmailVerificationRepo, FailedSigninRepo, MembershipRepo, PasswordResetRepo, SessionRepo,
    UserRepo,
};
use crate::session::SessionIssuer;

pub mod email_verify;
pub mod password_reset;
pub mod signin;
pub mod signout;
pub mod signup;

/// Composed dependencies for the password-auth flows.
///
/// Held inside an `Arc<IdentityService>` and shared across handler
/// task boundaries. Cheap to clone (every field is a small handle or
/// an `Arc`).
///
/// `membership_repo` is held but not yet consumed; the upcoming
/// session-issuance flow will wire it for org-membership checks
/// during session establishment. The `#[allow(dead_code)]` is
/// scoped to that single field instead of the whole struct now that
/// `rate_limiter` is consumed by the sign-in path.
pub struct IdentityService {
    pub(crate) config: Arc<IdentityConfig>,
    pub(crate) hasher: Arc<Argon2idHasher>,
    pub(crate) breach_client: Arc<dyn BreachListClient>,
    pub(crate) auditor: Arc<dyn Auditor>,
    pub(crate) outbox: EmailOutboxWriter,
    pub(crate) user_repo: UserRepo,
    #[allow(dead_code)] // forthcoming session-issuance flow consumes this.
    pub(crate) membership_repo: MembershipRepo,
    pub(crate) password_reset_repo: PasswordResetRepo,
    pub(crate) email_verification_repo: EmailVerificationRepo,
    pub(crate) failed_signin_repo: FailedSigninRepo,
    pub(crate) session_repo: SessionRepo,
    pub(crate) session_issuer: Arc<dyn SessionIssuer>,
    pub(crate) rate_limiter: Arc<dyn RateLimiter>,
    pub(crate) pool: sqlx::PgPool,
    /// `From:` address the producer stamps on every outbox row.
    pub(crate) outbound_from_address: String,
    /// Public base URL for token landing pages (used in email bodies).
    pub(crate) base_url: String,
}

/// Argument bundle for [`IdentityService::new`].
///
/// Bundled to keep the constructor's param list manageable as later
/// layers add ports.
pub struct IdentityServiceDeps {
    /// Effective configuration.
    pub config: IdentityConfig,
    /// Pre-built Argon2id hasher (so callers can run their own
    /// calibration if they want; otherwise [`IdentityService::new`]
    /// runs one.)
    pub hasher: Argon2idHasher,
    /// Breach-list lookup port.
    pub breach_client: Arc<dyn BreachListClient>,
    /// Audit-event sink. Use `Arc::new(zagrosi_core::NoopAuditor)` for
    /// tests / pre-prod.
    pub auditor: Arc<dyn Auditor>,
    /// Session-module session-issuance port.
    pub session_issuer: Arc<dyn SessionIssuer>,
    /// Rate-limit port. The rate-limit module's Valkey-backed impl swaps in here.
    pub rate_limiter: Arc<dyn RateLimiter>,
    /// Connection pool wired to the identity Postgres.
    pub pool: sqlx::PgPool,
    /// `From:` address the producer stamps on every outbox row.
    pub outbound_from_address: String,
    /// Public base URL for token landing pages (used in email bodies).
    pub base_url: String,
}

impl IdentityService {
    /// Construct a service from composed deps.
    ///
    /// Runs the Argon2id startup verify-bench
    /// ([`crate::password::calibrate`]) — a profile that exceeds 1.5 s
    /// returns [`IdentityError::Argon2ProfileTooSlow`] so the binary
    /// refuses to start under a configuration that would brown out.
    pub async fn new(deps: IdentityServiceDeps) -> Result<Self> {
        let hasher = Arc::new(deps.hasher);
        crate::password::calibrate(&hasher).await?;
        Ok(Self {
            user_repo: UserRepo::new(deps.pool.clone()),
            membership_repo: MembershipRepo::new(deps.pool.clone()),
            password_reset_repo: PasswordResetRepo::new(deps.pool.clone()),
            email_verification_repo: EmailVerificationRepo::new(deps.pool.clone()),
            failed_signin_repo: FailedSigninRepo::new(deps.pool.clone()),
            session_repo: SessionRepo::new(deps.pool.clone()),
            outbox: EmailOutboxWriter::new(),
            config: Arc::new(deps.config),
            hasher,
            breach_client: deps.breach_client,
            auditor: deps.auditor,
            session_issuer: deps.session_issuer,
            rate_limiter: deps.rate_limiter,
            pool: deps.pool,
            outbound_from_address: deps.outbound_from_address,
            base_url: deps.base_url,
        })
    }
}

/// Normalise an email address for lookup.
///
/// Lowercases the whole address and strips a `+`-tag suffix from the
/// local part (e.g. `Alice+work@Acme.COM` → `alice@acme.com`). This
/// matches the password-auth anti-enumeration assertion that `+`-aliases collide
/// with the bare address on sign-up.
#[must_use]
pub(crate) fn normalise_email(input: &str) -> String {
    let lower = input.trim().to_ascii_lowercase();
    let Some((local, domain)) = lower.split_once('@') else {
        return lower;
    };
    let local = local.split('+').next().unwrap_or(local);
    format!("{local}@{domain}")
}

/// Validate that `email` is well-formed.
pub(crate) fn validate_email(email: &str) -> Result<()> {
    if validator::ValidateEmail::validate_email(&email) {
        Ok(())
    } else {
        Err(IdentityError::InvalidEmail)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalise_lowercases() {
        assert_eq!(normalise_email("Alice@Acme.COM"), "alice@acme.com");
    }

    #[test]
    fn normalise_strips_plus_tag() {
        assert_eq!(normalise_email("alice+work@acme.com"), "alice@acme.com",);
    }

    #[test]
    fn normalise_trims() {
        assert_eq!(normalise_email("  alice@acme.com\n"), "alice@acme.com");
    }

    #[test]
    fn validate_email_accepts_normal() {
        validate_email("alice@example.com").unwrap();
    }

    #[test]
    fn validate_email_rejects_garbage() {
        assert!(matches!(
            validate_email("not-an-email"),
            Err(IdentityError::InvalidEmail),
        ));
    }
}
