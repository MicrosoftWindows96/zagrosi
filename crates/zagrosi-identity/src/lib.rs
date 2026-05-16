// SPDX-License-Identifier: AGPL-3.0-or-later

//! Identity, SSO, and SCIM foundation crate for the Zagrosi platform.
//!
//! This crate ships the user / organisation / session model, password
//! authentication, OIDC + SAML clients, SCIM 2.0 server, multi-IdP
//! routing, and the email outbox. Its public ports (`AuthContext`,
//! `Auditor`, `EmailTransport`, `BreachListClient`, `KeyProvider`,
//! `RateLimiter`, `MfaPolicy`, `SessionIntrospector`) live in
//! `zagrosi-core` so downstream crates depend on stable trait shapes
//! without pulling identity as a dependency.
//!
//! The crate skeleton ships the error type, configuration loader, and
//! workspace registration. The migration set lands the forward-only
//! `sqlx` migrations under [`MIGRATOR`] and the [`run_migrations`]
//! helper. Later layers light up domain types, persistence, `IdP`
//! clients, and HTTP routes.

#![deny(missing_docs)]

pub mod api_tokens;
pub mod config;
pub mod crypto;
pub mod domain;
pub mod email;
pub mod error;
pub mod http;
pub mod oidc;
pub mod password;
pub mod rate_limit;
pub mod repo;
pub mod routing;
#[cfg(feature = "saml")]
pub mod saml;
pub mod service;
pub mod service_tokens;
pub mod session;

pub use api_tokens::{
    ApiTokenCache, ApiTokenLastUsedReceiver, ApiTokenLastUsedSender, ApiTokenLastUsedUpdate,
    ApiTokenResolver, ApiTokenService, ApiTokenView, CachedApiToken, CreateApiTokenRequest,
    IssueApiTokenInput, IssuedApiToken, IssuedApiTokenResponse, PAT_RESOLVE_SCOPE,
    SCOPE_CATALOGUE_V0_1, SCOPE_TOKENS_READ, SCOPE_TOKENS_WRITE, api_token_last_used_channel,
};
pub use config::{
    DnsConfig, EmailConfig, IdentityConfig, LoadOptions, PlatformConfig, RateLimitBudget,
    RateLimitConfig, SessionConfig,
};
pub use crypto::{Envelope, KEY_ID_V0_1_STATIC, NONCE_LEN, Secrets, TAG_LEN};
pub use email::{
    DrainOutcome, EMAIL_OUTBOX_SUBJECT, EmailWorker, LettreTransport, OutboxDispatcher,
    OutboxState, ProcessOutcome,
};
pub use error::{IdentityError, Result};
pub use rate_limit::{RateLimitHeaders, ValkeyRateLimiter};
pub use service_tokens::{
    SVC_RESOLVE_SCOPE, ServiceTokenCache, ServiceTokenResolver, ServiceTokenService,
};
pub use session::{
    CSRF_COOKIE_NAME, CSRF_HEADER_NAME, IdentitySessionIntrospector, IdentitySessionIssuer,
    SESSION_COOKIE_NAME, SessionAttachment, SessionCache, SessionEventBus, SessionIssuer,
    SessionOrgSwitcher, SessionRevoker, SessionView,
};

use sqlx::PgPool;
use sqlx::migrate::Migrator;

pub use sqlx::migrate::MigrateError;

/// Embedded forward-only migrations for the identity schema.
///
/// The macro embeds every `*.sql` file under `crates/zagrosi-identity/
/// migrations/` at compile time, so binaries shipping this crate carry
/// the schema with them and apply it at startup via
/// [`run_migrations`]. The migration set targets `PostgreSQL` 17 verified
/// syntax; `PostgreSQL` 18 (the dev compose default) accepts the same
/// statements.
pub static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

/// Apply every embedded identity migration against `pool` in order.
///
/// Wraps [`MIGRATOR`] so callers (gateway / worker startup,
/// integration tests, the migration smoke runner) only touch a single
/// public surface. Migrations are idempotent: applying twice is a
/// no-op because `_sqlx_migrations` records the high-water mark.
///
/// # Errors
///
/// Returns [`MigrateError`] verbatim. Common variants include
/// connection failures, checksum mismatches (a previously-applied
/// migration file changed on disk), or DDL errors from the database.
pub async fn run_migrations(pool: &PgPool) -> std::result::Result<(), MigrateError> {
    MIGRATOR.run(pool).await
}
