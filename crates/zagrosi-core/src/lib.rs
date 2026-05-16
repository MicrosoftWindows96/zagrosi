// SPDX-License-Identifier: AGPL-3.0-or-later

//! Foundation library for the Zagrosi platform.
//!
//! Provides the cross-crate primitives that every other Zagrosi crate
//! consumes:
//!
//! - Shared error types (`ZagrosiError`, `Result`); see [`error`].
//! - A layered configuration loader (`CoreConfig`, `LoadOptions`); see
//!   [`config`].
//! - An off-by-default observability guard wrapping `tracing`,
//!   OpenTelemetry, and a Prometheus admin server; see [`observability`].
//! - Cross-crate ports + value objects consumed by `zagrosi-identity` and
//!   the future `zagrosi-rbac` / `zagrosi-audit` crates: [`auth_context`],
//!   [`audit`], [`email_transport`], [`breach_list_client`],
//!   [`key_provider`], [`rate_limiter`], [`mfa_policy`],
//!   [`session_introspector`].
//!
//! See `documentation/governance.md` for the project-wide conventions
//! this crate enforces (DCO, Conventional Commits, lint policy).

#![deny(missing_docs)]

pub mod audit;
pub mod auth_context;
pub mod breach_list_client;
pub mod config;
pub mod email_transport;
pub mod error;
pub mod key_provider;
pub mod mfa_policy;
pub mod observability;
pub mod rate_limiter;
pub mod session_introspector;

pub use audit::{
    AuditActor, AuditEvent, AuditEventError, AuditEventKind, AuditEventV1, AuditPayload,
    AuditResource, Auditor, NoopAuditor, ServiceName, ServiceNameError,
};
pub use auth_context::{
    AuthContext, AuthContextError, AuthError, AuthMethod, IdentityContext, RawTokenStr, TokenClass,
};
pub use breach_list_client::{BreachCheck, BreachListClient, BreachListError};
pub use config::{CoreConfig, LoadOptions, LogFormat};
pub use email_transport::{
    EmailMessage, EmailTransport, EmailTransportError, EmailTransportFault, PermanentFaultCategory,
    RedactedString,
};
pub use error::{Result, ZagrosiError};
pub use key_provider::{KeyHandle, KeyProvider, KeyProviderError, Signature, SignatureAlgorithm};
pub use mfa_policy::{AlwaysAllowMfaPolicy, AuthContinuation, Factor, MfaPolicy, Required};
pub use observability::Observability;
pub use rate_limiter::{RateLimitDecision, RateLimitKey, RateLimiter, RateLimiterError};
pub use session_introspector::SessionIntrospector;
