// SPDX-License-Identifier: AGPL-3.0-or-later

//! Gateway-to-domain auth contract.
//!
//! Identity attaches [`AuthContext`] as an axum extension after token
//! resolution; downstream consumers (RBAC, handlers) read it. RBAC
//! roles and permissions stay out of this struct: those derive from
//! membership state and live in the tenant-isolation layer's
//! `zagrosi-rbac` crate. Bearer-token scopes (PAT / SCIM / service
//! token) ARE carried because they describe the credential's grant,
//! a property of the token itself rather than the user's role.
//!
//! # Construction invariants
//!
//! [`AuthContext`] and [`IdentityContext`] hold load-bearing identity data;
//! the only legitimate construction path for fresh values is the `new`
//! constructor on each, which enforces:
//!
//! - non-nil `subject_id`, `session_id`, `org_id`, `correlation_id`,
//! - at least one entry in `amr` (RFC 8176 requires every authenticated request
//!   must carry the methods that produced it),
//! - `issued_at < expires_at` (no zombie / future-dated sessions).
//!
//! Deserialise paths exist for cross-process audit replay; production
//! gateway code MUST go through the constructor so invariants are checked
//! at the trust boundary. Field access is read-only via accessors.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Caller identity + active org + token metadata after authentication.
///
/// Attached to a request by the api-gateway middleware via
/// [`crate::SessionIntrospector::resolve`]. Carries bearer-token
/// scopes when the credential is a PAT / SCIM / service token, but
/// not RBAC roles or permissions: the tenant-isolation layer expands
/// those on top of the membership graph rather than encoding them
/// here.
///
/// Fields are private; construct via [`AuthContext::new`] and read via
/// the accessor methods.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthContext {
    subject_id: Uuid,
    session_id: Uuid,
    org_id: Uuid,
    auth_method: AuthMethod,
    token_class: TokenClass,
    amr: Vec<String>,
    acr: Option<String>,
    expires_at: DateTime<Utc>,
    issued_at: DateTime<Utc>,
    correlation_id: Uuid,
    /// Authorisation scopes carried by bearer-token auth methods
    /// (PAT, SCIM, service-token). Empty for session-based auth,
    /// which derives capabilities from the role-based access layer
    /// instead. Defaults to empty; populate via
    /// [`AuthContext::with_scopes`] at the bearer-token resolve site.
    ///
    /// Serialisation skips this field when empty so session payloads
    /// do not gain a `scopes: []` member, keeping the on-the-wire
    /// envelope identical to the pre-bearer-scope shape.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    scopes: Vec<String>,
}

impl AuthContext {
    /// Construct a fresh [`AuthContext`], enforcing every invariant the
    /// gateway-to-domain contract requires.
    ///
    /// # Errors
    ///
    /// Returns an [`AuthContextError`] if any invariant is violated:
    /// nil `subject_id` / `session_id` / `org_id` / `correlation_id`,
    /// empty `amr`, or `issued_at >= expires_at`.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        subject_id: Uuid,
        session_id: Uuid,
        org_id: Uuid,
        auth_method: AuthMethod,
        token_class: TokenClass,
        amr: Vec<String>,
        acr: Option<String>,
        issued_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
        correlation_id: Uuid,
    ) -> Result<Self, AuthContextError> {
        if subject_id.is_nil() {
            return Err(AuthContextError::NilUuid("subject_id"));
        }
        if session_id.is_nil() {
            return Err(AuthContextError::NilUuid("session_id"));
        }
        if org_id.is_nil() {
            return Err(AuthContextError::NilUuid("org_id"));
        }
        if correlation_id.is_nil() {
            return Err(AuthContextError::NilUuid("correlation_id"));
        }
        if amr.is_empty() {
            return Err(AuthContextError::EmptyAmr);
        }
        if issued_at >= expires_at {
            return Err(AuthContextError::InvalidTimeWindow);
        }
        Ok(Self {
            subject_id,
            session_id,
            org_id,
            auth_method,
            token_class,
            amr,
            acr,
            expires_at,
            issued_at,
            correlation_id,
            scopes: Vec::new(),
        })
    }

    /// Attach the bearer-token authorisation scopes to this context.
    ///
    /// Used by the personal-access-token / SCIM / service-token
    /// resolvers to thread the persisted scope list onto the
    /// resolved [`AuthContext`]. Session-based auth leaves scopes
    /// empty (capabilities derive from the RBAC layer instead).
    ///
    /// Consumes `self` so the call site cannot accidentally drop
    /// the scope list mid-pipeline.
    #[must_use]
    pub fn with_scopes(mut self, scopes: Vec<String>) -> Self {
        self.scopes = scopes;
        self
    }

    /// Authorisation scopes carried by this auth context (PAT /
    /// SCIM / service-token only). Returns an empty slice for
    /// session-based auth.
    #[must_use]
    pub fn scopes(&self) -> &[String] {
        &self.scopes
    }

    /// Returns `true` when `scope` is present in this context's
    /// scope list. Always returns `false` for session-based auth
    /// (scopes only apply to bearer tokens).
    #[must_use]
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.iter().any(|s| s == scope)
    }

    /// Subject (user) identifier.
    #[must_use]
    pub const fn subject_id(&self) -> Uuid {
        self.subject_id
    }

    /// Session identifier the bearer token resolves to.
    #[must_use]
    pub const fn session_id(&self) -> Uuid {
        self.session_id
    }

    /// Active organisation scope for this request.
    #[must_use]
    pub const fn org_id(&self) -> Uuid {
        self.org_id
    }

    /// How the caller authenticated.
    #[must_use]
    pub const fn auth_method(&self) -> AuthMethod {
        self.auth_method
    }

    /// Class of the bearer token used for this request.
    #[must_use]
    pub const fn token_class(&self) -> TokenClass {
        self.token_class
    }

    /// RFC 8176 Authentication Methods References (e.g. `["pwd"]`).
    #[must_use]
    pub fn amr(&self) -> &[String] {
        &self.amr
    }

    /// RFC 8176 Authentication Context Class Reference, when known.
    #[must_use]
    pub fn acr(&self) -> Option<&str> {
        self.acr.as_deref()
    }

    /// Wall-clock expiry of the underlying session/token.
    #[must_use]
    pub const fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    /// Wall-clock issuance time of the underlying session/token.
    #[must_use]
    pub const fn issued_at(&self) -> DateTime<Utc> {
        self.issued_at
    }

    /// Per-request correlation ID (propagated via the tracing layer).
    #[must_use]
    pub const fn correlation_id(&self) -> Uuid {
        self.correlation_id
    }
}

/// Subset of [`AuthContext`] usable by code that only needs the actor
/// identity (no token metadata). Cheap to clone.
///
/// Fields are private; construct via [`IdentityContext::new`] and read
/// via accessor methods.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(clippy::struct_field_names)]
pub struct IdentityContext {
    subject_id: Uuid,
    org_id: Uuid,
    correlation_id: Uuid,
}

impl IdentityContext {
    /// Construct a fresh [`IdentityContext`].
    ///
    /// # Errors
    ///
    /// Returns [`AuthContextError::NilUuid`] if any of the three identifiers
    /// is the nil UUID.
    pub const fn new(
        subject_id: Uuid,
        org_id: Uuid,
        correlation_id: Uuid,
    ) -> Result<Self, AuthContextError> {
        if subject_id.is_nil() {
            return Err(AuthContextError::NilUuid("subject_id"));
        }
        if org_id.is_nil() {
            return Err(AuthContextError::NilUuid("org_id"));
        }
        if correlation_id.is_nil() {
            return Err(AuthContextError::NilUuid("correlation_id"));
        }
        Ok(Self {
            subject_id,
            org_id,
            correlation_id,
        })
    }

    /// Subject (user) identifier.
    #[must_use]
    pub const fn subject_id(&self) -> Uuid {
        self.subject_id
    }

    /// Active organisation scope.
    #[must_use]
    pub const fn org_id(&self) -> Uuid {
        self.org_id
    }

    /// Per-request correlation ID.
    #[must_use]
    pub const fn correlation_id(&self) -> Uuid {
        self.correlation_id
    }
}

/// How a caller authenticated for the current request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AuthMethod {
    /// Password sign-in.
    Password,
    /// OIDC authorisation-code flow callback.
    Oidc,
    /// SAML 2.0 ACS.
    Saml,
    /// Personal access token bearer.
    ApiToken,
    /// SCIM bearer token.
    ScimToken,
    /// Worker / service token bearer.
    ServiceToken,
}

/// Class of the bearer token the gateway received.
///
/// The class is encoded in the token's prefix; how the prefix
/// participates in any hashing is a concern of the consumer (see the
/// session module's introspector).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum TokenClass {
    /// `sid_<43>`: session cookie or bearer.
    Session,
    /// `pat_<43>`: personal API token.
    PersonalAccessToken,
    /// `scim_<43>`: SCIM bearer.
    Scim,
    /// `svc_<43>`: worker service token.
    Service,
}

impl TokenClass {
    /// Prefix as it appears in the raw token (`sid_`, `pat_`, `scim_`, `svc_`).
    #[must_use]
    pub const fn prefix(self) -> &'static str {
        match self {
            Self::Session => "sid_",
            Self::PersonalAccessToken => "pat_",
            Self::Scim => "scim_",
            Self::Service => "svc_",
        }
    }

    /// Parse the prefix from a raw token; returns `None` if the prefix is
    /// not one of the four documented classes.
    ///
    /// **Note:** this only inspects the prefix; the body length / charset
    /// are not validated. Callers that need full validation must use
    /// [`RawTokenStr::parse`] which returns `(TokenClass, body)` after
    /// asserting the body is exactly 43 base64url characters, defending
    /// the session-module introspector fast-fail path against malformed input.
    #[must_use]
    pub fn from_prefix(raw: &str) -> Option<Self> {
        if raw.starts_with("sid_") {
            Some(Self::Session)
        } else if raw.starts_with("pat_") {
            Some(Self::PersonalAccessToken)
        } else if raw.starts_with("scim_") {
            Some(Self::Scim)
        } else if raw.starts_with("svc_") {
            Some(Self::Service)
        } else {
            None
        }
    }
}

/// Length of the body portion of every raw token (`sid_<43>`, `pat_<43>`,
/// `scim_<43>`, `svc_<43>`). 43 base64url characters encode 32 bytes of
/// entropy via the standard length formula `ceil(32 * 4 / 3)` rounded
/// down to remove the `=` padding character that base64url omits.
const TOKEN_BODY_LEN: usize = 43;

/// Strictly-validated raw token reference.
///
/// [`RawTokenStr::parse`] returns the parsed [`TokenClass`] and the
/// validated body slice. Validation rejects:
///
/// - missing prefix,
/// - body length other than 43 chars,
/// - any character outside the base64url alphabet `[A-Za-z0-9_-]`.
///
/// Session-module introspectors call this BEFORE touching the database so a
/// malformed prefix does not cost a DB round-trip per request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawTokenStr<'a> {
    class: TokenClass,
    body: &'a str,
}

impl<'a> RawTokenStr<'a> {
    /// Parse a raw token string into [`(TokenClass, body)`].
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::MalformedPrefix`] when no prefix matches, the
    /// body length differs from the 43-character token body size, or the body contains
    /// a character outside the base64url alphabet.
    pub fn parse(raw: &'a str) -> Result<Self, AuthError> {
        let class = TokenClass::from_prefix(raw).ok_or(AuthError::MalformedPrefix)?;
        let body = raw
            .get(class.prefix().len()..)
            .ok_or(AuthError::MalformedPrefix)?;
        if body.len() != TOKEN_BODY_LEN {
            return Err(AuthError::MalformedPrefix);
        }
        if !body
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return Err(AuthError::MalformedPrefix);
        }
        Ok(Self { class, body })
    }

    /// Token class.
    #[must_use]
    pub const fn class(self) -> TokenClass {
        self.class
    }

    /// Validated body (43 base64url chars, no prefix).
    #[must_use]
    pub const fn body(self) -> &'a str {
        self.body
    }
}

/// Errors produced by [`AuthContext::new`] / [`IdentityContext::new`]
/// when the caller violates a construction invariant.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AuthContextError {
    /// One of the load-bearing UUID fields was the nil UUID. The static
    /// string names which field was rejected.
    #[error("auth context field `{0}` must not be the nil UUID")]
    NilUuid(&'static str),
    /// `amr` was empty; RFC 8176 requires at least one method on every
    /// authenticated request.
    #[error("auth context `amr` must carry at least one entry")]
    EmptyAmr,
    /// `issued_at >= expires_at`. Sessions must close in the future.
    #[error("auth context `issued_at` must be strictly before `expires_at`")]
    InvalidTimeWindow,
}

/// Errors a [`crate::SessionIntrospector`] may surface to the gateway.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AuthError {
    /// Token does not start with one of the four documented prefixes,
    /// or the body length / charset failed [`RawTokenStr::parse`] checks.
    #[error("malformed token prefix")]
    MalformedPrefix,
    /// Token does not resolve to a live session.
    #[error("unauthorized")]
    Unauthorized,
    /// Session resolved but `expires_at` is in the past.
    #[error("session expired")]
    Expired,
    /// Session resolved but `revoked_at` is set.
    #[error("session revoked")]
    Revoked,
    /// Internal failure (DB / cache / health probe). Caller surfaces as 500.
    ///
    /// Carries the upstream error chain via `Box<dyn Error>` so logging
    /// callers can render the chain via `format!("{e:?}")` without losing
    /// the root cause. The [`std::fmt::Display`] impl deliberately renders
    /// only the static label `"internal"` so format strings ending up on a
    /// client response do not leak DB hostnames / credentials embedded in
    /// the underlying error.
    #[error("internal")]
    Internal(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
    /// Per-token rate-limit budget exhausted. Surfaced to the gateway
    /// so it can render `429 Too Many Requests` with the
    /// `Retry-After` header populated from `retry_after`. Used by
    /// the personal-access-token resolver and the SCIM / service
    /// token resolvers when their per-token budget trips.
    #[error("rate limited; retry after {retry_after:?}")]
    RateLimited {
        /// Wall-clock duration the caller should wait before retrying.
        retry_after: std::time::Duration,
    },
}

impl AuthError {
    /// Wrap any `std::error::Error + Send + Sync + 'static` source as the
    /// [`AuthError::Internal`] variant. Callers use this to lift sqlx /
    /// reqwest / cache errors without losing the chain.
    pub fn internal<E>(err: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::Internal(Box::new(err))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use static_assertions::assert_impl_all;

    assert_impl_all!(AuthContext: Send, Sync, Clone, std::fmt::Debug);
    assert_impl_all!(AuthContext: serde::Serialize, serde::de::DeserializeOwned);
    assert_impl_all!(IdentityContext: Send, Sync, Clone, std::fmt::Debug);
    assert_impl_all!(AuthError: Send, Sync, std::error::Error);
    assert_impl_all!(AuthContextError: Send, Sync, std::error::Error);
    assert_impl_all!(RawTokenStr<'static>: Send, Sync, Copy, std::fmt::Debug);
    const _: fn() = || {
        // Every error type must satisfy `'static + Send + Sync`. Without a
        // standalone helper `assert_impl_all!` cannot encode the `'static`
        // bound on its own.
        fn require_static<T: 'static + Send + Sync>() {}
        require_static::<AuthError>();
        require_static::<AuthContextError>();
    };

    fn valid_amr() -> Vec<String> {
        vec!["pwd".into()]
    }

    fn ts(secs: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(secs, 0)
            .unwrap_or_else(|| panic!("failed to build DateTime<Utc> from {secs}"))
    }

    fn valid_uuid(byte: u8) -> Uuid {
        Uuid::from_bytes([byte; 16])
    }

    fn valid_auth_context() -> AuthContext {
        AuthContext::new(
            valid_uuid(1),
            valid_uuid(2),
            valid_uuid(3),
            AuthMethod::Password,
            TokenClass::Session,
            valid_amr(),
            None,
            ts(0),
            ts(3600),
            valid_uuid(4),
        )
        .unwrap_or_else(|e| panic!("valid AuthContext rejected: {e}"))
    }

    #[test]
    fn auth_context_new_rejects_nil_subject_id() {
        let err = AuthContext::new(
            Uuid::nil(),
            valid_uuid(2),
            valid_uuid(3),
            AuthMethod::Password,
            TokenClass::Session,
            valid_amr(),
            None,
            ts(0),
            ts(3600),
            valid_uuid(4),
        )
        .expect_err("nil subject_id must reject");
        assert!(matches!(err, AuthContextError::NilUuid("subject_id")));
    }

    #[test]
    fn auth_context_new_rejects_nil_session_id() {
        let err = AuthContext::new(
            valid_uuid(1),
            Uuid::nil(),
            valid_uuid(3),
            AuthMethod::Password,
            TokenClass::Session,
            valid_amr(),
            None,
            ts(0),
            ts(3600),
            valid_uuid(4),
        )
        .expect_err("nil session_id must reject");
        assert!(matches!(err, AuthContextError::NilUuid("session_id")));
    }

    #[test]
    fn auth_context_new_rejects_nil_org_id() {
        let err = AuthContext::new(
            valid_uuid(1),
            valid_uuid(2),
            Uuid::nil(),
            AuthMethod::Password,
            TokenClass::Session,
            valid_amr(),
            None,
            ts(0),
            ts(3600),
            valid_uuid(4),
        )
        .expect_err("nil org_id must reject");
        assert!(matches!(err, AuthContextError::NilUuid("org_id")));
    }

    #[test]
    fn auth_context_new_rejects_empty_amr() {
        let err = AuthContext::new(
            valid_uuid(1),
            valid_uuid(2),
            valid_uuid(3),
            AuthMethod::Password,
            TokenClass::Session,
            Vec::new(),
            None,
            ts(0),
            ts(3600),
            valid_uuid(4),
        )
        .expect_err("empty amr must reject");
        assert!(matches!(err, AuthContextError::EmptyAmr));
    }

    #[test]
    fn auth_context_new_rejects_inverted_time_window() {
        let err = AuthContext::new(
            valid_uuid(1),
            valid_uuid(2),
            valid_uuid(3),
            AuthMethod::Password,
            TokenClass::Session,
            valid_amr(),
            None,
            ts(3600),
            ts(0),
            valid_uuid(4),
        )
        .expect_err("inverted time window must reject");
        assert!(matches!(err, AuthContextError::InvalidTimeWindow));
    }

    #[test]
    fn auth_context_new_rejects_zero_duration() {
        let err = AuthContext::new(
            valid_uuid(1),
            valid_uuid(2),
            valid_uuid(3),
            AuthMethod::Password,
            TokenClass::Session,
            valid_amr(),
            None,
            ts(100),
            ts(100),
            valid_uuid(4),
        )
        .expect_err("zero-duration sessions must reject");
        assert!(matches!(err, AuthContextError::InvalidTimeWindow));
    }

    #[test]
    fn auth_context_accessors_match_constructor_inputs() {
        let ctx = valid_auth_context();
        assert_eq!(ctx.subject_id(), valid_uuid(1));
        assert_eq!(ctx.session_id(), valid_uuid(2));
        assert_eq!(ctx.org_id(), valid_uuid(3));
        assert_eq!(ctx.auth_method(), AuthMethod::Password);
        assert_eq!(ctx.token_class(), TokenClass::Session);
        assert_eq!(ctx.amr(), &["pwd"]);
        assert!(ctx.acr().is_none());
        assert_eq!(ctx.issued_at(), ts(0));
        assert_eq!(ctx.expires_at(), ts(3600));
        assert_eq!(ctx.correlation_id(), valid_uuid(4));
    }

    #[test]
    fn identity_context_new_rejects_nil_uuids() {
        assert!(matches!(
            IdentityContext::new(Uuid::nil(), valid_uuid(2), valid_uuid(3)).unwrap_err(),
            AuthContextError::NilUuid("subject_id")
        ));
        assert!(matches!(
            IdentityContext::new(valid_uuid(1), Uuid::nil(), valid_uuid(3)).unwrap_err(),
            AuthContextError::NilUuid("org_id")
        ));
        assert!(matches!(
            IdentityContext::new(valid_uuid(1), valid_uuid(2), Uuid::nil()).unwrap_err(),
            AuthContextError::NilUuid("correlation_id")
        ));
    }

    #[test]
    fn token_class_prefix_round_trips() {
        assert_eq!(TokenClass::Session.prefix(), "sid_");
        assert_eq!(TokenClass::PersonalAccessToken.prefix(), "pat_");
        assert_eq!(TokenClass::Scim.prefix(), "scim_");
        assert_eq!(TokenClass::Service.prefix(), "svc_");
    }

    #[test]
    fn token_class_from_prefix_recognises_classes() {
        assert_eq!(
            TokenClass::from_prefix("sid_xyz"),
            Some(TokenClass::Session)
        );
        assert_eq!(
            TokenClass::from_prefix("pat_xyz"),
            Some(TokenClass::PersonalAccessToken)
        );
        assert_eq!(TokenClass::from_prefix("scim_xyz"), Some(TokenClass::Scim));
        assert_eq!(
            TokenClass::from_prefix("svc_xyz"),
            Some(TokenClass::Service)
        );
    }

    #[test]
    fn token_class_from_prefix_rejects_malformed() {
        assert!(TokenClass::from_prefix("abc_xxx").is_none());
        assert!(TokenClass::from_prefix("xyz").is_none());
        assert!(TokenClass::from_prefix("").is_none());
    }

    #[test]
    fn raw_token_str_parses_each_class() {
        // Body length 43, all base64url chars.
        let body43 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ";
        for prefix in ["sid_", "pat_", "scim_", "svc_"] {
            let raw = format!("{prefix}{body43}");
            let parsed = RawTokenStr::parse(&raw)
                .unwrap_or_else(|e| panic!("{prefix}+body should parse: {e}"));
            assert_eq!(parsed.body(), body43);
        }
    }

    #[test]
    fn raw_token_str_rejects_bare_prefix() {
        for prefix in ["sid_", "pat_", "scim_", "svc_"] {
            assert!(matches!(
                RawTokenStr::parse(prefix).unwrap_err(),
                AuthError::MalformedPrefix
            ));
        }
    }

    #[test]
    fn raw_token_str_rejects_short_body() {
        assert!(matches!(
            RawTokenStr::parse("sid_short").unwrap_err(),
            AuthError::MalformedPrefix
        ));
    }

    #[test]
    fn raw_token_str_rejects_long_body() {
        let long = format!("sid_{}", "a".repeat(TOKEN_BODY_LEN + 1));
        assert!(matches!(
            RawTokenStr::parse(&long).unwrap_err(),
            AuthError::MalformedPrefix
        ));
    }

    #[test]
    fn raw_token_str_rejects_non_base64url_chars() {
        // 43 chars but with one '!' (outside base64url).
        let mut body = "a".repeat(TOKEN_BODY_LEN);
        body.replace_range(0..1, "!");
        let raw = format!("sid_{body}");
        assert!(matches!(
            RawTokenStr::parse(&raw).unwrap_err(),
            AuthError::MalformedPrefix
        ));
    }

    #[test]
    fn raw_token_str_rejects_unknown_prefix() {
        let body43 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ";
        let raw = format!("xyz_{body43}");
        assert!(matches!(
            RawTokenStr::parse(&raw).unwrap_err(),
            AuthError::MalformedPrefix
        ));
    }

    #[test]
    fn auth_error_internal_carries_chain() {
        use std::io;
        let io_err = io::Error::new(io::ErrorKind::ConnectionRefused, "synthetic");
        let wrapped = AuthError::internal(io_err);
        // `Display` only shows the static label.
        assert_eq!(format!("{wrapped}"), "internal");
        // `Debug` (via thiserror's `#[source]`) keeps the chain.
        let dbg = format!("{wrapped:?}");
        assert!(dbg.contains("ConnectionRefused"));
    }

    #[test]
    fn auth_error_display_does_not_leak_source() {
        use std::io;
        let leaky = io::Error::other("password=hunter2 host=10.0.0.5");
        let wrapped = AuthError::internal(leaky);
        let rendered = format!("{wrapped}");
        assert!(!rendered.contains("hunter2"));
        assert!(!rendered.contains("10.0.0.5"));
    }

    #[test]
    fn auth_method_round_trips_every_variant() {
        // Closed-enum coverage: the exhaustive match below is a
        // compile-time guarantee that every variant is accounted for.
        // When a new variant lands the match becomes non-exhaustive and
        // the test fails to build until the contributor adds it.
        let variants = [
            AuthMethod::Password,
            AuthMethod::Oidc,
            AuthMethod::Saml,
            AuthMethod::ApiToken,
            AuthMethod::ScimToken,
            AuthMethod::ServiceToken,
        ];
        for variant in variants {
            // Drive the exhaustiveness check via match.
            match variant {
                AuthMethod::Password
                | AuthMethod::Oidc
                | AuthMethod::Saml
                | AuthMethod::ApiToken
                | AuthMethod::ScimToken
                | AuthMethod::ServiceToken => {}
            }
            let json = serde_json::to_string(&variant)
                .unwrap_or_else(|e| panic!("serialise {variant:?}: {e}"));
            let parsed: AuthMethod = serde_json::from_str(&json)
                .unwrap_or_else(|e| panic!("deserialise {variant:?}: {e}"));
            assert_eq!(parsed, variant);
        }
    }

    #[test]
    fn token_class_round_trips_every_variant() {
        let variants = [
            TokenClass::Session,
            TokenClass::PersonalAccessToken,
            TokenClass::Scim,
            TokenClass::Service,
        ];
        for variant in variants {
            match variant {
                TokenClass::Session
                | TokenClass::PersonalAccessToken
                | TokenClass::Scim
                | TokenClass::Service => {}
            }
            let json = serde_json::to_string(&variant)
                .unwrap_or_else(|e| panic!("serialise {variant:?}: {e}"));
            let parsed: TokenClass = serde_json::from_str(&json)
                .unwrap_or_else(|e| panic!("deserialise {variant:?}: {e}"));
            assert_eq!(parsed, variant);
        }
    }

    #[test]
    fn auth_context_serialises_only_documented_fields() {
        let ctx = valid_auth_context();
        let v: serde_json::Value =
            serde_json::to_value(&ctx).unwrap_or_else(|e| panic!("serialise AuthContext: {e}"));
        let obj = v
            .as_object()
            .unwrap_or_else(|| panic!("AuthContext must serialise to a JSON object"));
        let keys: std::collections::BTreeSet<_> = obj.keys().map(String::as_str).collect();
        // Session-based auth never populates `scopes`, so the
        // `skip_serializing_if = Vec::is_empty` attribute keeps the
        // session payload identical to the pre-bearer-scope shape.
        let expected: std::collections::BTreeSet<_> = [
            "subject_id",
            "session_id",
            "org_id",
            "auth_method",
            "token_class",
            "amr",
            "acr",
            "expires_at",
            "issued_at",
            "correlation_id",
        ]
        .into_iter()
        .collect();
        assert_eq!(keys, expected, "AuthContext keys must not drift");
        // RBAC fields (roles / permissions) MUST stay out of
        // AuthContext; those derive from membership state and live
        // on the RBAC layer. Token-bound scopes (`scopes`) are
        // permitted but only emitted when the bearer credential
        // populates them (see `auth_context_emits_scopes_when_populated`).
        for forbidden in ["role", "roles", "permissions"] {
            assert!(
                !obj.contains_key(forbidden),
                "AuthContext must not carry RBAC field `{forbidden}`"
            );
        }
        assert!(
            !obj.contains_key("scopes"),
            "session AuthContext must not emit empty `scopes`",
        );
    }

    #[test]
    fn auth_context_emits_scopes_when_populated() {
        let ctx = valid_auth_context().with_scopes(vec!["tokens:read".to_string()]);
        let v: serde_json::Value =
            serde_json::to_value(&ctx).unwrap_or_else(|e| panic!("serialise AuthContext: {e}"));
        let obj = v
            .as_object()
            .unwrap_or_else(|| panic!("AuthContext must serialise to a JSON object"));
        assert!(
            obj.contains_key("scopes"),
            "PAT-style AuthContext must emit `scopes` when populated",
        );
        assert_eq!(obj["scopes"], serde_json::json!(["tokens:read"]));
    }
}
