// SPDX-License-Identifier: AGPL-3.0-or-later

//! Errors produced by the `zagrosi-identity` crate.
//!
//! Per the workspace boundary policy (`zagrosi-core::error`), this is
//! the home for every identity-specific failure introduced across the
//! identity implementation. Downstream layers extend this enum; they
//! MUST NOT extend `ZagrosiError`.
//!
//! The crate skeleton ships only the variants needed for configuration
//! validation. Subsequent layers add hashing, session, OIDC, SAML,
//! SCIM, rate-limit, and email variants alongside their own code.

/// Errors produced by `zagrosi-identity`.
///
/// The `Config` variant holds a boxed [`figment::Error`] to keep the
/// enum itself small (mirrors `zagrosi_core::ZagrosiError::Config`);
/// `figment::Error` is otherwise large enough to bloat every
/// `Result<T, IdentityError>` returned across the workspace.
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    /// Configuration loading or parsing failed.
    #[error("configuration error: {0}")]
    Config(#[source] Box<figment::Error>),

    /// `ZAGROSI_SECRETS_KEY` is required but not present in the
    /// configuration. The 32-byte base64 master key is consumed by the
    /// AES-256-GCM secrets envelope.
    #[error("ZAGROSI_SECRETS_KEY is required (32-byte base64)")]
    MissingSecretsKey,

    /// `ZAGROSI_SECRETS_KEY` is present but malformed. Either it is not
    /// valid base64 or it does not decode to exactly 32 bytes.
    #[error("ZAGROSI_SECRETS_KEY is malformed: {reason}")]
    MalformedSecretsKey {
        /// Human-readable description of the validation failure.
        reason: String,
    },

    /// `ZAGROSI_VALKEY_URL` is required but not present in the
    /// configuration. The URL is consumed by the rate limiter
    /// (the rate-limit module).
    #[error("ZAGROSI_VALKEY_URL is required")]
    MissingValkeyUrl,

    /// AEAD authentication failed (tampered ciphertext, wrong key, or
    /// wrong nonce). The exact failure mode is intentionally not
    /// surfaced — AES-GCM verification is constant-time and disclosing
    /// which check failed would leak side-channel signal to attackers.
    #[error("aead integrity check failed")]
    IntegrityError,

    /// Envelope JSON is well-formed but a field is malformed (non-base64,
    /// wrong byte length, etc.). Carries a `&'static str` reason so the
    /// caller can branch on the cause without leaking attacker-supplied
    /// content into log surfaces.
    #[error("malformed secrets envelope: {0}")]
    MalformedEnvelope(&'static str),

    /// Envelope has a `key_id` not handled by this provider. v0.1 only
    /// handles [`crate::crypto::KEY_ID_V0_1_STATIC`]; future KMS
    /// provider handles `v0.2-kms-*`. Returning this variant (rather
    /// than [`IdentityError::IntegrityError`]) is the documented
    /// routing point for the future KMS layer's rewrap.
    #[error("unknown envelope key_id: {0}")]
    UnknownKeyId(String),

    /// Database / persistence error from the `sqlx` driver. The wrapped
    /// `sqlx::Error` carries the full diagnostic chain (Postgres SQLSTATE,
    /// operation, etc.) for log surfaces. Boxed to keep the enum small —
    /// `sqlx::Error` is otherwise large enough to bloat every
    /// `Result<T, IdentityError>` returned across repo call-sites.
    #[error("database error: {0}")]
    Database(#[source] Box<sqlx::Error>),

    /// HTTP response construction failed because a generated header
    /// value contained bytes that cannot be represented in an HTTP
    /// header. This is an internal invariant breach, never a caller
    /// validation failure.
    #[error("response header malformed: {reason}")]
    ResponseHeaderMalformed {
        /// Human-readable description of the malformed generated
        /// header.
        reason: String,
    },

    /// Raw token string failed prefix / body validation. Domain-layer
    /// `domain::token_format::parse_raw` is the single chokepoint; this
    /// variant is returned rather than the gateway-facing
    /// `zagrosi_core::AuthError::MalformedPrefix` so identity-internal
    /// flows (password reset, email verification) can branch on it
    /// without depending on the gateway port.
    #[error("malformed token: {0}")]
    MalformedToken(&'static str),

    /// `find_by_email_lower` looked up an address that does not match a
    /// live (`deleted_at IS NULL`) row. Used by repo callers that want
    /// to return a typed not-found rather than `Option`.
    #[error("user not found")]
    UserNotFound,

    /// `OrgRepo` lookup did not match a live row.
    #[error("organisation not found")]
    OrgNotFound,

    /// Token-hash lookup did not match a live row across sessions /
    /// PATs / SCIM tokens / refresh tokens / service tokens. Callers
    /// log this at `info` not `warn` — the bulk of these are scanners.
    #[error("token not found")]
    TokenNotFound,

    /// `UserRepo::create` (or membership create) hit the partial unique
    /// index on `email_lower` for a live user. Mapped from PG SQLSTATE
    /// `23505` against the relevant constraint name.
    #[error("email address already in use")]
    EmailAlreadyExists,

    /// `OrgRepo::create` hit the live-row unique partial index on `slug`.
    #[error("organisation slug already in use")]
    OrgSlugAlreadyExists,

    /// `MembershipRepo::create` hit the live-row partial unique on
    /// `(user_id, org_id)`. Distinct from `EmailAlreadyExists` so the
    /// password-auth org-join flow can branch on it cleanly.
    #[error("membership already exists")]
    MembershipAlreadyExists,

    /// `oidc_refresh_tokens` chain replay — a refresh token already
    /// marked `used_at IS NOT NULL` was redeemed again. The OIDC client
    /// translates this into a chain-wide revocation.
    #[error("oidc refresh-chain replay detected")]
    RefreshChainReplay,

    /// `saml_assertion_replay` PK collision — the same assertion ID
    /// landed twice for the same `org_idp_id`. The SAML SP translates
    /// this into an authentication failure.
    #[error("saml assertion replay detected")]
    AssertionReplay,

    /// `federated_identities` anchor `(protocol, iss, sub)` is taken
    /// by a tombstoned (`user_id` NULL) row. The legal re-attachment
    /// path is the admin merge flow (deferred to the admin layer).
    #[error("federated identity is tombstoned (admin merge required)")]
    FederatedIdentityTombstoned,

    /// `SessionRepo::update_active_org` lost the optimistic-lock
    /// race — the row's `version` no longer matches the caller's.
    /// The session module retries on this variant.
    #[error("optimistic lock conflict")]
    OptimisticLockConflict,

    /// Argon2id startup verify-bench exceeded 1.5 s; the configured
    /// profile would brown out under load. Binary refuses to start.
    #[error("argon2 profile too slow ({measured_ms}ms > 1500ms); refusing to start")]
    Argon2ProfileTooSlow {
        /// Measured verify-bench duration in milliseconds.
        measured_ms: u64,
    },

    /// Argon2id hash / verify failed at the algorithm layer (malformed
    /// PHC string, parameter mismatch). Distinct from `InvalidCredentials`
    /// because this is an internal failure, not a wrong-password branch.
    #[error("argon2 internal error: {0}")]
    Argon2Internal(&'static str),

    /// Submitted password is shorter than `IdentityConfig::password.min_length`.
    #[error("password too short (minimum {min} chars)")]
    PasswordTooShort {
        /// Minimum accepted password length.
        min: usize,
    },

    /// Submitted password exceeds the hard-coded 256-char `DoS` guard.
    #[error("password too long (maximum {max} chars)")]
    PasswordTooLong {
        /// Maximum accepted password length.
        max: usize,
    },

    /// Submitted password appears in the HIBP breach corpus.
    #[error("password appears in known-breach corpus")]
    PasswordBreached,

    /// HIBP service unreachable while mode is `online`. Sign-up
    /// fail-closes; surface a `Retry-After` to the caller.
    #[error("breach-list service unavailable; please retry")]
    BreachlistUnavailable,

    /// Sign-in credentials invalid. Constant-time path; the variant
    /// MUST NOT disclose whether the email or password was wrong.
    #[error("invalid credentials")]
    InvalidCredentials,

    /// User exists but cannot sign in (soft-deleted, locked, etc.).
    #[error("account disabled")]
    AccountDisabled,

    /// User exists but has not verified their email.
    #[error("email not verified")]
    EmailNotVerified,

    /// Single-use token (verification or reset) is past `expires_at`.
    #[error("token expired")]
    TokenExpired,

    /// Single-use token already consumed (`used_at IS NOT NULL`).
    #[error("token already used")]
    TokenAlreadyUsed,

    /// Token prefix does not match the expected class. Defence-in-depth
    /// pre-check; the prefix is part of the hash so the lookup would
    /// already fail without matching the right token table.
    #[error("token prefix mismatch (expected {expected})")]
    TokenPrefixMismatch {
        /// Expected prefix string (e.g. `"vrf_"`).
        expected: &'static str,
    },

    /// Email address malformed or unparseable.
    #[error("invalid email")]
    InvalidEmail,

    /// Rate-limit configuration failed validation at startup. The reason
    /// is a human-readable description of the violated invariant
    /// (malformed `<count>/<window>` literal, zero / out-of-range
    /// numeric, etc.).
    #[error("rate-limit configuration is malformed: {reason}")]
    MalformedRateLimit {
        /// Human-readable description of the validation failure.
        reason: String,
    },

    /// Session-resolver configuration failed validation at startup.
    /// Carries a human-readable description of the violated
    /// invariant (zero / out-of-range numeric, fail-closed TTL
    /// exceeding the healthy TTL, empty NATS URL when fail-closed
    /// is required, etc.).
    #[error("session configuration is malformed: {reason}")]
    MalformedSessionConfig {
        /// Human-readable description of the validation failure.
        reason: String,
    },

    /// Sliding-window per-IP / per-token bucket exhausted. `retry_after`
    /// populates the `Retry-After` header; `scope` identifies the
    /// bucket (sign-in, password reset, SCIM, etc.) for telemetry.
    #[error("rate limit exceeded for {scope}; retry in {retry_after:?}")]
    RateLimited {
        /// Wall-clock duration the caller should wait before retrying.
        retry_after: std::time::Duration,
        /// Bucket scope tag (`signin` / `password_reset` / `scim` / ...).
        scope: &'static str,
    },

    /// Per-account exponential lockout active. `retry_after` populates
    /// the `Retry-After` header; `attempts` is the breach count for
    /// telemetry.
    #[error("account locked out for {retry_after:?} after {attempts} failed attempts")]
    LockedOut {
        /// Wall-clock duration until the lockout expires.
        retry_after: std::time::Duration,
        /// Breach count for telemetry.
        attempts: u32,
    },

    /// Valkey backend unavailable. Sign-in / password-reset / SCIM
    /// endpoints fail closed: a 503 Service Unavailable surface is
    /// preferable to silently dropping rate-limit enforcement.
    #[error("rate-limit backend unavailable: {0}")]
    RateLimiterUnavailable(String),

    /// Caller submitted a malformed personal-access-token request
    /// body (empty / over-long display name, `expires_at` in the past,
    /// etc.). The reason is a human-readable description suitable for
    /// surfacing in the response body. It MUST NOT contain the
    /// raw token bytes or any other secret.
    #[error("invalid api-token request: {reason}")]
    InvalidApiTokenRequest {
        /// Human-readable description of the violated invariant.
        reason: String,
    },

    /// Personal-access-token scope string is not in the v0.1 catalogue
    /// (`tokens:read`, `tokens:write`, `me:read`). The bad scope
    /// string is echoed back so the SPA can highlight the offending
    /// chip.
    #[error("invalid scope: {scope}")]
    InvalidScope {
        /// Echo of the rejected scope string.
        scope: String,
    },

    /// Caller's auth context lacks the scope required to perform this
    /// action. The needed scope name is surfaced so the SPA can prompt
    /// the user to mint a new token with the necessary scope.
    #[error("insufficient scope; required: {needed}")]
    InsufficientScope {
        /// Scope string the caller would need.
        needed: &'static str,
    },

    /// OIDC start: no enabled OIDC `IdP` found for the requested org.
    /// Returned as `404 not_found` so cross-org probes do not leak the
    /// existence of an org without an OIDC `IdP` configured.
    #[error("no enabled oidc idp for org")]
    OidcIdpNotFound,

    /// OIDC start: more than one enabled OIDC `IdP` and the caller did not
    /// disambiguate via the `?domain=...` query parameter. Returns
    /// `400 idp_ambiguous` so the SPA can re-prompt with a domain hint.
    #[error("oidc idp selection ambiguous")]
    OidcAmbiguousIdp,

    /// OIDC config validation failed (issuer URL malformed, scopes
    /// missing `openid`, JWKS thumbprint not 64-hex, etc.). Reason is
    /// surfaced verbatim to admin callers; never reaches end users.
    #[error("oidc config invalid: {reason}")]
    OidcConfigInvalid {
        /// Human-readable description of the violated invariant.
        reason: String,
    },

    /// OIDC callback: `__Host-zagrosi_oidc` cookie absent. Treated as a
    /// state-mismatch from the auditor's perspective so attackers cannot
    /// distinguish a missing cookie from a forged state.
    #[error("oidc cookie missing")]
    OidcCookieMissing,

    /// OIDC callback: cookie present but envelope failed to open or its
    /// inner JSON shape is malformed. Mapped to the same generic
    /// callback-failed surface as `OidcStateMismatch`.
    #[error("oidc cookie malformed: {0}")]
    OidcCookieMalformed(&'static str),

    /// OIDC callback: query `state` parameter has no matching live
    /// pending row, OR the row's stored hashes do not constant-time
    /// match the cookie-carried raw values. Both sub-causes surface as
    /// the same enum variant so the auditor receives a single signal
    /// for the family without giving the attacker an oracle.
    #[error("oidc state mismatch")]
    OidcStateMismatch,

    /// OIDC callback: matching pending row already has `used_at IS NOT
    /// NULL`. Distinct audit signal so ops dashboards can spot replay
    /// attacks (vs. ordinary state errors).
    #[error("oidc callback replay")]
    OidcReplay,

    /// OIDC callback: pending row past `expires_at`. Auth window
    /// closed; caller restarts the flow.
    #[error("oidc pending expired")]
    OidcExpired,

    /// OIDC callback: RFC 9207 `iss` query parameter does not
    /// constant-time match the pinned issuer URL. Defends against the
    /// IdP-mix-up family of attacks.
    #[error("oidc iss mismatch")]
    OidcIssMismatch,

    /// OIDC callback: ID-token validation failed (signature, `iss`,
    /// `aud`, `azp`, `exp`, `iat`, `nonce`, `at_hash`, `c_hash`). The
    /// public surface is uniform; the audit event carries an internal
    /// sub-reason.
    #[error("oidc id token invalid: {0}")]
    OidcIdTokenInvalid(&'static str),

    /// OIDC callback: discovery JWKS document SHA-256 thumbprint does
    /// not match `org_idps.config.expected_jwks_thumbprint`.
    /// Defence-in-depth pin against compromised discovery.
    #[error("oidc jwks thumbprint mismatch")]
    OidcJwksThumbprintMismatch,

    /// OIDC JIT: the `IdP` issued an ID token whose `email_verified` is
    /// not `true` and the per-IdP override `allow_unverified_email_jit`
    /// is `false` (default). Caller must verify their email at the `IdP`
    /// before sign-in is permitted.
    #[error("oidc email not verified at idp")]
    OidcEmailNotVerified,

    /// OIDC JIT: a live `users` row already exists for the ID token's
    /// `email_lower` but the SSO anchor `(iss, sub)` is fresh. Refuses
    /// to auto-merge (admin-link required).
    #[error("oidc account already exists; admin link required")]
    OidcAccountAlreadyExists,

    /// OIDC: discovery / JWKS / token-endpoint HTTP exchange failed.
    /// The wrapped reason is `&'static str` so attacker-controlled
    /// detail never reaches log surfaces; the underlying error is logged
    /// once via `tracing::warn` at the call-site.
    #[error("oidc upstream failure: {0}")]
    OidcDiscoveryFailed(&'static str),

    /// OIDC JIT: the per-IdP `jit_provisioning` toggle is `false` and
    /// the federated-identities anchor is not (yet) linked. The user
    /// cannot sign in via SSO without admin onboarding. Distinct from
    /// `OidcStateMismatch` so the audit classifier routes this to the
    /// `signin_failed` family (admin-policy denial, not state forgery).
    #[error("oidc jit provisioning disabled")]
    OidcJitDisabled,

    /// SCIM `Group` resource not found in the caller's tenant scope.
    /// Cross-org IDs map to this variant — never `Forbidden` — so
    /// status-code probes cannot leak existence across tenants.
    #[error("scim group not found")]
    GroupNotFound,

    /// SCIM `Group.displayName` already in use within the caller's
    /// org. Mapped to `409 uniqueness` by the SCIM error envelope.
    #[error("scim group displayName already in use")]
    GroupDisplayNameExists,

    /// SCIM `If-Match` precondition failed — the caller's `ETag` does
    /// not match the row's current `(updated_at, row_version)` pair.
    /// Mapped to `412 precondition failed` by the SCIM error envelope.
    #[error("scim precondition failed")]
    ScimPreconditionFailed,

    /// Multi-IdP routing: caller submitted a domain that fails shape
    /// validation (empty, too long, illegal characters, idna-rejected,
    /// or otherwise unparseable). The `reason` is suitable for
    /// surfacing in the response body.
    #[error("invalid domain: {reason}")]
    InvalidDomain {
        /// Human-readable description of the violated invariant.
        reason: String,
    },

    /// Multi-IdP routing: domain-create / verify rejected because the
    /// domain is on the public-suffix list or curated catch-all
    /// blocklist. Distinct from [`IdentityError::InvalidDomain`] so
    /// the SPA can surface a tailored error chip.
    #[error("public email-domain cannot be claimed")]
    PublicEmailDomainCannotBeClaimed,

    /// Multi-IdP routing: DNS TXT verification failed (DNSSEC
    /// validation rejected, NXDOMAIN, SERVFAIL, no matching TXT,
    /// resolvers disagreed, or timeout). The `reason` is the
    /// `VerifyFailure` discriminator name; safe for callers to
    /// branch on.
    #[error("domain verification failed: {reason}")]
    DomainVerificationFailed {
        /// Stable failure-mode discriminator (`dnssec_bogus`,
        /// `nx_domain`, `serv_fail`, `no_matching_txt`,
        /// `resolver_disagreement`, `timeout`).
        reason: &'static str,
    },

    /// Multi-IdP routing: `IdentityConfig::dns` failed startup
    /// validation. Carries a human-readable description.
    #[error("dns configuration is malformed: {reason}")]
    MalformedDnsConfig {
        /// Human-readable description of the violated invariant.
        reason: String,
    },

    /// Email-outbox worker: `IdentityConfig::email` failed validation
    /// at [`crate::email::LettreTransport::from_config`] time (empty
    /// URL, non-`smtps://` scheme, unparseable URL, or empty
    /// `smtp_from`). Carries a human-readable description; it never
    /// includes the credentialed SMTP URL. Worker-construction-time
    /// only — never reaches an end-user HTTP surface.
    #[error("email transport configuration is malformed: {reason}")]
    EmailTransportConfig {
        /// Human-readable description of the violated invariant.
        reason: String,
    },

    /// Service-token issuance request failed validation (empty /
    /// malformed `service_name`, empty `allowed_subjects`, a subject
    /// pattern outside the permitted charset, or empty / over-long
    /// `display_name`). The `reason` is safe to surface in the
    /// response body — it never contains the raw token.
    #[error("invalid service-token request: {reason}")]
    InvalidServiceTokenRequest {
        /// Human-readable description of the violated invariant.
        reason: String,
    },
}

impl From<zagrosi_core::RateLimiterError> for IdentityError {
    fn from(err: zagrosi_core::RateLimiterError) -> Self {
        // The error enum is `#[non_exhaustive]`; future variants are
        // mapped onto `RateLimiterUnavailable` so the auth fail-closed
        // contract still holds when `zagrosi-core` adds new failure
        // shapes (timeout, partition, etc.).
        match err {
            zagrosi_core::RateLimiterError::Backend(msg) => Self::RateLimiterUnavailable(msg),
            other => Self::RateLimiterUnavailable(other.to_string()),
        }
    }
}

impl From<zagrosi_core::BreachListError> for IdentityError {
    fn from(_: zagrosi_core::BreachListError) -> Self {
        // Every failure mode of the lookup surfaces to the password
        // flow as `BreachlistUnavailable`. The password-auth design mandates
        // fail-closed when mode is `online`; consumers that opt into
        // `disabled` mode short-circuit before this conversion is
        // reachable.
        Self::BreachlistUnavailable
    }
}

impl From<argon2::Error> for IdentityError {
    fn from(_: argon2::Error) -> Self {
        Self::Argon2Internal("argon2 hash/verify failed")
    }
}

impl From<argon2::password_hash::Error> for IdentityError {
    fn from(err: argon2::password_hash::Error) -> Self {
        if matches!(err, argon2::password_hash::Error::Password) {
            Self::InvalidCredentials
        } else {
            Self::Argon2Internal("argon2 password-hash error")
        }
    }
}

impl From<figment::Error> for IdentityError {
    fn from(err: figment::Error) -> Self {
        Self::Config(Box::new(err))
    }
}

impl From<sqlx::Error> for IdentityError {
    fn from(err: sqlx::Error) -> Self {
        Self::Database(Box::new(err))
    }
}

/// Postgres SQLSTATE for unique-violation. See `repo::map_sqlx_error`.
const SQLSTATE_UNIQUE_VIOLATION: &str = "23505";

/// Postgres SQLSTATE for foreign-key violation. See `repo::map_sqlx_error`.
#[allow(dead_code)] // surfaced once the OIDC client lands refresh-chain FK checks.
const SQLSTATE_FOREIGN_KEY_VIOLATION: &str = "23503";

/// Map a `sqlx::Error` into a domain-classified [`IdentityError`].
///
/// Resolution rules:
/// - `RowNotFound` → caller-supplied `not_found` (e.g.
///   [`IdentityError::TokenNotFound`] or [`IdentityError::UserNotFound`]).
/// - `Database(pg)` with `SQLSTATE 23505` (unique violation) AND a
///   constraint name matching `unique_constraint` (when the caller
///   supplied one) → `unique`. When `unique_constraint` is `None`, any
///   23505 maps to `unique` (legacy behaviour, used only by repos
///   whose insert can hit exactly one unique index).
/// - any other error → [`IdentityError::Database`] verbatim.
///
/// Repo call-sites pre-bind the variant they want and the constraint
/// name they expect, keeping the mapping table local to the query
/// without leaking PG specifics into the public surface. Restricting
/// the mapping by constraint name defends against PK collisions or
/// secondary-index conflicts being silently misclassified as a
/// caller-domain conflict.
pub(crate) fn map_sqlx_error(
    err: sqlx::Error,
    not_found: IdentityError,
    unique: IdentityError,
    unique_constraint: Option<&str>,
) -> IdentityError {
    if matches!(err, sqlx::Error::RowNotFound) {
        return not_found;
    }
    if let sqlx::Error::Database(ref db_err) = err
        && db_err.code().as_deref() == Some(SQLSTATE_UNIQUE_VIOLATION)
    {
        let constraint_match =
            unique_constraint.is_none_or(|expected| db_err.constraint() == Some(expected));
        if constraint_match {
            return unique;
        }
    }
    IdentityError::from(err)
}

/// Crate-wide result type defaulting to [`IdentityError`].
pub type Result<T, E = IdentityError> = std::result::Result<T, E>;

impl axum::response::IntoResponse for IdentityError {
    #[allow(clippy::too_many_lines)] // taxonomic match is one big switch by design
    fn into_response(self) -> axum::response::Response {
        use axum::http::StatusCode;

        let (status, retry_after_secs): (StatusCode, Option<u32>) = match &self {
            // Client-side validation failures.
            Self::PasswordTooShort { .. }
            | Self::PasswordTooLong { .. }
            | Self::PasswordBreached
            | Self::InvalidEmail
            | Self::TokenPrefixMismatch { .. }
            | Self::TokenExpired
            | Self::TokenAlreadyUsed
            | Self::MalformedToken(_)
            | Self::InvalidApiTokenRequest { .. }
            | Self::InvalidServiceTokenRequest { .. }
            | Self::InvalidScope { .. }
            | Self::OidcAmbiguousIdp
            | Self::OidcConfigInvalid { .. }
            | Self::InvalidDomain { .. }
            | Self::PublicEmailDomainCannotBeClaimed => (StatusCode::BAD_REQUEST, None),

            // 422 — semantic-validation failures the request shape was
            // syntactically right but the operation could not complete
            // (e.g. DNS TXT verification rejected). Distinct from 400
            // so the SPA can branch ("retry verify" vs "fix the form").
            Self::DomainVerificationFailed { .. } => (StatusCode::UNPROCESSABLE_ENTITY, None),

            // Authentication failures (deliberately uniform — never
            // disclose which sub-cause). The OIDC callback failures
            // share the same uniform surface so an attacker cannot
            // distinguish "wrong state" from "wrong nonce" from "wrong
            // signature" from "expired pending row" — every branch
            // returns the same `unauthorized` envelope; sub-cause
            // lands in the audit event only. `OidcEmailNotVerified`
            // and `OidcJitDisabled` collapse onto the same envelope so
            // an attacker cannot enumerate which IdP marks an account
            // unverified or which org has JIT off.
            Self::InvalidCredentials
            | Self::AccountDisabled
            | Self::EmailNotVerified
            | Self::OidcCookieMissing
            | Self::OidcCookieMalformed(_)
            | Self::OidcStateMismatch
            | Self::OidcReplay
            | Self::OidcExpired
            | Self::OidcIssMismatch
            | Self::OidcIdTokenInvalid(_)
            | Self::OidcJwksThumbprintMismatch
            | Self::OidcEmailNotVerified
            | Self::OidcJitDisabled
            | Self::OidcDiscoveryFailed(_) => (StatusCode::UNAUTHORIZED, None),

            // Insufficient scope: caller is authenticated but lacks
            // the required capability for the route.
            Self::InsufficientScope { .. } => (StatusCode::FORBIDDEN, None),

            // Conflict / state surface. `OidcAccountAlreadyExists` is
            // the documented exception to the uniform OIDC failure
            // shape: callers MUST receive `account_already_exists` so
            // the support workflow (admin merge) can fire.
            Self::EmailAlreadyExists
            | Self::OrgSlugAlreadyExists
            | Self::MembershipAlreadyExists
            | Self::FederatedIdentityTombstoned
            | Self::AssertionReplay
            | Self::RefreshChainReplay
            | Self::OptimisticLockConflict
            | Self::OidcAccountAlreadyExists
            | Self::GroupDisplayNameExists => (StatusCode::CONFLICT, None),

            // Precondition (`If-Match`) failed. Surfaces from the SCIM
            // ETag concurrency-control path; reaching the standard
            // identity envelope is a misroute (SCIM handlers convert
            // to `ScimError` first), but the safe default keeps the
            // status code authoritative when leaks occur.
            Self::ScimPreconditionFailed => (StatusCode::PRECONDITION_FAILED, None),

            // Resource not found.
            Self::UserNotFound
            | Self::OrgNotFound
            | Self::TokenNotFound
            | Self::OidcIdpNotFound
            | Self::GroupNotFound => (StatusCode::NOT_FOUND, None),

            // Service unavailable — surface a Retry-After. Both the
            // breach-list outage and a Valkey-backed rate-limit outage
            // emit the same shape: 503 + 60-second hint.
            Self::BreachlistUnavailable | Self::RateLimiterUnavailable(_) => {
                (StatusCode::SERVICE_UNAVAILABLE, Some(60))
            }

            // Rate-limited — surface a Retry-After computed from the
            // bucket's wall-clock reset rounded up to the nearest
            // whole second (RFC 6585).
            Self::RateLimited { retry_after, .. } | Self::LockedOut { retry_after, .. } => (
                StatusCode::TOO_MANY_REQUESTS,
                Some(retry_after_secs_rounded_up(*retry_after)),
            ),

            // Internal errors that MUST NOT reach the client verbatim.
            Self::Config(_)
            | Self::MissingSecretsKey
            | Self::MalformedSecretsKey { .. }
            | Self::MissingValkeyUrl
            | Self::IntegrityError
            | Self::MalformedEnvelope(_)
            | Self::UnknownKeyId(_)
            | Self::Database(_)
            | Self::ResponseHeaderMalformed { .. }
            | Self::Argon2ProfileTooSlow { .. }
            | Self::Argon2Internal(_)
            | Self::MalformedRateLimit { .. }
            | Self::MalformedSessionConfig { .. }
            | Self::MalformedDnsConfig { .. }
            | Self::EmailTransportConfig { .. } => (StatusCode::INTERNAL_SERVER_ERROR, None),
        };

        let code = match self {
            Self::InvalidScope { .. } => "invalid_scope",
            Self::InsufficientScope { .. } => "insufficient_scope",
            Self::InvalidApiTokenRequest { .. } | Self::InvalidServiceTokenRequest { .. } => {
                "invalid_request"
            }
            Self::OidcAmbiguousIdp => "idp_ambiguous",
            Self::OidcConfigInvalid { .. } => "oidc_config_invalid",
            Self::OidcAccountAlreadyExists => "account_already_exists",
            Self::InvalidDomain { .. } => "invalid_domain",
            Self::PublicEmailDomainCannotBeClaimed => "public_email_domain_cannot_be_claimed",
            Self::DomainVerificationFailed { .. } => "verification_failed",
            // `OidcEmailNotVerified` no longer leaks via a distinct
            // public code; collapsed onto `oidc_callback_failed` so
            // attackers cannot enumerate "this IdP marks this account
            // unverified" as a side channel. Audit `sub_reason` still
            // distinguishes for ops dashboards.
            Self::OidcEmailNotVerified
            | Self::OidcJitDisabled
            | Self::OidcCookieMissing
            | Self::OidcCookieMalformed(_)
            | Self::OidcStateMismatch
            | Self::OidcReplay
            | Self::OidcExpired
            | Self::OidcIssMismatch
            | Self::OidcIdTokenInvalid(_)
            | Self::OidcJwksThumbprintMismatch
            | Self::OidcDiscoveryFailed(_) => "oidc_callback_failed",
            _ => match status {
                StatusCode::BAD_REQUEST => "bad_request",
                StatusCode::UNAUTHORIZED => "unauthorized",
                StatusCode::FORBIDDEN => "forbidden",
                StatusCode::CONFLICT => "conflict",
                StatusCode::NOT_FOUND => "not_found",
                StatusCode::PRECONDITION_FAILED => "precondition_failed",
                StatusCode::UNPROCESSABLE_ENTITY => "unprocessable_entity",
                StatusCode::SERVICE_UNAVAILABLE => "service_unavailable",
                StatusCode::TOO_MANY_REQUESTS => "rate_limited",
                _ => "internal_error",
            },
        };
        let body = serde_json::json!({
            "error": {
                "code": code,
                "message": status_message(status),
            }
        });

        let mut response = (status, axum::Json(body)).into_response();
        if let Some(secs) = retry_after_secs
            && let Ok(value) = axum::http::HeaderValue::from_str(&secs.to_string())
        {
            response
                .headers_mut()
                .insert(axum::http::header::RETRY_AFTER, value);
        }
        response
    }
}

const fn status_message(status: axum::http::StatusCode) -> &'static str {
    match status {
        axum::http::StatusCode::BAD_REQUEST => "request rejected",
        axum::http::StatusCode::UNAUTHORIZED => "authentication failed",
        axum::http::StatusCode::FORBIDDEN => "forbidden",
        axum::http::StatusCode::CONFLICT => "resource conflict",
        axum::http::StatusCode::NOT_FOUND => "not found",
        axum::http::StatusCode::PRECONDITION_FAILED => "precondition failed",
        axum::http::StatusCode::UNPROCESSABLE_ENTITY => "verification failed",
        axum::http::StatusCode::SERVICE_UNAVAILABLE => "temporarily unavailable",
        axum::http::StatusCode::TOO_MANY_REQUESTS => "rate limit exceeded",
        _ => "internal error",
    }
}

/// Round a [`std::time::Duration`] up to the next whole second so the
/// `Retry-After` header never advises a value that is too small to
/// satisfy the underlying bucket reset.
fn retry_after_secs_rounded_up(d: std::time::Duration) -> u32 {
    let secs = d.as_secs();
    let extra = u64::from(d.subsec_nanos() != 0);
    let total = secs.saturating_add(extra);
    u32::try_from(total).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use static_assertions::assert_impl_all;

    assert_impl_all!(IdentityError: Send, Sync);

    #[test]
    fn display_renders_missing_secrets_key() {
        let err = IdentityError::MissingSecretsKey;
        let rendered = format!("{err}");
        assert!(rendered.contains("ZAGROSI_SECRETS_KEY"));
        assert!(rendered.contains("32-byte base64"));
    }

    #[test]
    fn display_renders_malformed_secrets_key_with_reason() {
        let err = IdentityError::MalformedSecretsKey {
            reason: "not valid base64".into(),
        };
        let rendered = format!("{err}");
        assert!(rendered.contains("malformed"));
        assert!(rendered.contains("not valid base64"));
    }

    #[test]
    fn display_renders_missing_valkey_url() {
        let err = IdentityError::MissingValkeyUrl;
        let rendered = format!("{err}");
        assert!(rendered.contains("ZAGROSI_VALKEY_URL"));
    }

    #[test]
    fn display_renders_config_variant() {
        let figment_err = figment::Error::from("synthetic figment failure".to_string());
        let err = IdentityError::Config(Box::new(figment_err));
        let rendered = format!("{err}");
        assert!(rendered.starts_with("configuration error:"));
    }

    #[test]
    fn debug_renders_for_all_variants() {
        let _ = format!("{:?}", IdentityError::MissingSecretsKey);
        let _ = format!(
            "{:?}",
            IdentityError::MalformedSecretsKey { reason: "x".into() }
        );
        let _ = format!("{:?}", IdentityError::MissingValkeyUrl);
        let figment_err = figment::Error::from("x".to_string());
        let _ = format!("{:?}", IdentityError::Config(Box::new(figment_err)));
    }

    #[test]
    fn from_figment_error_produces_config_variant() {
        let figment_err = figment::Error::from("boom".to_string());
        let identity_err: IdentityError = figment_err.into();
        match identity_err {
            IdentityError::Config(_) => {}
            other => panic!("expected Config variant, got {other:?}"),
        }
    }

    #[test]
    fn result_alias_uses_identity_error_default() {
        fn returns_result() -> Result<u32> {
            Err(IdentityError::MissingSecretsKey)
        }
        assert!(returns_result().is_err());
    }
}
