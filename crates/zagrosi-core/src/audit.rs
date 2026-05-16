// SPDX-License-Identifier: AGPL-3.0-or-later

//! Audit port + versioned event envelope.
//!
//! Identity emits events via [`Auditor`]; the `PostgresAuditor` impl
//! lives in the tenant-isolation layer's `zagrosi-audit` crate. The
//! default impl shipped here is [`NoopAuditor`] so wiring works before the
//! audit crate lands.
//!
//! [`AuditEvent`] is a versioned envelope. v0.1 only ships [`AuditEventV1`];
//! future fields land via an additive `AuditEventV2` variant rather than by
//! editing v1, preserving forward compatibility for downstream audit storage.
//!
//! ## Wire-shape lock
//!
//! The envelope discriminator is the *string* `"schema_version": "1"`, not
//! a numeric `1`. Downstream consumers (Postgres JSONB readers, log shippers)
//! rely on the discriminator type being stable; the `audit_event_envelope_*`
//! tests below regression-guard against the type drifting to an integer.

use std::fmt;
use std::net::IpAddr;

use async_trait::async_trait;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Sink for identity-emitted audit events.
///
/// Implementations must be cheap to clone (or `Arc`-wrapped) so handlers
/// can call them on the hot request path. Identity rate-limits noisy
/// events (e.g. failed sign-in aggregation) before invoking the sink.
#[async_trait]
pub trait Auditor: Send + Sync + 'static {
    /// Record an event. Implementations are best-effort; failure must not
    /// propagate to the caller.
    async fn record(&self, event: AuditEvent);
}

/// Versioned audit-event envelope.
///
/// [`AuditEventV1`] is the v0.1 wire shape. Future `AuditEventV2` lands as
/// a new variant; consumers that only know v1 should treat unknown
/// variants as opaque (the tenant-isolation layer owns the deserialisation strategy).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "schema_version")]
#[non_exhaustive]
pub enum AuditEvent {
    /// v1 event payload.
    #[serde(rename = "1")]
    V1(AuditEventV1),
}

/// Maximum drift allowed between caller-supplied `AuditEventV1::occurred_at`
/// and host wall-clock.
///
/// Five seconds matches the industry-standard tolerance for distributed
/// event emission; a wider window enables forensic-timeline forgery.
pub const AUDIT_OCCURRED_AT_TOLERANCE_SECS: i64 = 5;

/// v1 audit-event payload.
///
/// Fields are private to enforce construction invariants via
/// [`AuditEventV1::new`] / [`AuditEventV1::new_at`]. Read access goes through
/// accessor methods. Serde derive remains in place for cross-process replay
/// (e.g. JSONB column round-trip in the upcoming `PostgresAuditor`).
#[derive(Clone, Serialize, Deserialize)]
pub struct AuditEventV1 {
    event_id: Uuid,
    event_kind: AuditEventKind,
    actor: AuditActor,
    resource: AuditResource,
    correlation_id: Uuid,
    occurred_at: DateTime<Utc>,
    org_id: Uuid,
    payload: AuditPayload,
}

impl AuditEventV1 {
    /// Construct a fresh v1 audit event, clamping `occurred_at` to
    /// `Utc::now()`. This is the recommended constructor for production
    /// code: it removes any caller-supplied wall-clock value entirely.
    #[must_use]
    pub fn new(
        event_kind: AuditEventKind,
        actor: AuditActor,
        resource: AuditResource,
        correlation_id: Uuid,
        org_id: Uuid,
        payload: AuditPayload,
    ) -> Self {
        Self {
            event_id: Uuid::now_v7(),
            event_kind,
            actor,
            resource,
            correlation_id,
            occurred_at: Utc::now(),
            org_id,
            payload,
        }
    }

    /// Construct a v1 audit event with a caller-supplied `occurred_at`,
    /// rejecting timestamps that drift more than
    /// [`AUDIT_OCCURRED_AT_TOLERANCE_SECS`] seconds from `Utc::now()`. Used
    /// by tests + by integration paths that bridge an upstream clock
    /// (e.g. an external `IdP` attestation timestamp the gateway did not
    /// synthesise).
    ///
    /// # Errors
    ///
    /// Returns [`AuditEventError::OccurredAtSkew`] when the caller's
    /// `occurred_at` is more than `AUDIT_OCCURRED_AT_TOLERANCE_SECS`
    /// seconds away from `Utc::now()` in either direction.
    #[allow(clippy::too_many_arguments)]
    pub fn new_at(
        event_id: Uuid,
        event_kind: AuditEventKind,
        actor: AuditActor,
        resource: AuditResource,
        correlation_id: Uuid,
        occurred_at: DateTime<Utc>,
        org_id: Uuid,
        payload: AuditPayload,
    ) -> Result<Self, AuditEventError> {
        let now = Utc::now();
        let diff = (now - occurred_at).num_seconds().saturating_abs();
        if diff > AUDIT_OCCURRED_AT_TOLERANCE_SECS {
            return Err(AuditEventError::OccurredAtSkew {
                drift_secs: diff,
                tolerance_secs: AUDIT_OCCURRED_AT_TOLERANCE_SECS,
            });
        }
        Ok(Self {
            event_id,
            event_kind,
            actor,
            resource,
            correlation_id,
            occurred_at,
            org_id,
            payload,
        })
    }

    /// Construct an event without clock-skew validation. Restricted to
    /// `#[cfg(test)]` so production code cannot instantiate audit events
    /// with arbitrary timestamps.
    #[cfg(test)]
    #[must_use]
    #[allow(clippy::too_many_arguments, clippy::missing_const_for_fn)]
    pub(crate) fn new_for_testing(
        event_id: Uuid,
        event_kind: AuditEventKind,
        actor: AuditActor,
        resource: AuditResource,
        correlation_id: Uuid,
        occurred_at: DateTime<Utc>,
        org_id: Uuid,
        payload: AuditPayload,
    ) -> Self {
        Self {
            event_id,
            event_kind,
            actor,
            resource,
            correlation_id,
            occurred_at,
            org_id,
            payload,
        }
    }

    /// Stable event identifier (UUID v7 recommended).
    #[must_use]
    pub const fn event_id(&self) -> Uuid {
        self.event_id
    }

    /// Discriminator across the event taxonomy.
    #[must_use]
    pub const fn event_kind(&self) -> AuditEventKind {
        self.event_kind
    }

    /// Who initiated the action.
    #[must_use]
    pub const fn actor(&self) -> &AuditActor {
        &self.actor
    }

    /// What the action targeted.
    #[must_use]
    pub const fn resource(&self) -> &AuditResource {
        &self.resource
    }

    /// Per-request correlation ID.
    #[must_use]
    pub const fn correlation_id(&self) -> Uuid {
        self.correlation_id
    }

    /// Wall-clock time the event occurred.
    #[must_use]
    pub const fn occurred_at(&self) -> DateTime<Utc> {
        self.occurred_at
    }

    /// Tenant scope of the event.
    #[must_use]
    pub const fn org_id(&self) -> Uuid {
        self.org_id
    }

    /// Free-form event-specific payload (PII-bearing — opaque on `Debug`).
    #[must_use]
    pub const fn payload(&self) -> &AuditPayload {
        &self.payload
    }
}

impl fmt::Debug for AuditEventV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuditEventV1")
            .field("event_id", &self.event_id)
            .field("event_kind", &self.event_kind)
            .field("actor", &self.actor)
            .field("resource", &self.resource)
            .field("correlation_id", &self.correlation_id)
            .field("occurred_at", &self.occurred_at)
            .field("org_id", &self.org_id)
            .field("payload", &self.payload)
            .finish()
    }
}

/// Errors raised by [`AuditEventV1::new_at`] and other validating
/// constructors when the caller-supplied data violates an invariant.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AuditEventError {
    /// Caller-supplied `occurred_at` drifts too far from `Utc::now()`.
    /// `drift_secs` is the absolute drift in seconds.
    #[error("occurred_at drifts {drift_secs}s from Utc::now() (tolerance: {tolerance_secs}s)")]
    OccurredAtSkew {
        /// Absolute drift in seconds.
        drift_secs: i64,
        /// Configured tolerance in seconds.
        tolerance_secs: i64,
    },
}

/// Audit-event payload newtype.
///
/// The inner `serde_json::Value` is intentionally kept opaque on the
/// outside: the [`fmt::Debug`] impl prints only the size in bytes so a
/// careless `tracing::debug!(?event)` never dumps emails / tokens / IPs /
/// password-reset URLs that producers may encode into the payload. Wire
/// serde is unchanged; consumers that legitimately need the inner value
/// call [`AuditPayload::as_value`].
#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AuditPayload(serde_json::Value);

impl AuditPayload {
    /// Wrap a `serde_json::Value` payload.
    #[must_use]
    pub const fn new(value: serde_json::Value) -> Self {
        Self(value)
    }

    /// Borrow the inner JSON value. Callers consuming the inner value are
    /// the trust boundary for whether its contents land in plaintext logs.
    #[must_use]
    pub const fn as_value(&self) -> &serde_json::Value {
        &self.0
    }

    /// Approximate byte-size of the serialised payload, used by the
    /// redacting `Debug` impl. Returns `0` for payloads that fail to
    /// serialise (which would be exceptional but must not panic).
    #[must_use]
    pub fn approx_byte_size(&self) -> usize {
        serde_json::to_vec(&self.0).map(|v| v.len()).unwrap_or(0)
    }
}

impl fmt::Debug for AuditPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<{} B redacted>", self.approx_byte_size())
    }
}

impl From<serde_json::Value> for AuditPayload {
    fn from(value: serde_json::Value) -> Self {
        Self(value)
    }
}

/// Logical service name validator.
///
/// Wraps an ASCII slug `^[A-Za-z0-9](?:[A-Za-z0-9_-]{0,62}[A-Za-z0-9])?$`
/// so producers cannot smuggle ANSI escapes / log-injection / unbounded
/// strings into Postgres / Prometheus labels / log shippers via
/// [`AuditActor::Service`]. Cardinality is bounded by the validator
/// (max 64 chars), which protects label cardinality at the metrics layer.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ServiceName(String);

/// Maximum length of a [`ServiceName`] in bytes (= chars, ASCII only).
pub const SERVICE_NAME_MAX_LEN: usize = 64;

impl ServiceName {
    /// Parse a service name, validating the slug contract.
    ///
    /// # Errors
    ///
    /// Returns [`ServiceNameError`] when the input violates length, charset,
    /// or boundary rules.
    pub fn parse(input: impl Into<String>) -> Result<Self, ServiceNameError> {
        let raw = input.into();
        if raw.is_empty() {
            return Err(ServiceNameError::Empty);
        }
        if raw.len() > SERVICE_NAME_MAX_LEN {
            return Err(ServiceNameError::TooLong {
                len: raw.len(),
                max: SERVICE_NAME_MAX_LEN,
            });
        }
        let bytes = raw.as_bytes();
        let first = bytes[0];
        let last = bytes[bytes.len() - 1];
        if !first.is_ascii_alphanumeric() || !last.is_ascii_alphanumeric() {
            return Err(ServiceNameError::InvalidBoundary);
        }
        for &b in bytes {
            if !(b.is_ascii_alphanumeric() || b == b'_' || b == b'-') {
                return Err(ServiceNameError::InvalidChar(char::from(b)));
            }
        }
        Ok(Self(raw))
    }

    /// Borrow the validated slug.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ServiceName {
    type Error = ServiceNameError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

impl From<ServiceName> for String {
    fn from(value: ServiceName) -> Self {
        value.0
    }
}

impl fmt::Display for ServiceName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// [`ServiceName`] validation failures.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum ServiceNameError {
    /// Empty input.
    #[error("service name must not be empty")]
    Empty,
    /// Too long.
    #[error("service name length {len} exceeds maximum {max}")]
    TooLong {
        /// Actual length in bytes.
        len: usize,
        /// Configured maximum.
        max: usize,
    },
    /// First or last character was not alphanumeric.
    #[error("service name must start and end with an alphanumeric character")]
    InvalidBoundary,
    /// A character outside the slug alphabet `[A-Za-z0-9_-]` was found.
    #[error("service name contains invalid character: `{0}`")]
    InvalidChar(char),
}

/// Discriminator across identity-emitted audit events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AuditEventKind {
    /// User signed up successfully.
    SignupCreated,
    /// Sign-up attempted with an email that already exists. Anti-enumeration
    /// — payload carries IP only, never the email-existence answer.
    SignupEmailCollisionAttempted,
    /// Email verification confirmed.
    EmailVerified,
    /// Sign-in succeeded.
    SigninSuccess,
    /// Sign-in failed (rate-limited per minute window).
    SigninFailed,
    /// Session revoked (explicit / cascade / SCIM-deactivate).
    SessionRevoked,
    /// User changed their password.
    PasswordChanged,
    /// Password reset requested (only emitted for known emails).
    PasswordResetRequested,
    /// `IdP` configuration created.
    IdpCreated,
    /// `IdP` configuration updated.
    IdpUpdated,
    /// `IdP` configuration deleted.
    IdpDeleted,
    /// `IdP` domain claim created (POST /domains). The DNS challenge
    /// is issued; verification has not yet happened. Distinct from
    /// [`AuditEventKind::IdpDomainVerified`] so the audit timeline
    /// records claim → verify (or claim → expire) transitions.
    IdpDomainCreated,
    /// `IdP` domain ownership verified via DNS TXT.
    IdpDomainVerified,
    /// `IdP` domain verification failed (DNSSEC / NX / mismatch).
    IdpDomainFailed,
    /// `IdP` domain claim soft-deleted. Recorded for verified rows so
    /// the audit timeline shows when an org gives up a domain claim.
    IdpDomainDeleted,
    /// SCIM created a user.
    ScimUserCreated,
    /// SCIM updated a user.
    ScimUserUpdated,
    /// SCIM flipped a user `active=false`.
    ScimUserDeactivated,
    /// SCIM deleted a user.
    ScimUserDeleted,
    /// SCIM created a group.
    ScimGroupCreated,
    /// SCIM updated a group.
    ScimGroupUpdated,
    /// SCIM deleted a group.
    ScimGroupDeleted,
    /// SCIM PATCH/PUT received without `If-Match`.
    ScimUnconditionalWrite,
    /// OIDC callback used a `oidc_pending_auth` row that was already used.
    OidcCallbackReplay,
    /// OIDC callback's CSRF cookie did not match the pending row.
    OidcStateMismatch,
    /// OIDC refresh-token chain replay detected.
    OidcRefreshReplay,
    /// SAML ACS received a previously-seen `AssertionID`.
    SamlAcsReplay,
    /// SAML ACS rejected an XSW-style payload.
    SamlXswRejected,
    /// SAML ACS rejected an invalid signature.
    SamlSignatureInvalid,
    /// User switched their active org on the same session.
    OrgSwitched,
    /// Account locked out after rate-limit / lockout breach.
    AccountLocked,
    /// Admin unlocked a previously-locked account.
    AccountUnlocked,
    /// Worker / service token issued.
    ServiceTokenCreated,
    /// Worker / service token revoked.
    ServiceTokenRevoked,
    /// Personal access token issued by a user (`pat_*`).
    ApiTokenCreated,
    /// Personal access token revoked (explicit DELETE or cascade).
    ApiTokenRevoked,
    /// Token-replay heuristic fired (refresh chain or session reuse).
    SuspectedTokenReplay,
    /// GDPR hard-purge completed for a user.
    GdprPurgeCompleted,
}

/// Who initiated the audited action.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum AuditActor {
    /// Authenticated end user.
    User {
        /// Subject identifier.
        user_id: Uuid,
        /// Source IP, when known.
        ip: Option<IpAddr>,
    },
    /// Worker / service-token bearer.
    Service {
        /// Logical service name (validated slug; see [`ServiceName`]).
        service_name: ServiceName,
    },
    /// Internal system (cron, migration, startup).
    System,
    /// Unauthenticated request (anti-enumeration audit only).
    Anonymous {
        /// Source IP, when known.
        ip: Option<IpAddr>,
    },
}

/// What the audited action targeted.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum AuditResource {
    /// User row.
    User {
        /// User identifier.
        user_id: Uuid,
    },
    /// Org row.
    Org {
        /// Org identifier.
        org_id: Uuid,
    },
    /// Session row.
    Session {
        /// Session identifier.
        session_id: Uuid,
    },
    /// API token row.
    ApiToken {
        /// API token identifier.
        token_id: Uuid,
    },
    /// SCIM bearer-token row.
    ScimToken {
        /// SCIM token identifier.
        token_id: Uuid,
    },
    /// Worker / service-token row.
    ServiceToken {
        /// Service token identifier.
        token_id: Uuid,
    },
    /// `IdP` configuration row.
    Idp {
        /// `IdP` identifier.
        idp_id: Uuid,
    },
    /// `IdP`-domain claim row.
    IdpDomain {
        /// Domain row identifier.
        domain_id: Uuid,
    },
    /// Outbound email row.
    Email {
        /// Email outbox identifier.
        email_id: Uuid,
    },
    /// Resource not applicable (e.g. system events).
    None,
}

/// Default [`Auditor`] impl — drops events on the floor.
///
/// The gateway / app composition root replaces this with the
/// `PostgresAuditor` once the tenant-isolation layer's audit crate lands.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopAuditor;

#[async_trait]
impl Auditor for NoopAuditor {
    async fn record(&self, _event: AuditEvent) {}
}

const _: ChronoDuration = ChronoDuration::seconds(AUDIT_OCCURRED_AT_TOLERANCE_SECS);

#[cfg(test)]
mod tests {
    use super::*;
    use static_assertions::{assert_impl_all, assert_obj_safe};

    assert_obj_safe!(Auditor);
    assert_impl_all!(AuditEventV1: Send, Sync, Clone, serde::Serialize, serde::de::DeserializeOwned);
    assert_impl_all!(AuditActor: Send, Sync, Clone, serde::Serialize, serde::de::DeserializeOwned);
    assert_impl_all!(AuditResource: Send, Sync, Clone, serde::Serialize, serde::de::DeserializeOwned);
    assert_impl_all!(AuditPayload: Send, Sync, Clone, serde::Serialize, serde::de::DeserializeOwned);
    assert_impl_all!(ServiceName: Send, Sync, Clone, std::fmt::Debug);
    assert_impl_all!(AuditEventError: Send, Sync, std::error::Error);
    assert_impl_all!(ServiceNameError: Send, Sync, std::error::Error);
    const _: fn() = || {
        fn require_static<T: 'static + Send + Sync>() {}
        require_static::<AuditEvent>();
        require_static::<AuditEventError>();
        require_static::<ServiceNameError>();
    };

    fn distinguishable_uuid(byte: u8) -> Uuid {
        Uuid::from_bytes([byte; 16])
    }

    fn fixture_event_v1() -> AuditEventV1 {
        AuditEventV1::new_for_testing(
            distinguishable_uuid(1),
            AuditEventKind::SigninSuccess,
            AuditActor::User {
                user_id: distinguishable_uuid(2),
                ip: Some(
                    "127.0.0.1"
                        .parse::<IpAddr>()
                        .unwrap_or_else(|e| panic!("ip parse: {e}")),
                ),
            },
            AuditResource::Session {
                session_id: distinguishable_uuid(3),
            },
            distinguishable_uuid(4),
            DateTime::<Utc>::from_timestamp(0, 0).unwrap_or_else(|| panic!("epoch construct")),
            distinguishable_uuid(5),
            AuditPayload::new(serde_json::json!({})),
        )
    }

    #[test]
    fn audit_event_v1_round_trips_json() {
        let original = fixture_event_v1();
        let json = serde_json::to_string(&original).unwrap_or_else(|e| panic!("serialise: {e}"));
        let parsed: AuditEventV1 =
            serde_json::from_str(&json).unwrap_or_else(|e| panic!("deserialise: {e}"));
        assert_eq!(parsed.event_kind(), AuditEventKind::SigninSuccess);
    }

    #[test]
    fn audit_event_envelope_carries_string_schema_version_one() {
        let envelope = AuditEvent::V1(fixture_event_v1());
        let v =
            serde_json::to_value(&envelope).unwrap_or_else(|e| panic!("serialise envelope: {e}"));
        // Wire-shape lock: discriminator MUST be a string `"1"`, never a
        // number `1`. Downstream JSONB readers depend on this.
        assert_eq!(v["schema_version"], serde_json::json!("1"));
        // Internally tagged: payload fields are flat on the envelope, no
        // nested `V1` wrapper.
        let obj = v.as_object().unwrap_or_else(|| panic!("envelope object"));
        assert!(
            !obj.contains_key("V1"),
            "AuditEvent must serialise as internally tagged, not externally tagged"
        );
        assert_eq!(obj["event_kind"], serde_json::json!("signin_success"));
    }

    #[test]
    fn audit_event_envelope_rejects_numeric_schema_version() {
        // Wire-shape lock regression: a numeric `1` discriminator must NOT
        // deserialise as v1. Future envelope versions can bump the string
        // (`"2"`, `"3"`) but the type itself must stay String forever.
        let payload = serde_json::json!({
            "schema_version": 1,
            "event_id": "00000000-0000-0000-0000-000000000001",
            "event_kind": "signin_success",
            "actor": { "kind": "system" },
            "resource": { "kind": "none" },
            "correlation_id": "00000000-0000-0000-0000-000000000004",
            "occurred_at": "1970-01-01T00:00:00Z",
            "org_id": "00000000-0000-0000-0000-000000000005",
            "payload": {}
        });
        let result: Result<AuditEvent, _> = serde_json::from_value(payload);
        assert!(
            result.is_err(),
            "numeric schema_version must fail to deserialise"
        );
    }

    #[test]
    fn audit_event_kind_round_trips_every_variant() {
        let variants = [
            AuditEventKind::SignupCreated,
            AuditEventKind::SignupEmailCollisionAttempted,
            AuditEventKind::EmailVerified,
            AuditEventKind::SigninSuccess,
            AuditEventKind::SigninFailed,
            AuditEventKind::SessionRevoked,
            AuditEventKind::PasswordChanged,
            AuditEventKind::PasswordResetRequested,
            AuditEventKind::IdpCreated,
            AuditEventKind::IdpUpdated,
            AuditEventKind::IdpDeleted,
            AuditEventKind::IdpDomainCreated,
            AuditEventKind::IdpDomainVerified,
            AuditEventKind::IdpDomainFailed,
            AuditEventKind::IdpDomainDeleted,
            AuditEventKind::ScimUserCreated,
            AuditEventKind::ScimUserUpdated,
            AuditEventKind::ScimUserDeactivated,
            AuditEventKind::ScimUserDeleted,
            AuditEventKind::ScimGroupCreated,
            AuditEventKind::ScimGroupUpdated,
            AuditEventKind::ScimGroupDeleted,
            AuditEventKind::ScimUnconditionalWrite,
            AuditEventKind::OidcCallbackReplay,
            AuditEventKind::OidcStateMismatch,
            AuditEventKind::OidcRefreshReplay,
            AuditEventKind::SamlAcsReplay,
            AuditEventKind::SamlXswRejected,
            AuditEventKind::SamlSignatureInvalid,
            AuditEventKind::OrgSwitched,
            AuditEventKind::AccountLocked,
            AuditEventKind::AccountUnlocked,
            AuditEventKind::ServiceTokenCreated,
            AuditEventKind::ServiceTokenRevoked,
            AuditEventKind::ApiTokenCreated,
            AuditEventKind::ApiTokenRevoked,
            AuditEventKind::SuspectedTokenReplay,
            AuditEventKind::GdprPurgeCompleted,
        ];
        for kind in variants {
            // Drive the exhaustiveness check via match — ensures the
            // variant array stays in lockstep with the enum.
            match kind {
                AuditEventKind::SignupCreated
                | AuditEventKind::SignupEmailCollisionAttempted
                | AuditEventKind::EmailVerified
                | AuditEventKind::SigninSuccess
                | AuditEventKind::SigninFailed
                | AuditEventKind::SessionRevoked
                | AuditEventKind::PasswordChanged
                | AuditEventKind::PasswordResetRequested
                | AuditEventKind::IdpCreated
                | AuditEventKind::IdpUpdated
                | AuditEventKind::IdpDeleted
                | AuditEventKind::IdpDomainCreated
                | AuditEventKind::IdpDomainVerified
                | AuditEventKind::IdpDomainFailed
                | AuditEventKind::IdpDomainDeleted
                | AuditEventKind::ScimUserCreated
                | AuditEventKind::ScimUserUpdated
                | AuditEventKind::ScimUserDeactivated
                | AuditEventKind::ScimUserDeleted
                | AuditEventKind::ScimGroupCreated
                | AuditEventKind::ScimGroupUpdated
                | AuditEventKind::ScimGroupDeleted
                | AuditEventKind::ScimUnconditionalWrite
                | AuditEventKind::OidcCallbackReplay
                | AuditEventKind::OidcStateMismatch
                | AuditEventKind::OidcRefreshReplay
                | AuditEventKind::SamlAcsReplay
                | AuditEventKind::SamlXswRejected
                | AuditEventKind::SamlSignatureInvalid
                | AuditEventKind::OrgSwitched
                | AuditEventKind::AccountLocked
                | AuditEventKind::AccountUnlocked
                | AuditEventKind::ServiceTokenCreated
                | AuditEventKind::ServiceTokenRevoked
                | AuditEventKind::ApiTokenCreated
                | AuditEventKind::ApiTokenRevoked
                | AuditEventKind::SuspectedTokenReplay
                | AuditEventKind::GdprPurgeCompleted => {}
            }
            let json = serde_json::to_string(&kind).unwrap_or_else(|e| panic!("serialise: {e}"));
            let parsed: AuditEventKind =
                serde_json::from_str(&json).unwrap_or_else(|e| panic!("deserialise: {e}"));
            assert_eq!(parsed, kind);
        }
    }

    #[test]
    fn audit_event_v1_new_clamps_to_now() {
        let payload = AuditPayload::new(serde_json::json!({"k": "v"}));
        let actor = AuditActor::System;
        let event = AuditEventV1::new(
            AuditEventKind::SigninSuccess,
            actor,
            AuditResource::None,
            distinguishable_uuid(4),
            distinguishable_uuid(5),
            payload,
        );
        let drift = (Utc::now() - event.occurred_at()).num_seconds().abs();
        assert!(
            drift <= 1,
            "occurred_at must clamp to now() (drift={drift}s)"
        );
    }

    #[test]
    fn audit_event_v1_new_at_rejects_far_future() {
        let future = Utc::now() + ChronoDuration::seconds(60);
        let result = AuditEventV1::new_at(
            distinguishable_uuid(1),
            AuditEventKind::SigninSuccess,
            AuditActor::System,
            AuditResource::None,
            distinguishable_uuid(4),
            future,
            distinguishable_uuid(5),
            AuditPayload::new(serde_json::json!({})),
        );
        let err = result.expect_err("60s drift must reject");
        assert!(matches!(err, AuditEventError::OccurredAtSkew { .. }));
    }

    #[test]
    fn audit_event_v1_new_at_rejects_far_past() {
        let past = Utc::now() - ChronoDuration::seconds(60);
        let result = AuditEventV1::new_at(
            distinguishable_uuid(1),
            AuditEventKind::SigninSuccess,
            AuditActor::System,
            AuditResource::None,
            distinguishable_uuid(4),
            past,
            distinguishable_uuid(5),
            AuditPayload::new(serde_json::json!({})),
        );
        let err = result.expect_err("60s drift must reject");
        assert!(matches!(err, AuditEventError::OccurredAtSkew { .. }));
    }

    #[test]
    fn audit_event_v1_new_at_accepts_within_tolerance() {
        let close = Utc::now() - ChronoDuration::seconds(2);
        AuditEventV1::new_at(
            distinguishable_uuid(1),
            AuditEventKind::SigninSuccess,
            AuditActor::System,
            AuditResource::None,
            distinguishable_uuid(4),
            close,
            distinguishable_uuid(5),
            AuditPayload::new(serde_json::json!({})),
        )
        .unwrap_or_else(|e| panic!("2s drift must pass: {e}"));
    }

    #[test]
    fn audit_payload_debug_redacts_contents() {
        let payload = AuditPayload::new(serde_json::json!({
            "email": "alice@example.com",
            "password_reset_token": "rst_secret_value"
        }));
        let rendered = format!("{payload:?}");
        assert!(!rendered.contains("alice"));
        assert!(!rendered.contains("rst_secret_value"));
        assert!(rendered.contains("redacted"));
        assert!(rendered.contains(" B "));
    }

    #[test]
    fn audit_event_v1_debug_does_not_leak_payload() {
        let payload = AuditPayload::new(serde_json::json!({
            "email": "alice@example.com",
            "ip": "10.0.0.5"
        }));
        let event = AuditEventV1::new(
            AuditEventKind::SigninFailed,
            AuditActor::Anonymous {
                ip: Some(
                    "10.0.0.5"
                        .parse::<IpAddr>()
                        .unwrap_or_else(|e| panic!("ip parse: {e}")),
                ),
            },
            AuditResource::None,
            distinguishable_uuid(4),
            distinguishable_uuid(5),
            payload,
        );
        let dbg = format!("{event:?}");
        // Top-level Debug includes the IP via AuditActor (intentional —
        // operators do see audit-actor IPs). The payload, however, must
        // be opaque.
        assert!(!dbg.contains("alice"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn service_name_accepts_valid_slugs() {
        for input in [
            "email-worker",
            "scim_worker",
            "outbox-pump-1",
            "Cron",
            "x",
            "z9",
        ] {
            ServiceName::parse(input).unwrap_or_else(|e| panic!("`{input}` should validate: {e}"));
        }
    }

    #[test]
    fn service_name_rejects_empty() {
        assert_eq!(ServiceName::parse("").unwrap_err(), ServiceNameError::Empty);
    }

    #[test]
    fn service_name_rejects_too_long() {
        let long = "a".repeat(SERVICE_NAME_MAX_LEN + 1);
        assert!(matches!(
            ServiceName::parse(long).unwrap_err(),
            ServiceNameError::TooLong { .. }
        ));
    }

    #[test]
    fn service_name_rejects_leading_dash() {
        assert_eq!(
            ServiceName::parse("-worker").unwrap_err(),
            ServiceNameError::InvalidBoundary
        );
    }

    #[test]
    fn service_name_rejects_trailing_underscore() {
        assert_eq!(
            ServiceName::parse("worker_").unwrap_err(),
            ServiceNameError::InvalidBoundary
        );
    }

    #[test]
    fn service_name_rejects_log_injection_attempts() {
        for input in ["alice\nadmin", "evil\x1b[31m", "a b", "a/b", ".."] {
            assert!(
                matches!(
                    ServiceName::parse(input).unwrap_err(),
                    ServiceNameError::InvalidChar(_) | ServiceNameError::InvalidBoundary
                ),
                "`{input}` should be rejected"
            );
        }
    }

    #[test]
    fn service_name_round_trips_through_serde() {
        let name = ServiceName::parse("email-worker").unwrap_or_else(|e| panic!("seed parse: {e}"));
        let json = serde_json::to_string(&name).unwrap_or_else(|e| panic!("serialise: {e}"));
        assert_eq!(json, "\"email-worker\"");
        let parsed: ServiceName =
            serde_json::from_str(&json).unwrap_or_else(|e| panic!("deserialise: {e}"));
        assert_eq!(parsed, name);
    }

    #[test]
    fn service_name_serde_rejects_invalid_input() {
        let bad: Result<ServiceName, _> = serde_json::from_str("\"-bad\"");
        assert!(bad.is_err(), "leading dash should fail at deserialise");
    }

    #[test]
    fn audit_actor_service_uses_service_name() {
        let name = ServiceName::parse("email-worker").unwrap_or_else(|e| panic!("parse: {e}"));
        let actor = AuditActor::Service { service_name: name };
        let json = serde_json::to_string(&actor).unwrap_or_else(|e| panic!("serialise: {e}"));
        let parsed: AuditActor =
            serde_json::from_str(&json).unwrap_or_else(|e| panic!("deserialise: {e}"));
        match parsed {
            AuditActor::Service { service_name } => {
                assert_eq!(service_name.as_str(), "email-worker");
            }
            other => panic!("expected Service, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn noop_auditor_drops_events_silently() {
        let auditor = NoopAuditor;
        auditor.record(AuditEvent::V1(fixture_event_v1())).await;
    }

    #[tokio::test]
    async fn noop_auditor_default_drops_events_silently() {
        // Type-checking exercise: confirm `NoopAuditor` derives `Default`
        // so downstream `Default::default::<NoopAuditor>()` works in
        // generic call sites without naming `NoopAuditor` directly.
        fn assert_default<T: Default>() {}
        assert_default::<NoopAuditor>();
        let auditor = NoopAuditor;
        auditor.record(AuditEvent::V1(fixture_event_v1())).await;
    }
}
