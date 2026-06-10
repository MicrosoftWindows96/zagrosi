// SPDX-License-Identifier: AGPL-3.0-or-later

//! Audit port + versioned event envelope.
//!
//! Identity emits events via [`Auditor`]; the `PostgresAuditor` impl
//! lives in the tenant-isolation layer's `zagrosi-audit` crate. The
//! default impl shipped here is [`NoopAuditor`] so wiring works before the
//! audit crate lands.
//!
//! [`AuditEvent`] is a versioned envelope. v0.1 only ships [`AuditEventV1`].
//! V1 was extended in place pre-release while the envelope had no persisted
//! consumers; from first release onward, changes land via an additive
//! `AuditEventV2` variant, preserving forward compatibility for downstream
//! audit storage.
//!
//! ## Wire-shape lock
//!
//! The envelope discriminator is the *string* `"schema_version": "1"`, not
//! a numeric `1`. Downstream consumers (Postgres JSONB readers, log shippers)
//! rely on the discriminator type being stable; the `audit_event_envelope_*`
//! tests below regression-guard against the type drifting to an integer.
//! Absent optional fields (`org_id`, `resource_id`, `before`, `after`)
//! serialize as explicit `null` — never via `skip_serializing_if` — so the
//! envelope key set is stable for downstream JSONB readers.

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
    /// Record an event. `record()` may apply backpressure (await bounded
    /// buffer space) when the sink is saturated; implementations document
    /// their bound. Failures still must not propagate as errors to the
    /// caller.
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
/// [`AuditEventV1::builder`] — the sole public construction path. Read
/// access goes through accessor methods. Serde derive remains in place for
/// cross-process replay (e.g. JSONB column round-trip in the upcoming
/// `PostgresAuditor`).
#[derive(Clone, Serialize, Deserialize)]
pub struct AuditEventV1 {
    event_id: Uuid,
    event_kind: AuditEventKind,
    actor: AuditActor,
    resource: AuditResource,
    resource_type: String,
    resource_id: Option<Uuid>,
    before: Option<AuditPayload>,
    after: Option<AuditPayload>,
    correlation_id: Uuid,
    occurred_at: DateTime<Utc>,
    #[serde(deserialize_with = "deserialize_org_id")]
    org_id: Option<Uuid>,
    metadata: AuditPayload,
}

/// Deserialize-side twin of the builder's nil-org coercion: a nil UUID in
/// replayed JSON (cross-process / JSONB round-trip) normalizes to `None` so
/// the "nil sentinel never reaches storage" invariant holds on every path
/// that can construct an event, not just the builder.
fn deserialize_org_id<'de, D>(deserializer: D) -> Result<Option<Uuid>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let org_id = Option::<Uuid>::deserialize(deserializer)?;
    Ok(org_id.filter(|id| !id.is_nil()))
}

impl AuditEventV1 {
    /// Sole public construction path. `org_id` is the tenant scope; `None`
    /// for instance-scoped / pre-org events. `Some(Uuid::nil())` is coerced
    /// to `None` (pinned: the nil sentinel must never reach storage).
    /// `correlation_id` is required because every emit site carries one.
    pub fn builder(
        event_kind: AuditEventKind,
        actor: AuditActor,
        org_id: Option<Uuid>,
        correlation_id: Uuid,
    ) -> AuditEventV1Builder {
        AuditEventV1Builder {
            event_kind,
            actor,
            org_id: org_id.filter(|id| !id.is_nil()),
            correlation_id,
            resource: None,
            resource_parts: None,
            before: None,
            after: None,
            metadata: None,
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

    /// What the action targeted (typed wire data).
    #[must_use]
    pub const fn resource(&self) -> &AuditResource {
        &self.resource
    }

    /// Generalized resource type string (e.g. `"session"`,
    /// `"custom_role"`); maps onto the `audit_events.resource_type` column.
    #[must_use]
    pub fn resource_type(&self) -> &str {
        &self.resource_type
    }

    /// Generalized resource identifier; maps onto the
    /// `audit_events.resource_id` column.
    #[must_use]
    pub const fn resource_id(&self) -> Option<Uuid> {
        self.resource_id
    }

    /// Entity snapshot before a mutation, when the producer recorded one
    /// (PII-bearing — opaque on `Debug`; never contains plaintext secrets).
    #[must_use]
    pub const fn before(&self) -> Option<&AuditPayload> {
        self.before.as_ref()
    }

    /// Entity snapshot after a mutation, when the producer recorded one
    /// (PII-bearing — opaque on `Debug`; never contains plaintext secrets).
    #[must_use]
    pub const fn after(&self) -> Option<&AuditPayload> {
        self.after.as_ref()
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

    /// Tenant scope of the event; `None` for instance-scoped / pre-org
    /// events (admin unlock, sign-in before org selection).
    #[must_use]
    pub const fn org_id(&self) -> Option<Uuid> {
        self.org_id
    }

    /// Free-form event-specific metadata (PII-bearing — opaque on `Debug`).
    #[must_use]
    pub const fn metadata(&self) -> &AuditPayload {
        &self.metadata
    }
}

impl fmt::Debug for AuditEventV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuditEventV1")
            .field("event_id", &self.event_id)
            .field("event_kind", &self.event_kind)
            .field("actor", &self.actor)
            .field("resource", &self.resource)
            .field("resource_type", &self.resource_type)
            .field("resource_id", &self.resource_id)
            .field("before", &self.before)
            .field("after", &self.after)
            .field("correlation_id", &self.correlation_id)
            .field("occurred_at", &self.occurred_at)
            .field("org_id", &self.org_id)
            .field("metadata", &self.metadata)
            .finish()
    }
}

/// Builder for [`AuditEventV1`]; obtain via [`AuditEventV1::builder`].
///
/// Defaults when a setter is not called: `resource = AuditResource::None`,
/// `resource_type = "none"`, `resource_id = None`, `before`/`after = None`,
/// `metadata = {}`.
#[derive(Debug)]
#[must_use = "builders do nothing unless `.build()` / `.build_at()` is called"]
pub struct AuditEventV1Builder {
    event_kind: AuditEventKind,
    actor: AuditActor,
    org_id: Option<Uuid>,
    correlation_id: Uuid,
    resource: Option<AuditResource>,
    resource_parts: Option<(String, Option<Uuid>)>,
    before: Option<AuditPayload>,
    after: Option<AuditPayload>,
    metadata: Option<AuditPayload>,
}

impl AuditEventV1Builder {
    /// Typed resource; derives `(resource_type, resource_id)` via the
    /// pinned mapping (`snake_case` of the serde tag + the variant's id
    /// field) unless [`Self::resource_parts`] supplies them explicitly.
    pub const fn resource(mut self, resource: AuditResource) -> Self {
        self.resource = Some(resource);
        self
    }

    /// Free-form resource identity for kinds without an [`AuditResource`]
    /// variant (rbac/audit producers: `"custom_role"`, `"role_assignment"`,
    /// `"resource_node"`, `"audit_partition"`, `"audit_export_destination"`,
    /// `"audit_retention_policy"`). Leaves `resource` at
    /// [`AuditResource::None`] unless [`Self::resource`] was also called.
    pub fn resource_parts(
        mut self,
        resource_type: impl Into<String>,
        resource_id: Option<Uuid>,
    ) -> Self {
        self.resource_parts = Some((resource_type.into(), resource_id));
        self
    }

    /// Entity snapshot before a mutation. Never include plaintext secrets —
    /// envelope/secret *ids* only.
    pub fn before(mut self, value: impl Into<AuditPayload>) -> Self {
        self.before = Some(value.into());
        self
    }

    /// Entity snapshot after a mutation. Never include plaintext secrets —
    /// envelope/secret *ids* only.
    pub fn after(mut self, value: impl Into<AuditPayload>) -> Self {
        self.after = Some(value.into());
        self
    }

    /// Free-form event-specific metadata (absorbs the pre-builder
    /// `payload` field).
    pub fn metadata(mut self, value: impl Into<AuditPayload>) -> Self {
        self.metadata = Some(value.into());
        self
    }

    /// Infallible build: `event_id = Uuid::now_v7()`,
    /// `occurred_at = Utc::now()`. This is the recommended path for
    /// production code: it removes any caller-supplied wall-clock value
    /// entirely.
    #[must_use]
    pub fn build(self) -> AuditEventV1 {
        self.finalize(Uuid::now_v7(), Utc::now())
    }

    /// Build with a caller-supplied id + timestamp, rejecting timestamps
    /// that drift more than [`AUDIT_OCCURRED_AT_TOLERANCE_SECS`] seconds
    /// from `Utc::now()`. Used by tests + by integration paths that bridge
    /// an upstream clock (e.g. an external `IdP` attestation timestamp the
    /// gateway did not synthesise).
    ///
    /// # Errors
    ///
    /// Returns [`AuditEventError::OccurredAtSkew`] when the caller's
    /// `occurred_at` is more than `AUDIT_OCCURRED_AT_TOLERANCE_SECS`
    /// seconds away from `Utc::now()` in either direction.
    pub fn build_at(
        self,
        event_id: Uuid,
        occurred_at: DateTime<Utc>,
    ) -> Result<AuditEventV1, AuditEventError> {
        let now = Utc::now();
        let diff = (now - occurred_at).num_seconds().saturating_abs();
        if diff > AUDIT_OCCURRED_AT_TOLERANCE_SECS {
            return Err(AuditEventError::OccurredAtSkew {
                drift_secs: diff,
                tolerance_secs: AUDIT_OCCURRED_AT_TOLERANCE_SECS,
            });
        }
        Ok(self.finalize(event_id, occurred_at))
    }

    /// Build without clock-skew validation. Restricted to `#[cfg(test)]`
    /// so production code cannot instantiate audit events with arbitrary
    /// timestamps.
    #[cfg(test)]
    pub(crate) fn build_at_unchecked(
        self,
        event_id: Uuid,
        occurred_at: DateTime<Utc>,
    ) -> AuditEventV1 {
        self.finalize(event_id, occurred_at)
    }

    fn finalize(self, event_id: Uuid, occurred_at: DateTime<Utc>) -> AuditEventV1 {
        let resource = self.resource.unwrap_or(AuditResource::None);
        let (resource_type, resource_id) = self
            .resource_parts
            .unwrap_or_else(|| derived_resource_parts(&resource));
        AuditEventV1 {
            event_id,
            event_kind: self.event_kind,
            actor: self.actor,
            resource,
            resource_type,
            resource_id,
            before: self.before,
            after: self.after,
            correlation_id: self.correlation_id,
            occurred_at,
            org_id: self.org_id,
            metadata: self
                .metadata
                .unwrap_or_else(|| AuditPayload::new(serde_json::json!({}))),
        }
    }
}

/// Pinned `AuditResource` → `(resource_type, resource_id)` mapping
/// (`snake_case` of the serde tag; the variant's id field).
fn derived_resource_parts(resource: &AuditResource) -> (String, Option<Uuid>) {
    let (resource_type, resource_id) = match resource {
        AuditResource::User { user_id } => ("user", Some(*user_id)),
        AuditResource::Org { org_id } => ("org", Some(*org_id)),
        AuditResource::Session { session_id } => ("session", Some(*session_id)),
        AuditResource::ApiToken { token_id } => ("api_token", Some(*token_id)),
        AuditResource::ScimToken { token_id } => ("scim_token", Some(*token_id)),
        AuditResource::ServiceToken { token_id } => ("service_token", Some(*token_id)),
        AuditResource::Idp { idp_id } => ("idp", Some(*idp_id)),
        AuditResource::IdpDomain { domain_id } => ("idp_domain", Some(*domain_id)),
        AuditResource::Email { email_id } => ("email", Some(*email_id)),
        AuditResource::None => ("none", None),
    };
    (resource_type.to_owned(), resource_id)
}

/// Errors raised by [`AuditEventV1Builder::build_at`] and other validating
/// construction paths when the caller-supplied data violates an invariant.
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
/// call [`AuditPayload::as_value`]. [`AuditEventV1`] reuses this newtype
/// for its `metadata`, `before`, and `after` fields so all three stay
/// redacted on `Debug`.
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
    /// Role binding granted to a member (RBAC mutation surface,
    /// section 09 producers).
    RoleGranted,
    /// Role binding revoked from a member.
    RoleRevoked,
    /// Custom role created.
    CustomRoleCreated,
    /// Custom role updated (name / entry-set changes).
    CustomRoleUpdated,
    /// Custom role deleted.
    CustomRoleDeleted,
    /// Audit rows erased by the retention / GDPR-erasure maintenance job
    /// (self-audit).
    AuditErased,
    /// Audit partition archived to cold storage by the archival
    /// maintenance job (self-audit).
    AuditPartitionArchived,
    /// SIEM export destination created (org-scoped SIEM CRUD).
    AuditExportDestinationCreated,
    /// SIEM export destination updated.
    AuditExportDestinationUpdated,
    /// SIEM export destination deleted.
    AuditExportDestinationDeleted,
    /// Session issued (sign-in success, any method). Emit sites land with
    /// the `PostgresAuditor` wiring, not in identity flows directly.
    SessionCreated,
    /// Session lifecycle ended (sign-out / expiry), as distinct from
    /// [`AuditEventKind::SessionRevoked`] (administrative / security
    /// revocation: explicit revoke, cascade, SCIM-deactivate).
    SessionDestroyed,
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
/// Its backpressure bound is zero: `record()` never waits.
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
        AuditEventV1::builder(
            AuditEventKind::SigninSuccess,
            AuditActor::User {
                user_id: distinguishable_uuid(2),
                ip: Some(
                    "127.0.0.1"
                        .parse::<IpAddr>()
                        .unwrap_or_else(|e| panic!("ip parse: {e}")),
                ),
            },
            Some(distinguishable_uuid(5)),
            distinguishable_uuid(4),
        )
        .resource(AuditResource::Session {
            session_id: distinguishable_uuid(3),
        })
        .build_at_unchecked(
            distinguishable_uuid(1),
            DateTime::<Utc>::from_timestamp(0, 0).unwrap_or_else(|| panic!("epoch construct")),
        )
    }

    fn system_builder() -> AuditEventV1Builder {
        AuditEventV1::builder(
            AuditEventKind::SigninSuccess,
            AuditActor::System,
            None,
            distinguishable_uuid(4),
        )
    }

    #[test]
    fn audit_event_v1_round_trips_json() {
        let original = fixture_event_v1();
        let json = serde_json::to_string(&original).unwrap_or_else(|e| panic!("serialise: {e}"));
        let parsed: AuditEventV1 =
            serde_json::from_str(&json).unwrap_or_else(|e| panic!("deserialise: {e}"));
        assert_eq!(parsed.event_kind(), AuditEventKind::SigninSuccess);
        assert_eq!(parsed.org_id(), Some(distinguishable_uuid(5)));
        assert_eq!(parsed.resource_type(), "session");
        assert_eq!(parsed.resource_id(), Some(distinguishable_uuid(3)));
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
        // Wire-shape lock: the exact envelope key set. Absent optional
        // fields serialize as explicit `null` (no `skip_serializing_if`)
        // so downstream JSONB readers see a stable key set.
        let keys: std::collections::BTreeSet<&str> = obj.keys().map(String::as_str).collect();
        let expected: std::collections::BTreeSet<&str> = [
            "schema_version",
            "event_id",
            "event_kind",
            "actor",
            "resource",
            "resource_type",
            "resource_id",
            "before",
            "after",
            "metadata",
            "correlation_id",
            "occurred_at",
            "org_id",
        ]
        .into_iter()
        .collect();
        assert_eq!(keys, expected, "envelope key set must not drift");
        assert!(
            !obj.contains_key("payload"),
            "the pre-builder `payload` key is gone (absorbed by `metadata`)"
        );
        // Fixture sets no before/after — both must be explicit nulls.
        assert_eq!(obj["before"], serde_json::Value::Null);
        assert_eq!(obj["after"], serde_json::Value::Null);
        assert_eq!(obj["resource_type"], serde_json::json!("session"));
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
            "resource_type": "none",
            "resource_id": null,
            "before": null,
            "after": null,
            "correlation_id": "00000000-0000-0000-0000-000000000004",
            "occurred_at": "1970-01-01T00:00:00Z",
            "org_id": null,
            "metadata": {}
        });
        let result: Result<AuditEvent, _> = serde_json::from_value(payload);
        assert!(
            result.is_err(),
            "numeric schema_version must fail to deserialise"
        );
    }

    #[test]
    fn audit_event_org_id_none_serializes_as_null_and_round_trips() {
        let event = system_builder().build();
        assert_eq!(event.org_id(), None);
        let v = serde_json::to_value(&event).unwrap_or_else(|e| panic!("serialise: {e}"));
        assert_eq!(
            v["org_id"],
            serde_json::Value::Null,
            "absent org must serialize as explicit null"
        );
        assert_eq!(
            v["resource_id"],
            serde_json::Value::Null,
            "absent resource_id must serialize as explicit null"
        );
        let parsed: AuditEventV1 =
            serde_json::from_value(v).unwrap_or_else(|e| panic!("deserialise: {e}"));
        assert_eq!(parsed.org_id(), None);
    }

    #[test]
    fn deserialize_coerces_nil_org_to_none() {
        // The nil-sentinel coercion must hold on the serde replay path,
        // not just the builder: a nil org in cross-process JSON
        // normalizes to `None` before it can reach storage.
        let mut v =
            serde_json::to_value(fixture_event_v1()).unwrap_or_else(|e| panic!("serialise: {e}"));
        v["org_id"] = serde_json::json!("00000000-0000-0000-0000-000000000000");
        let parsed: AuditEventV1 =
            serde_json::from_value(v).unwrap_or_else(|e| panic!("deserialise: {e}"));
        assert_eq!(parsed.org_id(), None);
    }

    #[test]
    fn audit_event_org_id_some_round_trips() {
        let org = distinguishable_uuid(5);
        let event = AuditEventV1::builder(
            AuditEventKind::SigninSuccess,
            AuditActor::System,
            Some(org),
            distinguishable_uuid(4),
        )
        .build();
        assert_eq!(event.org_id(), Some(org));
        let json = serde_json::to_string(&event).unwrap_or_else(|e| panic!("serialise: {e}"));
        let parsed: AuditEventV1 =
            serde_json::from_str(&json).unwrap_or_else(|e| panic!("deserialise: {e}"));
        assert_eq!(parsed.org_id(), Some(org));
    }

    #[test]
    fn builder_coerces_nil_org_to_none() {
        // Pinned decision: `Some(Uuid::nil())` coerces to `None` (not an
        // error) so the nil sentinel can never reach storage.
        let event = AuditEventV1::builder(
            AuditEventKind::SigninSuccess,
            AuditActor::System,
            Some(Uuid::nil()),
            distinguishable_uuid(4),
        )
        .build();
        assert_eq!(event.org_id(), None);
    }

    #[test]
    fn builder_defaults_when_setters_omitted() {
        let event = system_builder().build();
        assert!(matches!(event.resource(), AuditResource::None));
        assert_eq!(event.resource_type(), "none");
        assert_eq!(event.resource_id(), None);
        assert!(event.before().is_none());
        assert!(event.after().is_none());
        assert_eq!(event.metadata().as_value(), &serde_json::json!({}));
        assert_eq!(event.correlation_id(), distinguishable_uuid(4));
    }

    #[test]
    fn builder_populates_before_after_metadata() {
        let event = system_builder()
            .before(serde_json::json!({"name": "old"}))
            .after(serde_json::json!({"name": "new"}))
            .metadata(serde_json::json!({"k": "v"}))
            .build();
        assert_eq!(
            event.before().map(AuditPayload::as_value),
            Some(&serde_json::json!({"name": "old"}))
        );
        assert_eq!(
            event.after().map(AuditPayload::as_value),
            Some(&serde_json::json!({"name": "new"}))
        );
        assert_eq!(event.metadata().as_value(), &serde_json::json!({"k": "v"}));
    }

    #[test]
    fn builder_derives_resource_parts_for_every_resource_variant() {
        let id = distinguishable_uuid(9);
        let cases = [
            (AuditResource::User { user_id: id }, "user", Some(id)),
            (AuditResource::Org { org_id: id }, "org", Some(id)),
            (
                AuditResource::Session { session_id: id },
                "session",
                Some(id),
            ),
            (
                AuditResource::ApiToken { token_id: id },
                "api_token",
                Some(id),
            ),
            (
                AuditResource::ScimToken { token_id: id },
                "scim_token",
                Some(id),
            ),
            (
                AuditResource::ServiceToken { token_id: id },
                "service_token",
                Some(id),
            ),
            (AuditResource::Idp { idp_id: id }, "idp", Some(id)),
            (
                AuditResource::IdpDomain { domain_id: id },
                "idp_domain",
                Some(id),
            ),
            (AuditResource::Email { email_id: id }, "email", Some(id)),
            (AuditResource::None, "none", None),
        ];
        for (resource, expected_type, expected_id) in cases {
            // Exhaustiveness driver: adding an `AuditResource` variant
            // without a mapping row above fails this match.
            match &resource {
                AuditResource::User { .. }
                | AuditResource::Org { .. }
                | AuditResource::Session { .. }
                | AuditResource::ApiToken { .. }
                | AuditResource::ScimToken { .. }
                | AuditResource::ServiceToken { .. }
                | AuditResource::Idp { .. }
                | AuditResource::IdpDomain { .. }
                | AuditResource::Email { .. }
                | AuditResource::None => {}
            }
            let event = system_builder().resource(resource).build();
            assert_eq!(event.resource_type(), expected_type);
            assert_eq!(event.resource_id(), expected_id);
        }
    }

    #[test]
    fn builder_resource_parts_sets_freeform_identity() {
        let rid = distinguishable_uuid(8);
        let event = system_builder()
            .resource_parts("custom_role", Some(rid))
            .build();
        assert_eq!(event.resource_type(), "custom_role");
        assert_eq!(event.resource_id(), Some(rid));
        assert!(
            matches!(event.resource(), AuditResource::None),
            "resource_parts alone leaves the typed resource at None"
        );
    }

    #[test]
    fn builder_resource_parts_overrides_derived_strings_keeping_typed_resource() {
        let event = system_builder()
            .resource(AuditResource::Session {
                session_id: distinguishable_uuid(3),
            })
            .resource_parts("custom_role", None)
            .build();
        assert_eq!(event.resource_type(), "custom_role");
        assert_eq!(event.resource_id(), None);
        assert!(matches!(event.resource(), AuditResource::Session { .. }));
    }

    #[test]
    #[allow(clippy::too_many_lines)] // exhaustive 50-variant table, intentionally verbose
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
            AuditEventKind::RoleGranted,
            AuditEventKind::RoleRevoked,
            AuditEventKind::CustomRoleCreated,
            AuditEventKind::CustomRoleUpdated,
            AuditEventKind::CustomRoleDeleted,
            AuditEventKind::AuditErased,
            AuditEventKind::AuditPartitionArchived,
            AuditEventKind::AuditExportDestinationCreated,
            AuditEventKind::AuditExportDestinationUpdated,
            AuditEventKind::AuditExportDestinationDeleted,
            AuditEventKind::SessionCreated,
            AuditEventKind::SessionDestroyed,
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
                | AuditEventKind::GdprPurgeCompleted
                | AuditEventKind::RoleGranted
                | AuditEventKind::RoleRevoked
                | AuditEventKind::CustomRoleCreated
                | AuditEventKind::CustomRoleUpdated
                | AuditEventKind::CustomRoleDeleted
                | AuditEventKind::AuditErased
                | AuditEventKind::AuditPartitionArchived
                | AuditEventKind::AuditExportDestinationCreated
                | AuditEventKind::AuditExportDestinationUpdated
                | AuditEventKind::AuditExportDestinationDeleted
                | AuditEventKind::SessionCreated
                | AuditEventKind::SessionDestroyed => {}
            }
            let json = serde_json::to_string(&kind).unwrap_or_else(|e| panic!("serialise: {e}"));
            let parsed: AuditEventKind =
                serde_json::from_str(&json).unwrap_or_else(|e| panic!("deserialise: {e}"));
            assert_eq!(parsed, kind);
        }
    }

    #[test]
    fn new_audit_event_kinds_serialize_to_pinned_strings() {
        // Section 11's `audit_events.action` column stores these verbatim.
        let cases = [
            (AuditEventKind::RoleGranted, "role_granted"),
            (AuditEventKind::RoleRevoked, "role_revoked"),
            (AuditEventKind::CustomRoleCreated, "custom_role_created"),
            (AuditEventKind::CustomRoleUpdated, "custom_role_updated"),
            (AuditEventKind::CustomRoleDeleted, "custom_role_deleted"),
            (AuditEventKind::AuditErased, "audit_erased"),
            (
                AuditEventKind::AuditPartitionArchived,
                "audit_partition_archived",
            ),
            (
                AuditEventKind::AuditExportDestinationCreated,
                "audit_export_destination_created",
            ),
            (
                AuditEventKind::AuditExportDestinationUpdated,
                "audit_export_destination_updated",
            ),
            (
                AuditEventKind::AuditExportDestinationDeleted,
                "audit_export_destination_deleted",
            ),
            (AuditEventKind::SessionCreated, "session_created"),
            (AuditEventKind::SessionDestroyed, "session_destroyed"),
        ];
        for (kind, expected) in cases {
            let json = serde_json::to_string(&kind).unwrap_or_else(|e| panic!("serialise: {e}"));
            assert_eq!(json, format!("\"{expected}\""));
        }
    }

    #[test]
    fn build_clamps_occurred_at_to_now_and_mints_v7_id() {
        let event = system_builder()
            .metadata(serde_json::json!({"k": "v"}))
            .build();
        let drift = (Utc::now() - event.occurred_at()).num_seconds().abs();
        assert!(
            drift <= 1,
            "occurred_at must clamp to now() (drift={drift}s)"
        );
        assert_eq!(event.event_id().get_version_num(), 7);
    }

    #[test]
    fn build_at_rejects_far_future() {
        let future = Utc::now() + ChronoDuration::seconds(60);
        let err = system_builder()
            .build_at(distinguishable_uuid(1), future)
            .expect_err("60s drift must reject");
        assert!(matches!(err, AuditEventError::OccurredAtSkew { .. }));
    }

    #[test]
    fn build_at_rejects_far_past() {
        let past = Utc::now() - ChronoDuration::seconds(60);
        let err = system_builder()
            .build_at(distinguishable_uuid(1), past)
            .expect_err("60s drift must reject");
        assert!(matches!(err, AuditEventError::OccurredAtSkew { .. }));
    }

    #[test]
    fn build_at_accepts_within_tolerance() {
        let close = Utc::now() - ChronoDuration::seconds(2);
        let event = system_builder()
            .build_at(distinguishable_uuid(1), close)
            .unwrap_or_else(|e| panic!("2s drift must pass: {e}"));
        assert_eq!(event.event_id(), distinguishable_uuid(1));
        assert_eq!(event.occurred_at(), close);
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
        let event = AuditEventV1::builder(
            AuditEventKind::SigninFailed,
            AuditActor::Anonymous {
                ip: Some(
                    "10.0.0.5"
                        .parse::<IpAddr>()
                        .unwrap_or_else(|e| panic!("ip parse: {e}")),
                ),
            },
            None,
            distinguishable_uuid(4),
        )
        .metadata(serde_json::json!({
            "email": "alice@example.com",
            "ip": "10.0.0.5"
        }))
        .before(serde_json::json!({"secret": "marker_before"}))
        .after(serde_json::json!({"secret": "marker_after"}))
        .build();
        let dbg = format!("{event:?}");
        // Top-level Debug includes the IP via AuditActor (intentional —
        // operators do see audit-actor IPs). The metadata / before / after
        // payloads, however, must be opaque.
        assert!(!dbg.contains("alice"));
        assert!(!dbg.contains("marker_before"));
        assert!(!dbg.contains("marker_after"));
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
