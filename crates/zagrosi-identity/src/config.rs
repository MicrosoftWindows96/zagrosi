// SPDX-License-Identifier: AGPL-3.0-or-later

//! Layered configuration loader for `zagrosi-identity`.
//!
//! Reads configuration from environment variables and an optional TOML
//! file via `figment`. Environment values take precedence; the file
//! fills gaps. Unknown fields are tolerated so future-version configs
//! can deserialise without erroring on fields this crate does not yet
//! recognise.
//!
//! The crate skeleton ships the minimum surface needed to validate the
//! two env vars introduced by the foundation work: `ZAGROSI_SECRETS_KEY`
//! and `ZAGROSI_VALKEY_URL`. Later layers extend [`IdentityConfig`] with
//! Argon2 / password / breach-list / session / OIDC / DNS / rate-limit
//! / DB-pool fields alongside the code that consumes them.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use figment::Figment;
use figment::providers::{Env, Format, Toml};
use zeroize::Zeroize;

use crate::Result;
use crate::error::IdentityError;

/// Number of bytes the decoded `ZAGROSI_SECRETS_KEY` must contain.
///
/// Crate-private — `pub(crate)` keeps `crypto/secrets.rs` callers
/// honest while satisfying the workspace `unreachable_pub = warn`
/// lint without polluting the crate's public API surface with an
/// AEAD-internal length.
pub(crate) const SECRETS_KEY_LEN: usize = 32;

/// Heap-resident container for the decoded master key.
///
/// Wraps `Option<Box<[u8; 32]>>` so the master key never traverses a
/// stack-frame slot once it leaves [`IdentityConfig::load`]. `Drop`
/// zeroes the inner bytes; the custom [`std::fmt::Debug`] impl renders
/// only `<redacted>` so a careless `tracing::debug!(?cfg)` cannot dump
/// the master key into log surfaces.
#[derive(Default)]
struct DecodedSecretsKey(Option<Box<[u8; SECRETS_KEY_LEN]>>);

impl Clone for DecodedSecretsKey {
    fn clone(&self) -> Self {
        // Cloning duplicates the heap allocation so the original and the
        // clone each manage their own zeroize-on-drop lifecycle.
        Self(self.0.as_ref().map(|boxed| Box::new(**boxed)))
    }
}

impl std::fmt::Debug for DecodedSecretsKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0.as_ref() {
            Some(_) => f.write_str("DecodedSecretsKey(<redacted>)"),
            None => f.write_str("DecodedSecretsKey(None)"),
        }
    }
}

impl Drop for DecodedSecretsKey {
    fn drop(&mut self) {
        if let Some(mut boxed) = self.0.take() {
            boxed.zeroize();
        }
    }
}

/// Top-level configuration consumed by `zagrosi-identity`.
///
/// The base64 source string `secrets_key` is **never** rendered through
/// the derived `Debug` or serialised back out through serde — both paths
/// are intercepted by the hand-rolled impls below so a careless
/// `tracing::debug!(?cfg)` or `serde_json::to_string(&cfg)` cannot leak
/// the master key into log surfaces. Deserialise still works (figment
/// loads the env value into the field at construction time).
#[derive(Clone, Default, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case", default)]
pub struct IdentityConfig {
    /// 32-byte base64 master key for the AES-256-GCM secrets envelope.
    /// Sourced from `ZAGROSI_SECRETS_KEY`. Consumed by the secrets shim.
    /// `serde(skip_serializing)` ensures the raw base64 bytes never
    /// round-trip back to wire surfaces; deserialise stays enabled so
    /// figment can read the env var.
    #[serde(skip_serializing)]
    pub secrets_key: String,

    /// Valkey connection URL for the rate limiter. Sourced from
    /// `ZAGROSI_VALKEY_URL`. Consumed by the rate-limit module.
    pub valkey_url: String,

    /// Argon2id hashing profile. Defaults to OWASP 2024 baseline.
    /// The password-auth surface consumes this for sign-up / sign-in / password-reset.
    pub argon2: Argon2Config,

    /// Password policy. Length-only checks; no character-class
    /// rules per NIST SP 800-63B.
    pub password: PasswordConfig,

    /// Breach-list lookup configuration. HIBP k-anonymity client.
    pub breachlist: BreachlistConfig,

    /// Single-use email token (verify-email + password-reset) TTL.
    /// Defaults to 30 minutes per the password-auth design.
    #[serde(default = "default_email_token_ttl_minutes")]
    pub email_token_ttl_minutes: u32,

    /// Rate-limit + lockout policy consumed by the Valkey-backed
    /// [`zagrosi_core::RateLimiter`] impl ([`crate::rate_limit::ValkeyRateLimiter`]).
    #[serde(default)]
    pub rate_limit: RateLimitConfig,

    /// Session-resolver policy. Issuance TTL, cache sizing, fail-closed
    /// degraded-mode TTL, and the optional NATS broker URL for
    /// cross-replica revocation events.
    #[serde(default)]
    pub session: SessionConfig,

    /// Multi-IdP routing DNS verification policy. Enumerates the
    /// DNSSEC-validating resolvers consulted by the domain-ownership
    /// flow plus the per-domain verify cache TTL.
    #[serde(default)]
    pub dns: DnsConfig,

    /// Outbound-SMTP policy consumed by the email-outbox worker's
    /// [`crate::email::LettreTransport`]. Both fields default empty;
    /// unlike the secrets / Valkey / DNS knobs this is **not**
    /// validated at [`IdentityConfig::load`] time, because the
    /// gateway and migration-smoke binaries load the config without
    /// running the email worker. [`crate::email::LettreTransport::from_config`]
    /// performs the validation at worker-construction time instead, so
    /// a deploy that never starts the worker (e.g. a read-replica API
    /// node) does not need SMTP configured.
    #[serde(default)]
    pub email: EmailConfig,

    /// Platform-administration policy. v0.1 carries only the
    /// service-token admin allowlist; this is the interim gate until
    /// the RBAC layer lands a real role check. Defaults empty (no
    /// platform admins → the service-token routes 403 every caller)
    /// and is **not** validated at [`IdentityConfig::load`] time.
    #[serde(default)]
    pub platform: PlatformConfig,

    /// Decoded master key, populated by [`IdentityConfig::load`] on
    /// successful validation. Skipped by serde so it never round-trips
    /// through TOML / env / wire surfaces.
    #[serde(skip)]
    decoded_secrets_key: DecodedSecretsKey,
}

const fn default_email_token_ttl_minutes() -> u32 {
    30
}

/// Argon2id hashing profile.
///
/// Defaults track OWASP's 2024 baseline (`m=19456 KiB`, `t=2`, `p=1`),
/// which `argon2`'s built-in defaults already match. `max_concurrency`
/// caps the number of in-flight `spawn_blocking` Argon2id verifies so a
/// burst of sign-ins cannot exhaust the blocking pool.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case", default)]
pub struct Argon2Config {
    /// Memory cost in KiB. `ZAGROSI_ARGON2_M_COST`. Default `19456`.
    pub m_cost: u32,
    /// Iteration count. `ZAGROSI_ARGON2_T_COST`. Default `2`.
    pub t_cost: u32,
    /// Parallelism. `ZAGROSI_ARGON2_P_COST`. Default `1`.
    pub p_cost: u32,
    /// Maximum concurrent Argon2id operations. `ZAGROSI_ARGON2_MAX_CONCURRENCY`.
    /// Default: `num_cpus::get()`.
    pub max_concurrency: usize,
}

impl Default for Argon2Config {
    fn default() -> Self {
        Self {
            m_cost: 19_456,
            t_cost: 2,
            p_cost: 1,
            max_concurrency: num_cpus::get(),
        }
    }
}

/// Password policy.
///
/// Length-only per NIST SP 800-63B (no character-class rules).
/// `max_length` is hard-coded at 256 to bound `DoS` surface from
/// arbitrarily long Argon2id inputs.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case", default)]
pub struct PasswordConfig {
    /// Minimum accepted password length. `ZAGROSI_PASSWORD_MIN_LENGTH`.
    /// Default `12`. Validation rejects values below `12` (NIST floor).
    pub min_length: usize,
    /// Maximum accepted password length. Hard-coded `256`; not
    /// env-configurable (`DoS` guard).
    #[serde(default = "default_password_max_length")]
    pub max_length: usize,
}

impl Default for PasswordConfig {
    fn default() -> Self {
        Self {
            min_length: 12,
            max_length: 256,
        }
    }
}

const fn default_password_max_length() -> usize {
    256
}

/// Breach-list lookup mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum BreachlistMode {
    /// Live HIBP k-anonymity call. Production default.
    #[default]
    Online,
    /// Skip the call entirely. Intended for air-gapped deploys.
    Disabled,
    /// Reserved for the deferred mirror feature. Treated as
    /// [`BreachlistMode::Disabled`] in v0.1 with a deprecation warning.
    Offline,
}

/// HIBP-backed breach-list configuration.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case", default)]
pub struct BreachlistConfig {
    /// Mode switch. `ZAGROSI_PASSWORD_BREACHLIST_MODE`. Default `Online`.
    pub mode: BreachlistMode,
    /// HTTP request timeout in seconds. Hard-coded `5`.
    #[serde(default = "default_breachlist_timeout_secs")]
    pub timeout_secs: u64,
    /// HIBP range endpoint. Hard-coded
    /// `https://api.pwnedpasswords.com/range/`.
    #[serde(default = "default_breachlist_endpoint")]
    pub endpoint: String,
}

impl Default for BreachlistConfig {
    fn default() -> Self {
        Self {
            mode: BreachlistMode::Online,
            timeout_secs: default_breachlist_timeout_secs(),
            endpoint: default_breachlist_endpoint(),
        }
    }
}

const fn default_breachlist_timeout_secs() -> u64 {
    5
}

fn default_breachlist_endpoint() -> String {
    "https://api.pwnedpasswords.com/range/".to_string()
}

/// Sliding-window budget parsed from a `<count>/<window>` literal.
///
/// Used by [`RateLimitConfig::signin_per_ip`]. The `<window>` suffix
/// accepts `s`, `min`, or `h` to keep the env value human-readable
/// while staying unambiguous; `<count>` is bounded to `u32` so a
/// pathologically large limit cannot overflow the in-Lua INCR check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct RateLimitBudget {
    /// Maximum requests permitted per `window`.
    pub count: u32,
    /// Window duration in seconds. Always positive.
    pub window_seconds: u32,
}

impl RateLimitBudget {
    /// Default sign-in budget: 20 requests per minute per source IP.
    pub const SIGNIN_DEFAULT: Self = Self {
        count: 20,
        window_seconds: 60,
    };

    /// Default per-token budget: 60 requests per minute. `SCIM` `IdPs`
    /// frequently egress from small NAT pools shared by many users,
    /// so the per-token bucket is sized larger than the per-IP one
    /// to avoid throttling legitimate enterprise traffic.
    pub const SIGNIN_PER_TOKEN_DEFAULT: Self = Self {
        count: 60,
        window_seconds: 60,
    };

    /// Default per-PAT budget: 120 requests per minute. PATs back
    /// API and MCP clients which run hotter than SCIM provisioning
    /// agents; the wider budget reflects that traffic profile.
    pub const PAT_PER_MINUTE_DEFAULT: Self = Self {
        count: 120,
        window_seconds: 60,
    };

    /// Parse a `<count>/<window>` literal.
    ///
    /// `<window>` recognises `s`, `min`, and `h` suffixes. The bare
    /// integer form is rejected so misconfigurations cannot silently
    /// fall through to "unlimited".
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::MalformedRateLimit`] for any parse or
    /// validation failure (zero count, zero window, unknown suffix,
    /// non-numeric component).
    pub fn parse(literal: &str) -> Result<Self> {
        let trimmed = literal.trim();
        let Some((count_str, window_str)) = trimmed.split_once('/') else {
            return Err(IdentityError::MalformedRateLimit {
                reason: format!("expected `<count>/<window>`, got `{trimmed}`"),
            });
        };
        let count: u32 =
            count_str
                .trim()
                .parse()
                .map_err(|_| IdentityError::MalformedRateLimit {
                    reason: format!("count `{count_str}` is not a positive integer"),
                })?;
        if count == 0 {
            return Err(IdentityError::MalformedRateLimit {
                reason: "count must be > 0".into(),
            });
        }
        let window_seconds = parse_window(window_str.trim())?;
        Ok(Self {
            count,
            window_seconds,
        })
    }

    /// Render back to a `<count>/<window>` literal.
    #[must_use]
    pub fn render(&self) -> String {
        let suffix = match self.window_seconds {
            1 => "s".to_string(),
            60 => "min".to_string(),
            3_600 => "h".to_string(),
            other => format!("{other}s"),
        };
        format!("{}/{}", self.count, suffix)
    }
}

impl Default for RateLimitBudget {
    fn default() -> Self {
        Self::SIGNIN_DEFAULT
    }
}

impl TryFrom<String> for RateLimitBudget {
    type Error = IdentityError;
    fn try_from(value: String) -> Result<Self> {
        Self::parse(&value)
    }
}

impl From<RateLimitBudget> for String {
    fn from(value: RateLimitBudget) -> Self {
        value.render()
    }
}

fn parse_window(input: &str) -> Result<u32> {
    let (num_str, unit_secs) = if let Some(num) = input.strip_suffix("min") {
        (num, 60_u32)
    } else if let Some(num) = input.strip_suffix('h') {
        (num, 3_600_u32)
    } else if let Some(num) = input.strip_suffix('s') {
        (num, 1_u32)
    } else {
        return Err(IdentityError::MalformedRateLimit {
            reason: format!("window `{input}` missing s/min/h suffix"),
        });
    };
    let num_str = num_str.trim();
    let multiplier: u32 = if num_str.is_empty() {
        1
    } else {
        num_str
            .parse()
            .map_err(|_| IdentityError::MalformedRateLimit {
                reason: format!("window `{input}` is not a positive integer with s/min/h suffix"),
            })?
    };
    let total =
        multiplier
            .checked_mul(unit_secs)
            .ok_or_else(|| IdentityError::MalformedRateLimit {
                reason: format!("window `{input}` overflows u32 seconds"),
            })?;
    if total == 0 {
        return Err(IdentityError::MalformedRateLimit {
            reason: "window must be > 0".into(),
        });
    }
    Ok(total)
}

/// Rate-limit + lockout policy.
///
/// Sub-policies live here so the Valkey-backed limiter and downstream
/// session code can read consistent values:
///
/// - [`RateLimitConfig::signin_per_ip`] — sliding-window per-IP budget
///   for the sign-in / password-reset / email-verify endpoints.
/// - [`RateLimitConfig::lockout_initial_minutes`] — first lockout
///   length once a per-account breach threshold trips.
/// - [`RateLimitConfig::lockout_max_hours`] — exponential backoff cap.
/// - [`RateLimitConfig::valkey_pool_size`] — number of multiplexed
///   fred connections in the pool. `fred` already multiplexes a single
///   client across tasks; the pool is sized for parallelism under
///   sustained sign-in load.
///
/// Validation runs at [`IdentityConfig::load`] time so a misconfigured
/// deploy refuses to start instead of brown-outs at first sign-in.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case", default)]
pub struct RateLimitConfig {
    /// Per-source-IP budget for sign-in / password-reset / email-verify.
    /// `ZAGROSI_RATE_LIMIT_SIGNIN_PER_IP`. Default `20/min`.
    pub signin_per_ip: RateLimitBudget,
    /// Per-token budget for SCIM / service-token scopes (everything
    /// keyed on a token hash other than personal access tokens).
    /// `ZAGROSI_RATE_LIMIT_SIGNIN_PER_TOKEN`. Default `60/min`.
    /// Sized larger than the per-IP budget because `SCIM` `IdPs` commonly
    /// egress from small NAT pools shared by many tenant users.
    #[serde(default = "default_signin_per_token")]
    pub signin_per_token: RateLimitBudget,
    /// Per-PAT budget for personal-access-token resolves. PATs back
    /// API and MCP clients which run hotter than SCIM provisioning
    /// agents, so the bucket is sized larger than the generic
    /// per-token budget. `ZAGROSI_RATE_LIMIT_PAT_PER_MIN`.
    /// Default `120/min`.
    #[serde(default = "default_pat_per_minute")]
    pub pat_per_minute: RateLimitBudget,
    /// First lockout window. Subsequent breaches double up to
    /// [`RateLimitConfig::lockout_max_hours`] hours.
    /// `ZAGROSI_RATE_LIMIT_LOCKOUT_INITIAL_MINUTES`. Default `15`.
    pub lockout_initial_minutes: u32,
    /// Lockout cap. `ZAGROSI_RATE_LIMIT_LOCKOUT_MAX_HOURS`. Default `24`.
    pub lockout_max_hours: u32,
    /// Threshold of consecutive failed sign-ins that trips a lockout.
    /// Defaults to `5`; surfaced here so tests can override when
    /// constructing a service directly.
    #[serde(default = "default_lockout_threshold")]
    pub lockout_threshold: u32,
    /// Window after a successful unlock during which an in-flight
    /// stale failure (a wrong-password request that started before
    /// the success arrived) is dropped instead of bumping the breach
    /// counter. Defaults to `2000` ms which comfortably covers an
    /// Argon2id verify on the OWASP baseline profile while keeping
    /// the legitimate-attacker window short.
    /// `ZAGROSI_RATE_LIMIT_UNLOCK_GRACE_MS`.
    #[serde(default = "default_unlock_grace_ms")]
    pub unlock_grace_ms: u32,
    /// Number of fred connections in the multiplexed pool.
    /// `ZAGROSI_VALKEY_POOL_SIZE`. Default `num_cpus::get()`.
    #[serde(default = "default_valkey_pool_size")]
    pub valkey_pool_size: usize,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            signin_per_ip: RateLimitBudget::default(),
            signin_per_token: default_signin_per_token(),
            pat_per_minute: default_pat_per_minute(),
            lockout_initial_minutes: 15,
            lockout_max_hours: 24,
            lockout_threshold: default_lockout_threshold(),
            unlock_grace_ms: default_unlock_grace_ms(),
            valkey_pool_size: default_valkey_pool_size(),
        }
    }
}

const fn default_lockout_threshold() -> u32 {
    5
}

const fn default_unlock_grace_ms() -> u32 {
    2_000
}

const fn default_signin_per_token() -> RateLimitBudget {
    RateLimitBudget::SIGNIN_PER_TOKEN_DEFAULT
}

const fn default_pat_per_minute() -> RateLimitBudget {
    RateLimitBudget::PAT_PER_MINUTE_DEFAULT
}

fn default_valkey_pool_size() -> usize {
    num_cpus::get()
}

/// Session-resolver policy.
///
/// Tunes the gateway-facing fast-path cache plus the issuance TTL. The
/// cache TTL splits into a healthy-mode value and a fail-closed-mode
/// value; the resolver flips between them based on the NATS health
/// probe so a partition that drops the eviction stream cannot leave
/// stale `revoked_at` rows alive in the cache for longer than the
/// fail-closed window.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case", default)]
pub struct SessionConfig {
    /// Lifetime of a freshly minted browser / bearer session in days.
    /// `ZAGROSI_SESSION_TTL_DAYS`. Default `7`.
    #[serde(default = "default_session_ttl_days")]
    pub ttl_days: u32,

    /// Cache TTL applied while the NATS broker is connected and
    /// processing eviction events. `ZAGROSI_SESSION_CACHE_TTL_SECS`.
    /// Default `30`. Larger values trade revocation latency for fewer
    /// DB round-trips on the cache-miss path.
    #[serde(default = "default_session_cache_ttl_secs")]
    pub cache_ttl_secs: u32,

    /// Cache TTL applied when the NATS broker is unreachable. The
    /// resolver flips to this TTL on the next health-tick interval so
    /// stale revocations cannot survive the partition.
    /// `ZAGROSI_SESSION_FAIL_CLOSED_TTL_SECS`. Default `1`.
    #[serde(default = "default_session_fail_closed_ttl_secs")]
    pub fail_closed_ttl_secs: u32,

    /// Cache size cap (entries). The moka cache evicts least-recently-
    /// used entries when this size is exceeded.
    /// `ZAGROSI_SESSION_CACHE_CAPACITY`. Default `50_000`.
    #[serde(default = "default_session_cache_capacity")]
    pub cache_capacity: u64,

    /// NATS broker URL. Empty disables cross-replica eviction; the
    /// resolver still ships the password-update invariant + the
    /// fail-closed cache TTL so the 1-second revocation SLA is met
    /// even without a broker.
    /// `ZAGROSI_SESSION_NATS_URL`. Default empty.
    #[serde(default)]
    pub nats_url: String,

    /// Health-probe tick interval, in seconds. The resolver polls the
    /// NATS connection state at this cadence and flips the cache TTL
    /// between healthy and fail-closed values when the state changes.
    /// `ZAGROSI_SESSION_HEALTH_TICK_SECS`. Default `1`.
    #[serde(default = "default_session_health_tick_secs")]
    pub health_tick_secs: u32,

    /// Bound on the in-memory `last_seen_at` write-behind channel.
    /// Updates are coalesced server-side once per session per minute;
    /// channel-full drops the update silently because `last_seen_at`
    /// is best-effort metadata, not a security primitive.
    /// `ZAGROSI_SESSION_LAST_SEEN_BUFFER`. Default `10_000`.
    #[serde(default = "default_session_last_seen_buffer")]
    pub last_seen_buffer: usize,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            ttl_days: default_session_ttl_days(),
            cache_ttl_secs: default_session_cache_ttl_secs(),
            fail_closed_ttl_secs: default_session_fail_closed_ttl_secs(),
            cache_capacity: default_session_cache_capacity(),
            nats_url: String::new(),
            health_tick_secs: default_session_health_tick_secs(),
            last_seen_buffer: default_session_last_seen_buffer(),
        }
    }
}

impl SessionConfig {
    /// Validate inter-field invariants. Run from
    /// [`IdentityConfig::load`] so misconfigured deploys fail at
    /// startup rather than browning out under load.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::MalformedRateLimit`] (the closest
    /// existing variant for runtime-config validation) when an
    /// invariant is violated.
    pub fn validate(&self) -> Result<()> {
        if self.ttl_days == 0 {
            return Err(IdentityError::MalformedSessionConfig {
                reason: "session.ttl_days must be > 0".into(),
            });
        }
        if self.cache_ttl_secs == 0 {
            return Err(IdentityError::MalformedSessionConfig {
                reason: "session.cache_ttl_secs must be > 0".into(),
            });
        }
        if self.fail_closed_ttl_secs == 0 {
            return Err(IdentityError::MalformedSessionConfig {
                reason: "session.fail_closed_ttl_secs must be > 0".into(),
            });
        }
        if self.fail_closed_ttl_secs > self.cache_ttl_secs {
            return Err(IdentityError::MalformedSessionConfig {
                reason: format!(
                    "session.fail_closed_ttl_secs ({}) must be <= cache_ttl_secs ({})",
                    self.fail_closed_ttl_secs, self.cache_ttl_secs,
                ),
            });
        }
        if self.cache_capacity == 0 {
            return Err(IdentityError::MalformedSessionConfig {
                reason: "session.cache_capacity must be > 0".into(),
            });
        }
        if self.health_tick_secs == 0 {
            return Err(IdentityError::MalformedSessionConfig {
                reason: "session.health_tick_secs must be > 0".into(),
            });
        }
        if self.last_seen_buffer == 0 {
            return Err(IdentityError::MalformedSessionConfig {
                reason: "session.last_seen_buffer must be > 0".into(),
            });
        }
        Ok(())
    }
}

const fn default_session_ttl_days() -> u32 {
    7
}

const fn default_session_cache_ttl_secs() -> u32 {
    30
}

const fn default_session_fail_closed_ttl_secs() -> u32 {
    1
}

const fn default_session_cache_capacity() -> u64 {
    50_000
}

const fn default_session_health_tick_secs() -> u32 {
    1
}

const fn default_session_last_seen_buffer() -> usize {
    10_000
}

/// Multi-IdP routing DNS verification policy.
///
/// Drives the domain-ownership challenge flow consumed by
/// [`crate::routing::domain_verify`]. The `resolvers` field is a
/// comma-separated list of DNSSEC-validating resolver IPs; the
/// production default (`1.1.1.1,9.9.9.9`) names two independently
/// operated upstreams so a single-resolver compromise cannot grant
/// an attacker-controlled domain to an attacker-controlled `IdP`.
///
/// Validated by [`DnsConfig::validate`] at startup: at least two
/// resolvers MUST be configured, every entry MUST parse as an IP,
/// the verify TTL MUST be > 0 minutes, and the per-resolver timeout
/// MUST be > 0 ms. Misconfiguration refuses startup rather than
/// silently weakening the verification root-of-trust.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case", default)]
pub struct DnsConfig {
    /// Comma-separated list of DNSSEC-validating resolver IPs.
    /// `ZAGROSI_DNS_RESOLVERS`. Default `"1.1.1.1,9.9.9.9"`. Min 2
    /// entries enforced at startup.
    #[serde(default = "default_dns_resolvers")]
    pub resolvers: String,
    /// Cache TTL for resolver lookups, in minutes. The Moka cache
    /// keyed by `(domain, challenge_token)` short-circuits repeated
    /// verify attempts within this window. `ZAGROSI_DNS_VERIFY_TTL_MINUTES`.
    /// Default `10`.
    #[serde(default = "default_dns_verify_ttl_minutes")]
    pub verify_ttl_minutes: u32,
    /// Per-resolver query timeout, in milliseconds. Bounds tail
    /// latency on the verify path so a slow upstream cannot stall
    /// the admin SPA. `ZAGROSI_DNS_VERIFY_TIMEOUT_MS`. Default
    /// `5000`.
    #[serde(default = "default_dns_verify_timeout_ms")]
    pub verify_timeout_ms: u32,
    /// Cache capacity bound (entries). Defends against an admin
    /// spamming verify across many domains.
    /// `ZAGROSI_DNS_CACHE_CAPACITY`. Default `10_000`.
    #[serde(default = "default_dns_cache_capacity")]
    pub cache_capacity: u64,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            resolvers: default_dns_resolvers(),
            verify_ttl_minutes: default_dns_verify_ttl_minutes(),
            verify_timeout_ms: default_dns_verify_timeout_ms(),
            cache_capacity: default_dns_cache_capacity(),
        }
    }
}

impl DnsConfig {
    /// Parse [`DnsConfig::resolvers`] into a vec of IPs. Empty
    /// elements are dropped (so `"1.1.1.1, 9.9.9.9"` and
    /// `"1.1.1.1,,9.9.9.9"` both parse cleanly).
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::MalformedDnsConfig`] when an entry
    /// fails to parse as an IP address.
    pub fn parsed_resolvers(&self) -> Result<Vec<std::net::IpAddr>> {
        let mut out = Vec::new();
        for raw in self.resolvers.split(',') {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                continue;
            }
            let ip: std::net::IpAddr =
                trimmed
                    .parse()
                    .map_err(|_| IdentityError::MalformedDnsConfig {
                        reason: format!("`{trimmed}` is not a valid IP address"),
                    })?;
            out.push(ip);
        }
        Ok(out)
    }

    /// Validate inter-field invariants.
    ///
    /// At least two resolvers MUST be configured (single-resolver
    /// verification is a weaker root-of-trust). The verify TTL and
    /// per-resolver timeout MUST be > 0; the cache capacity MUST
    /// be > 0.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::MalformedDnsConfig`] for any
    /// invariant violation.
    pub fn validate(&self) -> Result<()> {
        let resolvers = self.parsed_resolvers()?;
        if resolvers.len() < 2 {
            return Err(IdentityError::MalformedDnsConfig {
                reason: format!(
                    "ZAGROSI_DNS_RESOLVERS must list at least 2 resolvers (got {})",
                    resolvers.len()
                ),
            });
        }
        // Reject duplicates: `1.1.1.1,1.1.1.1` would collapse the
        // dual-resolver trust model to a single upstream while still
        // satisfying the >=2 length guard. Dedupe via a temporary
        // BTreeSet so the error message can name the duplicate IP.
        let mut seen = std::collections::BTreeSet::new();
        for ip in &resolvers {
            if !seen.insert(*ip) {
                return Err(IdentityError::MalformedDnsConfig {
                    reason: format!(
                        "ZAGROSI_DNS_RESOLVERS contains duplicate entry `{ip}`; \
                         dual-resolver trust model requires distinct upstreams",
                    ),
                });
            }
        }
        if self.verify_ttl_minutes == 0 {
            return Err(IdentityError::MalformedDnsConfig {
                reason: "dns.verify_ttl_minutes must be > 0".into(),
            });
        }
        if self.verify_timeout_ms == 0 {
            return Err(IdentityError::MalformedDnsConfig {
                reason: "dns.verify_timeout_ms must be > 0".into(),
            });
        }
        if self.cache_capacity == 0 {
            return Err(IdentityError::MalformedDnsConfig {
                reason: "dns.cache_capacity must be > 0".into(),
            });
        }
        Ok(())
    }
}

fn default_dns_resolvers() -> String {
    "1.1.1.1,9.9.9.9".to_string()
}

const fn default_dns_verify_ttl_minutes() -> u32 {
    10
}

const fn default_dns_verify_timeout_ms() -> u32 {
    5_000
}

const fn default_dns_cache_capacity() -> u64 {
    10_000
}

/// Outbound-SMTP policy for the email-outbox worker.
///
/// `smtp_url` is an RFC-style connection URL parsed by
/// [`lettre::AsyncSmtpTransport::from_url`]. The email-outbox design
/// mandates implicit TLS, so [`crate::email::LettreTransport::from_config`]
/// rejects any scheme other than `smtps://`. `smtp_from` is the
/// envelope/header `From:` mailbox applied to every outbound message
/// (per-tenant override is deferred to the admin layer).
///
/// Both fields default empty. Validation is deferred to
/// [`crate::email::LettreTransport::from_config`] rather than
/// [`IdentityConfig::load`] so binaries that load the config without
/// running the worker (gateway read-replica, migration-smoke) start
/// cleanly without SMTP configured.
#[derive(Clone, Default, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case", default)]
pub struct EmailConfig {
    /// SMTP connection URL. `ZAGROSI_EMAIL.SMTP_URL`. MUST be
    /// `smtps://[user[:pass]@]host[:port]` — implicit TLS only. The
    /// password component is part of the URL; the surrounding
    /// `IdentityConfig` `Debug` impl renders this field as
    /// `<redacted>` so a credentialed URL never reaches a log line.
    pub smtp_url: String,
    /// Sender mailbox applied to every outbound message, e.g.
    /// `"Zagrosi <no-reply@example.com>"`. `ZAGROSI_EMAIL.SMTP_FROM`.
    pub smtp_from: String,
}

impl EmailConfig {
    /// `true` when neither field is set — the worker is disabled and
    /// the deploy never attempts SMTP.
    #[must_use]
    pub const fn is_unset(&self) -> bool {
        self.smtp_url.is_empty() && self.smtp_from.is_empty()
    }
}

impl std::fmt::Debug for EmailConfig {
    /// `smtp_url` may embed `user:password@`; render only whether it
    /// is set so a `tracing::debug!(?cfg)` cannot exfiltrate the SMTP
    /// credential. `smtp_from` is not a secret and renders verbatim.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmailConfig")
            .field(
                "smtp_url",
                if self.smtp_url.is_empty() {
                    &"<unset>"
                } else {
                    &"<redacted>"
                },
            )
            .field("smtp_from", &self.smtp_from)
            .finish()
    }
}

/// Platform-administration policy.
///
/// `admin_user_ids` is the interim service-token issuance gate: the
/// `/v1/service-tokens` routes accept only a session whose
/// `subject_id` is in this list. Empty (the default) means no
/// platform admins are configured, so every caller is refused — a
/// fail-closed default. Replaced by a real RBAC role check when the
/// tenant-isolation layer lands; until then this env/TOML allowlist
/// is the source of truth.
///
/// `ZAGROSI_PLATFORM.ADMIN_USER_IDS` — comma/array of UUIDs.
#[derive(Debug, Clone, Default, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case", default)]
pub struct PlatformConfig {
    /// User IDs permitted to mint / revoke service tokens. The list
    /// is small and admin-managed; lookup is a linear scan.
    pub admin_user_ids: Vec<uuid::Uuid>,
}

impl PlatformConfig {
    /// `true` when `user_id` is a configured platform admin.
    #[must_use]
    pub fn is_admin(&self, user_id: uuid::Uuid) -> bool {
        self.admin_user_ids.contains(&user_id)
    }
}

impl RateLimitConfig {
    /// Validate inter-field invariants.
    ///
    /// `lockout_max_hours * 60` MUST be >= `lockout_initial_minutes` so
    /// the exponential backoff cap actually exceeds the first lockout
    /// (otherwise the limiter would clamp before the first breach
    /// completed). `lockout_threshold` MUST be > 0 so a single failed
    /// sign-in cannot lock an account.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::MalformedRateLimit`] when any invariant
    /// is violated.
    pub fn validate(&self) -> Result<()> {
        if self.lockout_threshold == 0 {
            return Err(IdentityError::MalformedRateLimit {
                reason: "lockout_threshold must be > 0".into(),
            });
        }
        if self.lockout_initial_minutes == 0 {
            return Err(IdentityError::MalformedRateLimit {
                reason: "lockout_initial_minutes must be > 0".into(),
            });
        }
        if self.lockout_max_hours == 0 {
            return Err(IdentityError::MalformedRateLimit {
                reason: "lockout_max_hours must be > 0".into(),
            });
        }
        let cap_minutes = self.lockout_max_hours.saturating_mul(60);
        if cap_minutes < self.lockout_initial_minutes {
            return Err(IdentityError::MalformedRateLimit {
                reason: format!(
                    "lockout_max_hours ({}) * 60 = {} < lockout_initial_minutes ({})",
                    self.lockout_max_hours, cap_minutes, self.lockout_initial_minutes,
                ),
            });
        }
        if self.unlock_grace_ms == 0 {
            return Err(IdentityError::MalformedRateLimit {
                reason: "unlock_grace_ms must be > 0".into(),
            });
        }
        if self.valkey_pool_size == 0 {
            return Err(IdentityError::MalformedRateLimit {
                reason: "valkey_pool_size must be > 0".into(),
            });
        }
        Ok(())
    }

    /// Unlock-grace window, in milliseconds, exposed to the Lua
    /// state machine as `ARGV[5]` for the lockout script and `ARGV[1]`
    /// for the unlock script.
    #[must_use]
    pub const fn unlock_grace_ms(&self) -> u64 {
        self.unlock_grace_ms as u64
    }

    /// History-key retention TTL, in milliseconds. The hash holding
    /// `attempts` / `backoff_ms` / `last_locked_ms` lives at least
    /// this long so escalation memory survives the active lockout
    /// window plus a comfortable margin. Defaults to twice
    /// [`RateLimitConfig::max_backoff_ms`] with a 1-hour floor so a
    /// short cap (e.g. 1h for tests) still keeps history addressable
    /// past the typical attacker pause.
    #[must_use]
    pub fn history_ttl_ms(&self) -> u64 {
        let doubled = self.max_backoff_ms().saturating_mul(2);
        doubled.max(3_600_000)
    }

    /// Initial lockout backoff, in milliseconds.
    #[must_use]
    pub const fn initial_backoff_ms(&self) -> u64 {
        (self.lockout_initial_minutes as u64).saturating_mul(60_000)
    }

    /// Lockout cap, in milliseconds.
    #[must_use]
    pub const fn max_backoff_ms(&self) -> u64 {
        (self.lockout_max_hours as u64).saturating_mul(3_600_000)
    }
}

impl std::fmt::Debug for IdentityConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityConfig")
            .field("secrets_key", &"<redacted>")
            .field("valkey_url", &self.valkey_url)
            .field("argon2", &self.argon2)
            .field("password", &self.password)
            .field("breachlist", &self.breachlist)
            .field("email_token_ttl_minutes", &self.email_token_ttl_minutes)
            .field("rate_limit", &self.rate_limit)
            .field("session", &self.session)
            .field("dns", &self.dns)
            .field("email", &self.email)
            .field("platform", &self.platform)
            .field("decoded_secrets_key", &self.decoded_secrets_key)
            .finish()
    }
}

/// Options accepted by [`IdentityConfig::load`].
///
/// Duplicates the shape of `zagrosi_core::config::LoadOptions` rather
/// than importing it. Keeps the boundary clean so later sections can
/// add identity-specific options without coupling the two crates'
/// loader contracts.
#[derive(Debug, Default, Clone, Copy)]
pub struct LoadOptions<'a> {
    /// Environment variable prefix. Conventionally `"ZAGROSI_"`.
    pub env_prefix: &'a str,
    /// Optional path to a TOML configuration file.
    pub file_path: Option<&'a std::path::Path>,
}

impl IdentityConfig {
    /// Load configuration from environment variables and (optionally) a
    /// TOML file.
    ///
    /// Mirrors `zagrosi_core::CoreConfig::load`. After figment merges
    /// the layers, validates that:
    ///
    /// - `ZAGROSI_SECRETS_KEY` is present and decodes to exactly 32
    ///   bytes of base64.
    /// - `ZAGROSI_VALKEY_URL` is present and non-empty.
    ///
    /// # Errors
    ///
    /// - [`IdentityError::Config`] when env values or file contents
    ///   fail to deserialise into [`IdentityConfig`].
    /// - [`IdentityError::MissingSecretsKey`] if the env var is absent
    ///   or empty.
    /// - [`IdentityError::MalformedSecretsKey`] if the value is not
    ///   base64 or does not decode to exactly 32 bytes.
    /// - [`IdentityError::MissingValkeyUrl`] if the env var is absent
    ///   or empty.
    pub fn load(opts: LoadOptions<'_>) -> Result<Self> {
        let mut figment = Figment::new();
        if let Some(path) = opts.file_path {
            figment = figment.merge(Toml::file(path));
        }
        figment = figment.merge(Env::prefixed(opts.env_prefix));
        let mut cfg: Self = figment.extract()?;
        let decoded_bytes = cfg.validate_and_decode()?;
        cfg.rate_limit.validate()?;
        cfg.session.validate()?;
        cfg.dns.validate()?;
        cfg.decoded_secrets_key = DecodedSecretsKey(Some(decoded_bytes));
        Ok(cfg)
    }

    fn validate_and_decode(&self) -> Result<Box<[u8; SECRETS_KEY_LEN]>> {
        if self.secrets_key.is_empty() {
            return Err(IdentityError::MissingSecretsKey);
        }
        let mut decoded = BASE64_STANDARD.decode(&self.secrets_key).map_err(|_| {
            IdentityError::MalformedSecretsKey {
                reason: "not valid base64".into(),
            }
        })?;
        if decoded.len() != SECRETS_KEY_LEN {
            let actual_len = decoded.len();
            decoded.zeroize();
            return Err(IdentityError::MalformedSecretsKey {
                reason: format!("decoded length {actual_len} bytes, expected {SECRETS_KEY_LEN}"),
            });
        }
        if self.valkey_url.is_empty() {
            decoded.zeroize();
            return Err(IdentityError::MissingValkeyUrl);
        }
        // Password policy floor. NIST SP 800-63B sets the 8-char floor;
        // the project chose 12 chars.
        if self.password.min_length < 12 {
            decoded.zeroize();
            return Err(IdentityError::PasswordTooShort {
                min: self.password.min_length,
            });
        }
        // Allocate the master-key slot directly on the heap and copy into
        // it so the only authoritative copy lives behind a pointer that
        // `DecodedSecretsKey::Drop` can zeroize. The intermediate
        // `decoded: Vec<u8>` is then explicitly zeroized before drop.
        let mut boxed: Box<[u8; SECRETS_KEY_LEN]> = Box::new([0_u8; SECRETS_KEY_LEN]);
        boxed.copy_from_slice(&decoded);
        decoded.zeroize();
        Ok(boxed)
    }

    /// Borrow the decoded 32-byte master key.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::MissingSecretsKey`] when the config was
    /// constructed via [`Default::default`] without a subsequent
    /// successful [`IdentityConfig::load`]. Production call sites
    /// (`crypto::Secrets::from_config`) only ever see a `load`-validated
    /// config so this branch is purely for misuse safety.
    pub fn secrets_key(&self) -> Result<&[u8; SECRETS_KEY_LEN]> {
        self.decoded_secrets_key
            .0
            .as_deref()
            .ok_or(IdentityError::MissingSecretsKey)
    }

    /// Take ownership of the decoded master key, leaving `None` behind.
    ///
    /// Used by `crypto::Secrets::from_config` to move the boxed key
    /// straight into a `SecretBox` without producing a stack-frame copy
    /// of the underlying 32 bytes.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::MissingSecretsKey`] when the config was
    /// not successfully `load`-ed.
    pub(crate) fn take_secrets_key(&mut self) -> Result<Box<[u8; SECRETS_KEY_LEN]>> {
        self.decoded_secrets_key
            .0
            .take()
            .ok_or(IdentityError::MissingSecretsKey)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use static_assertions::assert_impl_all;

    assert_impl_all!(IdentityConfig: Send, Sync);
    assert_impl_all!(LoadOptions<'static>: Send, Sync, Copy);

    /// Base64-encoded zero-filled 32-byte key. Decodes to exactly
    /// 32 bytes; suitable for tests that only need the validation
    /// path to accept.
    const VALID_SECRETS_KEY_B64: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    /// Base64-encoded zero-filled 16-byte value. Valid base64 but
    /// shorter than the required 32 bytes.
    const SHORT_SECRETS_KEY_B64: &str = "AAAAAAAAAAAAAAAAAAAAAA==";

    #[test]
    fn missing_secrets_key_returns_missing_secrets_key() {
        figment::Jail::expect_with(|jail| {
            jail.clear_env();
            let result = IdentityConfig::load(LoadOptions {
                env_prefix: "ZAGROSI_",
                file_path: None,
            });
            match result {
                Err(IdentityError::MissingSecretsKey) => Ok(()),
                other => Err(figment::Error::from(format!(
                    "expected MissingSecretsKey, got {other:?}"
                ))),
            }
        });
    }

    #[test]
    fn malformed_secrets_key_non_base64_returns_malformed() {
        figment::Jail::expect_with(|jail| {
            jail.clear_env();
            jail.set_env("ZAGROSI_SECRETS_KEY", "!!!not-base64!!!");
            jail.set_env("ZAGROSI_VALKEY_URL", "redis://valkey:6379");
            let result = IdentityConfig::load(LoadOptions {
                env_prefix: "ZAGROSI_",
                file_path: None,
            });
            match result {
                Err(IdentityError::MalformedSecretsKey { reason }) => {
                    assert!(
                        reason.contains("base64"),
                        "expected reason to mention base64, got: {reason}"
                    );
                    Ok(())
                }
                other => Err(figment::Error::from(format!(
                    "expected MalformedSecretsKey, got {other:?}"
                ))),
            }
        });
    }

    #[test]
    fn malformed_secrets_key_wrong_length_returns_malformed() {
        figment::Jail::expect_with(|jail| {
            jail.clear_env();
            jail.set_env("ZAGROSI_SECRETS_KEY", SHORT_SECRETS_KEY_B64);
            jail.set_env("ZAGROSI_VALKEY_URL", "redis://valkey:6379");
            let result = IdentityConfig::load(LoadOptions {
                env_prefix: "ZAGROSI_",
                file_path: None,
            });
            match result {
                Err(IdentityError::MalformedSecretsKey { reason }) => {
                    assert!(
                        reason.contains("16 bytes"),
                        "expected reason to name actual length `16 bytes`, got: {reason}"
                    );
                    Ok(())
                }
                other => Err(figment::Error::from(format!(
                    "expected MalformedSecretsKey, got {other:?}"
                ))),
            }
        });
    }

    #[test]
    fn valid_32_byte_base64_passes_secrets_validation() {
        figment::Jail::expect_with(|jail| {
            jail.clear_env();
            jail.set_env("ZAGROSI_SECRETS_KEY", VALID_SECRETS_KEY_B64);
            jail.set_env("ZAGROSI_VALKEY_URL", "redis://valkey:6379");
            let cfg = IdentityConfig::load(LoadOptions {
                env_prefix: "ZAGROSI_",
                file_path: None,
            })
            .map_err(|e| figment::Error::from(e.to_string()))?;
            assert_eq!(cfg.secrets_key, VALID_SECRETS_KEY_B64);
            assert_eq!(cfg.valkey_url, "redis://valkey:6379");
            Ok(())
        });
    }

    #[test]
    fn missing_valkey_url_returns_missing() {
        figment::Jail::expect_with(|jail| {
            jail.clear_env();
            jail.set_env("ZAGROSI_SECRETS_KEY", VALID_SECRETS_KEY_B64);
            let result = IdentityConfig::load(LoadOptions {
                env_prefix: "ZAGROSI_",
                file_path: None,
            });
            match result {
                Err(IdentityError::MissingValkeyUrl) => Ok(()),
                other => Err(figment::Error::from(format!(
                    "expected MissingValkeyUrl, got {other:?}"
                ))),
            }
        });
    }

    #[test]
    fn valkey_url_round_trips() {
        figment::Jail::expect_with(|jail| {
            jail.clear_env();
            jail.set_env("ZAGROSI_SECRETS_KEY", VALID_SECRETS_KEY_B64);
            jail.set_env("ZAGROSI_VALKEY_URL", "redis://valkey-test:6379");
            let cfg = IdentityConfig::load(LoadOptions {
                env_prefix: "ZAGROSI_",
                file_path: None,
            })
            .map_err(|e| figment::Error::from(e.to_string()))?;
            assert_eq!(cfg.valkey_url, "redis://valkey-test:6379");
            Ok(())
        });
    }

    #[test]
    fn unknown_fields_in_file_are_tolerated() {
        figment::Jail::expect_with(|jail| {
            jail.clear_env();
            jail.create_file("test.toml", "unknown_future_field = \"ignored\"\n")?;
            jail.set_env("ZAGROSI_SECRETS_KEY", VALID_SECRETS_KEY_B64);
            jail.set_env("ZAGROSI_VALKEY_URL", "redis://valkey:6379");
            let path = jail.directory().join("test.toml");
            let cfg = IdentityConfig::load(LoadOptions {
                env_prefix: "ZAGROSI_",
                file_path: Some(&path),
            })
            .map_err(|e| figment::Error::from(e.to_string()))?;
            assert_eq!(cfg.secrets_key, VALID_SECRETS_KEY_B64);
            assert_eq!(cfg.valkey_url, "redis://valkey:6379");
            Ok(())
        });
    }

    #[test]
    fn file_only_loads_configuration() {
        figment::Jail::expect_with(|jail| {
            jail.clear_env();
            jail.create_file(
                "test.toml",
                &format!(
                    "secrets_key = \"{VALID_SECRETS_KEY_B64}\"\nvalkey_url = \"redis://from-file:6379\"\n"
                ),
            )?;
            let path = jail.directory().join("test.toml");
            let cfg = IdentityConfig::load(LoadOptions {
                env_prefix: "ZAGROSI_",
                file_path: Some(&path),
            })
            .map_err(|e| figment::Error::from(e.to_string()))?;
            assert_eq!(cfg.secrets_key, VALID_SECRETS_KEY_B64);
            assert_eq!(cfg.valkey_url, "redis://from-file:6379");
            Ok(())
        });
    }

    #[test]
    fn empty_secrets_key_env_returns_missing() {
        figment::Jail::expect_with(|jail| {
            jail.clear_env();
            jail.set_env("ZAGROSI_SECRETS_KEY", "");
            jail.set_env("ZAGROSI_VALKEY_URL", "redis://valkey:6379");
            let result = IdentityConfig::load(LoadOptions {
                env_prefix: "ZAGROSI_",
                file_path: None,
            });
            match result {
                Err(IdentityError::MissingSecretsKey) => Ok(()),
                other => Err(figment::Error::from(format!(
                    "expected MissingSecretsKey for empty env, got {other:?}"
                ))),
            }
        });
    }

    #[test]
    fn empty_valkey_url_env_returns_missing() {
        figment::Jail::expect_with(|jail| {
            jail.clear_env();
            jail.set_env("ZAGROSI_SECRETS_KEY", VALID_SECRETS_KEY_B64);
            jail.set_env("ZAGROSI_VALKEY_URL", "");
            let result = IdentityConfig::load(LoadOptions {
                env_prefix: "ZAGROSI_",
                file_path: None,
            });
            match result {
                Err(IdentityError::MissingValkeyUrl) => Ok(()),
                other => Err(figment::Error::from(format!(
                    "expected MissingValkeyUrl for empty env, got {other:?}"
                ))),
            }
        });
    }

    #[test]
    fn env_overrides_file_value() {
        figment::Jail::expect_with(|jail| {
            jail.clear_env();
            jail.create_file("test.toml", "valkey_url = \"redis://from-file:6379\"\n")?;
            jail.set_env("ZAGROSI_SECRETS_KEY", VALID_SECRETS_KEY_B64);
            jail.set_env("ZAGROSI_VALKEY_URL", "redis://from-env:6379");
            let path = jail.directory().join("test.toml");
            let cfg = IdentityConfig::load(LoadOptions {
                env_prefix: "ZAGROSI_",
                file_path: Some(&path),
            })
            .map_err(|e| figment::Error::from(e.to_string()))?;
            assert_eq!(cfg.valkey_url, "redis://from-env:6379");
            Ok(())
        });
    }

    #[test]
    fn debug_does_not_leak_master_key() {
        figment::Jail::expect_with(|jail| {
            jail.clear_env();
            jail.set_env("ZAGROSI_SECRETS_KEY", VALID_SECRETS_KEY_B64);
            jail.set_env("ZAGROSI_VALKEY_URL", "redis://valkey:6379");
            let cfg = IdentityConfig::load(LoadOptions {
                env_prefix: "ZAGROSI_",
                file_path: None,
            })
            .map_err(|e| figment::Error::from(e.to_string()))?;
            let rendered = format!("{cfg:?}");
            assert!(rendered.contains("redacted"));
            assert!(
                !rendered.contains(VALID_SECRETS_KEY_B64),
                "Debug must not leak the base64 master key"
            );
            assert!(
                !rendered.contains("AAAAAAA"),
                "Debug must not leak any prefix of the base64 master key"
            );
            Ok(())
        });
    }

    #[test]
    fn dns_default_resolvers_parse_and_validate() {
        let cfg = DnsConfig::default();
        cfg.validate()
            .unwrap_or_else(|e| panic!("default DnsConfig must validate: {e}"));
        let parsed = cfg
            .parsed_resolvers()
            .unwrap_or_else(|e| panic!("default resolvers must parse: {e}"));
        assert_eq!(parsed.len(), 2, "default ships exactly two resolvers");
    }

    #[test]
    fn dns_validate_rejects_duplicate_resolvers() {
        // CX-2 regression: `1.1.1.1,1.1.1.1` would pass the
        // length>=2 guard but collapse the dual-resolver trust
        // model to a single upstream. Reject at startup.
        let cfg = DnsConfig {
            resolvers: "1.1.1.1,1.1.1.1".to_string(),
            ..DnsConfig::default()
        };
        let err = cfg
            .validate()
            .expect_err("duplicate resolver IPs must reject");
        match err {
            IdentityError::MalformedDnsConfig { reason } => {
                assert!(
                    reason.contains("duplicate"),
                    "reason should mention duplicate, got: {reason}"
                );
            }
            other => panic!("expected MalformedDnsConfig, got {other:?}"),
        }
    }

    #[test]
    fn dns_validate_rejects_single_resolver() {
        let cfg = DnsConfig {
            resolvers: "1.1.1.1".to_string(),
            ..DnsConfig::default()
        };
        let err = cfg.validate().expect_err("single resolver must reject");
        match err {
            IdentityError::MalformedDnsConfig { reason } => {
                assert!(
                    reason.contains("at least 2"),
                    "reason should mention 2-resolver minimum, got: {reason}"
                );
            }
            other => panic!("expected MalformedDnsConfig, got {other:?}"),
        }
    }

    #[test]
    fn dns_validate_rejects_empty_resolvers() {
        let cfg = DnsConfig {
            resolvers: String::new(),
            ..DnsConfig::default()
        };
        assert!(matches!(
            cfg.validate().unwrap_err(),
            IdentityError::MalformedDnsConfig { .. }
        ));
    }

    #[test]
    fn dns_validate_rejects_unparseable_ip() {
        let cfg = DnsConfig {
            resolvers: "1.1.1.1,not-an-ip".to_string(),
            ..DnsConfig::default()
        };
        let err = cfg.validate().expect_err("non-IP entry must reject");
        match err {
            IdentityError::MalformedDnsConfig { reason } => {
                assert!(
                    reason.contains("not-an-ip"),
                    "reason should echo offending entry, got: {reason}"
                );
            }
            other => panic!("expected MalformedDnsConfig, got {other:?}"),
        }
    }

    #[test]
    fn dns_validate_rejects_zero_ttl() {
        let cfg = DnsConfig {
            verify_ttl_minutes: 0,
            ..DnsConfig::default()
        };
        assert!(matches!(
            cfg.validate().unwrap_err(),
            IdentityError::MalformedDnsConfig { .. }
        ));
    }

    #[test]
    fn dns_validate_rejects_zero_timeout() {
        let cfg = DnsConfig {
            verify_timeout_ms: 0,
            ..DnsConfig::default()
        };
        assert!(matches!(
            cfg.validate().unwrap_err(),
            IdentityError::MalformedDnsConfig { .. }
        ));
    }

    #[test]
    fn dns_parsed_resolvers_skips_blank_entries() {
        let cfg = DnsConfig {
            resolvers: "1.1.1.1, ,9.9.9.9, ".to_string(),
            ..DnsConfig::default()
        };
        let parsed = cfg
            .parsed_resolvers()
            .unwrap_or_else(|e| panic!("blank-elision parse: {e}"));
        assert_eq!(parsed.len(), 2);
    }

    #[test]
    fn identity_config_load_rejects_single_resolver_at_startup() {
        figment::Jail::expect_with(|jail| {
            jail.clear_env();
            jail.set_env("ZAGROSI_SECRETS_KEY", VALID_SECRETS_KEY_B64);
            jail.set_env("ZAGROSI_VALKEY_URL", "redis://valkey:6379");
            jail.set_env("ZAGROSI_DNS.RESOLVERS", "1.1.1.1");
            let result = IdentityConfig::load(LoadOptions {
                env_prefix: "ZAGROSI_",
                file_path: None,
            });
            match result {
                Err(IdentityError::MalformedDnsConfig { .. }) => Ok(()),
                other => Err(figment::Error::from(format!(
                    "expected MalformedDnsConfig for single resolver, got {other:?}"
                ))),
            }
        });
    }

    #[test]
    fn serialize_skips_secrets_key_field() {
        figment::Jail::expect_with(|jail| {
            jail.clear_env();
            jail.set_env("ZAGROSI_SECRETS_KEY", VALID_SECRETS_KEY_B64);
            jail.set_env("ZAGROSI_VALKEY_URL", "redis://valkey:6379");
            let cfg = IdentityConfig::load(LoadOptions {
                env_prefix: "ZAGROSI_",
                file_path: None,
            })
            .map_err(|e| figment::Error::from(e.to_string()))?;
            let rendered =
                serde_json::to_string(&cfg).map_err(|e| figment::Error::from(e.to_string()))?;
            assert!(
                !rendered.contains(VALID_SECRETS_KEY_B64),
                "serde_json::to_string must not emit the master key"
            );
            assert!(
                !rendered.contains("secrets_key"),
                "secrets_key field must be skip_serialized"
            );
            assert!(rendered.contains("valkey_url"));
            Ok(())
        });
    }
}
