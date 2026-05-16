// SPDX-License-Identifier: AGPL-3.0-or-later

//! Rate-limit + lockout port.
//!
//! Identity's sign-in / password-reset / SCIM endpoints call
//! [`RateLimiter::check`] before the constant-time path. The Valkey-backed
//! sliding-window impl ships in `zagrosi-identity`.
//!
//! Keys distinguish per-IP token-bucket budgets from per-account
//! exponential lockouts and from per-token (PAT / SCIM / service)
//! budgets. The `scope` field lets a single backend host multiple buckets
//! without collision (e.g. sign-in vs password-reset both per-IP).

use async_trait::async_trait;
use std::fmt;
use std::net::IpAddr;
use std::time::Duration;

/// Sliding-window rate limiter + lockout.
#[async_trait]
pub trait RateLimiter: Send + Sync + 'static {
    /// Probe + decrement. Returns the decision the caller must enforce.
    async fn check(&self, key: &RateLimitKey) -> Result<RateLimitDecision, RateLimiterError>;

    /// Force-clear the lockout for a key (admin unlock path).
    async fn unlock(&self, key: &RateLimitKey) -> Result<(), RateLimiterError>;
}

/// Bucket key + scope.
///
/// The [`fmt::Debug`] impl deliberately redacts the SHA-256 token hash on
/// [`RateLimitKey::PerToken`]: that hash IS the auth credential at the DB
/// layer (`sessions` / `api_tokens` / `scim_tokens` / `service_tokens` are
/// keyed on the same column), so a careless `tracing::debug!(?key)` after
/// a rate-limit decision would leak the credential to anyone with log read.
#[derive(Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RateLimitKey {
    /// Per-source-IP bucket.
    PerIp {
        /// Caller IP address.
        ip: IpAddr,
        /// Scope tag (e.g. `"signin"`, `"password_reset"`).
        scope: &'static str,
    },
    /// Per-account bucket (used for exponential lockout).
    PerAccount {
        /// User identifier.
        user_id: uuid::Uuid,
        /// Scope tag.
        scope: &'static str,
    },
    /// Per-token bucket (PAT / SCIM / service token).
    PerToken {
        /// SHA-256 hash of the prefix-included raw token.
        token_hash: [u8; 32],
        /// Scope tag.
        scope: &'static str,
    },
}

impl fmt::Debug for RateLimitKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PerIp { ip, scope } => f
                .debug_struct("PerIp")
                .field("ip", ip)
                .field("scope", scope)
                .finish(),
            Self::PerAccount { user_id, scope } => f
                .debug_struct("PerAccount")
                .field("user_id", user_id)
                .field("scope", scope)
                .finish(),
            Self::PerToken {
                token_hash: _,
                scope,
            } => f
                .debug_struct("PerToken")
                .field("token_hash", &"<redacted>")
                .field("scope", scope)
                .finish(),
        }
    }
}

/// Decision the caller must enforce.
///
/// `PartialEq + Eq` are derived so rate-limit telemetry can compare
/// `RateLimitDecision` values directly (assertions like `assert_eq!(decision,
/// RateLimitDecision::Allow { .. })` are weaker than equality on the inner
/// fields). `Duration` is `PartialEq + Eq`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
#[non_exhaustive]
pub enum RateLimitDecision {
    /// Request allowed. `remaining` is the remaining budget for this
    /// window; `reset_in` is wall-clock time until the window resets.
    Allow {
        /// Remaining budget for this window.
        remaining: u32,
        /// Wall-clock duration until the window resets.
        reset_in: Duration,
    },
    /// Request denied. `retry_after` populates the `Retry-After` header.
    Deny {
        /// Wall-clock duration the caller should wait before retrying.
        retry_after: Duration,
    },
    /// Account/token locked out (exponential breach). `attempts` is the
    /// breach count for telemetry; `retry_after` populates `Retry-After`.
    LockedOut {
        /// Wall-clock duration until the lockout expires.
        retry_after: Duration,
        /// Breach count for telemetry.
        attempts: u32,
    },
}

/// Backend failure modes.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RateLimiterError {
    /// Backend unavailable (Valkey down). Caller fails closed.
    #[error("backend unavailable: {0}")]
    Backend(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use static_assertions::{assert_impl_all, assert_obj_safe};

    assert_obj_safe!(RateLimiter);
    assert_impl_all!(RateLimitKey: Send, Sync, Clone, PartialEq, Eq, std::hash::Hash);
    assert_impl_all!(
        RateLimitDecision: Send,
        Sync,
        Clone,
        PartialEq,
        Eq,
        std::fmt::Debug
    );
    assert_impl_all!(RateLimiterError: Send, Sync, std::error::Error);
    const _: fn() = || {
        fn require_static<T: 'static + Send + Sync>() {}
        require_static::<RateLimiterError>();
    };

    #[test]
    fn per_token_debug_redacts_token_hash() {
        let key = RateLimitKey::PerToken {
            token_hash: [0xAA; 32],
            scope: "signin",
        };
        let rendered = format!("{key:?}");
        assert!(!rendered.contains("aa"), "raw hex must not appear");
        assert!(!rendered.contains("AA"), "raw hex must not appear");
        assert!(rendered.contains("redacted"));
        assert!(rendered.contains("signin"));
    }

    #[test]
    fn per_ip_debug_keeps_ip_and_scope() {
        let key = RateLimitKey::PerIp {
            ip: "10.0.0.7"
                .parse::<IpAddr>()
                .unwrap_or_else(|e| panic!("parse: {e}")),
            scope: "signin",
        };
        let rendered = format!("{key:?}");
        assert!(rendered.contains("10.0.0.7"));
        assert!(rendered.contains("signin"));
    }

    #[test]
    fn per_account_debug_keeps_user_and_scope() {
        let user_id = uuid::Uuid::from_bytes([7; 16]);
        let key = RateLimitKey::PerAccount {
            user_id,
            scope: "lockout",
        };
        let rendered = format!("{key:?}");
        assert!(rendered.contains(&user_id.to_string()));
        assert!(rendered.contains("lockout"));
    }

    #[test]
    fn rate_limit_decision_compares_via_partial_eq() {
        let allow_a = RateLimitDecision::Allow {
            remaining: 5,
            reset_in: Duration::from_secs(60),
        };
        let allow_b = RateLimitDecision::Allow {
            remaining: 5,
            reset_in: Duration::from_secs(60),
        };
        let allow_c = RateLimitDecision::Allow {
            remaining: 4,
            reset_in: Duration::from_secs(60),
        };
        assert_eq!(allow_a, allow_b);
        assert_ne!(allow_a, allow_c);
    }
}
