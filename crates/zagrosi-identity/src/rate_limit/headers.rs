// SPDX-License-Identifier: AGPL-3.0-or-later

//! Rate-limit response headers.
//!
//! Limited endpoints emit:
//!
//! - `Retry-After: <seconds>` (RFC 6585) on 429.
//! - `RateLimit-Limit`, `RateLimit-Remaining`, `RateLimit-Reset`
//!   (`draft-ietf-httpapi-ratelimit-headers`) on every response, success
//!   or 429.
//!
//! The struct produced here is consumed by:
//!
//! 1. The auth service layer (`signin`, `password_reset`, `email_verify`)
//!    after a successful sliding-window probe — the handler attaches
//!    the headers to its 200 response.
//! 2. [`crate::error::IdentityError`]'s `IntoResponse` mapping for the
//!    [`crate::error::IdentityError::RateLimited`] /
//!    [`crate::error::IdentityError::LockedOut`] variants — the error
//!    response carries `Retry-After` plus the same draft-ietf trio so
//!    a polite client can compute its own backoff without parsing the
//!    body.

use axum::http::{HeaderMap, HeaderName, HeaderValue, header};
use std::time::Duration;

/// Header names from `draft-ietf-httpapi-ratelimit-headers`.
const RATELIMIT_LIMIT: HeaderName = HeaderName::from_static("ratelimit-limit");
const RATELIMIT_REMAINING: HeaderName = HeaderName::from_static("ratelimit-remaining");
const RATELIMIT_RESET: HeaderName = HeaderName::from_static("ratelimit-reset");

/// Response-header bundle for a single rate-limit probe.
///
/// `limit` is the configured budget for the bucket. `remaining` is how
/// many requests are still available *after* the current call has been
/// counted. `reset` is wall-clock until the current window resets;
/// `retry_after` is the same value rounded up to whole seconds for the
/// `Retry-After` header (only emitted on 429 responses).
///
/// `remaining` saturates at 0 — a 429 response carries `remaining: 0`
/// rather than wrapping around.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimitHeaders {
    /// Configured budget for the bucket (`RateLimit-Limit`).
    pub limit: u32,
    /// Remaining budget for this window (`RateLimit-Remaining`).
    pub remaining: u32,
    /// Wall-clock duration until the window resets (`RateLimit-Reset`).
    pub reset: Duration,
    /// Set to `Some(_)` only on 429 responses; renders `Retry-After`.
    pub retry_after: Option<Duration>,
}

impl RateLimitHeaders {
    /// Construct headers for a permitted request.
    #[must_use]
    pub const fn allow(limit: u32, remaining: u32, reset: Duration) -> Self {
        Self {
            limit,
            remaining,
            reset,
            retry_after: None,
        }
    }

    /// Construct headers for a denied request. `remaining` clamps to 0.
    #[must_use]
    pub const fn deny(limit: u32, retry_after: Duration) -> Self {
        Self {
            limit,
            remaining: 0,
            reset: retry_after,
            retry_after: Some(retry_after),
        }
    }

    /// Insert the headers into `headers`.
    ///
    /// Existing values for the same header names are overwritten; the
    /// caller is expected to layer rate-limit headers as the last step
    /// before returning the response.
    pub fn apply(&self, headers: &mut HeaderMap) {
        let _ = insert_u32(headers, &RATELIMIT_LIMIT, self.limit);
        let _ = insert_u32(headers, &RATELIMIT_REMAINING, self.remaining);
        let _ = insert_u32(
            headers,
            &RATELIMIT_RESET,
            duration_secs_rounded_up(self.reset),
        );
        if let Some(retry_after) = self.retry_after {
            let secs = duration_secs_rounded_up(retry_after);
            let _ = insert_u32(headers, &header::RETRY_AFTER, secs);
        }
    }
}

fn insert_u32(headers: &mut HeaderMap, name: &HeaderName, value: u32) -> Result<(), ()> {
    HeaderValue::from_str(&value.to_string()).map_or(Err(()), |hv| {
        headers.insert(name.clone(), hv);
        Ok(())
    })
}

/// Round a [`Duration`] up to the next whole second (RFC 6585 +
/// `draft-ietf-httpapi-ratelimit-headers` both require integer
/// second values).
fn duration_secs_rounded_up(d: Duration) -> u32 {
    let secs = d.as_secs();
    let extra = u64::from(d.subsec_nanos() != 0);
    let total = secs.saturating_add(extra);
    u32::try_from(total).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_renders_no_retry_after() {
        let headers = RateLimitHeaders::allow(20, 19, Duration::from_secs(45));
        let mut map = HeaderMap::new();
        headers.apply(&mut map);
        assert_eq!(
            map.get("ratelimit-limit").map(|h| h.to_str().ok()),
            Some(Some("20"))
        );
        assert_eq!(
            map.get("ratelimit-remaining").map(|h| h.to_str().ok()),
            Some(Some("19"))
        );
        assert_eq!(
            map.get("ratelimit-reset").map(|h| h.to_str().ok()),
            Some(Some("45"))
        );
        assert!(map.get(header::RETRY_AFTER).is_none());
    }

    #[test]
    fn deny_renders_retry_after_and_zero_remaining() {
        let headers = RateLimitHeaders::deny(20, Duration::from_secs(60));
        let mut map = HeaderMap::new();
        headers.apply(&mut map);
        assert_eq!(
            map.get("ratelimit-limit").map(|h| h.to_str().ok()),
            Some(Some("20"))
        );
        assert_eq!(
            map.get("ratelimit-remaining").map(|h| h.to_str().ok()),
            Some(Some("0"))
        );
        assert_eq!(
            map.get("ratelimit-reset").map(|h| h.to_str().ok()),
            Some(Some("60"))
        );
        assert_eq!(
            map.get(header::RETRY_AFTER).map(|h| h.to_str().ok()),
            Some(Some("60"))
        );
    }

    #[test]
    fn duration_rounds_up_subsec_nanos() {
        assert_eq!(duration_secs_rounded_up(Duration::from_millis(1500)), 2);
        assert_eq!(duration_secs_rounded_up(Duration::from_secs(30)), 30);
        assert_eq!(duration_secs_rounded_up(Duration::from_millis(0)), 0);
        assert_eq!(duration_secs_rounded_up(Duration::from_micros(1)), 1);
    }

    #[test]
    fn duration_clamps_at_u32_max() {
        let huge = Duration::from_secs(u64::from(u32::MAX) + 5);
        assert_eq!(duration_secs_rounded_up(huge), u32::MAX);
    }
}
