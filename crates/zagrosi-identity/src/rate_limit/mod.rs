// SPDX-License-Identifier: AGPL-3.0-or-later

//! Rate-limit + lockout module.
//!
//! Three tightly-scoped sub-modules ship the public surface:
//!
//! - [`lua`] holds the two server-side Lua scripts (sliding-window
//!   token bucket + per-account exponential lockout). They run
//!   atomically inside Valkey so multi-replica clients converge on a
//!   single counter / lockout state without round-trip races.
//!
//! - [`valkey`] hosts [`ValkeyRateLimiter`], the concrete impl of
//!   [`zagrosi_core::RateLimiter`]. The struct multiplexes a `fred`
//!   client pool, pre-loads both scripts on init, and dispatches by
//!   key variant: `PerIp` / `PerToken` go to the sliding window,
//!   `PerAccount` goes to the lockout state machine.
//!
//! - [`headers`] renders the `Retry-After` (RFC 6585) and
//!   `RateLimit-Limit` / `RateLimit-Remaining` / `RateLimit-Reset`
//!   trio (`draft-ietf-httpapi-ratelimit-headers`) for both 200 and
//!   429 responses.
//!
//! The per-minute upsert against `failed_signin_aggregates` lives at
//! [`crate::repo::FailedSigninRepo::record_failure`]; rate-limit
//! callers consume it via [`crate::repo::FailedSigninRepo`] rather
//! than re-implementing the SQL — the same upsert powers the audit
//! "first-in-window" branch.

pub mod headers;
pub mod lua;
pub mod valkey;

pub use headers::RateLimitHeaders;
pub use valkey::ValkeyRateLimiter;
