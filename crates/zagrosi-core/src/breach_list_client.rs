// SPDX-License-Identifier: AGPL-3.0-or-later

//! Breach-list lookup port.
//!
//! Identity's password-policy gate checks every new password
//! against a known-breached corpus. The HIBP-online k-anonymity client
//! ships as the default impl in `zagrosi-identity`; an offline-mirror
//! impl is reserved for air-gapped deploys.

use async_trait::async_trait;

/// Lookup port for known-breached passwords.
///
/// Implementations MUST NOT transmit the raw password. HIBP uses
/// k-anonymity (SHA-1 prefix exchange); offline mirrors compare against a
/// local hash list. Other strategies that leak the password are forbidden.
#[async_trait]
pub trait BreachListClient: Send + Sync + 'static {
    /// Check whether the given password is known-breached.
    async fn check(&self, password: &str) -> Result<BreachCheck, BreachListError>;
}

/// Outcome of a breach-list lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum BreachCheck {
    /// Password not found in any consulted breach list.
    Clean,
    /// Password appears in at least one breach list.
    Breached {
        /// Number of times the password has been seen across breaches.
        occurrences: u64,
    },
    /// Lookup unavailable (mode `disabled` or upstream down). Caller
    /// decides fail-open vs fail-closed; identity fail-closes when mode
    /// is `online`.
    Unavailable,
}

/// Failure modes the lookup may surface.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BreachListError {
    /// Upstream lookup timed out.
    #[error("upstream timeout")]
    Timeout,
    /// Upstream returned a non-success response.
    #[error("upstream error: {0}")]
    Upstream(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use static_assertions::{assert_impl_all, assert_obj_safe};

    assert_obj_safe!(BreachListClient);
    assert_impl_all!(BreachCheck: Send, Sync, Clone, Copy, PartialEq, Eq);
}
