// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! HIBP k-anonymity breach-list client.
//!
//! Implements [`zagrosi_core::BreachListClient`] against the
//! `https://api.pwnedpasswords.com/range/<5-hex-prefix>` endpoint.
//! The raw password never leaves the process; only the first 5 hex
//! chars of its uppercase SHA-1 digest are transmitted, and the
//! `Add-Padding: true` header keeps the response length opaque to
//! on-path observers.
//!
//! `sha1` is restricted to this single legacy-API path. All other
//! hashing in the crate uses `sha2` per `Cargo.toml`'s explicit
//! comment.

use std::time::Duration;

use async_trait::async_trait;
use sha1::{Digest as _, Sha1};
use zagrosi_core::{BreachCheck, BreachListClient, BreachListError};

use crate::config::{BreachlistConfig, BreachlistMode};

/// HIBP-backed breach-list client.
///
/// Mode behaviour:
/// - [`BreachlistMode::Online`]: live HIBP call with 5 s timeout.
/// - [`BreachlistMode::Disabled`]: short-circuits to
///   [`BreachCheck::Clean`] without any network I/O.
/// - [`BreachlistMode::Offline`]: reserved for the deferred mirror
///   feature; treated as `Disabled` for v0.1 with a deprecation
///   warning.
pub struct HibpBreachClient {
    http: reqwest::Client,
    cfg: BreachlistConfig,
}

impl HibpBreachClient {
    /// Construct from the configured HTTP client + breachlist config.
    /// The caller owns the `reqwest::Client` (typically shared across
    /// the identity surface to amortise TLS handshakes).
    #[must_use]
    pub const fn new(http: reqwest::Client, cfg: BreachlistConfig) -> Self {
        Self { http, cfg }
    }

    /// Borrow the live mode (test / observability use).
    #[must_use]
    pub const fn mode(&self) -> BreachlistMode {
        self.cfg.mode
    }
}

#[async_trait]
impl BreachListClient for HibpBreachClient {
    async fn check(&self, password: &str) -> Result<BreachCheck, BreachListError> {
        match self.cfg.mode {
            BreachlistMode::Disabled => return Ok(BreachCheck::Clean),
            BreachlistMode::Offline => {
                tracing::warn!(
                    target: "breachlist.offline_mode_deprecated",
                    "ZAGROSI_PASSWORD_BREACHLIST_MODE=offline is reserved; treating as disabled",
                );
                return Ok(BreachCheck::Clean);
            }
            BreachlistMode::Online => {}
        }

        let mut hasher = Sha1::new();
        hasher.update(password.as_bytes());
        let digest = hasher.finalize();
        let mut hex_buf = String::with_capacity(40);
        for byte in &digest {
            use std::fmt::Write as _;
            // hex::encode_upper would allocate; Write into a stack-resident
            // String avoids the secondary allocation per check.
            let _ = write!(&mut hex_buf, "{byte:02X}");
        }
        let (prefix, suffix) = hex_buf.split_at(5);

        let url = format!("{}{prefix}", self.cfg.endpoint);
        let request = self.http.get(&url).header("Add-Padding", "true").send();
        let response = tokio::time::timeout(Duration::from_secs(self.cfg.timeout_secs), request)
            .await
            .map_err(|_| BreachListError::Timeout)?
            .map_err(|err| BreachListError::Upstream(err.to_string()))?;
        if !response.status().is_success() {
            return Err(BreachListError::Upstream(format!(
                "HIBP returned status {}",
                response.status()
            )));
        }
        let body = response
            .text()
            .await
            .map_err(|err| BreachListError::Upstream(err.to_string()))?;

        for line in body.lines() {
            let Some((line_suffix, count_str)) = line.split_once(':') else {
                continue;
            };
            if line_suffix.eq_ignore_ascii_case(suffix) {
                let count: u64 = count_str.trim().parse().unwrap_or(0);
                if count == 0 {
                    return Ok(BreachCheck::Clean);
                }
                return Ok(BreachCheck::Breached { occurrences: count });
            }
        }
        Ok(BreachCheck::Clean)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use static_assertions::{assert_impl_all, assert_obj_safe};

    assert_obj_safe!(BreachListClient);
    assert_impl_all!(HibpBreachClient: Send, Sync);

    fn http() -> reqwest::Client {
        reqwest::Client::new()
    }

    #[tokio::test]
    async fn disabled_mode_returns_clean_without_network() {
        let cfg = BreachlistConfig {
            mode: BreachlistMode::Disabled,
            timeout_secs: 5,
            // Use an obviously-invalid endpoint so any accidental
            // network call would fail loudly. Disabled mode must
            // short-circuit before reading this field.
            endpoint: "http://invalid.invalid/".into(),
        };
        let client = HibpBreachClient::new(http(), cfg);
        let check = client.check("hunter2").await.unwrap();
        assert_eq!(check, BreachCheck::Clean);
    }

    #[tokio::test]
    async fn offline_mode_short_circuits_with_warning() {
        let cfg = BreachlistConfig {
            mode: BreachlistMode::Offline,
            timeout_secs: 5,
            endpoint: "http://invalid.invalid/".into(),
        };
        let client = HibpBreachClient::new(http(), cfg);
        let check = client.check("hunter2").await.unwrap();
        assert_eq!(check, BreachCheck::Clean);
    }
}
