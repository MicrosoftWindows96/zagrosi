// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! Argon2id startup calibration.
//!
//! Runs a single hash + verify cycle at `IdentityService::new(...)` and
//! decides whether the configured profile is fit for production:
//!
//! - measured `< 0.3 s` → emit a `tracing::warn!` (target
//!   `argon2.profile_too_fast`); sign-ins still proceed.
//! - measured `> 1.5 s` → return [`IdentityError::Argon2ProfileTooSlow`]
//!   so the binary refuses to start.
//! - measured in `[0.3 s, 1.5 s]` → proceed silently.
//!
//! This is the only place that emits the calibration outcome. The
//! benchmark itself runs once; it does not impact request-path latency.

use std::time::Instant;

use crate::error::IdentityError;
use crate::password::hasher::Argon2idHasher;

/// Lower threshold (inclusive). Below this the profile is faster than
/// OWASP 2024 baseline expects and the operator is warned.
pub const FAST_THRESHOLD_MS: u64 = 300;

/// Upper threshold (inclusive). Above this the profile would brown out
/// under load; refuse to start.
pub const SLOW_THRESHOLD_MS: u64 = 1_500;

/// Run the startup verify-bench against `hasher`. See module docs for
/// the threshold semantics.
///
/// # Errors
///
/// Returns [`IdentityError::Argon2ProfileTooSlow`] when the measured
/// duration exceeds [`SLOW_THRESHOLD_MS`]. Returns the underlying
/// hasher error verbatim if hash / verify itself fails.
pub async fn calibrate(hasher: &Argon2idHasher) -> Result<(), IdentityError> {
    let phc = hasher.hash("argon2-calibration").await?;
    let start = Instant::now();
    let _ = hasher.verify("argon2-calibration", &phc).await?;
    #[allow(clippy::cast_possible_truncation)]
    let elapsed_ms = start.elapsed().as_millis() as u64;
    if elapsed_ms < FAST_THRESHOLD_MS {
        tracing::warn!(
            target: "argon2.profile_too_fast",
            measured_ms = elapsed_ms,
            threshold_ms = FAST_THRESHOLD_MS,
            "argon2 verify under 0.3s; sign-ins will proceed but profile is below OWASP 2024 baseline",
        );
    } else if elapsed_ms > SLOW_THRESHOLD_MS {
        return Err(IdentityError::Argon2ProfileTooSlow {
            measured_ms: elapsed_ms,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Argon2Config;

    fn fast_cfg() -> Argon2Config {
        Argon2Config {
            m_cost: 8,
            t_cost: 1,
            p_cost: 1,
            max_concurrency: 2,
        }
    }

    #[tokio::test]
    async fn calibrate_succeeds_with_minimal_profile() {
        // Minimal profile is fast (< 0.3s) but the warn path still
        // returns Ok so sign-ins proceed.
        let hasher = Argon2idHasher::new(&fast_cfg()).unwrap();
        calibrate(&hasher).await.unwrap();
    }
}
