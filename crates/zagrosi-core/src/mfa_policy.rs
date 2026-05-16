// SPDX-License-Identifier: AGPL-3.0-or-later

//! MFA policy port + auth-API continuation envelope.
//!
//! v0.1 ships [`AlwaysAllowMfaPolicy`] which always returns
//! [`Required::No`]. Future TOTP / `WebAuthn` impls plug in via the same
//! trait. The auth-API continuation envelope ([`AuthContinuation`]) is
//! generic over the session-view type so identity can plug its concrete
//! `SessionView` without `zagrosi-core` needing the type.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::auth_context::IdentityContext;

/// MFA policy decision sink.
#[async_trait]
pub trait MfaPolicy: Send + Sync + 'static {
    /// v0.1 stub always returns [`Required::No`]. TOTP / `WebAuthn` lands
    /// later without breaking the auth API.
    async fn evaluate(&self, ctx: &IdentityContext) -> Required;
}

/// Whether MFA is required for a given identity context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Required {
    /// No additional factor required.
    No,
    /// MFA required. Caller renders a challenge keyed on `challenge_id`.
    Yes {
        /// Acceptable factor types.
        factors: Vec<Factor>,
        /// Stable identifier for this challenge instance.
        challenge_id: uuid::Uuid,
    },
}

/// MFA factor types (v0.1 ships none; reserved for future splits).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Factor {
    /// Time-based one-time password.
    Totp,
    /// `WebAuthn` (FIDO2) authenticator.
    Webauthn,
}

/// Auth-API response envelope.
///
/// Wire shape:
///
/// ```json
/// { "kind": "session", "session": { ... } }
/// { "kind": "mfa_required", "challenge_id": "...", "factors": ["totp"] }
/// ```
///
/// Generic over the session-view type so identity can return its concrete
/// `SessionView` without leaking the type into `zagrosi-core`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum AuthContinuation<S> {
    /// Authentication complete; session attached.
    Session {
        /// Session view payload.
        session: S,
    },
    /// MFA required before session is issued.
    MfaRequired {
        /// Stable identifier for the issued challenge.
        challenge_id: uuid::Uuid,
        /// Acceptable factor types.
        factors: Vec<Factor>,
    },
}

/// Default impl: never requires MFA.
#[derive(Debug, Default, Clone, Copy)]
pub struct AlwaysAllowMfaPolicy;

#[async_trait]
impl MfaPolicy for AlwaysAllowMfaPolicy {
    async fn evaluate(&self, _ctx: &IdentityContext) -> Required {
        Required::No
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use static_assertions::{assert_impl_all, assert_obj_safe};
    use uuid::Uuid;

    assert_obj_safe!(MfaPolicy);
    assert_impl_all!(Required: Send, Sync, Clone, PartialEq, Eq, serde::Serialize, serde::de::DeserializeOwned);
    assert_impl_all!(AuthContinuation<()>: Send, Sync, Clone, std::fmt::Debug, serde::Serialize, serde::de::DeserializeOwned);

    fn fixture_ctx(byte: u8) -> IdentityContext {
        IdentityContext::new(
            Uuid::from_bytes([byte; 16]),
            Uuid::from_bytes([byte.wrapping_add(1); 16]),
            Uuid::from_bytes([byte.wrapping_add(2); 16]),
        )
        .unwrap_or_else(|e| panic!("fixture build: {e}"))
    }

    #[tokio::test]
    async fn always_allow_returns_required_no_for_arbitrary_contexts() {
        // The design notes demanded a property-style assertion across arbitrary
        // identity contexts. We cycle the seed byte across non-zero values
        // to produce 10 distinct contexts (no two share a (subject, org,
        // correlation) triple) and verify the policy is constant.
        let policy = AlwaysAllowMfaPolicy;
        for seed in 1_u8..=10_u8 {
            let decision = policy.evaluate(&fixture_ctx(seed)).await;
            assert_eq!(decision, Required::No, "seed={seed}");
        }
    }

    #[test]
    fn auth_continuation_session_serialises_with_kind_session() {
        let cont: AuthContinuation<()> = AuthContinuation::Session { session: () };
        let v = serde_json::to_value(&cont).expect("serialise");
        assert_eq!(v["kind"], serde_json::json!("session"));
    }

    #[test]
    fn auth_continuation_mfa_required_serialises_with_kind_mfa_required() {
        let cont: AuthContinuation<()> = AuthContinuation::MfaRequired {
            challenge_id: Uuid::nil(),
            factors: vec![Factor::Totp],
        };
        let v = serde_json::to_value(&cont).expect("serialise");
        assert_eq!(v["kind"], serde_json::json!("mfa_required"));
    }
}
