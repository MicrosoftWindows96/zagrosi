// SPDX-License-Identifier: AGPL-3.0-or-later

//! Auth-API continuation envelope wrapping.
//!
//! Every successful auth call (sign-in, OIDC callback, SAML ACS)
//! returns its session payload wrapped in an
//! [`zagrosi_core::AuthContinuation`] envelope so future MFA factors
//! can land without breaking the API shape. The envelope's first
//! variant (`Session`) carries the session view; subsequent variants
//! (`MfaRequired`, etc.) layer on later under feature flags.
//!
//! `MfaPolicy::evaluate` is consulted to decide which envelope
//! variant to surface. v0.1 ships
//! [`zagrosi_core::AlwaysAllowMfaPolicy`] which always returns
//! [`zagrosi_core::Required::No`], so every successful call wraps as
//! `Session { session: <view> }`.

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zagrosi_core::AuthContinuation;

use chrono::{DateTime, Utc};

/// Public-facing session view embedded inside the
/// [`zagrosi_core::AuthContinuation::Session`] variant. Captures only
/// fields the SPA / API client needs; sensitive material (token
/// hashes, last-seen IP) stays server-side.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionView {
    /// Session row primary key.
    pub session_id: Uuid,
    /// Owning user.
    pub user_id: Uuid,
    /// Active org at issue time (or after a `PATCH /v1/sessions/me`).
    pub org_id: Option<Uuid>,
    /// Hard expiry timestamp.
    pub expires_at: DateTime<Utc>,
    /// CSRF echo value the SPA must copy into the
    /// `X-Zagrosi-CSRF` header on every unsafe browser request.
    pub csrf_token: String,
    /// Optional raw `sid_*` bearer token. `None` for browser-cookie
    /// responses (the value already lives in the `Set-Cookie`
    /// header); `Some(...)` for API / MCP clients that opted into
    /// bearer mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_token: Option<String>,
}

impl SessionView {
    /// Wrap a [`SessionView`] inside the `Session` envelope variant
    /// so the auth handler can serialise the canonical JSON shape.
    #[must_use]
    pub const fn into_continuation(self) -> AuthContinuation<Self> {
        AuthContinuation::Session { session: self }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn fixture_view() -> SessionView {
        SessionView {
            session_id: Uuid::from_bytes([0x11; 16]),
            user_id: Uuid::from_bytes([0x22; 16]),
            org_id: Some(Uuid::from_bytes([0x33; 16])),
            expires_at: Utc.with_ymd_and_hms(2026, 12, 31, 23, 59, 59).unwrap(),
            csrf_token: "csrf-test-value".to_string(),
            raw_token: None,
        }
    }

    #[test]
    fn into_continuation_emits_session_variant() {
        let view = fixture_view();
        let cont = view.clone().into_continuation();
        match cont {
            AuthContinuation::Session { session } => assert_eq!(session, view),
            other => panic!("expected Session variant, got {other:?}"),
        }
    }

    #[test]
    fn serialises_to_session_envelope_shape() {
        let view = fixture_view();
        let cont = view.into_continuation();
        let json = serde_json::to_value(&cont).expect("serialise");
        assert_eq!(json["kind"], serde_json::json!("session"));
        assert!(json["session"].is_object());
        assert_eq!(
            json["session"]["csrf_token"],
            serde_json::json!("csrf-test-value")
        );
    }

    #[test]
    fn raw_token_omitted_when_none() {
        let view = fixture_view();
        let cont = view.into_continuation();
        let json = serde_json::to_string(&cont).expect("serialise");
        assert!(!json.contains("raw_token"));
    }

    #[test]
    fn raw_token_present_when_some() {
        let mut view = fixture_view();
        view.raw_token = Some("sid_xyz".to_string());
        let cont = view.into_continuation();
        let json = serde_json::to_string(&cont).expect("serialise");
        assert!(json.contains("raw_token"));
        assert!(json.contains("sid_xyz"));
    }
}
