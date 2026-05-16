// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! Request / response DTOs for the personal-access-token surface.
//!
//! `IssuedApiTokenResponse` is the only shape that carries the raw
//! `pat_*` token. It is emitted exactly once, on `POST /v1/api-tokens`,
//! and never returned again. Listing or getting an existing token
//! yields [`ApiTokenView`] which omits the secret entirely.

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::domain::ApiToken;

/// Request body for `POST /v1/api-tokens`.
#[derive(Debug, Clone, Deserialize)]
pub struct CreateApiTokenRequest {
    /// Human-set label shown on the token-management UI. Required;
    /// trimmed and validated for length 1..=`DISPLAY_NAME_MAX_LEN`.
    pub display_name: String,
    /// Authorisation scopes. Each string must be present in
    /// [`super::SCOPE_CATALOGUE_V0_1`].
    pub scopes: Vec<String>,
    /// Optional hard-expiry timestamp. `None` mints a no-expiry PAT.
    /// When present, must be at least one minute in the future.
    pub expires_at: Option<DateTime<Utc>>,
}

/// Response body for `POST /v1/api-tokens`.
///
/// The `token` field is the raw `pat_*` value. It is only present in
/// this response shape; subsequent `GET` requests for the same token
/// id yield [`ApiTokenView`] with no `token` field. The raw value
/// MUST NOT be logged or persisted by the server.
#[derive(Debug, Clone, Serialize)]
pub struct IssuedApiTokenResponse {
    /// Application-generated UUID v7 primary key.
    pub id: Uuid,
    /// Display name as persisted (trimmed input).
    pub display_name: String,
    /// Persisted scope list.
    pub scopes: Vec<String>,
    /// Optional hard-expiry timestamp.
    pub expires_at: Option<DateTime<Utc>>,
    /// Row creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Raw `pat_<43>` token. Returned exactly once.
    pub token: String,
}

/// Internal carrier returned by [`super::service::ApiTokenService::issue`].
///
/// Pairs the persisted [`ApiToken`] aggregate with the raw token
/// string so the HTTP layer can build [`IssuedApiTokenResponse`]
/// without having to re-mint or re-hash.
#[derive(Debug, Clone)]
pub struct IssuedApiToken {
    /// Persisted aggregate.
    pub token: ApiToken,
    /// Raw `pat_<43>` token string. Caller copies this into the
    /// response body and drops the local binding.
    pub raw_token: String,
}

/// View of an existing PAT.
///
/// Returned by `GET /v1/api-tokens` (list) and
/// `GET /v1/api-tokens/{id}` (single). The raw token is never
/// exposed via this shape; only metadata.
#[derive(Debug, Clone, Serialize)]
pub struct ApiTokenView {
    /// Application-generated UUID v7 primary key.
    pub id: Uuid,
    /// Display name.
    pub display_name: String,
    /// Persisted scope list.
    pub scopes: Vec<String>,
    /// Last-used timestamp; `None` until the resolver write-behind
    /// has fired against this token.
    pub last_used_at: Option<DateTime<Utc>>,
    /// Last source IP that introspected the token.
    pub last_used_ip: Option<IpAddr>,
    /// Optional hard expiry.
    pub expires_at: Option<DateTime<Utc>>,
    /// Row creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Revocation timestamp; `None` for live tokens.
    pub revoked_at: Option<DateTime<Utc>>,
}

impl From<ApiToken> for ApiTokenView {
    fn from(value: ApiToken) -> Self {
        Self {
            id: value.id,
            display_name: value.display_name,
            scopes: value.scopes,
            last_used_at: value.last_used_at,
            last_used_ip: value.last_used_ip,
            expires_at: value.expires_at,
            created_at: value.created_at,
            revoked_at: value.revoked_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use static_assertions::assert_impl_all;

    assert_impl_all!(CreateApiTokenRequest: Send, Sync, Clone, std::fmt::Debug);
    assert_impl_all!(IssuedApiTokenResponse: Send, Sync, Clone, std::fmt::Debug);
    assert_impl_all!(IssuedApiToken: Send, Sync, Clone, std::fmt::Debug);
    assert_impl_all!(ApiTokenView: Send, Sync, Clone, std::fmt::Debug);

    #[test]
    fn create_request_round_trips_minimal_body() {
        let body = serde_json::json!({
            "display_name": "ci-bot",
            "scopes": ["tokens:read"],
        });
        let parsed: CreateApiTokenRequest =
            serde_json::from_value(body).expect("parse minimal body");
        assert_eq!(parsed.display_name, "ci-bot");
        assert_eq!(parsed.scopes, vec!["tokens:read".to_string()]);
        assert!(parsed.expires_at.is_none());
    }

    #[test]
    fn create_request_round_trips_with_expiry() {
        let body = serde_json::json!({
            "display_name": "ci-bot",
            "scopes": ["tokens:read", "tokens:write"],
            "expires_at": "2027-01-01T00:00:00Z",
        });
        let parsed: CreateApiTokenRequest =
            serde_json::from_value(body).expect("parse with expiry");
        assert_eq!(parsed.scopes.len(), 2);
        assert!(parsed.expires_at.is_some());
    }

    #[test]
    fn issued_response_serialises_token_field() {
        let resp = IssuedApiTokenResponse {
            id: Uuid::nil(),
            display_name: "ci".into(),
            scopes: vec!["tokens:read".into()],
            expires_at: None,
            created_at: Utc::now(),
            token: "pat_dummybody".into(),
        };
        let v = serde_json::to_value(&resp).expect("serialise");
        assert!(
            v.get("token").is_some(),
            "issuance response must carry token"
        );
        assert_eq!(v["token"], "pat_dummybody");
    }

    #[test]
    fn view_does_not_carry_token_field() {
        let view = ApiTokenView {
            id: Uuid::nil(),
            display_name: "ci".into(),
            scopes: vec![],
            last_used_at: None,
            last_used_ip: None,
            expires_at: None,
            created_at: Utc::now(),
            revoked_at: None,
        };
        let v = serde_json::to_value(&view).expect("serialise");
        assert!(
            v.get("token").is_none(),
            "view shape MUST NOT carry the raw token"
        );
    }
}
