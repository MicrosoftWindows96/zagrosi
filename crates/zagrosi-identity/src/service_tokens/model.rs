// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown)]
//! Request / response DTOs for the service-token HTTP surface.
//!
//! [`IssuedServiceTokenResponse`] is the only shape that ever carries
//! the raw `svc_…` string and is returned at most once, on
//! `POST /v1/service-tokens`. [`ServiceTokenView`] (list / get) never
//! includes it.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::domain::ServiceToken;

/// `POST /v1/service-tokens` request body.
#[derive(Debug, Clone, Deserialize)]
pub struct CreateServiceTokenRequest {
    /// Caller identity (`^[a-z][a-z0-9-]{1,63}$`), e.g. `email-worker`.
    pub service_name: String,
    /// Non-empty NATS-subject allowlist; each entry matches
    /// `[A-Za-z0-9_*>.-]+`. Enforcement of the allowlist itself
    /// lives in the worker pool (split-11); this surface only
    /// validates + persists it.
    pub allowed_subjects: Vec<String>,
    /// Human-facing label shown in the admin UI.
    pub display_name: String,
}

/// Sanitised metadata row (list / get). Never carries the token.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ServiceTokenView {
    /// Row id.
    pub id: Uuid,
    /// Caller identity.
    pub service_name: String,
    /// NATS-subject allowlist.
    pub allowed_subjects: Vec<String>,
    /// Admin-UI label.
    pub display_name: String,
    /// Issued-at.
    pub created_at: DateTime<Utc>,
    /// Revocation timestamp, when revoked.
    pub revoked_at: Option<DateTime<Utc>>,
}

impl From<ServiceToken> for ServiceTokenView {
    fn from(t: ServiceToken) -> Self {
        Self {
            id: t.id,
            service_name: t.service_name,
            allowed_subjects: t.allowed_subjects,
            display_name: t.display_name,
            created_at: t.created_at,
            revoked_at: t.revoked_at,
        }
    }
}

/// Issuance result. `raw_token` is the only place the `svc_…` string
/// exists in process memory; it is [`Zeroizing`] so the buffer is
/// wiped on drop, and the [`std::fmt::Debug`] impl elides it so a
/// `tracing::debug!(?issued)` cannot leak the credential.
pub struct IssuedServiceToken {
    /// Persisted row (no raw token).
    pub record: ServiceToken,
    /// Raw `svc_<43>` token — surface to the caller exactly once.
    pub raw_token: Zeroizing<String>,
}

impl std::fmt::Debug for IssuedServiceToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IssuedServiceToken")
            .field("record", &self.record)
            .field("raw_token", &"<redacted>")
            .finish()
    }
}

/// `201` body for `POST /v1/service-tokens`. Carries the raw token
/// once; the SPA must surface it immediately (never re-fetchable).
///
/// `Debug` is hand-rolled to elide `token`: the struct is built from
/// the [`IssuedServiceToken`] (whose own `Debug` redacts the raw
/// token) and then flows through the axum response stack where a
/// request-tracing span or error handler could `?`-format it.
/// Without this impl a derived `Debug` would leak the live `svc_…`
/// credential into a log line — mirrors the
/// `zagrosi_core::EmailMessage` / [`IssuedServiceToken`] policy.
#[derive(Clone, Serialize)]
pub struct IssuedServiceTokenResponse {
    /// Row id.
    pub id: Uuid,
    /// Caller identity.
    pub service_name: String,
    /// NATS-subject allowlist.
    pub allowed_subjects: Vec<String>,
    /// Admin-UI label.
    pub display_name: String,
    /// Issued-at.
    pub created_at: DateTime<Utc>,
    /// Raw `svc_<43>` token. Returned exactly once.
    pub token: String,
}

impl std::fmt::Debug for IssuedServiceTokenResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IssuedServiceTokenResponse")
            .field("id", &self.id)
            .field("service_name", &self.service_name)
            .field("allowed_subjects", &self.allowed_subjects)
            .field("display_name", &self.display_name)
            .field("created_at", &self.created_at)
            .field("token", &"<redacted>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issued_debug_redacts_raw_token() {
        let issued = IssuedServiceToken {
            record: ServiceToken {
                id: Uuid::nil(),
                service_name: "email-worker".into(),
                token_hash: [0u8; 32],
                allowed_subjects: vec!["email.outbox.queue".into()],
                display_name: "Email worker".into(),
                created_at: Utc::now(),
                revoked_at: None,
                deleted_at: None,
            },
            raw_token: Zeroizing::new("svc_SECRETSECRETSECRETSECRETSECRETSECRETSECR".into()),
        };
        let rendered = format!("{issued:?}");
        assert!(!rendered.contains("SECRET"), "raw token must be redacted");
        assert!(rendered.contains("<redacted>"));
    }

    #[test]
    fn response_debug_redacts_token() {
        let resp = IssuedServiceTokenResponse {
            id: Uuid::nil(),
            service_name: "email-worker".into(),
            allowed_subjects: vec!["email.outbox.queue".into()],
            display_name: "Email worker".into(),
            created_at: Utc::now(),
            token: "svc_LEAKYLEAKYLEAKYLEAKYLEAKYLEAKYLEAKYLEAKYLEA".into(),
        };
        let rendered = format!("{resp:?}");
        assert!(
            !rendered.contains("LEAKY"),
            "response Debug must redact token"
        );
        assert!(rendered.contains("<redacted>"));
    }

    #[test]
    fn view_from_domain_drops_hash_and_keeps_metadata() {
        let view = ServiceTokenView::from(ServiceToken {
            id: Uuid::from_u128(7),
            service_name: "scim-bridge".into(),
            token_hash: [9u8; 32],
            allowed_subjects: vec!["identity.>".into()],
            display_name: "SCIM bridge".into(),
            created_at: Utc::now(),
            revoked_at: None,
            deleted_at: None,
        });
        assert_eq!(view.service_name, "scim-bridge");
        assert_eq!(view.allowed_subjects, vec!["identity.>".to_string()]);
    }
}
