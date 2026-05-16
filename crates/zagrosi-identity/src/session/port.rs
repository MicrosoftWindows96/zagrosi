// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! Session-module session-issuance port consumed by password-auth flows.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Session the session module issues to a successful sign-in.
///
/// Minimal shape; the session module may extend this struct with cookie
/// material, AMR / ACR values, or device-fingerprint hashes. Password-auth
/// only inspects `id` and `expires_at` for response shaping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedSession {
    /// Session row primary key.
    pub id: Uuid,
    /// Owning user.
    pub user_id: Uuid,
    /// Active org at issue time. `None` for sessions that defer org
    /// pick-up to the first authenticated request.
    pub org_id: Option<Uuid>,
    /// Hard expiry timestamp.
    pub expires_at: DateTime<Utc>,
    /// Raw `sid_*` cookie value the gateway attaches as the
    /// `__Host-zagrosi_session` cookie. Owned by the caller after
    /// issue; password-auth never persists this string.
    pub raw_token: String,
}

/// Session-module session-issuance port.
///
/// `Send + Sync + 'static` so the impl can live behind an
/// `Arc<dyn SessionIssuer>` inside `IdentityServiceDeps`. Password-auth
/// tests use a fake; the session module supplies the canonical concrete
/// impl.
///
/// Surface visibility is `pub` so the apps/api-gateway composition
/// root can construct `IdentityServiceDeps` from outside this crate.
/// The trait is intentionally distinct from
/// `zagrosi_core::SessionIntrospector` so consumers cannot conflate
/// session-issue with session-resolve responsibilities.
#[async_trait]
pub trait SessionIssuer: Send + Sync + 'static {
    /// Issue a fresh password-auth session for `user_id`.
    ///
    /// `org_id` is `None` when the user has zero or many memberships
    /// and the active-org pick is deferred. `amr` is a list of RFC
    /// 8176 authentication-method-reference values; password-auth
    /// passes `["pwd"]`.
    async fn issue_password_session(
        &self,
        user_id: Uuid,
        org_id: Option<Uuid>,
        amr: &[&str],
    ) -> Result<IssuedSession, crate::error::IdentityError>;
}
