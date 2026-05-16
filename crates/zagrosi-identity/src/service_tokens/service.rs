// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! Service-token service: issue / list / get / revoke.
//!
//! Platform-level (no org scoping in the data model — see
//! `migrations/...016_service_tokens.sql`). The HTTP layer gates
//! every route on the platform-admin allowlist
//! ([`crate::config::PlatformConfig`]); this service trusts that the
//! caller is already an authorised platform admin and records the
//! admin's identity + active-org session as the audit actor / scope.
//!
//! Concurrency: revoke mirrors the PAT race-safe contract — bump the
//! cache generation BEFORE the `UPDATE ... WHERE revoked_at IS NULL`,
//! emit the audit event only when the UPDATE actually mutated a row.
//! No cross-replica NATS eviction (matches the `api_tokens`
//! precedent; cross-replica staleness is bounded by the cache TTL).

use std::sync::Arc;

use uuid::Uuid;
use zagrosi_core::{
    AuditActor, AuditEvent, AuditEventKind, AuditEventV1, AuditPayload, AuditResource, Auditor,
};

use crate::domain::token_format::{TokenPrefix, hash_token, mint};
use crate::error::{IdentityError, Result};
use crate::repo::{NewServiceToken, ServiceTokenRepo};
use crate::service_tokens::cache::ServiceTokenCache;
use crate::service_tokens::model::{
    CreateServiceTokenRequest, IssuedServiceToken, ServiceTokenView,
};

/// Max `display_name` length (chars). Generous; the field is an
/// admin-UI label, not an identifier.
pub const SERVICE_DISPLAY_NAME_MAX_LEN: usize = 120;

/// Composed service for the service-token surface. Cheap to clone.
#[derive(Clone)]
pub struct ServiceTokenService {
    repo: ServiceTokenRepo,
    cache: ServiceTokenCache,
    auditor: Arc<dyn Auditor>,
}

impl ServiceTokenService {
    /// Wire dependencies.
    #[must_use]
    pub fn new(
        repo: ServiceTokenRepo,
        cache: ServiceTokenCache,
        auditor: Arc<dyn Auditor>,
    ) -> Self {
        Self {
            repo,
            cache,
            auditor,
        }
    }

    /// Mint + persist a service token. Returns the raw `svc_…`
    /// exactly once. Emits `ServiceTokenCreated`.
    ///
    /// `actor_user_id` / `actor_org_id` identify the platform admin's
    /// session (the HTTP gate already proved admin status); they
    /// scope the audit event, not the token (the token is
    /// org-agnostic).
    ///
    /// # Errors
    ///
    /// [`IdentityError::InvalidServiceTokenRequest`] for any
    /// validation failure; [`IdentityError::Database`] /
    /// [`IdentityError::TokenNotFound`] (unique-collision) for sqlx.
    pub async fn create(
        &self,
        actor_user_id: Uuid,
        actor_org_id: Uuid,
        correlation_id: Uuid,
        req: CreateServiceTokenRequest,
    ) -> Result<IssuedServiceToken> {
        validate_service_name(&req.service_name)?;
        validate_allowed_subjects(&req.allowed_subjects)?;
        let display_name = req.display_name.trim();
        if display_name.is_empty() {
            return Err(IdentityError::InvalidServiceTokenRequest {
                reason: "display_name must not be empty".into(),
            });
        }
        if display_name.chars().count() > SERVICE_DISPLAY_NAME_MAX_LEN {
            return Err(IdentityError::InvalidServiceTokenRequest {
                reason: format!("display_name exceeds {SERVICE_DISPLAY_NAME_MAX_LEN} characters"),
            });
        }

        let raw_token = mint(TokenPrefix::Service);
        let hash = hash_token(&raw_token);
        let id = Uuid::now_v7();
        let subjects: Vec<&str> = req.allowed_subjects.iter().map(String::as_str).collect();

        let record = self
            .repo
            .create(NewServiceToken {
                id,
                service_name: &req.service_name,
                token_hash: &hash.0,
                allowed_subjects: &subjects,
                display_name,
            })
            .await?;

        self.auditor
            .record(AuditEvent::V1(AuditEventV1::new(
                AuditEventKind::ServiceTokenCreated,
                AuditActor::User {
                    user_id: actor_user_id,
                    ip: None,
                },
                AuditResource::ServiceToken { token_id: id },
                correlation_id,
                actor_org_id,
                AuditPayload::new(serde_json::json!({
                    "service_name": req.service_name,
                    "allowed_subjects": req.allowed_subjects,
                    "display_name": display_name,
                })),
            )))
            .await;

        Ok(IssuedServiceToken {
            record,
            raw_token: zeroize::Zeroizing::new(raw_token),
        })
    }

    /// List every live service token, newest first.
    pub async fn list(&self) -> Result<Vec<ServiceTokenView>> {
        Ok(self
            .repo
            .list()
            .await?
            .into_iter()
            .map(ServiceTokenView::from)
            .collect())
    }

    /// Fetch one service token by id (any revocation state, so the
    /// admin UI can show a `revoked_at`). [`IdentityError::TokenNotFound`]
    /// when missing or soft-deleted.
    pub async fn get(&self, id: Uuid) -> Result<ServiceTokenView> {
        self.repo
            .find_by_id(id)
            .await?
            .map(ServiceTokenView::from)
            .ok_or(IdentityError::TokenNotFound)
    }

    /// Revoke a service token. [`IdentityError::TokenNotFound`] when
    /// missing, soft-deleted, or already revoked. Emits
    /// `ServiceTokenRevoked` only when the UPDATE actually mutated a
    /// row (no duplicate emission under a concurrent-revoke race).
    pub async fn revoke(
        &self,
        actor_user_id: Uuid,
        actor_org_id: Uuid,
        correlation_id: Uuid,
        id: Uuid,
    ) -> Result<()> {
        let target = self
            .repo
            .find_by_id(id)
            .await?
            .ok_or(IdentityError::TokenNotFound)?;
        if target.revoked_at.is_some() {
            return Err(IdentityError::TokenNotFound);
        }

        // Bump BEFORE the UPDATE so an in-flight resolver that
        // snapshotted the prior generation gets its insert rejected.
        self.cache.bump_generation(id);

        let rows = self.repo.revoke(id).await?;
        if rows == 0 {
            // A concurrent revoker won the race; no audit emission.
            return Err(IdentityError::TokenNotFound);
        }

        let _ = self.cache.evict_by_token_id(id).await;

        self.auditor
            .record(AuditEvent::V1(AuditEventV1::new(
                AuditEventKind::ServiceTokenRevoked,
                AuditActor::User {
                    user_id: actor_user_id,
                    ip: None,
                },
                AuditResource::ServiceToken { token_id: id },
                correlation_id,
                actor_org_id,
                AuditPayload::new(serde_json::json!({
                    "service_name": target.service_name,
                })),
            )))
            .await;
        Ok(())
    }
}

/// `^[a-z][a-z0-9-]{1,63}$` — first char lowercase letter, then
/// 1..=63 of `[a-z0-9-]` (total length 2..=64). A constrained format
/// (vs free-form) lets worker bootstrap fail loudly on an identity
/// typo instead of silently mis-authenticating.
fn validate_service_name(name: &str) -> Result<()> {
    let bad = |reason: &str| IdentityError::InvalidServiceTokenRequest {
        reason: reason.to_owned(),
    };
    // Char-count, not byte-len: the documented invariant + error
    // message + the `^[a-z][a-z0-9-]{1,63}$` shape are all
    // character-based. (Equal for the valid ASCII charset; counting
    // chars keeps the length error accurate for a multibyte input
    // instead of misreporting it as a charset failure.)
    let len = name.chars().count();
    if !(2..=64).contains(&len) {
        return Err(bad("service_name must be 2..=64 characters"));
    }
    let mut chars = name.chars();
    let first = chars.next().ok_or_else(|| bad("service_name is empty"))?;
    if !first.is_ascii_lowercase() {
        return Err(bad("service_name must start with a lowercase letter"));
    }
    if !chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') {
        return Err(bad(
            "service_name may contain only [a-z0-9-] after the first character",
        ));
    }
    Ok(())
}

/// Non-empty array; each entry non-empty and limited to the NATS
/// subject charset `[A-Za-z0-9_*>.-]`. An empty array is rejected
/// because it is ambiguous (deny-all vs allow-all) — the worker pool
/// must receive an explicit allowlist.
fn validate_allowed_subjects(subjects: &[String]) -> Result<()> {
    let bad = |reason: &str| IdentityError::InvalidServiceTokenRequest {
        reason: reason.to_owned(),
    };
    if subjects.is_empty() {
        return Err(bad("allowed_subjects must not be empty"));
    }
    for s in subjects {
        if s.is_empty() {
            return Err(bad("allowed_subjects entries must not be empty"));
        }
        if !s
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '*' | '>' | '.' | '-'))
        {
            return Err(bad(
                "allowed_subjects entries may contain only [A-Za-z0-9_*>.-]",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use static_assertions::assert_impl_all;

    assert_impl_all!(ServiceTokenService: Send, Sync, Clone);

    #[test]
    fn service_name_accepts_canonical() {
        validate_service_name("email-worker").expect("valid");
        validate_service_name("scim-bridge2").expect("valid");
    }

    #[test]
    fn service_name_rejects_bad_shapes() {
        for bad in ["", "a", "1abc", "Email", "ab_cd", "ab cd", &"a".repeat(65)] {
            assert!(
                validate_service_name(bad).is_err(),
                "{bad:?} should be rejected",
            );
        }
    }

    #[test]
    fn allowed_subjects_rejects_empty_and_bad_charset() {
        assert!(validate_allowed_subjects(&[]).is_err());
        assert!(validate_allowed_subjects(&[String::new()]).is_err());
        assert!(validate_allowed_subjects(&["bad subject".to_string()]).is_err());
        validate_allowed_subjects(&["email.outbox.queue".to_string(), "identity.>".to_string()])
            .expect("valid subjects");
    }
}
