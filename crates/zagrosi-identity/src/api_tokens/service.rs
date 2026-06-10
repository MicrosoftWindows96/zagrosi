// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! Personal-access-token service: issue / list / get / revoke.
//!
//! Every method is `(caller_user_id, caller_org_id)`-scoped so the
//! tenant-isolation invariant holds at the API surface.
//! Cross-user / cross-org reads return `TokenNotFound` rather than
//! `Forbidden` (matches the section-08 / section-12 anti-enumeration
//! contract).

use std::sync::Arc;

use chrono::{Duration, Utc};
use uuid::Uuid;
use zagrosi_core::{
    AuditActor, AuditEvent, AuditEventKind, AuditEventV1, AuditPayload, AuditResource, Auditor,
};

use crate::api_tokens::cache::ApiTokenCache;
use crate::api_tokens::model::{ApiTokenView, CreateApiTokenRequest, IssuedApiToken};
use crate::api_tokens::{DISPLAY_NAME_MAX_LEN, is_known_scope};
use crate::domain::token_format::{TokenPrefix, hash_token, mint};
use crate::error::{IdentityError, Result};
use crate::repo::{ApiTokenRepo, NewApiToken, OrgScoped};

/// Argument bundle for [`ApiTokenService::issue`]. Carries the
/// caller's identity (so the service can stamp `user_id` / `org_id`
/// into the row) plus the validated request body.
#[derive(Debug, Clone)]
pub struct IssueApiTokenInput {
    /// Caller (PAT owner).
    pub caller_user_id: Uuid,
    /// Caller's active org. The PAT will be scoped to this org.
    pub caller_org_id: Uuid,
    /// Caller-supplied request body. Validated by the service.
    pub request: CreateApiTokenRequest,
    /// Caller-controlled correlation id for audit trace continuity.
    pub correlation_id: Uuid,
}

/// Composed service for the PAT surface. Cheap to clone; every
/// dependency is an `Arc`-flavoured handle.
#[derive(Clone)]
pub struct ApiTokenService {
    repo: ApiTokenRepo,
    cache: ApiTokenCache,
    auditor: Arc<dyn Auditor>,
}

impl ApiTokenService {
    /// Wire dependencies.
    #[must_use]
    pub fn new(repo: ApiTokenRepo, cache: ApiTokenCache, auditor: Arc<dyn Auditor>) -> Self {
        Self {
            repo,
            cache,
            auditor,
        }
    }

    /// Mint a fresh PAT, persist it, and return `(row, raw_token)`.
    ///
    /// # Errors
    ///
    /// - [`IdentityError::InvalidApiTokenRequest`] for empty /
    ///   over-long display name or `expires_at` in the past.
    /// - [`IdentityError::InvalidScope`] for any scope string outside
    ///   [`super::SCOPE_CATALOGUE_V0_1`].
    /// - [`IdentityError::Database`] for any underlying sqlx failure.
    pub async fn issue(&self, input: IssueApiTokenInput) -> Result<IssuedApiToken> {
        let req = input.request;
        let display_name = req.display_name.trim();
        if display_name.is_empty() {
            return Err(IdentityError::InvalidApiTokenRequest {
                reason: "display_name must not be empty".into(),
            });
        }
        if display_name.chars().count() > DISPLAY_NAME_MAX_LEN {
            return Err(IdentityError::InvalidApiTokenRequest {
                reason: format!("display_name exceeds {DISPLAY_NAME_MAX_LEN} characters",),
            });
        }
        for scope in &req.scopes {
            if !is_known_scope(scope) {
                return Err(IdentityError::InvalidScope {
                    scope: scope.clone(),
                });
            }
        }
        if let Some(exp) = req.expires_at {
            let earliest = Utc::now() + Duration::minutes(1);
            if exp < earliest {
                return Err(IdentityError::InvalidApiTokenRequest {
                    reason: "expires_at must be at least one minute in the future".into(),
                });
            }
        }

        let raw_token = mint(TokenPrefix::Pat);
        let hash = hash_token(&raw_token);
        let id = Uuid::now_v7();
        let scope_strs: Vec<&str> = req.scopes.iter().map(String::as_str).collect();

        let scoped = OrgScoped::new(&self.repo, input.caller_org_id);
        let persisted = scoped
            .create(NewApiToken {
                id,
                token_hash: hash.as_slice(),
                user_id: input.caller_user_id,
                display_name,
                scopes: &scope_strs,
                expires_at: req.expires_at,
            })
            .await?;

        self.auditor
            .record(AuditEvent::V1(
                AuditEventV1::builder(
                    AuditEventKind::ApiTokenCreated,
                    AuditActor::User {
                        user_id: input.caller_user_id,
                        ip: None,
                    },
                    Some(input.caller_org_id),
                    input.correlation_id,
                )
                .resource(AuditResource::ApiToken { token_id: id })
                .metadata(AuditPayload::new(serde_json::json!({
                    "display_name": display_name,
                    "scopes": req.scopes,
                    "expires_at": req.expires_at,
                })))
                .build(),
            ))
            .await;

        Ok(IssuedApiToken {
            token: persisted,
            raw_token,
        })
    }

    /// List live PATs owned by `caller_user_id` in `caller_org_id`.
    pub async fn list(
        &self,
        caller_user_id: Uuid,
        caller_org_id: Uuid,
    ) -> Result<Vec<ApiTokenView>> {
        let scoped = OrgScoped::new(&self.repo, caller_org_id);
        let rows = scoped.list_for_user(caller_user_id).await?;
        Ok(rows.into_iter().map(ApiTokenView::from).collect())
    }

    /// Fetch one PAT by id, scoped to `(caller_user_id, caller_org_id)`.
    ///
    /// Returns the row regardless of `revoked_at` so the
    /// owner-visible token-management UI can surface the revocation
    /// timestamp on previously-revoked tokens (audit trail).
    /// [`IdentityError::TokenNotFound`] when the row does not exist
    /// or belongs to a different user / org. The error envelope is
    /// identical for both shapes so the route does not double as an
    /// existence oracle.
    pub async fn get(
        &self,
        caller_user_id: Uuid,
        caller_org_id: Uuid,
        token_id: Uuid,
    ) -> Result<ApiTokenView> {
        let scoped = OrgScoped::new(&self.repo, caller_org_id);
        scoped
            .find_by_id_for_user(caller_user_id, token_id)
            .await?
            .map(ApiTokenView::from)
            .ok_or(IdentityError::TokenNotFound)
    }

    /// Revoke a PAT scoped to `(caller_user_id, caller_org_id)`.
    ///
    /// Returns [`IdentityError::TokenNotFound`] when the row is
    /// missing, already revoked, or belongs to another user / org.
    /// Concurrent-safe: the cache generation is bumped BEFORE the
    /// `UPDATE ... WHERE revoked_at IS NULL` so an in-flight
    /// resolver that snapshotted the prior generation cannot land a
    /// stale cache entry. The audit event is emitted only when the
    /// UPDATE actually mutated a row, preventing duplicate
    /// `ApiTokenRevoked` emissions under concurrent revoke races.
    pub async fn revoke(
        &self,
        caller_user_id: Uuid,
        caller_org_id: Uuid,
        token_id: Uuid,
        correlation_id: Uuid,
    ) -> Result<()> {
        let scoped = OrgScoped::new(&self.repo, caller_org_id);
        // Ownership + existence pre-check (404 vs 200 disambiguation).
        // The follow-up UPDATE's WHERE clause re-applies the live-row
        // predicate, so a race that revokes the row between this
        // read and the UPDATE collapses cleanly to a `rows == 0`
        // outcome below.
        let target = scoped
            .find_by_id_for_user(caller_user_id, token_id)
            .await?
            .ok_or(IdentityError::TokenNotFound)?;
        if target.revoked_at.is_some() {
            return Err(IdentityError::TokenNotFound);
        }

        // Bump the cache generation BEFORE the UPDATE so any
        // in-flight resolver that snapshotted the prior generation
        // gets its `insert_with_guard` rejected. Eviction itself
        // happens on the resolver's next miss; the bump is the
        // race-safe primitive.
        self.cache.bump_generation(token_id);

        let rows_affected = scoped.revoke(token_id).await?;
        if rows_affected == 0 {
            // Concurrent revoker won the race; no audit emission.
            return Err(IdentityError::TokenNotFound);
        }

        // Cache eviction (synchronous moka invalidate) so subsequent
        // resolves re-read the DB and surface the revoked state.
        let _ = self.cache.evict_by_token_id(token_id).await;

        self.auditor
            .record(AuditEvent::V1(
                AuditEventV1::builder(
                    AuditEventKind::ApiTokenRevoked,
                    AuditActor::User {
                        user_id: caller_user_id,
                        ip: None,
                    },
                    Some(caller_org_id),
                    correlation_id,
                )
                .resource(AuditResource::ApiToken { token_id })
                .metadata(AuditPayload::new(serde_json::json!({
                    "owner_user_id": target.user_id,
                })))
                .build(),
            ))
            .await;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use static_assertions::assert_impl_all;

    assert_impl_all!(ApiTokenService: Send, Sync, Clone);

    #[test]
    fn issue_input_round_trips_correlation_id() {
        let input = IssueApiTokenInput {
            caller_user_id: Uuid::nil(),
            caller_org_id: Uuid::nil(),
            request: CreateApiTokenRequest {
                display_name: "x".into(),
                scopes: vec![],
                expires_at: None,
            },
            correlation_id: Uuid::from_bytes([7; 16]),
        };
        let cloned = input.clone();
        assert_eq!(cloned.correlation_id, input.correlation_id);
    }
}
