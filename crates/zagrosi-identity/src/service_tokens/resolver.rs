// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! Service-token (`svc_*`) branch of the gateway-facing introspector.
//!
//! Mirrors [`crate::api_tokens::ApiTokenResolver`] so the gateway
//! middleware does not branch on token kind: same
//! `Result<AuthContext, AuthError>` return shape, same cache + DB +
//! per-token rate-limit pipeline. Differences vs the PAT resolver,
//! both forced by the `service_tokens` schema:
//!
//! - **No expiry.** The table has no `expires_at`; the only terminal
//!   states are `revoked_at` / `deleted_at`. `AuthContext::new`
//!   still requires `issued_at < expires_at`, so a far-future expiry
//!   is synthesised from `created_at` (indistinguishable from "no
//!   expiry", same trick the PAT resolver uses for null-expiry PATs).
//! - **No write-behind.** No `last_used_at` column → nothing to
//!   coalesce off the hot path.
//!
//! ## Org-agnostic AuthContext
//!
//! Service tokens are platform-level: no user, no session, no org.
//! [`AuthContext::new`] forbids nil `subject_id` / `session_id` /
//! `org_id`, so all three carry the token's own id as a non-nil
//! sentinel. **The org_id is never a tenant scope here** — the
//! worker pool (split-11) routes per message and reads the NATS
//! allowlist from the context's `scopes`. `auth_method =
//! ServiceToken`, `token_class = Service`, `amr = ["svc"]`,
//! `scopes = allowed_subjects`.

use std::net::IpAddr;
use std::sync::Arc;

use async_trait::async_trait;
use uuid::Uuid;
use zagrosi_core::{
    AuthContext, AuthError, AuthMethod, RateLimitDecision, RateLimitKey, RateLimiter,
    SessionIntrospector, TokenClass,
};

use crate::domain::token_format::{TokenHash, TokenPrefix, hash_token, parse_raw};
use crate::repo::ServiceTokenRepo;
use crate::service_tokens::cache::{CachedServiceToken, ServiceTokenCache};

/// Stable per-token rate-limit bucket scope. Part of the Valkey
/// storage-key format (`rl:svc_resolve:token:<hex>`); renaming needs
/// a coordinated migration of in-flight limiter state.
pub const SVC_RESOLVE_SCOPE: &str = "svc_resolve";

/// Days of synthesised lifetime for the `AuthContext` expiry of a
/// (no-expiry-by-schema) service token. 100 years — far enough that
/// it reads as "no expiry" while satisfying the
/// `issued_at < expires_at` constructor invariant.
const SYNTHETIC_LIFETIME_DAYS: i64 = 36_500;

/// Concrete `svc_*` resolver. Cheap to clone; every dependency is an
/// `Arc`-flavoured handle.
#[derive(Clone)]
pub struct ServiceTokenResolver {
    repo: ServiceTokenRepo,
    cache: ServiceTokenCache,
    rate_limiter: Arc<dyn RateLimiter>,
}

impl ServiceTokenResolver {
    /// Wire dependencies.
    #[must_use]
    pub fn new(
        repo: ServiceTokenRepo,
        cache: ServiceTokenCache,
        rate_limiter: Arc<dyn RateLimiter>,
    ) -> Self {
        Self {
            repo,
            cache,
            rate_limiter,
        }
    }

    /// Cache accessor for the service layer's revoke-eviction path.
    #[must_use]
    pub const fn cache(&self) -> &ServiceTokenCache {
        &self.cache
    }

    /// Resolve a raw `svc_*` token. `ip` is accepted for signature
    /// parity with the PAT resolver but unused (no `last_used_ip`
    /// column on `service_tokens`).
    pub async fn resolve_with_observation(
        &self,
        raw_token: &str,
        _ip: Option<IpAddr>,
    ) -> Result<AuthContext, AuthError> {
        let (prefix, _body) = parse_raw(raw_token).map_err(|_| AuthError::MalformedPrefix)?;
        if prefix != TokenPrefix::Service {
            return Err(AuthError::MalformedPrefix);
        }
        let hash = hash_token(raw_token);

        if let Some(entry) = self.cache.get(&hash).await {
            return self.finalise_cached(entry, hash).await;
        }

        let row = self
            .repo
            .find_by_token_hash(&hash.0)
            .await
            .map_err(AuthError::internal)?
            .ok_or(AuthError::Unauthorized)?;

        // Defence-in-depth constant-time compare. The partial-unique
        // index already narrowed to ≤ 1 live row; the explicit
        // `ct_eq` is the documented svc_ branch invariant so a future
        // call site that bypasses the index cannot leak a non-CT
        // compare.
        let row_hash = TokenHash(row.token_hash);
        if !hash.ct_eq(&row_hash) {
            return Err(AuthError::Unauthorized);
        }

        let post_read_generation = self.cache.current_generation(row.id);

        if row.revoked_at.is_some() || row.deleted_at.is_some() {
            return Err(AuthError::Revoked);
        }

        self.enforce_rate_limit(&hash).await?;

        let cached = CachedServiceToken {
            token_id: row.id,
            service_name: row.service_name,
            allowed_subjects: row.allowed_subjects,
            revoked_at: row.revoked_at,
            created_at: row.created_at,
        };
        let _ = self
            .cache
            .insert_with_guard(hash, cached.clone(), post_read_generation)
            .await;
        Self::context_from_cached(&cached)
    }

    async fn finalise_cached(
        &self,
        cached: CachedServiceToken,
        hash: TokenHash,
    ) -> Result<AuthContext, AuthError> {
        if cached.revoked_at.is_some() {
            return Err(AuthError::Revoked);
        }
        self.enforce_rate_limit(&hash).await?;
        Self::context_from_cached(&cached)
    }

    /// Build the org-agnostic `AuthContext` for a resolved service
    /// token.
    ///
    /// **Downstream contract (load-bearing):** `subject_id`,
    /// `session_id`, and `org_id` are all the token's own id — a
    /// non-nil *sentinel*, not identities. `AuthContext::new` only
    /// forbids nil for these, so the sentinel satisfies the
    /// constructor without implying a user / session / tenant.
    /// Any consumer that uses `ctx.org_id()` (or `subject_id`) as a
    /// **tenant scope** MUST first gate on
    /// `ctx.token_class() == TokenClass::Service` (equivalently
    /// `auth_method() == ServiceToken`) and route by
    /// `ctx.scopes()` (the NATS `allowed_subjects`) instead. The
    /// RLS / tenant-isolation layer (split-03) owns enforcing this
    /// guard centrally; until it lands, no in-tree handler consumes
    /// a service-token `AuthContext` for an org-scoped query (the
    /// service-token routes themselves audit-scope on the *human
    /// admin's* session org, passed in by the HTTP layer, never on
    /// this sentinel).
    // TODO(split-03 RBAC): centralise the `token_class == Service`
    // tenant-scope guard in the RLS layer.
    fn context_from_cached(cached: &CachedServiceToken) -> Result<AuthContext, AuthError> {
        let sentinel = cached.token_id;
        let effective_expires_at = cached
            .created_at
            .checked_add_signed(chrono::Duration::days(SYNTHETIC_LIFETIME_DAYS))
            .ok_or_else(|| {
                AuthError::internal(std::io::Error::other(
                    "synthesised service-token expiry overflows DateTime<Utc>",
                ))
            })?;
        let ctx = AuthContext::new(
            sentinel,
            sentinel,
            sentinel,
            AuthMethod::ServiceToken,
            TokenClass::Service,
            vec!["svc".to_string()],
            None,
            cached.created_at,
            effective_expires_at,
            Uuid::now_v7(),
        )
        .map_err(AuthError::internal)?;
        // `allowed_subjects` rides on the bearer-scope channel; the
        // worker-pool NATS wrapper (split-11) reads it back via
        // `AuthContext::scopes()`.
        Ok(ctx.with_scopes(cached.allowed_subjects.clone()))
    }

    async fn enforce_rate_limit(&self, hash: &TokenHash) -> Result<(), AuthError> {
        let key = RateLimitKey::PerToken {
            token_hash: hash.0,
            scope: SVC_RESOLVE_SCOPE,
        };
        match self.rate_limiter.check(&key).await {
            Ok(RateLimitDecision::Allow { .. }) => Ok(()),
            Ok(
                RateLimitDecision::Deny { retry_after }
                | RateLimitDecision::LockedOut { retry_after, .. },
            ) => Err(AuthError::RateLimited { retry_after }),
            Ok(_) => Err(AuthError::RateLimited {
                retry_after: std::time::Duration::from_secs(60),
            }),
            Err(err) => Err(AuthError::internal(err)),
        }
    }
}

#[async_trait]
impl SessionIntrospector for ServiceTokenResolver {
    async fn resolve(&self, raw_token: &str) -> Result<AuthContext, AuthError> {
        self.resolve_with_observation(raw_token, None).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use static_assertions::assert_impl_all;

    assert_impl_all!(ServiceTokenResolver: Send, Sync, Clone);

    #[test]
    fn svc_resolve_scope_is_stable() {
        assert_eq!(SVC_RESOLVE_SCOPE, "svc_resolve");
    }

    #[test]
    fn context_from_cached_builds_service_token_context() {
        let cached = CachedServiceToken {
            token_id: Uuid::from_u128(0x5151),
            service_name: "email-worker".into(),
            allowed_subjects: vec!["email.outbox.queue".into(), "identity.>".into()],
            revoked_at: None,
            created_at: chrono::Utc::now(),
        };
        let ctx = ServiceTokenResolver::context_from_cached(&cached).expect("ctx builds");
        assert_eq!(ctx.token_class(), TokenClass::Service);
        assert_eq!(ctx.auth_method(), AuthMethod::ServiceToken);
        assert_eq!(ctx.subject_id(), cached.token_id);
        assert_eq!(ctx.org_id(), cached.token_id);
        assert_eq!(ctx.amr(), &["svc"]);
        assert!(ctx.has_scope("identity.>"));
        assert!(ctx.expires_at() > ctx.issued_at());
    }
}
