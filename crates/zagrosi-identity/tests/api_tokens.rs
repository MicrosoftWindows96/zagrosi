// SPDX-License-Identifier: AGPL-3.0-or-later

//! Personal-access-token integration coverage:
//!
//! - CRUD via [`ApiTokenService`] (issue / list / get / revoke).
//! - Resolver fast path via [`ApiTokenResolver`] (cache hit / cache
//!   miss / revoke / expiry / cascade-soft-delete).
//! - Scope enforcement via [`AuthContext::has_scope`].
//! - Per-token rate limit via the
//!   [`RateLimitDecision::Deny`] / [`AuthError::RateLimited`] mapping.
//! - Last-used write-behind drain.

#![allow(
    clippy::cast_possible_truncation,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::map_unwrap_or,
    clippy::missing_panics_doc,
    clippy::too_many_lines
)]

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use chrono::{TimeDelta, Utc};
use common::{TestEnv, TestResult, migrated_env, seed_org, seed_user};
use http_body_util::BodyExt;
use serde_json::Value;
use serial_test::serial;
use tower::ServiceExt;
use uuid::Uuid;
use zagrosi_core::{
    AuditEvent, Auditor, AuthContext, AuthError, AuthMethod, NoopAuditor, RateLimitDecision,
    RateLimitKey, RateLimiter, RateLimiterError, SessionIntrospector, TokenClass,
};
use zagrosi_identity::api_tokens::{
    ApiTokenCache, ApiTokenResolver, ApiTokenService, CreateApiTokenRequest, IssueApiTokenInput,
    api_token_last_used_channel, write_behind::drain_once,
};
use zagrosi_identity::domain::{TokenPrefix, hash_token, mint};
use zagrosi_identity::error::IdentityError;
use zagrosi_identity::http::api_tokens::{ApiTokensState, router as api_tokens_router};
use zagrosi_identity::repo::{
    ApiTokenRepo, SessionRepo, UserRepo, soft_delete_org, soft_delete_user,
};
use zagrosi_identity::session::{
    IdentitySessionIntrospector, SessionCache as IdSessionCache,
    write_behind::channel as session_last_seen_channel,
};

const HEALTHY_TTL: Duration = Duration::from_secs(30);
const CACHE_CAPACITY: u64 = 64;
const CHANNEL_CAPACITY: usize = 64;

// ---------------------------------------------------------------------
// Shared fixtures
// ---------------------------------------------------------------------

fn cache() -> ApiTokenCache {
    ApiTokenCache::new(CACHE_CAPACITY, HEALTHY_TTL)
}

fn allow_always() -> Arc<dyn RateLimiter> {
    Arc::new(AllowAlwaysRateLimiter)
}

fn build_service(repo: ApiTokenRepo, cache: ApiTokenCache) -> ApiTokenService {
    ApiTokenService::new(repo, cache, Arc::new(NoopAuditor))
}

/// Resolver repos ride the AUTH pool (pre-tenant-context hash lookups —
/// the section-05 `zagrosi_auth` mechanism), exactly as the composition
/// root wires production.
fn build_resolver(
    env: &TestEnv,
    cache: ApiTokenCache,
    rate_limiter: Arc<dyn RateLimiter>,
) -> (
    ApiTokenResolver,
    zagrosi_identity::api_tokens::ApiTokenLastUsedReceiver,
) {
    let (sender, receiver) = api_token_last_used_channel(CHANNEL_CAPACITY);
    let repo = ApiTokenRepo::new(env.db.auth_pool().clone());
    let resolver = ApiTokenResolver::new(repo, cache, sender, rate_limiter);
    (resolver, receiver)
}

#[derive(Clone, Default)]
struct AllowAlwaysRateLimiter;

#[async_trait]
impl RateLimiter for AllowAlwaysRateLimiter {
    async fn check(&self, _key: &RateLimitKey) -> Result<RateLimitDecision, RateLimiterError> {
        Ok(RateLimitDecision::Allow {
            remaining: u32::MAX,
            reset_in: Duration::from_secs(60),
        })
    }
    async fn unlock(&self, _key: &RateLimitKey) -> Result<(), RateLimiterError> {
        Ok(())
    }
}

#[derive(Clone, Default)]
struct DenyAlwaysRateLimiter;

#[async_trait]
impl RateLimiter for DenyAlwaysRateLimiter {
    async fn check(&self, _key: &RateLimitKey) -> Result<RateLimitDecision, RateLimiterError> {
        Ok(RateLimitDecision::Deny {
            retry_after: Duration::from_secs(30),
        })
    }
    async fn unlock(&self, _key: &RateLimitKey) -> Result<(), RateLimiterError> {
        Ok(())
    }
}

/// Allows up to `budget` calls, denies the rest. Counts atomically.
#[derive(Clone)]
struct CountingRateLimiter {
    budget: Arc<AtomicU32>,
}

impl CountingRateLimiter {
    fn new(budget: u32) -> Self {
        Self {
            budget: Arc::new(AtomicU32::new(budget)),
        }
    }
}

#[async_trait]
impl RateLimiter for CountingRateLimiter {
    async fn check(&self, _key: &RateLimitKey) -> Result<RateLimitDecision, RateLimiterError> {
        let prev = self.budget.fetch_sub(1, Ordering::SeqCst);
        if prev == 0 {
            // Restore so the counter doesn't underflow.
            self.budget.fetch_add(1, Ordering::SeqCst);
            Ok(RateLimitDecision::Deny {
                retry_after: Duration::from_secs(15),
            })
        } else {
            Ok(RateLimitDecision::Allow {
                remaining: prev.saturating_sub(1),
                reset_in: Duration::from_secs(60),
            })
        }
    }
    async fn unlock(&self, _key: &RateLimitKey) -> Result<(), RateLimiterError> {
        Ok(())
    }
}

/// Captures every event the auditor receives so tests can assert on
/// kind / actor / payload.
#[derive(Default)]
struct CapturingAuditor {
    events: tokio::sync::Mutex<Vec<AuditEvent>>,
}

#[async_trait]
impl Auditor for CapturingAuditor {
    async fn record(&self, event: AuditEvent) {
        self.events.lock().await.push(event);
    }
}

impl CapturingAuditor {
    async fn events(&self) -> Vec<AuditEvent> {
        self.events.lock().await.clone()
    }
}

// ---------------------------------------------------------------------
// Service: issue / validation
// ---------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn issue_persists_hashed_token_and_returns_raw() -> TestResult {
    let env = migrated_env().await?;
    let org = seed_org(&env.pool, "issue-org").await?;
    let user = seed_user(&env.pool, "issue@example.com").await?;
    let repo = ApiTokenRepo::new(env.pool.clone());
    let svc = build_service(repo.clone(), cache());

    let issued = svc
        .issue(IssueApiTokenInput {
            caller_user_id: user,
            caller_org_id: org,
            request: CreateApiTokenRequest {
                display_name: "ci-bot".into(),
                scopes: vec!["tokens:read".into()],
                expires_at: None,
            },
            correlation_id: Uuid::now_v7(),
        })
        .await?;

    assert!(issued.raw_token.starts_with("pat_"));
    assert_eq!(issued.raw_token.len(), 4 + 43);

    // Verify persisted hash matches SHA-256 of the raw token.
    let expected_hash = hash_token(&issued.raw_token);
    // Hash lookups are the auth-path query: assert over the auth pool.
    let row = ApiTokenRepo::new(env.db.auth_pool().clone())
        .find_live_by_token_hash(&expected_hash.0)
        .await?
        .expect("hash lookup must hit the freshly issued row");
    assert_eq!(row.id, issued.token.id);
    assert_eq!(row.user_id, user);
    assert_eq!(row.org_id, org);
    assert_eq!(row.scopes, vec!["tokens:read".to_string()]);
    Ok(())
}

#[tokio::test]
#[serial]
async fn issue_rejects_empty_display_name() -> TestResult {
    let env = migrated_env().await?;
    let org = seed_org(&env.pool, "issue-empty").await?;
    let user = seed_user(&env.pool, "empty@example.com").await?;
    let svc = build_service(ApiTokenRepo::new(env.pool.clone()), cache());

    let err = svc
        .issue(IssueApiTokenInput {
            caller_user_id: user,
            caller_org_id: org,
            request: CreateApiTokenRequest {
                display_name: "   ".into(),
                scopes: vec![],
                expires_at: None,
            },
            correlation_id: Uuid::now_v7(),
        })
        .await
        .expect_err("empty display_name must reject");
    assert!(matches!(err, IdentityError::InvalidApiTokenRequest { .. }));
    Ok(())
}

#[tokio::test]
#[serial]
async fn issue_rejects_unknown_scope() -> TestResult {
    let env = migrated_env().await?;
    let org = seed_org(&env.pool, "issue-scope").await?;
    let user = seed_user(&env.pool, "scope@example.com").await?;
    let svc = build_service(ApiTokenRepo::new(env.pool.clone()), cache());

    let err = svc
        .issue(IssueApiTokenInput {
            caller_user_id: user,
            caller_org_id: org,
            request: CreateApiTokenRequest {
                display_name: "x".into(),
                scopes: vec!["fake:scope".into()],
                expires_at: None,
            },
            correlation_id: Uuid::now_v7(),
        })
        .await
        .expect_err("unknown scope must reject");
    match err {
        IdentityError::InvalidScope { scope } => assert_eq!(scope, "fake:scope"),
        other => panic!("expected InvalidScope, got {other:?}"),
    }
    Ok(())
}

#[tokio::test]
#[serial]
async fn issue_rejects_past_expires_at() -> TestResult {
    let env = migrated_env().await?;
    let org = seed_org(&env.pool, "issue-past").await?;
    let user = seed_user(&env.pool, "past@example.com").await?;
    let svc = build_service(ApiTokenRepo::new(env.pool.clone()), cache());

    let err = svc
        .issue(IssueApiTokenInput {
            caller_user_id: user,
            caller_org_id: org,
            request: CreateApiTokenRequest {
                display_name: "x".into(),
                scopes: vec![],
                expires_at: Some(Utc::now() - TimeDelta::hours(1)),
            },
            correlation_id: Uuid::now_v7(),
        })
        .await
        .expect_err("past expires_at must reject");
    assert!(matches!(err, IdentityError::InvalidApiTokenRequest { .. }));
    Ok(())
}

// ---------------------------------------------------------------------
// Service: list / get / revoke + tenant isolation
// ---------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn list_scopes_to_caller_user_and_org() -> TestResult {
    let env = migrated_env().await?;
    let org_a = seed_org(&env.pool, "iso-a").await?;
    let org_b = seed_org(&env.pool, "iso-b").await?;
    let user_a = seed_user(&env.pool, "alice@example.com").await?;
    let user_b = seed_user(&env.pool, "bob@example.com").await?;
    let repo = ApiTokenRepo::new(env.pool.clone());
    let svc = build_service(repo.clone(), cache());

    // Two PATs for alice in org_a, one PAT for bob in org_a, one
    // PAT for alice in org_b.
    for label in ["alice-1", "alice-2"] {
        svc.issue(IssueApiTokenInput {
            caller_user_id: user_a,
            caller_org_id: org_a,
            request: CreateApiTokenRequest {
                display_name: label.into(),
                scopes: vec![],
                expires_at: None,
            },
            correlation_id: Uuid::now_v7(),
        })
        .await?;
    }
    svc.issue(IssueApiTokenInput {
        caller_user_id: user_b,
        caller_org_id: org_a,
        request: CreateApiTokenRequest {
            display_name: "bob-1".into(),
            scopes: vec![],
            expires_at: None,
        },
        correlation_id: Uuid::now_v7(),
    })
    .await?;
    svc.issue(IssueApiTokenInput {
        caller_user_id: user_a,
        caller_org_id: org_b,
        request: CreateApiTokenRequest {
            display_name: "alice-org-b".into(),
            scopes: vec![],
            expires_at: None,
        },
        correlation_id: Uuid::now_v7(),
    })
    .await?;

    let alice_in_a = svc.list(user_a, org_a).await?;
    assert_eq!(alice_in_a.len(), 2);

    let bob_in_a = svc.list(user_b, org_a).await?;
    assert_eq!(bob_in_a.len(), 1);
    assert_eq!(bob_in_a[0].display_name, "bob-1");

    // Cross-user probe within the same org returns nothing for
    // bob even though alice has live PATs there.
    let alice_seen_by_bob = svc.list(user_b, org_a).await?;
    assert!(
        alice_seen_by_bob
            .iter()
            .all(|t| t.display_name != "alice-1")
    );

    Ok(())
}

#[tokio::test]
#[serial]
async fn get_cross_user_returns_token_not_found() -> TestResult {
    let env = migrated_env().await?;
    let org = seed_org(&env.pool, "iso-cu").await?;
    let alice = seed_user(&env.pool, "iso-alice@example.com").await?;
    let bob = seed_user(&env.pool, "iso-bob@example.com").await?;
    let svc = build_service(ApiTokenRepo::new(env.pool.clone()), cache());

    let issued = svc
        .issue(IssueApiTokenInput {
            caller_user_id: alice,
            caller_org_id: org,
            request: CreateApiTokenRequest {
                display_name: "alice-pat".into(),
                scopes: vec![],
                expires_at: None,
            },
            correlation_id: Uuid::now_v7(),
        })
        .await?;

    let err = svc
        .get(bob, org, issued.token.id)
        .await
        .expect_err("cross-user GET must 404");
    assert!(matches!(err, IdentityError::TokenNotFound));
    Ok(())
}

#[tokio::test]
#[serial]
async fn get_cross_org_returns_token_not_found() -> TestResult {
    let env = migrated_env().await?;
    let org_a = seed_org(&env.pool, "iso-co-a").await?;
    let org_b = seed_org(&env.pool, "iso-co-b").await?;
    let user = seed_user(&env.pool, "co@example.com").await?;
    let svc = build_service(ApiTokenRepo::new(env.pool.clone()), cache());

    let issued = svc
        .issue(IssueApiTokenInput {
            caller_user_id: user,
            caller_org_id: org_a,
            request: CreateApiTokenRequest {
                display_name: "in-a".into(),
                scopes: vec![],
                expires_at: None,
            },
            correlation_id: Uuid::now_v7(),
        })
        .await?;

    let err = svc
        .get(user, org_b, issued.token.id)
        .await
        .expect_err("cross-org GET must 404");
    assert!(matches!(err, IdentityError::TokenNotFound));
    Ok(())
}

#[tokio::test]
#[serial]
async fn revoke_marks_revoked_at_and_subsequent_revoke_returns_404() -> TestResult {
    let env = migrated_env().await?;
    let org = seed_org(&env.pool, "rev-org").await?;
    let user = seed_user(&env.pool, "rev@example.com").await?;
    let repo = ApiTokenRepo::new(env.pool.clone());
    let svc = build_service(repo.clone(), cache());

    let issued = svc
        .issue(IssueApiTokenInput {
            caller_user_id: user,
            caller_org_id: org,
            request: CreateApiTokenRequest {
                display_name: "to-revoke".into(),
                scopes: vec![],
                expires_at: None,
            },
            correlation_id: Uuid::now_v7(),
        })
        .await?;

    // First revoke succeeds.
    svc.revoke(user, org, issued.token.id, Uuid::now_v7())
        .await?;

    // Second revoke is idempotent: row no longer in caller's live
    // list, so the service returns TokenNotFound.
    let err = svc
        .revoke(user, org, issued.token.id, Uuid::now_v7())
        .await
        .expect_err("double revoke must 404");
    assert!(matches!(err, IdentityError::TokenNotFound));

    // Confirm the row's revoked_at is non-null at the storage level.
    let row = sqlx::query!(
        "SELECT revoked_at FROM api_tokens WHERE id = $1",
        issued.token.id
    )
    .fetch_one(env.db.migrate_pool())
    .await?;
    assert!(row.revoked_at.is_some());
    Ok(())
}

#[tokio::test]
#[serial]
async fn revoke_other_user_token_returns_token_not_found() -> TestResult {
    let env = migrated_env().await?;
    let org = seed_org(&env.pool, "rev-cross").await?;
    let alice = seed_user(&env.pool, "rev-alice@example.com").await?;
    let bob = seed_user(&env.pool, "rev-bob@example.com").await?;
    let svc = build_service(ApiTokenRepo::new(env.pool.clone()), cache());

    let issued = svc
        .issue(IssueApiTokenInput {
            caller_user_id: alice,
            caller_org_id: org,
            request: CreateApiTokenRequest {
                display_name: "alice-pat".into(),
                scopes: vec![],
                expires_at: None,
            },
            correlation_id: Uuid::now_v7(),
        })
        .await?;

    let err = svc
        .revoke(bob, org, issued.token.id, Uuid::now_v7())
        .await
        .expect_err("cross-user revoke must 404");
    assert!(matches!(err, IdentityError::TokenNotFound));
    Ok(())
}

// ---------------------------------------------------------------------
// Resolver: bearer auth round trip
// ---------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn resolver_round_trips_to_auth_context() -> TestResult {
    let env = migrated_env().await?;
    let org = seed_org(&env.pool, "rs-org").await?;
    let user = seed_user(&env.pool, "rs@example.com").await?;
    let repo = ApiTokenRepo::new(env.pool.clone());
    let cache = cache();
    let svc = build_service(repo.clone(), cache.clone());
    let (resolver, _rx) = build_resolver(&env, cache, allow_always());

    let issued = svc
        .issue(IssueApiTokenInput {
            caller_user_id: user,
            caller_org_id: org,
            request: CreateApiTokenRequest {
                display_name: "bearer".into(),
                scopes: vec!["tokens:read".into(), "me:read".into()],
                expires_at: None,
            },
            correlation_id: Uuid::now_v7(),
        })
        .await?;

    let ctx = resolver
        .resolve(&issued.raw_token)
        .await
        .expect("valid PAT must resolve");
    assert_eq!(ctx.subject_id(), user);
    assert_eq!(ctx.org_id(), org);
    assert_eq!(ctx.session_id(), issued.token.id);
    assert_eq!(ctx.auth_method(), AuthMethod::ApiToken);
    assert_eq!(ctx.token_class(), TokenClass::PersonalAccessToken);
    assert!(ctx.has_scope("tokens:read"));
    assert!(ctx.has_scope("me:read"));
    assert!(!ctx.has_scope("tokens:write"));
    Ok(())
}

#[tokio::test]
#[serial]
async fn resolver_rejects_revoked_token() -> TestResult {
    let env = migrated_env().await?;
    let org = seed_org(&env.pool, "rev-rs").await?;
    let user = seed_user(&env.pool, "rev-rs@example.com").await?;
    let repo = ApiTokenRepo::new(env.pool.clone());
    let cache = cache();
    let svc = build_service(repo.clone(), cache.clone());
    let (resolver, _rx) = build_resolver(&env, cache, allow_always());

    let issued = svc
        .issue(IssueApiTokenInput {
            caller_user_id: user,
            caller_org_id: org,
            request: CreateApiTokenRequest {
                display_name: "to-revoke".into(),
                scopes: vec![],
                expires_at: None,
            },
            correlation_id: Uuid::now_v7(),
        })
        .await?;
    svc.revoke(user, org, issued.token.id, Uuid::now_v7())
        .await?;

    let err = resolver
        .resolve(&issued.raw_token)
        .await
        .expect_err("revoked PAT must reject");
    // The unique partial index masks revoked rows from
    // `find_live_by_token_hash`; the resolver therefore returns
    // Unauthorized rather than Revoked. Either is acceptable per the
    // gateway-facing contract — both render as 401.
    assert!(matches!(err, AuthError::Unauthorized | AuthError::Revoked));
    Ok(())
}

#[tokio::test]
#[serial]
async fn resolver_rejects_expired_token() -> TestResult {
    let env = migrated_env().await?;
    let org = seed_org(&env.pool, "exp-rs").await?;
    let user = seed_user(&env.pool, "exp@example.com").await?;

    // Insert directly so we can land an `expires_at` in the past
    // (the service-layer validator forbids past expiry).
    let raw = mint(TokenPrefix::Pat);
    let h = hash_token(&raw);
    let id = Uuid::now_v7();
    sqlx::query!(
        r"INSERT INTO api_tokens (id, token_hash, user_id, org_id, display_name, scopes, expires_at)
          VALUES ($1, $2, $3, $4, 'expired', '{}', $5)",
        id,
        h.as_slice(),
        user,
        org,
        Utc::now() - TimeDelta::hours(1),
    )
    .execute(env.db.migrate_pool())
    .await?;

    let (resolver, _rx) = build_resolver(&env, cache(), allow_always());
    let err = resolver
        .resolve(&raw)
        .await
        .expect_err("expired PAT must reject");
    assert!(matches!(err, AuthError::Expired | AuthError::Unauthorized));
    Ok(())
}

#[tokio::test]
#[serial]
async fn resolver_rejects_malformed_prefix_without_db_touch() -> TestResult {
    let env = migrated_env().await?;
    let (resolver, _rx) = build_resolver(&env, cache(), allow_always());

    let err = resolver
        .resolve("xxx_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        .await
        .expect_err("unknown prefix must reject");
    assert!(matches!(err, AuthError::MalformedPrefix));

    let err = resolver
        .resolve("sid_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        .await
        .expect_err("session prefix must not resolve via PAT path");
    assert!(matches!(err, AuthError::MalformedPrefix));
    Ok(())
}

#[tokio::test]
#[serial]
async fn resolver_rejects_token_after_user_soft_delete_cascade() -> TestResult {
    let env = migrated_env().await?;
    let org = seed_org(&env.pool, "cas-u").await?;
    let user = seed_user(&env.pool, "cas-u@example.com").await?;
    let repo = ApiTokenRepo::new(env.pool.clone());
    let cache = cache();
    let svc = build_service(repo.clone(), cache.clone());
    let (resolver, _rx) = build_resolver(&env, cache, allow_always());

    let issued = svc
        .issue(IssueApiTokenInput {
            caller_user_id: user,
            caller_org_id: org,
            request: CreateApiTokenRequest {
                display_name: "cas".into(),
                scopes: vec![],
                expires_at: None,
            },
            correlation_id: Uuid::now_v7(),
        })
        .await?;

    // Apply the user soft-delete cascade — the cascade revokes the
    // user's PATs in the same transaction.
    let mut tx = env.pool.begin().await?;
    // The user cascade touches tenanted rows; as zagrosi_app it needs
    // org context (cross-org purge is the maintenance role's job).
    zagrosi_identity::repo::with_org_context(&mut tx, org).await?;
    soft_delete_user(&mut tx, user).await?;
    tx.commit().await?;

    let err = resolver
        .resolve(&issued.raw_token)
        .await
        .expect_err("post-cascade PAT must reject");
    assert!(matches!(err, AuthError::Unauthorized | AuthError::Revoked));
    Ok(())
}

#[tokio::test]
#[serial]
async fn resolver_rejects_token_after_org_soft_delete_cascade() -> TestResult {
    let env = migrated_env().await?;
    let org = seed_org(&env.pool, "cas-o").await?;
    let user = seed_user(&env.pool, "cas-o@example.com").await?;
    let repo = ApiTokenRepo::new(env.pool.clone());
    let cache = cache();
    let svc = build_service(repo.clone(), cache.clone());
    let (resolver, _rx) = build_resolver(&env, cache, allow_always());

    let issued = svc
        .issue(IssueApiTokenInput {
            caller_user_id: user,
            caller_org_id: org,
            request: CreateApiTokenRequest {
                display_name: "cas".into(),
                scopes: vec![],
                expires_at: None,
            },
            correlation_id: Uuid::now_v7(),
        })
        .await?;

    let mut tx = env.pool.begin().await?;
    soft_delete_org(&mut tx, org).await?;
    tx.commit().await?;

    let err = resolver
        .resolve(&issued.raw_token)
        .await
        .expect_err("post-org-cascade PAT must reject");
    assert!(matches!(err, AuthError::Unauthorized | AuthError::Revoked));
    Ok(())
}

// ---------------------------------------------------------------------
// Resolver: cache + write-behind
// ---------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn cache_hit_returns_same_auth_context_as_db_read() -> TestResult {
    let env = migrated_env().await?;
    let org = seed_org(&env.pool, "cache-hit").await?;
    let user = seed_user(&env.pool, "cache-hit@example.com").await?;
    let repo = ApiTokenRepo::new(env.pool.clone());
    let cache = cache();
    let svc = build_service(repo.clone(), cache.clone());
    let (resolver, _rx) = build_resolver(&env, cache.clone(), allow_always());

    let issued = svc
        .issue(IssueApiTokenInput {
            caller_user_id: user,
            caller_org_id: org,
            request: CreateApiTokenRequest {
                display_name: "cached".into(),
                scopes: vec!["tokens:read".into()],
                expires_at: None,
            },
            correlation_id: Uuid::now_v7(),
        })
        .await?;

    let first = resolver.resolve(&issued.raw_token).await?;
    let second = resolver.resolve(&issued.raw_token).await?;
    assert_eq!(first.subject_id(), second.subject_id());
    assert_eq!(first.session_id(), second.session_id());
    assert_eq!(first.org_id(), second.org_id());
    assert_eq!(first.scopes(), second.scopes());

    // The freshly-resolved hash MUST be a cache hit on direct probe.
    let hash = hash_token(&issued.raw_token);
    assert!(
        cache.get(&hash).await.is_some(),
        "post-resolve cache lookup must hit",
    );
    Ok(())
}

#[tokio::test]
#[serial]
async fn revocation_evicts_cache_entry() -> TestResult {
    let env = migrated_env().await?;
    let org = seed_org(&env.pool, "cache-rev").await?;
    let user = seed_user(&env.pool, "cache-rev@example.com").await?;
    let repo = ApiTokenRepo::new(env.pool.clone());
    let cache = cache();
    let svc = build_service(repo.clone(), cache.clone());
    let (resolver, _rx) = build_resolver(&env, cache.clone(), allow_always());

    let issued = svc
        .issue(IssueApiTokenInput {
            caller_user_id: user,
            caller_org_id: org,
            request: CreateApiTokenRequest {
                display_name: "evict".into(),
                scopes: vec![],
                expires_at: None,
            },
            correlation_id: Uuid::now_v7(),
        })
        .await?;

    // Prime cache.
    resolver.resolve(&issued.raw_token).await?;
    let hash = hash_token(&issued.raw_token);
    assert!(
        cache.get(&hash).await.is_some(),
        "post-resolve cache lookup must hit",
    );

    svc.revoke(user, org, issued.token.id, Uuid::now_v7())
        .await?;
    // Allow moka's async eviction listener to settle.
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        cache.get(&hash).await.is_none(),
        "post-revoke cache lookup must miss",
    );

    let err = resolver
        .resolve(&issued.raw_token)
        .await
        .expect_err("post-revoke resolve must reject");
    assert!(matches!(err, AuthError::Unauthorized | AuthError::Revoked));
    Ok(())
}

#[tokio::test]
#[serial]
async fn write_behind_drain_persists_last_used_columns() -> TestResult {
    let env = migrated_env().await?;
    let org = seed_org(&env.pool, "wb-org").await?;
    let user = seed_user(&env.pool, "wb@example.com").await?;
    let repo = ApiTokenRepo::new(env.pool.clone());
    let cache = cache();
    let svc = build_service(repo.clone(), cache.clone());
    let (resolver, mut rx) = build_resolver(&env, cache, allow_always());

    let issued = svc
        .issue(IssueApiTokenInput {
            caller_user_id: user,
            caller_org_id: org,
            request: CreateApiTokenRequest {
                display_name: "wb".into(),
                scopes: vec![],
                expires_at: None,
            },
            correlation_id: Uuid::now_v7(),
        })
        .await?;

    // Resolve with an observed IP so the channel carries it.
    let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 7));
    resolver
        .resolve_with_observation(&issued.raw_token, Some(ip))
        .await?;

    // Drain — single event in the batch.
    let drained = drain_once(&mut rx, &repo, 16).await;
    assert_eq!(drained, 1);

    let row = sqlx::query!(
        "SELECT last_used_at, last_used_ip FROM api_tokens WHERE id = $1",
        issued.token.id
    )
    .fetch_one(env.db.migrate_pool())
    .await?;
    assert!(row.last_used_at.is_some());
    assert_eq!(row.last_used_ip.map(|n| n.ip()), Some(ip));
    Ok(())
}

#[tokio::test]
#[serial]
async fn write_behind_coalesces_repeats_within_window() -> TestResult {
    let env = migrated_env().await?;
    let org = seed_org(&env.pool, "wb-c").await?;
    let user = seed_user(&env.pool, "wb-c@example.com").await?;
    let repo = ApiTokenRepo::new(env.pool.clone());
    let cache = cache();
    let svc = build_service(repo.clone(), cache.clone());
    let (resolver, mut rx) = build_resolver(&env, cache, allow_always());

    let issued = svc
        .issue(IssueApiTokenInput {
            caller_user_id: user,
            caller_org_id: org,
            request: CreateApiTokenRequest {
                display_name: "wb-c".into(),
                scopes: vec![],
                expires_at: None,
            },
            correlation_id: Uuid::now_v7(),
        })
        .await?;

    // Five quick resolves of the same PAT — coalesce window is 60s
    // so the drain should issue exactly one UPDATE.
    for _ in 0..5 {
        resolver.resolve(&issued.raw_token).await?;
    }
    let drained = drain_once(&mut rx, &repo, 64).await;
    assert_eq!(
        drained, 1,
        "five resolves of same PAT must coalesce to one UPDATE"
    );
    Ok(())
}

// ---------------------------------------------------------------------
// Resolver: rate limit
// ---------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn rate_limited_resolve_returns_rate_limited_error() -> TestResult {
    let env = migrated_env().await?;
    let org = seed_org(&env.pool, "rl-org").await?;
    let user = seed_user(&env.pool, "rl@example.com").await?;
    let repo = ApiTokenRepo::new(env.pool.clone());
    let svc = build_service(repo.clone(), cache());

    let issued = svc
        .issue(IssueApiTokenInput {
            caller_user_id: user,
            caller_org_id: org,
            request: CreateApiTokenRequest {
                display_name: "rl".into(),
                scopes: vec![],
                expires_at: None,
            },
            correlation_id: Uuid::now_v7(),
        })
        .await?;

    let (resolver, _rx) = build_resolver(&env, cache(), Arc::new(DenyAlwaysRateLimiter));
    let err = resolver
        .resolve(&issued.raw_token)
        .await
        .expect_err("denying limiter must return RateLimited");
    assert!(matches!(err, AuthError::RateLimited { .. }));
    Ok(())
}

#[tokio::test]
#[serial]
async fn rate_limit_runs_on_cache_hit_too() -> TestResult {
    let env = migrated_env().await?;
    let org = seed_org(&env.pool, "rl-cache").await?;
    let user = seed_user(&env.pool, "rl-cache@example.com").await?;
    let repo = ApiTokenRepo::new(env.pool.clone());
    let cache = cache();
    let svc = build_service(repo.clone(), cache.clone());

    let issued = svc
        .issue(IssueApiTokenInput {
            caller_user_id: user,
            caller_org_id: org,
            request: CreateApiTokenRequest {
                display_name: "rl-c".into(),
                scopes: vec![],
                expires_at: None,
            },
            correlation_id: Uuid::now_v7(),
        })
        .await?;

    // Budget = 2: first two succeed; the third must trip even
    // though the entry is cache-hot.
    let limiter = Arc::new(CountingRateLimiter::new(2));
    let (resolver, _rx) = build_resolver(&env, cache, limiter);

    resolver.resolve(&issued.raw_token).await?;
    resolver.resolve(&issued.raw_token).await?;
    let err = resolver
        .resolve(&issued.raw_token)
        .await
        .expect_err("third call must trip rate limit");
    assert!(matches!(err, AuthError::RateLimited { .. }));
    Ok(())
}

// ---------------------------------------------------------------------
// Audit-event capture
// ---------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn audit_emits_api_token_created_and_revoked() -> TestResult {
    use zagrosi_core::AuditEventKind;

    let env = migrated_env().await?;
    let org = seed_org(&env.pool, "audit-org").await?;
    let user = seed_user(&env.pool, "audit@example.com").await?;
    let repo = ApiTokenRepo::new(env.pool.clone());
    let auditor = Arc::new(CapturingAuditor::default());
    let svc = ApiTokenService::new(repo, cache(), auditor.clone());

    let issued = svc
        .issue(IssueApiTokenInput {
            caller_user_id: user,
            caller_org_id: org,
            request: CreateApiTokenRequest {
                display_name: "audited".into(),
                scopes: vec!["tokens:read".into()],
                expires_at: None,
            },
            correlation_id: Uuid::now_v7(),
        })
        .await?;
    svc.revoke(user, org, issued.token.id, Uuid::now_v7())
        .await?;

    let events = auditor.events().await;
    let kinds: Vec<AuditEventKind> = events
        .iter()
        .filter_map(|e| match e {
            AuditEvent::V1(v) => Some(v.event_kind()),
            _ => None,
        })
        .collect();
    assert!(kinds.contains(&AuditEventKind::ApiTokenCreated));
    assert!(kinds.contains(&AuditEventKind::ApiTokenRevoked));
    Ok(())
}

// ---------------------------------------------------------------------
// Introspector dispatch
// ---------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn introspector_dispatches_pat_to_resolver() -> TestResult {
    let env = migrated_env().await?;
    let org = seed_org(&env.pool, "intro").await?;
    let user = seed_user(&env.pool, "intro@example.com").await?;
    let repo = ApiTokenRepo::new(env.pool.clone());
    let pat_cache = cache();
    let svc = build_service(repo.clone(), pat_cache.clone());

    let issued = svc
        .issue(IssueApiTokenInput {
            caller_user_id: user,
            caller_org_id: org,
            request: CreateApiTokenRequest {
                display_name: "intro".into(),
                scopes: vec!["tokens:read".into()],
                expires_at: None,
            },
            correlation_id: Uuid::now_v7(),
        })
        .await?;

    let (last_used_tx, _last_used_rx) = api_token_last_used_channel(CHANNEL_CAPACITY);
    // Auth-path lookups ride the auth pool (section-05).
    let resolver = ApiTokenResolver::new(
        ApiTokenRepo::new(env.db.auth_pool().clone()),
        pat_cache,
        last_used_tx,
        allow_always(),
    );

    let session_repo = SessionRepo::new(env.pool.clone());
    let user_repo = UserRepo::new(env.pool.clone());
    let session_cache = IdSessionCache::new(CACHE_CAPACITY, HEALTHY_TTL);
    let (session_last_seen, _session_rx) = session_last_seen_channel(CHANNEL_CAPACITY);
    let introspector =
        IdentitySessionIntrospector::new(session_repo, user_repo, session_cache, session_last_seen)
            .with_api_token_resolver(Arc::new(resolver));

    let ctx = introspector.resolve(&issued.raw_token).await?;
    assert_eq!(ctx.token_class(), TokenClass::PersonalAccessToken);
    assert_eq!(ctx.auth_method(), AuthMethod::ApiToken);
    assert_eq!(ctx.subject_id(), user);
    assert_eq!(ctx.org_id(), org);
    assert!(ctx.has_scope("tokens:read"));
    Ok(())
}

#[tokio::test]
#[serial]
async fn introspector_without_pat_resolver_rejects_pat_prefix() -> TestResult {
    let env = migrated_env().await?;
    let session_repo = SessionRepo::new(env.pool.clone());
    let user_repo = UserRepo::new(env.pool.clone());
    let session_cache = IdSessionCache::new(CACHE_CAPACITY, HEALTHY_TTL);
    let (session_last_seen, _session_rx) = session_last_seen_channel(CHANNEL_CAPACITY);
    let introspector =
        IdentitySessionIntrospector::new(session_repo, user_repo, session_cache, session_last_seen);

    let raw = mint(TokenPrefix::Pat);
    let err = introspector
        .resolve(&raw)
        .await
        .expect_err("pat without wired resolver must reject");
    assert!(matches!(err, AuthError::MalformedPrefix));
    Ok(())
}

// ---------------------------------------------------------------------
// Cache generation guard
// ---------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn cache_insert_with_guard_drops_after_eviction_bumps_generation() -> TestResult {
    use zagrosi_identity::api_tokens::CachedApiToken;
    use zagrosi_identity::domain::TokenHash;

    let cache = ApiTokenCache::new(8, Duration::from_secs(30));
    let token_id = Uuid::from_bytes([9; 16]);
    let hash = TokenHash([0xAB; 32]);
    let value = CachedApiToken {
        token_id,
        user_id: Uuid::from_bytes([1; 16]),
        org_id: Uuid::from_bytes([2; 16]),
        scopes: vec![],
        expires_at: None,
        revoked_at: None,
        created_at: Utc::now(),
    };

    let snapshot_before_revoke = cache.current_generation(token_id);
    cache.bump_generation(token_id);
    let inserted = cache
        .insert_with_guard(hash, value.clone(), snapshot_before_revoke)
        .await;
    assert!(
        !inserted,
        "stale snapshot must reject insert after a generation bump",
    );
    assert!(
        cache.get(&hash).await.is_none(),
        "no cache entry must exist when guard rejects insert",
    );
    Ok(())
}

#[tokio::test]
#[serial]
async fn cache_insert_with_guard_admits_when_generation_unchanged() -> TestResult {
    use zagrosi_identity::api_tokens::CachedApiToken;
    use zagrosi_identity::domain::TokenHash;

    let cache = ApiTokenCache::new(8, Duration::from_secs(30));
    let token_id = Uuid::from_bytes([10; 16]);
    let hash = TokenHash([0xCD; 32]);
    let value = CachedApiToken {
        token_id,
        user_id: Uuid::from_bytes([1; 16]),
        org_id: Uuid::from_bytes([2; 16]),
        scopes: vec!["tokens:read".into()],
        expires_at: None,
        revoked_at: None,
        created_at: Utc::now(),
    };

    let snapshot = cache.current_generation(token_id);
    let inserted = cache.insert_with_guard(hash, value.clone(), snapshot).await;
    assert!(inserted, "matching snapshot must admit the insert");
    assert!(cache.get(&hash).await.is_some());
    Ok(())
}

// ---------------------------------------------------------------------
// `revoke` race + audit semantics
// ---------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn concurrent_revoke_emits_single_audit_event() -> TestResult {
    use zagrosi_core::AuditEventKind;

    let env = migrated_env().await?;
    let org = seed_org(&env.pool, "race-rev").await?;
    let user = seed_user(&env.pool, "race@example.com").await?;
    let repo = ApiTokenRepo::new(env.pool.clone());
    let auditor = Arc::new(CapturingAuditor::default());
    let svc = ApiTokenService::new(repo, cache(), auditor.clone());

    let issued = svc
        .issue(IssueApiTokenInput {
            caller_user_id: user,
            caller_org_id: org,
            request: CreateApiTokenRequest {
                display_name: "race".into(),
                scopes: vec![],
                expires_at: None,
            },
            correlation_id: Uuid::now_v7(),
        })
        .await?;

    // Two concurrent revocations of the same PAT. Only one should
    // mutate the row and emit `ApiTokenRevoked`.
    let svc_a = svc.clone();
    let svc_b = svc.clone();
    let id = issued.token.id;
    let handle_a = tokio::spawn(async move { svc_a.revoke(user, org, id, Uuid::now_v7()).await });
    let handle_b = tokio::spawn(async move { svc_b.revoke(user, org, id, Uuid::now_v7()).await });
    let res_a = handle_a.await.unwrap();
    let res_b = handle_b.await.unwrap();

    let successes = [&res_a, &res_b].iter().filter(|r| r.is_ok()).count();
    let failures = [&res_a, &res_b].iter().filter(|r| r.is_err()).count();
    assert_eq!(successes, 1, "exactly one revoke must succeed");
    assert_eq!(failures, 1, "the loser must surface TokenNotFound");

    let events = auditor.events().await;
    let revoke_count = events
        .iter()
        .filter(|e| match e {
            AuditEvent::V1(v) => v.event_kind() == AuditEventKind::ApiTokenRevoked,
            _ => false,
        })
        .count();
    assert_eq!(
        revoke_count, 1,
        "exactly one ApiTokenRevoked event must be emitted",
    );
    Ok(())
}

// ---------------------------------------------------------------------
// `last_used_at` monotonicity
// ---------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn last_used_update_is_monotonic_under_late_event() -> TestResult {
    use zagrosi_identity::repo::OrgScoped;

    let env = migrated_env().await?;
    let org = seed_org(&env.pool, "mono").await?;
    let user = seed_user(&env.pool, "mono@example.com").await?;
    let repo = ApiTokenRepo::new(env.pool.clone());
    let svc = build_service(repo.clone(), cache());

    let issued = svc
        .issue(IssueApiTokenInput {
            caller_user_id: user,
            caller_org_id: org,
            request: CreateApiTokenRequest {
                display_name: "mono".into(),
                scopes: vec![],
                expires_at: None,
            },
            correlation_id: Uuid::now_v7(),
        })
        .await?;

    let scoped = OrgScoped::new(&repo, org);
    let later = Utc::now();
    let earlier = later - TimeDelta::seconds(120);
    let later_ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 9));
    let earlier_ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1));

    // Land the newer write first, then a late older write. The
    // older write must NOT overwrite the newer timestamp / IP.
    scoped
        .update_last_used(issued.token.id, later, Some(later_ip))
        .await?;
    scoped
        .update_last_used(issued.token.id, earlier, Some(earlier_ip))
        .await?;

    let row = sqlx::query!(
        "SELECT last_used_at, last_used_ip FROM api_tokens WHERE id = $1",
        issued.token.id,
    )
    .fetch_one(env.db.migrate_pool())
    .await?;
    let stored_at = row.last_used_at.expect("last_used_at populated");
    assert_eq!(
        stored_at.timestamp(),
        later.timestamp(),
        "later timestamp must win",
    );
    assert_eq!(row.last_used_ip.map(|n| n.ip()), Some(later_ip));
    Ok(())
}

// ---------------------------------------------------------------------
// Service-level GET surfaces revoked tokens (spec §157)
// ---------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn service_get_returns_row_with_revoked_at_set() -> TestResult {
    let env = migrated_env().await?;
    let org = seed_org(&env.pool, "get-rev").await?;
    let user = seed_user(&env.pool, "getrev@example.com").await?;
    let repo = ApiTokenRepo::new(env.pool.clone());
    let svc = build_service(repo, cache());

    let issued = svc
        .issue(IssueApiTokenInput {
            caller_user_id: user,
            caller_org_id: org,
            request: CreateApiTokenRequest {
                display_name: "get-rev".into(),
                scopes: vec![],
                expires_at: None,
            },
            correlation_id: Uuid::now_v7(),
        })
        .await?;
    svc.revoke(user, org, issued.token.id, Uuid::now_v7())
        .await?;

    let view = svc.get(user, org, issued.token.id).await?;
    assert!(
        view.revoked_at.is_some(),
        "GET on revoked PAT must surface the revocation timestamp (spec §157)",
    );
    assert_eq!(view.id, issued.token.id);
    Ok(())
}

// ---------------------------------------------------------------------
// HTTP harness + handler-level integration
// ---------------------------------------------------------------------

fn pat_auth_ctx(user: Uuid, token_id: Uuid, org: Uuid, scopes: Vec<String>) -> AuthContext {
    let now = Utc::now();
    AuthContext::new(
        user,
        token_id,
        org,
        AuthMethod::ApiToken,
        TokenClass::PersonalAccessToken,
        vec!["pat".into()],
        None,
        now,
        now + chrono::Duration::hours(1),
        Uuid::now_v7(),
    )
    .expect("build pat AuthContext")
    .with_scopes(scopes)
}

fn build_http_app(svc: Arc<ApiTokenService>) -> Router<()> {
    api_tokens_router(ApiTokensState::new(svc))
}

async fn http_send(
    app: Router<()>,
    mut req: Request<Body>,
    ctx: AuthContext,
) -> (StatusCode, Value) {
    req.extensions_mut().insert(ctx);
    let resp = app.oneshot(req).await.expect("router oneshot");
    let status = resp.status();
    let bytes = resp
        .into_body()
        .collect()
        .await
        .expect("collect body")
        .to_bytes();
    let body: Value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, body)
}

#[tokio::test]
#[serial]
async fn http_post_returns_201_with_raw_token_and_get_omits_token() -> TestResult {
    let env = migrated_env().await?;
    let org = seed_org(&env.pool, "http-post").await?;
    let user = seed_user(&env.pool, "http-post@example.com").await?;
    let svc = Arc::new(build_service(ApiTokenRepo::new(env.pool.clone()), cache()));

    // POST /v1/api-tokens through a session-cookie-authenticated
    // caller (scopes don't apply for sessions). The bearer-token id
    // in the AuthContext is unused for the POST path.
    let session_ctx = AuthContext::new(
        user,
        Uuid::now_v7(),
        org,
        AuthMethod::Password,
        TokenClass::Session,
        vec!["pwd".into()],
        None,
        Utc::now(),
        Utc::now() + chrono::Duration::hours(1),
        Uuid::now_v7(),
    )
    .expect("session ctx");

    let post_body = serde_json::json!({
        "display_name": "ci-bot",
        "scopes": ["tokens:read"],
    });
    let post_req = Request::builder()
        .method("POST")
        .uri("/v1/api-tokens")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&post_body)?))?;
    let (status, body) =
        http_send(build_http_app(svc.clone()), post_req, session_ctx.clone()).await;
    assert_eq!(status, StatusCode::CREATED);
    assert!(
        body.get("token").is_some(),
        "POST /v1/api-tokens response MUST carry the raw token"
    );
    let token_id: Uuid = body["id"].as_str().unwrap().parse()?;

    // GET /v1/api-tokens/{id} must omit the `token` field.
    let get_req = Request::builder()
        .method("GET")
        .uri(format!("/v1/api-tokens/{token_id}"))
        .body(Body::empty())?;
    let (status, body) = http_send(build_http_app(svc), get_req, session_ctx).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.get("token").is_none(),
        "GET response MUST NOT carry the raw token",
    );
    assert_eq!(body["display_name"], "ci-bot");
    Ok(())
}

#[tokio::test]
#[serial]
async fn http_pat_caller_without_scope_returns_403_insufficient_scope() -> TestResult {
    let env = migrated_env().await?;
    let org = seed_org(&env.pool, "http-403").await?;
    let user = seed_user(&env.pool, "http-403@example.com").await?;
    let repo = ApiTokenRepo::new(env.pool.clone());
    let svc = Arc::new(build_service(repo.clone(), cache()));

    // PAT bearer with only `me:read` (missing tokens:write for POST).
    let issued = svc
        .issue(IssueApiTokenInput {
            caller_user_id: user,
            caller_org_id: org,
            request: CreateApiTokenRequest {
                display_name: "limited".into(),
                scopes: vec!["me:read".into()],
                expires_at: None,
            },
            correlation_id: Uuid::now_v7(),
        })
        .await?;
    let pat_ctx = pat_auth_ctx(user, issued.token.id, org, vec!["me:read".into()]);

    let post_body = serde_json::json!({
        "display_name": "should-fail",
        "scopes": [],
    });
    let post_req = Request::builder()
        .method("POST")
        .uri("/v1/api-tokens")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&post_body)?))?;
    let (status, body) = http_send(build_http_app(svc), post_req, pat_ctx).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"]["code"], "insufficient_scope");
    Ok(())
}

#[tokio::test]
#[serial]
async fn http_self_revoke_succeeds_then_resolve_returns_unauthorized() -> TestResult {
    let env = migrated_env().await?;
    let org = seed_org(&env.pool, "self-rev").await?;
    let user = seed_user(&env.pool, "selfrev@example.com").await?;
    let repo = ApiTokenRepo::new(env.pool.clone());
    let pat_cache = cache();
    let svc = Arc::new(build_service(repo.clone(), pat_cache.clone()));
    let (resolver, _rx) = build_resolver(&env, pat_cache, allow_always());

    let issued = svc
        .issue(IssueApiTokenInput {
            caller_user_id: user,
            caller_org_id: org,
            request: CreateApiTokenRequest {
                display_name: "self-killer".into(),
                scopes: vec!["tokens:write".into()],
                expires_at: None,
            },
            correlation_id: Uuid::now_v7(),
        })
        .await?;

    // Resolver works pre-revoke.
    resolver.resolve(&issued.raw_token).await?;

    // Self-revoke via HTTP DELETE with the same token's auth ctx.
    let pat_ctx = pat_auth_ctx(user, issued.token.id, org, vec!["tokens:write".into()]);
    let delete_req = Request::builder()
        .method("DELETE")
        .uri(format!("/v1/api-tokens/{}", issued.token.id))
        .body(Body::empty())?;
    let (status, _body) = http_send(build_http_app(svc), delete_req, pat_ctx).await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // Resolver now refuses the same token (cache evicted +
    // revoked_at set on the row).
    let err = resolver
        .resolve(&issued.raw_token)
        .await
        .expect_err("post-self-revoke resolve must reject");
    assert!(matches!(err, AuthError::Unauthorized | AuthError::Revoked));
    Ok(())
}

#[tokio::test]
#[serial]
async fn http_get_revoked_returns_revoked_at_field_set() -> TestResult {
    let env = migrated_env().await?;
    let org = seed_org(&env.pool, "http-get-rev").await?;
    let user = seed_user(&env.pool, "http-rev@example.com").await?;
    let svc = Arc::new(build_service(ApiTokenRepo::new(env.pool.clone()), cache()));

    let session_ctx = AuthContext::new(
        user,
        Uuid::now_v7(),
        org,
        AuthMethod::Password,
        TokenClass::Session,
        vec!["pwd".into()],
        None,
        Utc::now(),
        Utc::now() + chrono::Duration::hours(1),
        Uuid::now_v7(),
    )
    .expect("session ctx");

    let issued = svc
        .issue(IssueApiTokenInput {
            caller_user_id: user,
            caller_org_id: org,
            request: CreateApiTokenRequest {
                display_name: "viewable".into(),
                scopes: vec![],
                expires_at: None,
            },
            correlation_id: Uuid::now_v7(),
        })
        .await?;
    svc.revoke(user, org, issued.token.id, Uuid::now_v7())
        .await?;

    let req = Request::builder()
        .method("GET")
        .uri(format!("/v1/api-tokens/{}", issued.token.id))
        .body(Body::empty())?;
    let (status, body) = http_send(build_http_app(svc), req, session_ctx).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body["revoked_at"].is_string(),
        "GET on revoked PAT must surface revoked_at as ISO8601 string (spec §157)",
    );
    Ok(())
}

#[tokio::test]
#[serial]
async fn http_error_response_does_not_leak_bearer_or_db_artefact() -> TestResult {
    let env = migrated_env().await?;
    let org = seed_org(&env.pool, "leak").await?;
    let user = seed_user(&env.pool, "leak@example.com").await?;
    let svc = Arc::new(build_service(ApiTokenRepo::new(env.pool.clone()), cache()));

    let session_ctx = AuthContext::new(
        user,
        Uuid::now_v7(),
        org,
        AuthMethod::Password,
        TokenClass::Session,
        vec!["pwd".into()],
        None,
        Utc::now(),
        Utc::now() + chrono::Duration::hours(1),
        Uuid::now_v7(),
    )
    .expect("session ctx");

    // 404 path: GET a token that does not exist.
    let missing = Uuid::now_v7();
    let req = Request::builder()
        .method("GET")
        .uri(format!("/v1/api-tokens/{missing}"))
        .body(Body::empty())?;
    let (status, body) = http_send(build_http_app(svc.clone()), req, session_ctx.clone()).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let serialised = body.to_string();
    assert!(
        !serialised.contains("token_hash"),
        "404 body must not mention the token_hash column",
    );
    assert!(
        !serialised.contains("api_tokens"),
        "404 body must not mention the api_tokens table",
    );
    assert!(
        !serialised.contains("pat_"),
        "404 body must not echo any pat-prefixed token bytes",
    );
    Ok(())
}
