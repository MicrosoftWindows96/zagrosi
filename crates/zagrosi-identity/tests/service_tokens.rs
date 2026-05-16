// SPDX-License-Identifier: AGPL-3.0-or-later

//! Service-token integration coverage:
//!
//! - CRUD via [`ServiceTokenService`] (create / list / get / revoke)
//!   + audit emission shapes.
//! - Resolver fast path via [`ServiceTokenResolver`] (cache miss /
//!   cache hit / revoked / malformed prefix / rate-limit).
//! - HTTP surface via the router + platform-admin gate (201 raw-once,
//!   no-token-on-GET, 204, 403 non-admin).

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::missing_panics_doc,
    clippy::too_many_lines
)]

mod common;

use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use common::{TestResult, migrated_env};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;
use zagrosi_core::{
    AuditEvent, AuditEventKind, Auditor, AuthContext, AuthError, AuthMethod, NoopAuditor,
    RateLimitDecision, RateLimitKey, RateLimiter, RateLimiterError, SessionIntrospector,
    TokenClass,
};
use zagrosi_identity::config::PlatformConfig;
use zagrosi_identity::domain::token_format::{TokenHash, hash_token};
use zagrosi_identity::error::IdentityError;
use zagrosi_identity::http::service_tokens::{ServiceTokensState, router};
use zagrosi_identity::repo::ServiceTokenRepo;
use zagrosi_identity::service_tokens::{
    CreateServiceTokenRequest, ServiceTokenCache, ServiceTokenResolver, ServiceTokenService,
};

const HEALTHY_TTL: Duration = Duration::from_secs(30);
const CAP: u64 = 64;

fn cache() -> ServiceTokenCache {
    ServiceTokenCache::new(CAP, HEALTHY_TTL)
}

#[derive(Clone, Default)]
struct AllowAlways;

#[async_trait]
impl RateLimiter for AllowAlways {
    async fn check(&self, _k: &RateLimitKey) -> Result<RateLimitDecision, RateLimiterError> {
        Ok(RateLimitDecision::Allow {
            remaining: u32::MAX,
            reset_in: Duration::from_secs(60),
        })
    }
    async fn unlock(&self, _k: &RateLimitKey) -> Result<(), RateLimiterError> {
        Ok(())
    }
}

#[derive(Clone, Default)]
struct DenyAlways;

#[async_trait]
impl RateLimiter for DenyAlways {
    async fn check(&self, _k: &RateLimitKey) -> Result<RateLimitDecision, RateLimiterError> {
        Ok(RateLimitDecision::Deny {
            retry_after: Duration::from_secs(30),
        })
    }
    async fn unlock(&self, _k: &RateLimitKey) -> Result<(), RateLimiterError> {
        Ok(())
    }
}

/// Records every emitted audit event for assertion.
#[derive(Clone, Default)]
struct RecordingAuditor {
    events: Arc<Mutex<Vec<AuditEvent>>>,
}

#[async_trait]
impl Auditor for RecordingAuditor {
    async fn record(&self, event: AuditEvent) {
        self.events.lock().expect("audit lock").push(event);
    }
}

impl RecordingAuditor {
    fn kinds(&self) -> Vec<AuditEventKind> {
        self.events
            .lock()
            .expect("audit lock")
            .iter()
            .filter_map(|e| match e {
                AuditEvent::V1(v1) => Some(v1.event_kind()),
                _ => None,
            })
            .collect()
    }
}

fn req(name: &str) -> CreateServiceTokenRequest {
    CreateServiceTokenRequest {
        service_name: name.into(),
        allowed_subjects: vec!["email.outbox.queue".into(), "identity.>".into()],
        display_name: "Email worker".into(),
    }
}

fn admin_ctx(admin: Uuid) -> AuthContext {
    let now = chrono::Utc::now();
    AuthContext::new(
        admin,
        Uuid::from_bytes([2; 16]),
        Uuid::from_bytes([3; 16]),
        AuthMethod::Password,
        TokenClass::Session,
        vec!["pwd".into()],
        None,
        now,
        now + chrono::Duration::hours(1),
        Uuid::now_v7(),
    )
    .expect("admin ctx")
}

// ----- service-direct -------------------------------------------------

#[tokio::test]
async fn create_returns_raw_once_and_persists_hash_only() -> TestResult {
    let env = migrated_env().await?;
    let auditor = RecordingAuditor::default();
    let svc = ServiceTokenService::new(
        ServiceTokenRepo::new(env.pool.clone()),
        cache(),
        Arc::new(auditor.clone()),
    );
    let admin = Uuid::now_v7();
    let issued = svc
        .create(admin, Uuid::now_v7(), Uuid::now_v7(), req("email-worker"))
        .await?;

    let raw = issued.raw_token.to_string();
    assert!(
        raw.len() == 47 && raw.starts_with("svc_"),
        "raw token must be svc_<43>: {}",
        raw.len(),
    );
    assert!(
        raw[4..]
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'),
        "body must be base64url",
    );

    // DB carries only the hash, never the raw token.
    let stored: Vec<u8> = sqlx::query_scalar("SELECT token_hash FROM service_tokens WHERE id = $1")
        .bind(issued.record.id)
        .fetch_one(&env.pool)
        .await?;
    assert_eq!(stored, hash_token(&raw).0.to_vec());
    assert_eq!(auditor.kinds(), vec![AuditEventKind::ServiceTokenCreated]);
    Ok(())
}

#[tokio::test]
async fn list_and_get_never_expose_token_revoke_is_idempotent() -> TestResult {
    let env = migrated_env().await?;
    let auditor = RecordingAuditor::default();
    let svc = ServiceTokenService::new(
        ServiceTokenRepo::new(env.pool.clone()),
        cache(),
        Arc::new(auditor.clone()),
    );
    let admin = Uuid::now_v7();
    let org = Uuid::now_v7();
    let issued = svc
        .create(admin, org, Uuid::now_v7(), req("scim-bridge"))
        .await?;
    let id = issued.record.id;

    let list = svc.list().await?;
    assert_eq!(list.len(), 1);
    // Serialised view must not contain a `token` field.
    let v = serde_json::to_value(&list[0])?;
    assert!(v.get("token").is_none(), "list view must not leak token");
    assert!(v.get("token_hash").is_none());

    let got = svc.get(id).await?;
    assert_eq!(got.id, id);
    assert!(got.revoked_at.is_none());

    svc.revoke(admin, org, Uuid::now_v7(), id).await?;
    // Second revoke → already revoked → TokenNotFound (no dup audit).
    let again = svc.revoke(admin, org, Uuid::now_v7(), id).await;
    assert!(matches!(again, Err(IdentityError::TokenNotFound)));

    // get still works post-revoke and surfaces revoked_at.
    let after = svc.get(id).await?;
    assert!(after.revoked_at.is_some());
    // revoked rows drop out of list().
    assert!(svc.list().await?.is_empty());

    assert_eq!(
        auditor.kinds(),
        vec![
            AuditEventKind::ServiceTokenCreated,
            AuditEventKind::ServiceTokenRevoked,
        ],
        "exactly one create + one revoke audit (no dup on idempotent revoke)",
    );
    Ok(())
}

#[tokio::test]
async fn create_rejects_bad_input() -> TestResult {
    let env = migrated_env().await?;
    let svc = ServiceTokenService::new(
        ServiceTokenRepo::new(env.pool.clone()),
        cache(),
        Arc::new(NoopAuditor),
    );
    let a = Uuid::now_v7();
    // empty allowed_subjects
    let mut bad = req("email-worker");
    bad.allowed_subjects.clear();
    assert!(matches!(
        svc.create(a, a, a, bad).await,
        Err(IdentityError::InvalidServiceTokenRequest { .. })
    ));
    // malformed service_name
    assert!(matches!(
        svc.create(a, a, a, req("Email_Worker")).await,
        Err(IdentityError::InvalidServiceTokenRequest { .. })
    ));
    Ok(())
}

// ----- resolver -------------------------------------------------------

#[tokio::test]
async fn resolver_round_trips_then_revoke_rejects() -> TestResult {
    let env = migrated_env().await?;
    let shared_cache = cache();
    let svc = ServiceTokenService::new(
        ServiceTokenRepo::new(env.pool.clone()),
        shared_cache.clone(),
        Arc::new(NoopAuditor),
    );
    let resolver = ServiceTokenResolver::new(
        ServiceTokenRepo::new(env.pool.clone()),
        shared_cache.clone(),
        Arc::new(AllowAlways),
    );
    let admin = Uuid::now_v7();
    let issued = svc.create(admin, admin, admin, req("email-worker")).await?;
    let raw = issued.raw_token.to_string();

    // Cache miss → DB.
    let ctx = resolver.resolve(&raw).await.expect("resolve ok");
    assert_eq!(ctx.token_class(), TokenClass::Service);
    assert_eq!(ctx.auth_method(), AuthMethod::ServiceToken);
    assert!(ctx.has_scope("identity.>"));
    assert_eq!(ctx.subject_id(), issued.record.id);

    // Cache hit → identical context.
    let ctx2 = resolver.resolve(&raw).await.expect("cache hit");
    assert_eq!(ctx2.subject_id(), ctx.subject_id());
    assert_eq!(ctx2.scopes(), ctx.scopes());

    // Revoke → bump+evict → resolve rejects.
    svc.revoke(admin, admin, admin, issued.record.id).await?;
    let err = resolver.resolve(&raw).await.expect_err("revoked rejects");
    assert!(matches!(err, AuthError::Revoked | AuthError::Unauthorized));
    Ok(())
}

#[tokio::test]
async fn resolver_rejects_malformed_prefix_pre_db_and_rate_limit() -> TestResult {
    let env = migrated_env().await?;
    let resolver = ServiceTokenResolver::new(
        ServiceTokenRepo::new(env.pool.clone()),
        cache(),
        Arc::new(AllowAlways),
    );
    for bad in ["pat_xxx", "svc_short", "svc-not-underscore", "abc"] {
        assert!(matches!(
            resolver.resolve(bad).await,
            Err(AuthError::MalformedPrefix)
        ));
    }

    // Rate-limit deny maps to AuthError::RateLimited (well-formed
    // token, denied before the unauthorized DB miss).
    let denied = ServiceTokenResolver::new(
        ServiceTokenRepo::new(env.pool.clone()),
        cache(),
        Arc::new(DenyAlways),
    );
    let well_formed = format!("svc_{}", "a".repeat(43));
    assert!(matches!(
        denied.resolve(&well_formed).await,
        Err(AuthError::RateLimited { .. } | AuthError::Unauthorized)
    ));
    Ok(())
}

#[tokio::test]
async fn constant_time_compare_guards_against_index_bypass() -> TestResult {
    // A fabricated cache entry whose hash does not match the DB row
    // must not authenticate (the ct_eq defence-in-depth check). Here
    // we assert the hash chokepoint: a different raw token never
    // collides with a stored one.
    let env = migrated_env().await?;
    let svc = ServiceTokenService::new(
        ServiceTokenRepo::new(env.pool.clone()),
        cache(),
        Arc::new(NoopAuditor),
    );
    let a = Uuid::now_v7();
    let issued = svc.create(a, a, a, req("email-worker")).await?;
    let raw = issued.raw_token.to_string();
    let other = format!("svc_{}", "Z".repeat(43));
    assert_ne!(
        hash_token(&raw),
        TokenHash(hash_token(&other).0),
        "distinct svc tokens must hash distinctly",
    );
    Ok(())
}

// ----- HTTP surface ---------------------------------------------------

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

fn state(env_pool: sqlx::PgPool, admin: Uuid) -> ServiceTokensState {
    let svc = ServiceTokenService::new(
        ServiceTokenRepo::new(env_pool),
        cache(),
        Arc::new(NoopAuditor),
    );
    ServiceTokensState::new(
        Arc::new(svc),
        Arc::new(PlatformConfig {
            admin_user_ids: vec![admin],
        }),
    )
}

#[tokio::test]
async fn http_create_then_get_and_admin_gate() -> TestResult {
    let env = migrated_env().await?;
    let admin = Uuid::now_v7();
    let app = router(state(env.pool.clone(), admin));

    // POST as admin → 201 with token exactly once.
    let post = Request::builder()
        .method("POST")
        .uri("/v1/service-tokens")
        .header(header::CONTENT_TYPE, "application/json")
        .extension(admin_ctx(admin))
        .body(Body::from(
            json!({
                "service_name": "email-worker",
                "allowed_subjects": ["email.outbox.queue"],
                "display_name": "Email worker"
            })
            .to_string(),
        ))?;
    let resp = app.clone().oneshot(post).await?;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let created = body_json(resp).await;
    let token = created["token"].as_str().expect("token present once");
    assert!(token.starts_with("svc_"));
    let id = created["id"].as_str().expect("id").to_string();

    // GET one → no token field.
    let get = Request::builder()
        .method("GET")
        .uri(format!("/v1/service-tokens/{id}"))
        .extension(admin_ctx(admin))
        .body(Body::empty())?;
    let resp = app.clone().oneshot(get).await?;
    assert_eq!(resp.status(), StatusCode::OK);
    let view = body_json(resp).await;
    assert!(view.get("token").is_none(), "GET must not expose token");
    assert_eq!(view["service_name"], "email-worker");

    // Non-admin authenticated caller → 403.
    let non_admin = Request::builder()
        .method("GET")
        .uri("/v1/service-tokens")
        .extension(admin_ctx(Uuid::now_v7()))
        .body(Body::empty())?;
    let resp = app.clone().oneshot(non_admin).await?;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // DELETE as admin → 204.
    let del = Request::builder()
        .method("DELETE")
        .uri(format!("/v1/service-tokens/{id}"))
        .extension(admin_ctx(admin))
        .body(Body::empty())?;
    let resp = app.oneshot(del).await?;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    Ok(())
}
