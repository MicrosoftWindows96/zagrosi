// SPDX-License-Identifier: AGPL-3.0-or-later

//! Sign-up + provisioning under enforced RLS as `zagrosi_app`.
//!
//! NOTE vs the section plan: password sign-up in this codebase creates a
//! USER only (`users` / `email_verifications` / `email_outbox` — all P5); no
//! org or membership row exists in that flow yet (org-creation +
//! creator→owner assignment arrive with the identity retrofit). The
//! signup test therefore pins the real flow end-to-end under RLS plus
//! the no-GUC-residue property; the membership-write-under-RLS proof
//! lives in `jit_provisioning_completes_as_app_role`, which exercises
//! the SCIM/JIT shape (org context set in-transaction before the
//! membership insert).
//!
//! Extension points: the rbac schema section adds root-node /
//! `org_permission_versions` assertions (SECURITY DEFINER trigger) here;
//! the identity retrofit adds the creator→`org_owner` assertion.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::IpAddr;
use std::sync::Arc;

use async_trait::async_trait;
use serial_test::serial;
use uuid::Uuid;
use zagrosi_core::{
    BreachCheck, BreachListClient, BreachListError, NoopAuditor, RateLimitDecision, RateLimitKey,
    RateLimiter, RateLimiterError,
};
use zagrosi_identity::config::{Argon2Config, BreachlistConfig, IdentityConfig, PasswordConfig};
use zagrosi_identity::password::Argon2idHasher;
use zagrosi_identity::repo::{with_org_context, with_user_context};
use zagrosi_identity::service::signup::SignUpRequest;
use zagrosi_identity::service::{IdentityService, IdentityServiceDeps};
use zagrosi_identity::session::{IssuedSession, SessionIssuer};
use zagrosi_test_support::{TestDb, seed_org};

type TestError = Box<dyn std::error::Error + Send + Sync>;
type TestResult = Result<(), TestError>;

#[derive(Default)]
struct FakeSessionIssuer;

#[async_trait]
impl SessionIssuer for FakeSessionIssuer {
    async fn issue_password_session(
        &self,
        user_id: Uuid,
        org_id: Option<Uuid>,
        amr: &[&str],
    ) -> zagrosi_identity::error::Result<IssuedSession> {
        let _ = (org_id, amr);
        Ok(IssuedSession {
            id: Uuid::now_v7(),
            user_id,
            org_id,
            raw_token: "sid_test".into(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
        })
    }
}

struct AlwaysCleanBreach;
#[async_trait]
impl BreachListClient for AlwaysCleanBreach {
    async fn check(&self, _password: &str) -> Result<BreachCheck, BreachListError> {
        Ok(BreachCheck::Clean)
    }
}

struct AllowAll;
#[async_trait]
impl RateLimiter for AllowAll {
    async fn check(&self, _key: &RateLimitKey) -> Result<RateLimitDecision, RateLimiterError> {
        Ok(RateLimitDecision::Allow {
            remaining: 100,
            reset_in: std::time::Duration::from_secs(60),
        })
    }
    async fn unlock(&self, _key: &RateLimitKey) -> Result<(), RateLimiterError> {
        Ok(())
    }
}

const fn fast_argon_cfg() -> Argon2Config {
    Argon2Config {
        m_cost: 8,
        t_cost: 1,
        p_cost: 1,
        max_concurrency: 4,
    }
}

async fn build_service(pool: sqlx::PgPool) -> Arc<IdentityService> {
    let mut config = IdentityConfig::default();
    config.secrets_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into();
    config.valkey_url = "redis://test:6379".into();
    config.argon2 = fast_argon_cfg();
    config.password = PasswordConfig {
        min_length: 12,
        max_length: 256,
    };
    config.breachlist = BreachlistConfig::default();
    config.email_token_ttl_minutes = 30;
    let hasher = Argon2idHasher::new(&fast_argon_cfg()).unwrap();
    let deps = IdentityServiceDeps {
        config,
        hasher,
        breach_client: Arc::new(AlwaysCleanBreach),
        auditor: Arc::new(NoopAuditor),
        session_issuer: Arc::new(FakeSessionIssuer),
        rate_limiter: Arc::new(AllowAll),
        pool,
        outbound_from_address: "noreply@example.test".into(),
        base_url: "https://rls.zagrosi.example".into(),
    };
    Arc::new(IdentityService::new(deps).await.unwrap())
}

fn ip() -> IpAddr {
    "203.0.113.10".parse().unwrap()
}

#[tokio::test]
#[serial]
async fn signup_completes_as_app_role() -> TestResult {
    let db = TestDb::new().await?;
    let svc = build_service(db.app_pool().clone()).await;

    svc.sign_up(SignUpRequest {
        email: "rls-one@example.test".into(),
        password: "correct-horse-battery-staple".into(),
        display_name: "RLS One".into(),
        ip: ip(),
        correlation_id: Uuid::now_v7(),
    })
    .await?;

    // A second, distinct sign-up on the SAME pool: no GUC residue from
    // the first (txn-scoped set_config + the RESET ALL release hook).
    svc.sign_up(SignUpRequest {
        email: "rls-two@example.test".into(),
        password: "correct-horse-battery-staple".into(),
        display_name: "RLS Two".into(),
        ip: ip(),
        correlation_id: Uuid::now_v7(),
    })
    .await?;

    let unset: bool =
        sqlx::query_scalar("SELECT NULLIF(current_setting('app.org_id', true), '') IS NULL")
            .fetch_one(db.app_pool())
            .await?;
    assert!(unset, "no app.org_id residue may survive a sign-up");

    let users: i64 =
        sqlx::query_scalar("SELECT count(*) FROM users WHERE email_lower LIKE 'rls-%'")
            .fetch_one(db.migrate_pool())
            .await?;
    assert_eq!(users, 2, "both sign-ups must have landed");
    Ok(())
}

#[tokio::test]
#[serial]
async fn jit_provisioning_completes_as_app_role() -> TestResult {
    // The SCIM/JIT shape: org context comes from the token/IdP and is
    // set in-transaction BEFORE the membership insert — the P2 WITH
    // CHECK admits the write; without the GUC it would refuse.
    let db = TestDb::new().await?;
    let org = seed_org(db.migrate_pool(), "jit-org").await?;
    let user_id = Uuid::now_v7();

    let mut tx = db.app_pool().begin().await?;
    with_org_context(&mut tx, org).await?;
    with_user_context(&mut tx, user_id).await?;
    sqlx::query("INSERT INTO users (id, email, display_name) VALUES ($1, $2, $3)")
        .bind(user_id)
        .bind("jit@example.test")
        .bind("JIT User")
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO user_org_memberships (id, user_id, org_id, joined_via, jit_provisioned_at)
         VALUES ($1, $2, $3, 'scim', now())",
    )
    .bind(Uuid::now_v7())
    .bind(user_id)
    .bind(org)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    let rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM user_org_memberships WHERE user_id = $1 AND org_id = $2",
    )
    .bind(user_id)
    .bind(org)
    .fetch_one(db.migrate_pool())
    .await?;
    assert_eq!(rows, 1, "JIT membership write must land under RLS");
    Ok(())
}
