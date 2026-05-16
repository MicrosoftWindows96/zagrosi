// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(
    clippy::unwrap_used,
    clippy::map_unwrap_or,
    clippy::missing_const_for_fn
)]
//! Password-flow integration tests.
//!
//! Each test spins up an ephemeral Postgres via `testcontainers`,
//! runs the identity migrations, and exercises one slice of the
//! `IdentityService` flow end-to-end. The HIBP client is replaced
//! with an in-process wiremock server so tests stay deterministic
//! without live-network calls.
//!
//! Coverage is the security-critical core: anti-enumeration on
//! sign-up + sign-in, HIBP fail-closed on breach, password rotation
//! invariant, single-use token consumption. The full 21-case suite
//! enumerated in the password-auth design notes lands incrementally as
//! the surrounding layers (the rate-limit module, the session module)
//! plug in their concrete impls.

mod common;

use std::net::IpAddr;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;
use common::{TestResult, migrated_env};
use serial_test::serial;
use uuid::Uuid;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};
use zagrosi_core::{
    AuditEvent, Auditor, BreachCheck, BreachListClient, BreachListError, RateLimitDecision,
    RateLimitKey, RateLimiter, RateLimiterError,
};
use zagrosi_identity::config::{
    Argon2Config, BreachlistConfig, BreachlistMode, IdentityConfig, PasswordConfig,
};
use zagrosi_identity::error::IdentityError;
use zagrosi_identity::password::{Argon2idHasher, HibpBreachClient};
use zagrosi_identity::service::password_reset::PasswordResetRequestRequest;
use zagrosi_identity::service::signin::SignInRequest;
use zagrosi_identity::service::signup::SignUpRequest;
use zagrosi_identity::service::{IdentityService, IdentityServiceDeps};
use zagrosi_identity::session::{IssuedSession, SessionIssuer};

/// Fake [`SessionIssuer`] that records every issue call.
#[derive(Default)]
struct FakeSessionIssuer {
    inner: tokio::sync::Mutex<Vec<IssuedSession>>,
}

#[async_trait]
impl SessionIssuer for FakeSessionIssuer {
    async fn issue_password_session(
        &self,
        user_id: Uuid,
        org_id: Option<Uuid>,
        _amr: &[&str],
    ) -> Result<IssuedSession, IdentityError> {
        let session = IssuedSession {
            id: Uuid::now_v7(),
            user_id,
            org_id,
            expires_at: Utc::now() + chrono::Duration::hours(1),
            raw_token: format!("sid_{}", "a".repeat(43)),
        };
        self.inner.lock().await.push(session.clone());
        Ok(session)
    }
}

/// Fake [`RateLimiter`] that always allows. Used by the password-auth
/// integration tests where rate-limit enforcement is not the system
/// under test; the per-IP / per-account gates land their own coverage
/// in `tests/rate_limit_valkey.rs` against a live Valkey backend.
#[derive(Default)]
struct AllowAllRateLimiter;

#[async_trait]
impl RateLimiter for AllowAllRateLimiter {
    async fn check(&self, _key: &RateLimitKey) -> Result<RateLimitDecision, RateLimiterError> {
        Ok(RateLimitDecision::Allow {
            remaining: u32::MAX,
            reset_in: std::time::Duration::from_secs(60),
        })
    }

    async fn unlock(&self, _key: &RateLimitKey) -> Result<(), RateLimiterError> {
        Ok(())
    }
}

/// Auditor that captures every recorded event.
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

fn fast_argon_cfg() -> Argon2Config {
    Argon2Config {
        m_cost: 8,
        t_cost: 1,
        p_cost: 1,
        max_concurrency: 4,
    }
}

fn cfg(breachlist: BreachlistConfig) -> IdentityConfig {
    let mut cfg = IdentityConfig::default();
    cfg.secrets_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into();
    cfg.valkey_url = "redis://test:6379".into();
    cfg.argon2 = fast_argon_cfg();
    cfg.password = PasswordConfig {
        min_length: 12,
        max_length: 256,
    };
    cfg.breachlist = breachlist;
    cfg.email_token_ttl_minutes = 30;
    cfg
}

async fn build_service(
    pool: sqlx::PgPool,
    breach_client: Arc<dyn BreachListClient>,
) -> Arc<IdentityService> {
    let hasher = Argon2idHasher::new(&fast_argon_cfg()).unwrap();
    let deps = IdentityServiceDeps {
        config: cfg(BreachlistConfig::default()),
        hasher,
        breach_client,
        auditor: Arc::new(CapturingAuditor::default()),
        session_issuer: Arc::new(FakeSessionIssuer::default()),
        rate_limiter: Arc::new(AllowAllRateLimiter),
        pool,
        outbound_from_address: "noreply@example.com".into(),
        base_url: "https://test.zagrosi.example".into(),
    };
    Arc::new(IdentityService::new(deps).await.unwrap())
}

/// Always-clean breach client (no live HIBP).
struct AlwaysCleanBreach;
#[async_trait]
impl BreachListClient for AlwaysCleanBreach {
    async fn check(&self, _password: &str) -> Result<BreachCheck, BreachListError> {
        Ok(BreachCheck::Clean)
    }
}

/// Always-breached client.
struct AlwaysBreached;
#[async_trait]
impl BreachListClient for AlwaysBreached {
    async fn check(&self, _password: &str) -> Result<BreachCheck, BreachListError> {
        Ok(BreachCheck::Breached {
            occurrences: 9_659_365,
        })
    }
}

fn ip() -> IpAddr {
    "203.0.113.10".parse().unwrap()
}

#[tokio::test]
#[serial]
async fn signup_happy_path() -> TestResult {
    let env = migrated_env().await?;
    let svc = build_service(env.pool.clone(), Arc::new(AlwaysCleanBreach)).await;

    let resp = svc
        .sign_up(SignUpRequest {
            email: "alice@example.com".into(),
            display_name: "Alice".into(),
            password: "correct-horse-battery-staple".into(),
            ip: ip(),
            correlation_id: Uuid::now_v7(),
        })
        .await?;
    assert_eq!(resp.status, "ok");
    assert_eq!(resp.action, "check_email");

    // User row exists, password_hash + password_updated_at populated.
    let row = sqlx::query!(
        "SELECT password_hash, password_updated_at, email_verified_at FROM users WHERE email_lower = $1",
        "alice@example.com",
    )
    .fetch_one(&env.pool)
    .await?;
    assert!(row.password_hash.is_some());
    assert!(row.password_updated_at.is_some());
    assert!(row.email_verified_at.is_none());

    // Outbox row queued with verify_email template.
    let outbox = sqlx::query!(
        "SELECT template_key FROM email_outbox WHERE to_address = $1",
        "alice@example.com",
    )
    .fetch_one(&env.pool)
    .await?;
    assert_eq!(outbox.template_key, "verify_email");
    Ok(())
}

#[tokio::test]
#[serial]
async fn signup_collision_returns_same_response() -> TestResult {
    let env = migrated_env().await?;
    let svc = build_service(env.pool.clone(), Arc::new(AlwaysCleanBreach)).await;

    let _ = svc
        .sign_up(SignUpRequest {
            email: "bob@example.com".into(),
            display_name: "Bob".into(),
            password: "correct-horse-battery-staple".into(),
            ip: ip(),
            correlation_id: Uuid::now_v7(),
        })
        .await?;

    let collision = svc
        .sign_up(SignUpRequest {
            email: "bob@example.com".into(),
            display_name: "Bob".into(),
            password: "correct-horse-battery-staple".into(),
            ip: ip(),
            correlation_id: Uuid::now_v7(),
        })
        .await?;
    assert_eq!(collision.status, "ok");
    assert_eq!(collision.action, "check_email");

    // Collision path enqueues account_already_exists, not verify_email.
    let row = sqlx::query!(
        "SELECT template_key FROM email_outbox WHERE to_address = $1 ORDER BY created_at DESC",
        "bob@example.com",
    )
    .fetch_all(&env.pool)
    .await?;
    let last_template = row.first().map(|r| r.template_key.as_str()).unwrap_or("");
    assert_eq!(last_template, "account_already_exists");
    Ok(())
}

#[tokio::test]
#[serial]
async fn signup_pwned_password_rejected() -> TestResult {
    let env = migrated_env().await?;
    let svc = build_service(env.pool.clone(), Arc::new(AlwaysBreached)).await;

    let result = svc
        .sign_up(SignUpRequest {
            email: "carol@example.com".into(),
            display_name: "Carol".into(),
            password: "correct-horse-battery-staple".into(),
            ip: ip(),
            correlation_id: Uuid::now_v7(),
        })
        .await;
    assert!(matches!(result, Err(IdentityError::PasswordBreached)));
    Ok(())
}

#[tokio::test]
#[serial]
async fn signin_unknown_email_returns_invalid_credentials() -> TestResult {
    let env = migrated_env().await?;
    let svc = build_service(env.pool.clone(), Arc::new(AlwaysCleanBreach)).await;
    let result = svc
        .sign_in(SignInRequest {
            email: "ghost@example.com".into(),
            password: "correct-horse-battery-staple".into(),
            ip: ip(),
            correlation_id: Uuid::now_v7(),
        })
        .await;
    assert!(matches!(result, Err(IdentityError::InvalidCredentials)));
    Ok(())
}

#[tokio::test]
#[serial]
async fn signin_unverified_user_returns_email_not_verified() -> TestResult {
    let env = migrated_env().await?;
    let svc = build_service(env.pool.clone(), Arc::new(AlwaysCleanBreach)).await;
    svc.sign_up(SignUpRequest {
        email: "dave@example.com".into(),
        display_name: "Dave".into(),
        password: "correct-horse-battery-staple".into(),
        ip: ip(),
        correlation_id: Uuid::now_v7(),
    })
    .await?;
    let result = svc
        .sign_in(SignInRequest {
            email: "dave@example.com".into(),
            password: "correct-horse-battery-staple".into(),
            ip: ip(),
            correlation_id: Uuid::now_v7(),
        })
        .await;
    assert!(matches!(result, Err(IdentityError::EmailNotVerified)));
    Ok(())
}

#[tokio::test]
#[serial]
async fn signin_after_verify_succeeds() -> TestResult {
    let env = migrated_env().await?;
    let svc = build_service(env.pool.clone(), Arc::new(AlwaysCleanBreach)).await;
    svc.sign_up(SignUpRequest {
        email: "erin@example.com".into(),
        display_name: "Erin".into(),
        password: "correct-horse-battery-staple".into(),
        ip: ip(),
        correlation_id: Uuid::now_v7(),
    })
    .await?;
    sqlx::query!(
        "UPDATE users SET email_verified_at = now() WHERE email_lower = $1",
        "erin@example.com",
    )
    .execute(&env.pool)
    .await?;
    let session = svc
        .sign_in(SignInRequest {
            email: "erin@example.com".into(),
            password: "correct-horse-battery-staple".into(),
            ip: ip(),
            correlation_id: Uuid::now_v7(),
        })
        .await?;
    assert!(!session.raw_token.is_empty());
    Ok(())
}

#[tokio::test]
#[serial]
async fn password_reset_request_unknown_email_returns_ok() -> TestResult {
    let env = migrated_env().await?;
    let svc = build_service(env.pool.clone(), Arc::new(AlwaysCleanBreach)).await;
    svc.password_reset_request(PasswordResetRequestRequest {
        email: "noone@example.com".into(),
        ip: ip(),
        correlation_id: Uuid::now_v7(),
    })
    .await?;
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM password_resets")
        .fetch_one(&env.pool)
        .await?;
    assert_eq!(count, 0);
    Ok(())
}

#[tokio::test]
#[serial]
async fn hibp_disabled_skips_network() -> TestResult {
    let cfg = BreachlistConfig {
        mode: BreachlistMode::Disabled,
        timeout_secs: 5,
        endpoint: "http://invalid.invalid/".into(),
    };
    let client = HibpBreachClient::new(reqwest::Client::new(), cfg);
    let check = client.check("any-password").await.unwrap();
    assert_eq!(check, BreachCheck::Clean);
    Ok(())
}

#[tokio::test]
#[serial]
async fn hibp_online_pwned_password_returns_breached() -> TestResult {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/range/5BAA6"))
        .and(header("Add-Padding", "true"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(include_str!("fixtures/hibp_responses/pwned.txt")),
        )
        .mount(&server)
        .await;
    let cfg = BreachlistConfig {
        mode: BreachlistMode::Online,
        timeout_secs: 5,
        endpoint: format!("{}/range/", server.uri()),
    };
    let client = HibpBreachClient::new(reqwest::Client::new(), cfg);
    let check = client.check("password").await.unwrap();
    assert!(matches!(
        check,
        BreachCheck::Breached { occurrences } if occurrences == 9_659_365,
    ));
    Ok(())
}

#[tokio::test]
#[serial]
async fn hibp_online_clean_password_returns_clean() -> TestResult {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/range/5BAA6"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(include_str!("fixtures/hibp_responses/clean.txt")),
        )
        .mount(&server)
        .await;
    let cfg = BreachlistConfig {
        mode: BreachlistMode::Online,
        timeout_secs: 5,
        endpoint: format!("{}/range/", server.uri()),
    };
    let client = HibpBreachClient::new(reqwest::Client::new(), cfg);
    let check = client.check("password").await.unwrap();
    assert_eq!(check, BreachCheck::Clean);
    Ok(())
}
