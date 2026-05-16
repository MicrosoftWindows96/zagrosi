// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared fixtures for `zagrosi-identity` integration tests.
//!
//! Spins up a fresh Postgres container per fixture invocation and
//! runs every identity migration before yielding the pool. Mirrors
//! the pattern in `tests/migrations_smoke.rs` so each new section's
//! integration suite stays self-contained.

#![allow(dead_code)] // shared helpers used selectively per test file
#![allow(unreachable_pub)] // each test binary includes this via `mod common;`
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::missing_const_for_fn
)]

#[cfg(feature = "saml")]
pub mod saml_helpers;

// Section-16 compose-aware harness. These modules carry no test
// functions themselves; they are the bookkeeping layer the
// `tests/{oidc_flow,oidc_negative,saml_negative_corpus,
// multi_idp_routing,scim_conformance,scim_inbound_authentik}.rs`
// suites consume. Every compose-touching helper is inert unless
// `RUN_INTEGRATION=1` (see [`integration_enabled`]) so the default
// `cargo test --workspace` slice on a developer box without docker
// still compiles + passes.
pub mod authentik;
pub mod compose;
pub mod fixtures;
pub mod mailpit;
pub mod simplesaml;

use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use std::error::Error;
use std::time::Duration;
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::ContainerAsync;
use testcontainers_modules::testcontainers::ImageExt;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use uuid::Uuid;
use zagrosi_identity::run_migrations;

/// Default Postgres image tag — tracks the dev compose major.
pub const PG_DEFAULT_TAG: &str = "18-alpine";

/// Boxed dynamic error type so any failure lifts via `?`.
pub type TestError = Box<dyn Error + Send + Sync>;
/// Test return alias.
pub type TestResult<T = ()> = Result<T, TestError>;

/// Per-test container + pool. Drop order: pool first, then container.
pub struct TestEnv {
    /// Pool wired to the container.
    pub pool: PgPool,
    /// Owns the container lifetime.
    _pg: ContainerAsync<Postgres>,
}

/// Spin up a fresh PG container at the requested tag.
pub async fn pg_env(tag: &str) -> TestResult<TestEnv> {
    let container = Postgres::default().with_tag(tag).start().await?;
    let host = container.get_host().await?;
    let port = container.get_host_port_ipv4(5432).await?;
    let url = format!("postgres://postgres:postgres@{host}:{port}/postgres");
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .acquire_timeout(Duration::from_secs(15))
        .connect(&url)
        .await?;
    Ok(TestEnv {
        pool,
        _pg: container,
    })
}

/// Spin up a PG container, run every identity migration, return the
/// ready pool.
pub async fn migrated_env() -> TestResult<TestEnv> {
    let env = pg_env(PG_DEFAULT_TAG).await?;
    run_migrations(&env.pool).await?;
    Ok(env)
}

/// Insert a minimal `orgs` row and return its UUID v7.
pub async fn seed_org(pool: &PgPool, slug: &str) -> TestResult<Uuid> {
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO orgs (id, slug, display_name) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(slug)
        .bind(slug)
        .execute(pool)
        .await?;
    Ok(id)
}

/// Insert a minimal `users` row and return its UUID v7.
pub async fn seed_user(pool: &PgPool, email: &str) -> TestResult<Uuid> {
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO users (id, email, display_name) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(email)
        .bind(email)
        .execute(pool)
        .await?;
    Ok(id)
}

/// Environment variable that opts a process into the compose-backed
/// integration suites. Set to `1` by the `rust / sso-integration` CI
/// job (and by `scripts/smoke-sso.sh` consumers) once
/// `deploy/docker/compose.test.yaml` is healthy.
pub const RUN_INTEGRATION_ENV: &str = "RUN_INTEGRATION";

/// Base-URL environment variable. The compose-backed suites point at
/// an externally-running identity surface (the `rust / sso-integration`
/// job brings the gateway up alongside the test stack) so the harness
/// does not duplicate the section-06 `IdentityService` wiring.
pub const TEST_BASE_URL_ENV: &str = "ZAGROSI_TEST_BASE_URL";

/// `DATABASE_URL` pointing at the compose stack's Postgres. Used by
/// the integration suites to assert post-conditions (federated
/// identities, replay rows, session revocation) directly.
pub const DATABASE_URL_ENV: &str = "DATABASE_URL";

/// Returns `true` when `RUN_INTEGRATION=1` is present in the
/// environment. EVERY compose-touching test gates on this and returns
/// early when it is `false`, so `cargo test --workspace` on a box
/// without docker still passes the unit-test slice (acceptance
/// criterion §16.5).
#[must_use]
pub fn integration_enabled() -> bool {
    std::env::var(RUN_INTEGRATION_ENV)
        .map(|v| v == "1")
        .unwrap_or(false)
}

/// Skip-guard macro for the compose suites.
///
/// Expands to an early `return` (with an explanatory `eprintln!` only
/// when the test was *explicitly* opted in via `--ignored`-style
/// runners) when [`integration_enabled`] is `false`. Keeps the
/// no-docker `cargo test --workspace` slice green while leaving the
/// real assertions reachable in CI.
#[macro_export]
macro_rules! require_integration {
    () => {
        if !$crate::common::integration_enabled() {
            return;
        }
    };
}

/// Test-scoped handle over the compose stack.
///
/// Per the section-16 plan the harness is "stubs only; full impl is
/// bookkeeping": it owns a reqwest client + a Postgres pool wired to
/// the compose stack and the externally-running identity base URL. It
/// deliberately does NOT re-spawn an in-process `IdentityService`
/// (that wiring is section-06-owned and consuming it here would
/// duplicate logic the plan forbids — "only consume their public
/// surfaces"). Constructed only after a [`integration_enabled`] gate,
/// so the panics below are unreachable in the no-docker slice.
pub struct Identity {
    base_url: String,
    http: reqwest::Client,
    pool: PgPool,
}

impl Identity {
    /// Wire to the compose stack. Reads [`TEST_BASE_URL_ENV`] (default
    /// `http://127.0.0.1:8080`) + [`DATABASE_URL_ENV`], builds a
    /// reqwest client, connects the pool, and applies the identity
    /// migrations (idempotent).
    ///
    /// # Panics
    ///
    /// Panics if invoked without [`DATABASE_URL_ENV`] set. This is
    /// unreachable in `cargo test --workspace` because every caller
    /// is guarded by [`require_integration!`]; the panic exists so a
    /// contributor who flips a gate off without the compose stack
    /// gets a deterministic failure rather than a hang.
    pub async fn start() -> Self {
        assert!(
            integration_enabled(),
            "Identity::start() reached without RUN_INTEGRATION=1 — guard the \
             call site with require_integration!()"
        );
        let base_url = std::env::var(TEST_BASE_URL_ENV)
            .unwrap_or_else(|_| "http://127.0.0.1:8080".to_string());
        let database_url = std::env::var(DATABASE_URL_ENV).expect(
            "DATABASE_URL must point at the compose stack's Postgres for the \
             integration suites",
        );
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("build reqwest client");
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .acquire_timeout(Duration::from_secs(15))
            .connect(&database_url)
            .await
            .expect("connect compose Postgres");
        run_migrations(&pool)
            .await
            .expect("apply identity migrations");
        Self {
            base_url,
            http,
            pool,
        }
    }

    /// Externally-running identity base URL (no trailing slash).
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Shared reqwest client (redirects disabled so 302 assertions
    /// inspect `Location` directly).
    #[must_use]
    pub fn http(&self) -> &reqwest::Client {
        &self.http
    }

    /// Pool wired to the compose Postgres for post-condition asserts.
    #[must_use]
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}
