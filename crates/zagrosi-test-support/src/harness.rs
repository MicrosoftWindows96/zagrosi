// SPDX-License-Identifier: AGPL-3.0-or-later

//! `TestDb`: per-test ephemeral Postgres on the custom image, with
//! role-specific pools.

use crate::bootstrap;
use crate::error::HarnessError;
use crate::image;
use crate::migrations::run_all_migrations;
use crate::minio::MinioHarness;
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use std::time::Duration;
use testcontainers_modules::testcontainers::core::WaitFor;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use testcontainers_modules::testcontainers::{ContainerAsync, GenericImage, ImageExt};
use uuid::Uuid;

/// Superuser credentials for the bootstrap connection (ephemeral
/// containers). Deliberately not reachable through [`DbRole`]/[`TestDb::dsn`]
/// — the crate's rule is that test suites never connect as superuser.
const SUPERUSER_USER: &str = "postgres";
const SUPERUSER_PASSWORD: &str = "postgres";

/// Database name the harness operates in (the image default).
const DB_NAME: &str = "postgres";

/// The four runtime database roles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DbRole {
    /// `zagrosi_migrate` — migrations/backfills; owns every table.
    Migrate,
    /// `zagrosi_app` — request-path role; RLS-bound once policies land.
    App,
    /// `zagrosi_auth` — pre-tenant-context authentication lookups.
    Auth,
    /// `zagrosi_maintenance` — retention/archival/export jobs.
    Maintenance,
}

impl DbRole {
    const fn credentials(self) -> (&'static str, &'static str) {
        match self {
            Self::Migrate => ("zagrosi_migrate", bootstrap::MIGRATE_PASSWORD),
            Self::App => ("zagrosi_app", bootstrap::APP_PASSWORD),
            Self::Auth => ("zagrosi_auth", bootstrap::AUTH_PASSWORD),
            Self::Maintenance => ("zagrosi_maintenance", bootstrap::MAINTENANCE_PASSWORD),
        }
    }
}

/// Per-test ephemeral Postgres on the custom image. Field order = drop
/// order: pools close before the container stops (mirrors identity's
/// existing `TestEnv` convention).
pub struct TestDb {
    bootstrap_pool: PgPool,
    migrate_pool: PgPool,
    app_pool: PgPool,
    auth_pool: PgPool,
    maintenance_pool: PgPool,
    host: String,
    port: u16,
    container: ContainerAsync<GenericImage>,
}

impl TestDb {
    /// Boot a container, run the superuser bootstrap + all migrations,
    /// build the role pools.
    ///
    /// # Errors
    ///
    /// Fails if docker is unavailable, the image cannot start, or any
    /// bootstrap/migration step fails.
    pub async fn new() -> Result<Self, HarnessError> {
        Self::start(None).await
    }

    /// Like [`TestDb::new`], plus a `MinIO` container on a shared docker
    /// network with the server-side S3 env wired into Postgres (the
    /// section-01 contract `pg_parquet` reads).
    ///
    /// # Errors
    ///
    /// As [`TestDb::new`], plus `MinIO` container/bucket failures.
    // Transitively !Send via MinioHarness::start (upstream exec stream is
    // !Sync); dev-only crate, future consumed locally.
    #[allow(clippy::future_not_send)]
    pub async fn with_minio() -> Result<(Self, MinioHarness), HarnessError> {
        let network = format!("zg-ts-{}", Uuid::now_v7().simple());
        let minio = MinioHarness::start(&network).await?;
        let db = Self::start(Some((&network, &minio))).await?;
        Ok((db, minio))
    }

    async fn start(minio: Option<(&str, &MinioHarness)>) -> Result<Self, HarnessError> {
        let image_ref = image::pg_image();
        let (name, tag) = image::split_image_ref(&image_ref);
        let mut request = GenericImage::new(name, tag)
            // The entrypoint starts a temp server for initdb, stops it,
            // then starts the real one — wait for the second ready line.
            .with_wait_for(WaitFor::message_on_stderr(
                "database system is ready to accept connections",
            ))
            .with_wait_for(WaitFor::message_on_stderr(
                "database system is ready to accept connections",
            ))
            .with_env_var("POSTGRES_PASSWORD", SUPERUSER_PASSWORD)
            // Pin the BGW's target database explicitly instead of relying on
            // the image hook's default chain landing on the right name.
            // Note: pg_partman_bgw.role defaults to the container superuser
            // here; production provisioning differs (section 11 cares).
            .with_env_var("ZAGROSI_PARTMAN_DBNAME", DB_NAME);
        if let Some((network, minio)) = minio {
            request = request
                .with_network(network)
                .with_env_var("AWS_ACCESS_KEY_ID", minio.access_key())
                .with_env_var("AWS_SECRET_ACCESS_KEY", minio.secret_key())
                .with_env_var("AWS_ENDPOINT_URL", minio.internal_endpoint())
                .with_env_var("AWS_REGION", "us-east-1")
                // pg_parquet 0.5.x: env-only opt-in for non-TLS endpoints;
                // path-style addressing is its default.
                .with_env_var("AWS_ALLOW_HTTP", "true");
        }
        let container = request.start().await?;
        let host = container.get_host().await?.to_string();
        let port = container.get_host_port_ipv4(5432).await?;

        let bootstrap_pool = connect_with_retry(&superuser_dsn(&host, port)).await?;
        bootstrap::create_roles(&bootstrap_pool).await?;
        bootstrap::grant_database_access(&bootstrap_pool, DB_NAME).await?;
        bootstrap::install_extensions(&bootstrap_pool).await?;

        let migrate_pool = connect(&dsn_for(&host, port, DbRole::Migrate)).await?;
        run_all_migrations(&migrate_pool).await?;
        bootstrap::apply_interim_grants(&bootstrap_pool).await?;

        let app_pool = connect(&dsn_for(&host, port, DbRole::App)).await?;
        let auth_pool = connect(&dsn_for(&host, port, DbRole::Auth)).await?;
        let maintenance_pool = connect(&dsn_for(&host, port, DbRole::Maintenance)).await?;

        Ok(Self {
            bootstrap_pool,
            migrate_pool,
            app_pool,
            auth_pool,
            maintenance_pool,
            host,
            port,
            container,
        })
    }

    /// `zagrosi_migrate` pool — migrations, backfills, owner-level asserts.
    #[must_use]
    pub const fn migrate_pool(&self) -> &PgPool {
        &self.migrate_pool
    }

    /// `zagrosi_app` pool — the default for tenant-shaped test traffic.
    #[must_use]
    pub const fn app_pool(&self) -> &PgPool {
        &self.app_pool
    }

    /// `zagrosi_auth` pool — pre-tenant-context lookup paths.
    #[must_use]
    pub const fn auth_pool(&self) -> &PgPool {
        &self.auth_pool
    }

    /// `zagrosi_maintenance` pool — retention/archival/export jobs.
    #[must_use]
    pub const fn maintenance_pool(&self) -> &PgPool {
        &self.maintenance_pool
    }

    /// Superuser pool. Container bootstrap + image smoke assertions ONLY —
    /// never use it in crate test suites (the whole point of the harness is
    /// that test traffic cannot silently bypass RLS).
    #[must_use]
    pub const fn bootstrap_pool(&self) -> &PgPool {
        &self.bootstrap_pool
    }

    /// Role DSN string, for tests that configure a service-under-test via
    /// `ZAGROSI_DATABASE_URL` / `_MIGRATE_URL` / `_AUTH_URL` /
    /// `_MAINTENANCE_URL`.
    #[must_use]
    pub fn dsn(&self, role: DbRole) -> String {
        dsn_for(&self.host, self.port, role)
    }

    /// The underlying container (image-level assertions, exec).
    #[must_use]
    pub const fn container(&self) -> &ContainerAsync<GenericImage> {
        &self.container
    }
}

fn dsn_for(host: &str, port: u16, role: DbRole) -> String {
    let (user, password) = role.credentials();
    format!("postgres://{user}:{password}@{host}:{port}/{DB_NAME}")
}

/// Internal only: the superuser DSN never leaves the harness.
fn superuser_dsn(host: &str, port: u16) -> String {
    format!("postgres://{SUPERUSER_USER}:{SUPERUSER_PASSWORD}@{host}:{port}/{DB_NAME}")
}

async fn connect(url: &str) -> Result<PgPool, HarnessError> {
    Ok(PgPoolOptions::new()
        .max_connections(4)
        .acquire_timeout(Duration::from_secs(15))
        .connect(url)
        .await?)
}

/// First connection after container start: the double ready-line wait makes
/// this near-instant, but retry briefly to absorb scheduler jitter.
async fn connect_with_retry(url: &str) -> Result<PgPool, HarnessError> {
    let mut last_err: Option<sqlx::Error> = None;
    for _ in 0..30 {
        match connect(url).await {
            Ok(pool) => match sqlx::query("SELECT 1").execute(&pool).await {
                Ok(_) => return Ok(pool),
                Err(err) => last_err = Some(err),
            },
            Err(HarnessError::Sqlx(err)) => last_err = Some(err),
            Err(other) => return Err(other),
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    Err(last_err.map_or_else(
        || HarnessError::Config("postgres never became reachable".to_string()),
        HarnessError::Sqlx,
    ))
}
