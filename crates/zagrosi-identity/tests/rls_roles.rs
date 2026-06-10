// SPDX-License-Identifier: AGPL-3.0-or-later

//! Role provisioning: exact attributes, idempotency, loud failure on
//! misprovisioned environments (identity migration 021).

use serial_test::serial;
use sqlx::postgres::PgPoolOptions;
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::ImageExt;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use zagrosi_test_support::{TestDb, run_all_migrations};

type TestError = Box<dyn std::error::Error + Send + Sync>;
type TestResult = Result<(), TestError>;

#[tokio::test]
#[serial]
async fn roles_exist_with_exact_attributes() -> TestResult {
    let db = TestDb::new().await?;
    let rows: Vec<(String, bool, bool, bool)> = sqlx::query_as(
        "SELECT rolname, rolcanlogin, rolbypassrls, rolsuper
         FROM pg_roles WHERE rolname LIKE 'zagrosi_%' ORDER BY rolname",
    )
    .fetch_all(db.migrate_pool())
    .await?;
    let expected = [
        ("zagrosi_app", true, false, false),
        ("zagrosi_auth", true, false, false),
        ("zagrosi_maintenance", true, true, false),
        ("zagrosi_migrate", true, true, false),
    ];
    assert_eq!(rows.len(), expected.len(), "exactly four zagrosi roles");
    for ((name, login, bypass, superuser), row) in expected.iter().zip(&rows) {
        assert_eq!(row.0, *name);
        assert_eq!(row.1, *login, "{name} LOGIN");
        assert_eq!(row.2, *bypass, "{name} BYPASSRLS");
        assert_eq!(row.3, *superuser, "{name} NOSUPERUSER");
    }
    Ok(())
}

#[tokio::test]
#[serial]
async fn roles_migration_idempotent() -> TestResult {
    // The harness pre-creates the roles (superuser bootstrap), then the
    // migration's CREATE ROLE guards no-op; running the whole set a
    // second time applies nothing and succeeds.
    let db = TestDb::new().await?;
    run_all_migrations(db.migrate_pool()).await?;
    Ok(())
}

#[tokio::test]
#[serial]
async fn migration_fails_loudly_on_misprovisioned_roles() -> TestResult {
    // Throwaway plain Postgres where zagrosi_maintenance exists WITHOUT
    // BYPASSRLS: the migration's attribute-assertion block must abort
    // with an actionable error, not proceed silently.
    let container = Postgres::default().with_tag("18-alpine").start().await?;
    let host = container.get_host().await?;
    let port = container.get_host_port_ipv4(5432).await?;
    let dsn = format!("postgres://postgres:postgres@{host}:{port}/postgres");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&dsn)
        .await?;
    sqlx::raw_sql(
        "CREATE ROLE zagrosi_migrate LOGIN NOSUPERUSER BYPASSRLS;
         CREATE ROLE zagrosi_app LOGIN NOSUPERUSER NOBYPASSRLS;
         CREATE ROLE zagrosi_auth LOGIN NOSUPERUSER NOBYPASSRLS;
         CREATE ROLE zagrosi_maintenance LOGIN NOSUPERUSER NOBYPASSRLS;",
    )
    .execute(&pool)
    .await?;

    let err = zagrosi_identity::MIGRATOR
        .run(&pool)
        .await
        .expect_err("migrations must abort on a BYPASSRLS-less maintenance role");
    let rendered = format!("{err:#}");
    assert!(
        rendered.contains("zagrosi_maintenance") && rendered.contains("misprovisioned"),
        "error must name the role and the problem, got: {rendered}"
    );
    Ok(())
}
