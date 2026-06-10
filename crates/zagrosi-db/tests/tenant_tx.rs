// SPDX-License-Identifier: AGPL-3.0-or-later

//! Integration tests for the tenant-transaction plumbing against a live
//! Postgres (testcontainers, `postgres:18-alpine`).
//!
//! Every pool here is `max_connections(1)` so acquire → release →
//! reacquire observes the *same physical connection* — the only way to
//! prove transaction-locality and the `RESET ALL` release hook.
//!
//! GUC and `RESET ALL` mechanics are role-agnostic, so these tests run
//! as the container default superuser. That is acceptable for this
//! crate only: the unit-wide "never test as superuser" rule starts
//! biting in section-05, when roles and policies exist.

use std::error::Error;

use serial_test::serial;
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use testcontainers_modules::testcontainers::{ContainerAsync, ImageExt};
use uuid::Uuid;
use zagrosi_db::{GUC_ORG_ID, GUC_USER_ID, begin_tenant_tx, begin_tenant_tx_as_user};

type TestError = Box<dyn Error + Send + Sync>;
type TestResult = Result<(), TestError>;

/// Per-test fixture. Field declaration order *is* drop order: the pool
/// closes before the container stops.
struct TestDb {
    pool: PgPool,
    dsn: String,
    _container: ContainerAsync<Postgres>,
}

/// Boot a plain `postgres:18-alpine` and connect a size-1 pool
/// (no release hook — the hook tests build their own pool from `dsn`).
async fn single_conn_db() -> Result<TestDb, TestError> {
    let container = Postgres::default().with_tag("18-alpine").start().await?;
    let host = container.get_host().await?;
    let port = container.get_host_port_ipv4(5432).await?;
    let dsn = format!("postgres://postgres:postgres@{host}:{port}/postgres");
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&dsn)
        .await?;
    Ok(TestDb {
        pool,
        dsn,
        _container: container,
    })
}

/// Read a GUC inside whatever executor the caller hands over.
async fn read_guc<'e, E>(executor: E, guc: &str) -> Result<Option<String>, TestError>
where
    E: sqlx::PgExecutor<'e>,
{
    let value: Option<String> = sqlx::query_scalar("SELECT current_setting($1, true)")
        .bind(guc)
        .fetch_one(executor)
        .await?;
    Ok(value)
}

/// Assert a GUC is unset using the exact `NULLIF(...) IS NULL` shape the
/// future RLS policies use — pinning the fail-closed contract rather
/// than a PG-version artifact ("unset" may read as NULL or '').
async fn assert_guc_unset(pool: &PgPool, guc: &str) -> TestResult {
    let is_unset: bool = sqlx::query_scalar("SELECT NULLIF(current_setting($1, true), '') IS NULL")
        .bind(guc)
        .fetch_one(pool)
        .await?;
    assert!(is_unset, "GUC `{guc}` must read as unset (NULL or '')");
    Ok(())
}

#[tokio::test]
#[serial]
async fn begin_tenant_tx_sets_org_guc_transaction_locally() -> TestResult {
    let db = single_conn_db().await?;
    let org = Uuid::now_v7();

    // Rollback case.
    let mut tx = begin_tenant_tx(&db.pool, org).await?;
    let value = read_guc(tx.as_executor(), GUC_ORG_ID).await?;
    assert_eq!(value.as_deref(), Some(org.to_string().as_str()));
    tx.rollback().await?;
    assert_guc_unset(&db.pool, GUC_ORG_ID).await?;

    // Commit case: transaction-local set_config dies on commit too.
    let mut tx = begin_tenant_tx(&db.pool, org).await?;
    let value = read_guc(tx.as_executor(), GUC_ORG_ID).await?;
    assert_eq!(value.as_deref(), Some(org.to_string().as_str()));
    tx.commit().await?;
    assert_guc_unset(&db.pool, GUC_ORG_ID).await?;
    Ok(())
}

#[tokio::test]
#[serial]
async fn begin_tenant_tx_as_user_sets_both_gucs() -> TestResult {
    let db = single_conn_db().await?;
    let org = Uuid::now_v7();
    let user = Uuid::now_v7();

    let mut tx = begin_tenant_tx_as_user(&db.pool, org, user).await?;
    let org_value = read_guc(tx.as_executor(), GUC_ORG_ID).await?;
    let user_value = read_guc(tx.as_executor(), GUC_USER_ID).await?;
    assert_eq!(org_value.as_deref(), Some(org.to_string().as_str()));
    assert_eq!(user_value.as_deref(), Some(user.to_string().as_str()));
    assert_eq!(tx.org_id(), org);
    assert_eq!(tx.user_id(), Some(user));
    tx.commit().await?;

    assert_guc_unset(&db.pool, GUC_ORG_ID).await?;
    assert_guc_unset(&db.pool, GUC_USER_ID).await?;
    Ok(())
}

#[tokio::test]
async fn nil_ids_are_rejected_with_errors_not_panics() -> TestResult {
    // The nil guards run before any DB I/O, so a lazy pool (no
    // container, no connection) is sufficient — and proves the
    // rejection happens without touching the database.
    let pool = PgPoolOptions::new().connect_lazy("postgres://nobody@127.0.0.1:1/unreachable")?;

    let nil_org = begin_tenant_tx(&pool, Uuid::nil()).await;
    assert!(matches!(nil_org, Err(zagrosi_db::Error::NilOrgId)));

    let nil_org_user = begin_tenant_tx_as_user(&pool, Uuid::nil(), Uuid::now_v7()).await;
    assert!(matches!(nil_org_user, Err(zagrosi_db::Error::NilOrgId)));

    let nil_user = begin_tenant_tx_as_user(&pool, Uuid::now_v7(), Uuid::nil()).await;
    assert!(matches!(nil_user, Err(zagrosi_db::Error::NilUserId)));
    Ok(())
}

#[tokio::test]
#[serial]
async fn debug_assertion_verification_path_yields_usable_transaction() -> TestResult {
    // Under cfg(debug_assertions) — the default test profile —
    // construction runs the read-back verification. This smoke test
    // proves the verified transaction is usable without asserting on
    // the verification internals.
    let db = single_conn_db().await?;
    let org = Uuid::now_v7();

    let mut tx = begin_tenant_tx(&db.pool, org).await?;
    let one: i32 = sqlx::query_scalar("SELECT 1")
        .fetch_one(tx.as_executor())
        .await?;
    assert_eq!(one, 1);
    assert_eq!(tx.org_id(), org);
    assert_eq!(tx.user_id(), None);
    tx.commit().await?;
    Ok(())
}

#[tokio::test]
#[serial]
async fn after_release_hook_resets_leaked_session_state() -> TestResult {
    let db = single_conn_db().await?;
    // Build the pool under test via the role-pool builder so the
    // RESET ALL hook is attached; size 1 so reacquire observes the
    // same physical connection.
    let pool = zagrosi_db::connect_role_pool_with(PgPoolOptions::new().max_connections(1), &db.dsn)
        .await?;

    // Deliberately do what production code must never do: a
    // session-scoped (is_local = false) set_config that outlives any
    // transaction.
    let leaked = Uuid::now_v7();
    let leaked_pid: i32;
    {
        let mut conn = pool.acquire().await?;
        leaked_pid = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *conn)
            .await?;
        sqlx::query("SELECT set_config($1, $2, false)")
            .bind(GUC_ORG_ID)
            .bind(leaked.to_string())
            .fetch_optional(&mut *conn)
            .await?;
        let value = read_guc(&mut *conn, GUC_ORG_ID).await?;
        assert_eq!(
            value.as_deref(),
            Some(leaked.to_string().as_str()),
            "precondition: the session-scoped leak is visible before release"
        );
        // `conn` drops here → release → after_release runs RESET ALL.
    }

    // Same backend pid ⇒ the same physical connection survived release
    // (the hook returned Ok(true)); a clean read on it ⇒ the hook
    // actually issued RESET ALL rather than the pool discarding the
    // connection and handing us a fresh one.
    let reacquired_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&pool)
        .await?;
    assert_eq!(
        reacquired_pid, leaked_pid,
        "reacquire must observe the same physical connection"
    );
    assert_guc_unset(&pool, GUC_ORG_ID).await?;
    Ok(())
}
