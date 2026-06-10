// SPDX-License-Identifier: AGPL-3.0-or-later

//! Harness self-tests: role pools, role attributes, ordered migration
//! runner, pinned extensions. Requires docker (same convention as
//! identity's `migrations_smoke.rs` — no `RUN_INTEGRATION` gate).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use zagrosi_test_support::image::{PINNED_PG_PARQUET_VERSION, PINNED_PG_PARTMAN_VERSION};
use zagrosi_test_support::{TestDb, migration_sets, run_all_migrations};

type TestError = Box<dyn std::error::Error + Send + Sync>;

#[tokio::test]
#[serial_test::serial]
async fn run_all_migrations_applies_registered_sets_in_order() -> Result<(), TestError> {
    let db = TestDb::new().await?;

    // Registry order is identity-first; later sections append rbac/audit.
    let names: Vec<&str> = migration_sets().iter().map(|s| s.name).collect();
    assert!(
        names.starts_with(&["identity"]),
        "registry must start with identity, got {names:?}"
    );

    // Shared-history-table design (sqlx 0.8.6 has no per-set table API):
    // every registered set's versions must all be recorded as applied.
    for set in migration_sets() {
        for migration in set.migrator.iter() {
            let applied: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM _sqlx_migrations WHERE version = $1 AND success)",
            )
            .bind(migration.version)
            .fetch_one(db.migrate_pool())
            .await?;
            assert!(
                applied,
                "set '{}' version {} not recorded as applied",
                set.name, migration.version
            );
        }
    }

    // No two sets may share a version number (the shared table would mask
    // the collision; the runner pre-checks it — assert the registry is
    // actually disjoint today).
    let mut versions: Vec<i64> = migration_sets()
        .iter()
        .flat_map(|s| s.migrator.iter().map(|m| m.version))
        .collect();
    let total = versions.len();
    versions.sort_unstable();
    versions.dedup();
    assert_eq!(
        total,
        versions.len(),
        "cross-set migration version collision"
    );

    // Every public table owned by zagrosi_migrate — section 05's FORCE RLS
    // semantics depend on this ownership.
    let foreign_owned: Vec<(String, String)> = sqlx::query_as(
        "SELECT tablename::text, tableowner::text FROM pg_tables
         WHERE schemaname = 'public' AND tableowner <> 'zagrosi_migrate'",
    )
    .fetch_all(db.migrate_pool())
    .await?;
    assert!(
        foreign_owned.is_empty(),
        "tables not owned by zagrosi_migrate: {foreign_owned:?}"
    );

    Ok(())
}

#[tokio::test]
#[serial_test::serial]
async fn run_all_migrations_is_idempotent() -> Result<(), TestError> {
    let db = TestDb::new().await?;
    let count_before: i64 = sqlx::query_scalar("SELECT count(*) FROM _sqlx_migrations")
        .fetch_one(db.migrate_pool())
        .await?;

    run_all_migrations(db.migrate_pool()).await?;

    let count_after: i64 = sqlx::query_scalar("SELECT count(*) FROM _sqlx_migrations")
        .fetch_one(db.migrate_pool())
        .await?;
    assert_eq!(count_before, count_after, "second run must apply nothing");
    Ok(())
}

#[tokio::test]
#[serial_test::serial]
async fn role_pools_connect_as_their_roles() -> Result<(), TestError> {
    let db = TestDb::new().await?;
    for (pool, expected) in [
        (db.migrate_pool(), "zagrosi_migrate"),
        (db.app_pool(), "zagrosi_app"),
        (db.auth_pool(), "zagrosi_auth"),
        (db.maintenance_pool(), "zagrosi_maintenance"),
    ] {
        let current: String = sqlx::query_scalar("SELECT current_user")
            .fetch_one(pool)
            .await?;
        assert_eq!(current, expected);
    }
    Ok(())
}

#[tokio::test]
#[serial_test::serial]
async fn role_attributes_match_catalog() -> Result<(), TestError> {
    let db = TestDb::new().await?;
    let rows: Vec<(String, bool, bool, bool)> = sqlx::query_as(
        "SELECT rolname::text, rolsuper, rolbypassrls, rolcanlogin
         FROM pg_roles WHERE rolname LIKE 'zagrosi_%' ORDER BY rolname",
    )
    .fetch_all(db.migrate_pool())
    .await?;

    let get = |name: &str| {
        rows.iter()
            .find(|(n, ..)| n == name)
            .unwrap_or_else(|| panic!("role {name} missing"))
    };

    let (_, superuser, bypassrls, login) = get("zagrosi_app");
    assert!(
        !superuser && !bypassrls && *login,
        "zagrosi_app attributes wrong"
    );
    let (_, superuser, bypassrls, login) = get("zagrosi_auth");
    assert!(
        !superuser && !bypassrls && *login,
        "zagrosi_auth attributes wrong"
    );
    let (_, superuser, bypassrls, login) = get("zagrosi_migrate");
    assert!(
        !superuser && *bypassrls && *login,
        "zagrosi_migrate attributes wrong"
    );
    let (_, superuser, bypassrls, login) = get("zagrosi_maintenance");
    assert!(
        !superuser && *bypassrls && *login,
        "zagrosi_maintenance attributes wrong"
    );
    Ok(())
}

#[tokio::test]
#[serial_test::serial]
async fn pinned_extensions_install() -> Result<(), TestError> {
    let db = TestDb::new().await?;

    // Bootstrap pre-installs both; a redundant create must also succeed.
    sqlx::raw_sql(
        "CREATE EXTENSION IF NOT EXISTS pg_partman SCHEMA partman;
         CREATE EXTENSION IF NOT EXISTS pg_parquet;",
    )
    .execute(db.bootstrap_pool())
    .await?;

    let partman: String =
        sqlx::query_scalar("SELECT extversion FROM pg_extension WHERE extname = 'pg_partman'")
            .fetch_one(db.bootstrap_pool())
            .await?;
    assert_eq!(partman, PINNED_PG_PARTMAN_VERSION);

    let parquet: String =
        sqlx::query_scalar("SELECT extversion FROM pg_extension WHERE extname = 'pg_parquet'")
            .fetch_one(db.bootstrap_pool())
            .await?;
    assert_eq!(parquet, PINNED_PG_PARQUET_VERSION);
    Ok(())
}
