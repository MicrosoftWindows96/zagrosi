// SPDX-License-Identifier: AGPL-3.0-or-later

//! Migration smoke + schema posture for the rbac set: manifest
//! fidelity, idempotency, RLS ENABLE+FORCE with explicit-role policies,
//! and the verb grant matrix.
//!
//! Bookkeeping lands in the shared `_sqlx_migrations` history table
//! (documented deviation from the plan's `_sqlx_migrations_rbac`: the
//! pinned sqlx 0.8.x has no per-`Migrator` history-table configuration;
//! see `zagrosi-test-support::migrations`), so the manifest assertions
//! filter to the rbac set's version timestamps.

use serial_test::serial;
use zagrosi_test_support::{TestDb, rls_catalog, run_all_migrations};

type TestError = Box<dyn std::error::Error + Send + Sync>;
type TestResult = Result<(), TestError>;

/// The rbac set's version timestamps (filename leading numeric prefix).
const RBAC_VERSIONS: [i64; 4] = [
    20_260_611_100_000,
    20_260_611_100_100,
    20_260_611_100_200,
    20_260_611_100_300,
];

const RBAC_TABLES: [&str; 5] = [
    "resource_nodes",
    "org_permission_versions",
    "custom_roles",
    "custom_role_entries",
    "role_assignments",
];

#[tokio::test]
#[serial]
async fn rbac_manifest_recorded_and_idempotent() -> TestResult {
    // TestDb::new() already ran identity -> rbac in order; assert the
    // bookkeeping landed and a second full run applies nothing new.
    let db = TestDb::new().await?;
    let versions: Vec<i64> = sqlx::query_scalar(
        "SELECT version FROM _sqlx_migrations WHERE version = ANY($1) ORDER BY version",
    )
    .bind(RBAC_VERSIONS.to_vec())
    .fetch_all(db.migrate_pool())
    .await?;
    assert_eq!(versions, RBAC_VERSIONS.to_vec(), "rbac manifest mismatch");

    run_all_migrations(db.migrate_pool()).await?;
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*)::BIGINT FROM _sqlx_migrations WHERE version = ANY($1)")
            .bind(RBAC_VERSIONS.to_vec())
            .fetch_one(db.migrate_pool())
            .await?;
    assert_eq!(count, 4, "second run must be a no-op");
    Ok(())
}

#[tokio::test]
#[serial]
async fn rbac_tables_are_rls_forced_with_explicit_role_policies() -> TestResult {
    let db = TestDb::new().await?;
    for table in RBAC_TABLES {
        let (rls_enabled, rls_forced): (bool, bool) = sqlx::query_as(
            "SELECT c.relrowsecurity, c.relforcerowsecurity
             FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
             WHERE n.nspname = 'public' AND c.relname = $1",
        )
        .bind(table)
        .fetch_one(db.migrate_pool())
        .await?;
        assert!(rls_enabled, "{table}: RLS not enabled");
        assert!(rls_forced, "{table}: RLS not forced");

        let app_policies: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_policies
             WHERE tablename = $1 AND 'zagrosi_app' = ANY(roles)",
        )
        .bind(table)
        .fetch_one(db.migrate_pool())
        .await?;
        assert_eq!(
            app_policies, 4,
            "{table}: want the four P1 verb policies TO zagrosi_app"
        );
    }
    Ok(())
}

#[tokio::test]
#[serial]
async fn rbac_grants_match_the_matrix() -> TestResult {
    // zagrosi_app verbs come from the catalog's app_verbs (also asserted
    // workspace-wide by identity's rls_grants suite); maintenance gets
    // SELECT only; auth gets nothing on rbac tables.
    let db = TestDb::new().await?;
    for entry in rls_catalog()
        .iter()
        .filter(|e| RBAC_TABLES.contains(&e.table))
    {
        for privilege in ["SELECT", "INSERT", "UPDATE", "DELETE"] {
            let want_app = entry.app_verbs.contains(&privilege);
            let has_app: bool = sqlx::query_scalar("SELECT has_table_privilege($1, $2, $3)")
                .bind("zagrosi_app")
                .bind(entry.table)
                .bind(privilege)
                .fetch_one(db.migrate_pool())
                .await?;
            assert_eq!(
                has_app, want_app,
                "zagrosi_app {privilege} on {} must be {want_app}",
                entry.table
            );

            let want_maintenance = privilege == "SELECT";
            let has_maintenance: bool =
                sqlx::query_scalar("SELECT has_table_privilege($1, $2, $3)")
                    .bind("zagrosi_maintenance")
                    .bind(entry.table)
                    .bind(privilege)
                    .fetch_one(db.migrate_pool())
                    .await?;
            assert_eq!(
                has_maintenance, want_maintenance,
                "zagrosi_maintenance {privilege} on {} must be {want_maintenance}",
                entry.table
            );

            let has_auth: bool = sqlx::query_scalar("SELECT has_table_privilege($1, $2, $3)")
                .bind("zagrosi_auth")
                .bind(entry.table)
                .bind(privilege)
                .fetch_one(db.migrate_pool())
                .await?;
            assert!(
                !has_auth,
                "zagrosi_auth must hold nothing on {} (found {privilege})",
                entry.table
            );
        }
    }
    Ok(())
}

#[tokio::test]
#[serial]
async fn catalog_covers_all_five_rbac_tables_as_p1() -> TestResult {
    // The section-05 completeness gate (identity's rls_completeness
    // suite) iterates the shared catalog; this pins the five rbac
    // entries it depends on, with seeders for the isolation proptests.
    for table in RBAC_TABLES {
        let entry = rls_catalog()
            .iter()
            .find(|e| e.table == table)
            .unwrap_or_else(|| panic!("catalog entry missing for {table}"));
        assert!(
            matches!(entry.pattern, zagrosi_test_support::RlsPattern::P1Standard),
            "{table}: must be cataloged P1"
        );
        assert!(entry.seed.is_some(), "{table}: must register a seeder");
    }
    Ok(())
}
