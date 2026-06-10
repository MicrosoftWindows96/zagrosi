// SPDX-License-Identifier: AGPL-3.0-or-later

//! The heart of the section: cross-tenant isolation property suites over
//! every tenanted table, iterated generically from the machine-readable
//! catalog (a future table added without a seeder fails loudly).
//!
//! proptest drives a small number of randomized cases (org pairs +
//! seed multiplicity — container cost caps the case count) against ONE
//! shared container per test (booting per case would dominate runtime);
//! every case uses fresh random orgs so cases cannot interfere.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use proptest::prelude::*;
use proptest::test_runner::{Config, TestRunner};
use serial_test::serial;
use sqlx::PgPool;
use uuid::Uuid;
use zagrosi_db::begin_tenant_tx;
use zagrosi_test_support::{RlsCatalogEntry, RlsPattern, TestDb, rls_catalog, seed_org};

type TestError = Box<dyn std::error::Error + Send + Sync>;
type TestResult = Result<(), TestError>;

fn tenanted() -> impl Iterator<Item = &'static RlsCatalogEntry> {
    rls_catalog().iter().filter(|e| {
        matches!(
            e.pattern,
            RlsPattern::P1Standard | RlsPattern::P2OrgOrSelf | RlsPattern::P3NullableOrg
        )
    })
}

/// Seed `n` rows per table for one org via the migrate pool (BYPASSRLS).
async fn seed_all(migrate: &PgPool, org: Uuid, n: u32) -> TestResult {
    for entry in tenanted() {
        let seed = entry.seed.unwrap_or_else(|| {
            panic!(
                "catalog entry `{}` is tenanted but registers no seeder",
                entry.table
            )
        });
        for _ in 0..n {
            seed(migrate, org).await?;
        }
    }
    Ok(())
}

#[test]
#[serial]
fn cross_tenant_reads_return_zero_foreign_rows() {
    let rt = tokio::runtime::Runtime::new().expect("runtime");
    // Keep a runtime-context guard alive for the whole test so the
    // ContainerAsync drop (async teardown) runs inside the runtime.
    let _enter = rt.enter();
    let db = rt.block_on(TestDb::new()).expect("harness");
    let mut runner = TestRunner::new(Config::with_cases(3));
    runner
        .run(&(1u32..3), |rows_per_table| {
            rt.block_on(async {
                let org_a = seed_org(
                    db.migrate_pool(),
                    &format!("iso-a-{}", Uuid::now_v7().simple()),
                )
                .await?;
                let org_b = seed_org(
                    db.migrate_pool(),
                    &format!("iso-b-{}", Uuid::now_v7().simple()),
                )
                .await?;
                seed_all(db.migrate_pool(), org_a, rows_per_table).await?;
                seed_all(db.migrate_pool(), org_b, rows_per_table).await?;

                for entry in tenanted() {
                    // Ground truth via BYPASSRLS.
                    let truth_a: i64 = sqlx::query_scalar(&format!(
                        "SELECT count(*) FROM {} WHERE org_id = $1",
                        entry.table
                    ))
                    .bind(org_a)
                    .fetch_one(db.migrate_pool())
                    .await?;
                    assert!(truth_a > 0, "{}: seeder produced no rows", entry.table);

                    // As zagrosi_app under org A: exactly org A's rows —
                    // zero org-B rows (and for P3, NULL-org rows may add).
                    let mut tx = begin_tenant_tx(db.app_pool(), org_a).await?;
                    let visible_b: i64 = sqlx::query_scalar(&format!(
                        "SELECT count(*) FROM {} WHERE org_id = $1",
                        entry.table
                    ))
                    .bind(org_b)
                    .fetch_one(tx.as_executor())
                    .await?;
                    let visible_a: i64 = sqlx::query_scalar(&format!(
                        "SELECT count(*) FROM {} WHERE org_id = $1",
                        entry.table
                    ))
                    .bind(org_a)
                    .fetch_one(tx.as_executor())
                    .await?;
                    tx.commit().await?;
                    assert_eq!(visible_b, 0, "{}: foreign rows leaked", entry.table);
                    assert_eq!(visible_a, truth_a, "{}: own rows missing", entry.table);
                }
                Ok::<(), TestError>(())
            })
            .map_err(|e| TestCaseError::fail(e.to_string()))
        })
        .expect("property held");
}

#[test]
#[serial]
fn cross_tenant_writes_touch_zero_rows() {
    let rt = tokio::runtime::Runtime::new().expect("runtime");
    // Keep a runtime-context guard alive for the whole test so the
    // ContainerAsync drop (async teardown) runs inside the runtime.
    let _enter = rt.enter();
    let db = rt.block_on(TestDb::new()).expect("harness");
    let mut runner = TestRunner::new(Config::with_cases(3));
    runner
        .run(&(1u32..3), |rows_per_table| {
            rt.block_on(async {
                let org_a = seed_org(
                    db.migrate_pool(),
                    &format!("wr-a-{}", Uuid::now_v7().simple()),
                )
                .await?;
                let org_b = seed_org(
                    db.migrate_pool(),
                    &format!("wr-b-{}", Uuid::now_v7().simple()),
                )
                .await?;
                seed_all(db.migrate_pool(), org_b, rows_per_table).await?;

                for entry in tenanted() {
                    // Deliberately broad WHERE: every org-B row. Under org-A
                    // context both UPDATE and DELETE must touch zero rows.
                    let mut tx = begin_tenant_tx(db.app_pool(), org_a).await?;
                    let updated = sqlx::query(&format!(
                        "UPDATE {} SET org_id = org_id WHERE org_id = $1",
                        entry.table
                    ))
                    .bind(org_b)
                    .execute(tx.as_executor())
                    .await?
                    .rows_affected();
                    let deleted =
                        sqlx::query(&format!("DELETE FROM {} WHERE org_id = $1", entry.table))
                            .bind(org_b)
                            .execute(tx.as_executor())
                            .await?
                            .rows_affected();
                    tx.rollback().await?;
                    assert_eq!(updated, 0, "{}: cross-tenant UPDATE leaked", entry.table);
                    assert_eq!(deleted, 0, "{}: cross-tenant DELETE leaked", entry.table);
                }
                Ok::<(), TestError>(())
            })
            .map_err(|e| TestCaseError::fail(e.to_string()))
        })
        .expect("property held");
}

#[test]
#[serial]
fn fail_closed_without_guc() {
    let rt = tokio::runtime::Runtime::new().expect("runtime");
    // Keep a runtime-context guard alive for the whole test so the
    // ContainerAsync drop (async teardown) runs inside the runtime.
    let _enter = rt.enter();
    let db = rt.block_on(TestDb::new()).expect("harness");
    let mut runner = TestRunner::new(Config::with_cases(2));
    runner
        .run(&(1u32..3), |rows_per_table| {
            rt.block_on(async {
                let org = seed_org(
                    db.migrate_pool(),
                    &format!("fc-{}", Uuid::now_v7().simple()),
                )
                .await?;
                seed_all(db.migrate_pool(), org, rows_per_table).await?;

                for entry in tenanted() {
                    // No GUC at all (plain pool connection).
                    let bare: i64 = sqlx::query_scalar(&format!(
                        "SELECT count(*) FROM {} WHERE org_id IS NOT NULL",
                        entry.table
                    ))
                    .fetch_one(db.app_pool())
                    .await?;
                    assert_eq!(
                        bare, 0,
                        "{}: no-GUC SELECT must see zero org rows",
                        entry.table
                    );

                    // GUC explicitly set to the empty string.
                    let mut conn = db.app_pool().acquire().await?;
                    sqlx::query("SELECT set_config('app.org_id', '', false)")
                        .fetch_optional(&mut *conn)
                        .await?;
                    let empty: i64 = sqlx::query_scalar(&format!(
                        "SELECT count(*) FROM {} WHERE org_id IS NOT NULL",
                        entry.table
                    ))
                    .fetch_one(&mut *conn)
                    .await?;
                    sqlx::query("RESET ALL").execute(&mut *conn).await?;
                    assert_eq!(
                        empty, 0,
                        "{}: empty-GUC SELECT must see zero org rows",
                        entry.table
                    );

                    // INSERT carrying a real org_id without context must
                    // fail the WITH CHECK — the seeders double as the
                    // probe (parent P5 rows insert fine; the tenanted
                    // insert is the one that must refuse).
                    let seed = entry.seed.expect("tenanted entries have seeders");
                    let outcome = seed(db.app_pool(), org).await;
                    assert!(
                        outcome.is_err(),
                        "{}: org-attributed INSERT without GUC must fail WITH CHECK",
                        entry.table
                    );
                }
                Ok::<(), TestError>(())
            })
            .map_err(|e| TestCaseError::fail(e.to_string()))
        })
        .expect("property held");
}
