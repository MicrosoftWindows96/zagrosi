// SPDX-License-Identifier: AGPL-3.0-or-later

//! P3 nullable-org on `failed_signin_aggregates`: NULL-org (IP-only)
//! rows are platform-scoped; org rows bind to the GUC; the pre-login
//! recording path (no org context) keeps working.
//!
//! Pinned write-arm decision (plan §5.4): the write policies carry the
//! nullable arm — `WITH CHECK (org_id IS NULL OR org = GUC)` — because
//! `FailedSigninRepo` records failures pre-auth without org context and
//! today always passes `org_id = NULL`. Org-attributed rows therefore
//! require org context at write time.

use chrono::Utc;
use serial_test::serial;
use uuid::Uuid;
use zagrosi_db::begin_tenant_tx;
use zagrosi_identity::repo::FailedSigninRepo;
use zagrosi_test_support::{TestDb, seed_org};

type TestError = Box<dyn std::error::Error + Send + Sync>;
type TestResult = Result<(), TestError>;

async fn seed_aggregate(db: &TestDb, org: Option<Uuid>) -> TestResult {
    sqlx::query(
        "INSERT INTO failed_signin_aggregates
             (id, org_id, ip, window_start, count, first_attempt_at, last_attempt_at)
         VALUES ($1, $2, '198.51.100.9'::inet, now(), 1, now(), now())",
    )
    .bind(Uuid::now_v7())
    .bind(org)
    .execute(db.migrate_pool())
    .await?;
    Ok(())
}

#[tokio::test]
#[serial]
async fn null_org_rows_visible_alongside_own_org() -> TestResult {
    let db = TestDb::new().await?;
    let org_a = seed_org(db.migrate_pool(), "p3-a").await?;
    let org_b = seed_org(db.migrate_pool(), "p3-b").await?;
    seed_aggregate(&db, None).await?;
    seed_aggregate(&db, Some(org_a)).await?;
    seed_aggregate(&db, Some(org_b)).await?;

    let mut tx = begin_tenant_tx(db.app_pool(), org_a).await?;
    let visible: Vec<Option<Uuid>> = sqlx::query_scalar(
        "SELECT org_id FROM failed_signin_aggregates ORDER BY org_id NULLS FIRST",
    )
    .fetch_all(tx.as_executor())
    .await?;
    tx.commit().await?;
    assert_eq!(
        visible,
        vec![None, Some(org_a)],
        "org-A context sees NULL-org rows + own rows, never org B's"
    );
    Ok(())
}

#[tokio::test]
#[serial]
async fn prelogin_write_paths_still_work() -> TestResult {
    let db = TestDb::new().await?;
    // The production recording path: FailedSigninRepo over the app pool,
    // no transaction, no GUC — org is always NULL here by design.
    let repo = FailedSigninRepo::new(db.app_pool().clone());
    let ip: std::net::IpAddr = "203.0.113.99".parse()?;
    let first = repo.record_failure(None, None, ip, Utc::now()).await?;
    assert!(first.first_in_window);
    let second = repo.record_failure(None, None, ip, Utc::now()).await?;
    assert!(!second.first_in_window);
    assert_eq!(second.count, 2, "upsert path must keep counting");
    Ok(())
}
