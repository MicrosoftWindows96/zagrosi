// SPDX-License-Identifier: AGPL-3.0-or-later

//! The SECURITY DEFINER org-root provisioning trigger: an org INSERT as
//! `zagrosi_app` with NO tenant GUC (sign-up happens pre-org-context;
//! `orgs` is P5/no-RLS) must yield exactly one live root node and one
//! version row, with no cross-org interference.

use serial_test::serial;
use sqlx::PgPool;
use uuid::Uuid;
use zagrosi_test_support::TestDb;

type TestError = Box<dyn std::error::Error + Send + Sync>;
type TestResult = Result<(), TestError>;

/// Insert an org over `pool` (no GUC — the signup shape) and return its id.
async fn insert_org_as(pool: &PgPool, slug: &str) -> Result<Uuid, TestError> {
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO orgs (id, slug, display_name) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(slug)
        .bind(slug)
        .execute(pool)
        .await?;
    Ok(id)
}

async fn root_and_version_counts(db: &TestDb, org: Uuid) -> Result<(i64, i64, i64), TestError> {
    // Owner-level ground truth (BYPASSRLS).
    let roots: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM resource_nodes
         WHERE org_id = $1 AND scope_type = 'org' AND parent_id IS NULL AND deleted_at IS NULL",
    )
    .bind(org)
    .fetch_one(db.migrate_pool())
    .await?;
    let versions: i64 =
        sqlx::query_scalar("SELECT count(*) FROM org_permission_versions WHERE org_id = $1")
            .bind(org)
            .fetch_one(db.migrate_pool())
            .await?;
    let version_value: i64 = sqlx::query_scalar(
        "SELECT coalesce(max(version), 0) FROM org_permission_versions WHERE org_id = $1",
    )
    .bind(org)
    .fetch_one(db.migrate_pool())
    .await?;
    Ok((roots, versions, version_value))
}

#[tokio::test]
#[serial]
async fn app_role_org_insert_without_guc_provisions_root_and_version() -> TestResult {
    let db = TestDb::new().await?;
    let org = insert_org_as(db.app_pool(), "trigger-org").await?;
    let (roots, versions, version_value) = root_and_version_counts(&db, org).await?;
    assert_eq!(roots, 1, "exactly one live org-root node");
    assert_eq!(versions, 1, "exactly one version row");
    assert_eq!(version_value, 1, "version starts at 1");
    Ok(())
}

#[tokio::test]
#[serial]
async fn second_org_is_unaffected_by_the_first() -> TestResult {
    let db = TestDb::new().await?;
    let first = insert_org_as(db.app_pool(), "trigger-one").await?;
    let second = insert_org_as(db.app_pool(), "trigger-two").await?;
    for org in [first, second] {
        let (roots, versions, _) = root_and_version_counts(&db, org).await?;
        assert_eq!(roots, 1, "org {org}: exactly one live root");
        assert_eq!(versions, 1, "org {org}: exactly one version row");
    }
    // The two roots are distinct rows.
    let distinct_roots: i64 = sqlx::query_scalar(
        "SELECT count(DISTINCT id) FROM resource_nodes
         WHERE org_id = ANY($1) AND scope_type = 'org' AND deleted_at IS NULL",
    )
    .bind(vec![first, second])
    .fetch_one(db.migrate_pool())
    .await?;
    assert_eq!(distinct_roots, 2);
    Ok(())
}
