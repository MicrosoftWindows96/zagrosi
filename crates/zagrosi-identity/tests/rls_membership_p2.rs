// SPDX-License-Identifier: AGPL-3.0-or-later

//! P2 org-or-self on `user_org_memberships`: the self-arm lists a user's
//! own memberships across orgs, and never authorizes writes.

use serial_test::serial;
use uuid::Uuid;
use zagrosi_test_support::{TestDb, seed_org, seed_user};

type TestError = Box<dyn std::error::Error + Send + Sync>;
type TestResult = Result<(), TestError>;

async fn seed_membership(db: &TestDb, user: Uuid, org: Uuid) -> TestResult {
    sqlx::query(
        "INSERT INTO user_org_memberships (id, user_id, org_id, joined_via)
         VALUES ($1, $2, $3, 'manual')",
    )
    .bind(Uuid::now_v7())
    .bind(user)
    .bind(org)
    .execute(db.migrate_pool())
    .await?;
    Ok(())
}

#[tokio::test]
#[serial]
async fn self_arm_lists_own_memberships_across_orgs() -> TestResult {
    let db = TestDb::new().await?;
    let org_a = seed_org(db.migrate_pool(), "p2-a").await?;
    let org_b = seed_org(db.migrate_pool(), "p2-b").await?;
    let me = seed_user(db.migrate_pool(), "p2-me@example.test").await?;
    let other = seed_user(db.migrate_pool(), "p2-other@example.test").await?;
    seed_membership(&db, me, org_a).await?;
    seed_membership(&db, me, org_b).await?;
    seed_membership(&db, other, org_a).await?;

    // As zagrosi_app with ONLY app.user_id set (no org GUC): both of my
    // membership rows visible; the other user's rows invisible.
    let mut tx = db.app_pool().begin().await?;
    zagrosi_identity::repo::with_user_context(&mut tx, me).await?;
    let mine: i64 =
        sqlx::query_scalar("SELECT count(*) FROM user_org_memberships WHERE user_id = $1")
            .bind(me)
            .fetch_one(&mut *tx)
            .await?;
    let others: i64 = sqlx::query_scalar("SELECT count(*) FROM user_org_memberships")
        .fetch_one(&mut *tx)
        .await?;
    tx.commit().await?;
    assert_eq!(mine, 2, "self-arm must list my memberships across orgs");
    assert_eq!(others, 2, "only my rows are visible without an org GUC");
    Ok(())
}

#[tokio::test]
#[serial]
async fn self_arm_never_authorizes_writes() -> TestResult {
    let db = TestDb::new().await?;
    let org_a = seed_org(db.migrate_pool(), "p2w-a").await?;
    let org_b = seed_org(db.migrate_pool(), "p2w-b").await?;
    let me = seed_user(db.migrate_pool(), "p2w-me@example.test").await?;
    seed_membership(&db, me, org_a).await?;

    // app.user_id set, NO org GUC: INSERT/UPDATE/DELETE refused / zero rows.
    let mut tx = db.app_pool().begin().await?;
    zagrosi_identity::repo::with_user_context(&mut tx, me).await?;
    let insert = sqlx::query(
        "INSERT INTO user_org_memberships (id, user_id, org_id, joined_via)
         VALUES ($1, $2, $3, 'manual')",
    )
    .bind(Uuid::now_v7())
    .bind(me)
    .bind(org_a)
    .execute(&mut *tx)
    .await;
    assert!(insert.is_err(), "self-arm INSERT must fail WITH CHECK");
    tx.rollback().await?;

    let mut tx = db.app_pool().begin().await?;
    zagrosi_identity::repo::with_user_context(&mut tx, me).await?;
    let updated =
        sqlx::query("UPDATE user_org_memberships SET basic_role = 'owner' WHERE user_id = $1")
            .bind(me)
            .execute(&mut *tx)
            .await?
            .rows_affected();
    let deleted = sqlx::query("DELETE FROM user_org_memberships WHERE user_id = $1")
        .bind(me)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    tx.rollback().await?;
    assert_eq!(updated, 0, "self-arm UPDATE must touch zero rows");
    assert_eq!(deleted, 0, "self-arm DELETE must touch zero rows");

    // app.user_id set to self + org GUC set to a FOREIGN org: my org-A
    // row is still not writable (the org arm filters it out).
    let mut tx = zagrosi_db::begin_tenant_tx_as_user(db.app_pool(), org_b, me).await?;
    let cross =
        sqlx::query("UPDATE user_org_memberships SET basic_role = 'owner' WHERE org_id = $1")
            .bind(org_a)
            .execute(tx.as_executor())
            .await?
            .rows_affected();
    tx.rollback().await?;
    assert_eq!(cross, 0, "foreign-org context must not write my row");
    Ok(())
}
