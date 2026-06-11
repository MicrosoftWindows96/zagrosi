// SPDX-License-Identifier: AGPL-3.0-or-later

//! Backfill migration (rbac 004) against staged application: identity
//! set first, legacy rows seeded, then the rbac set — proving roots /
//! version rows for pre-existing orgs, the fixed `basic_role` mapping,
//! earliest-membership owner promotion, and the exactly-one-owner
//! invariant. Soft-deleted memberships and orgs get nothing.

use serial_test::serial;
use sqlx::PgPool;
use uuid::Uuid;
use zagrosi_test_support::{TestDb, run_identity_migrations, run_rbac_migrations};

type TestError = Box<dyn std::error::Error + Send + Sync>;
type TestResult = Result<(), TestError>;

async fn seed_org(pool: &PgPool, slug: &str, deleted: bool) -> Result<Uuid, TestError> {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO orgs (id, slug, display_name, deleted_at)
         VALUES ($1, $2, $2, CASE WHEN $3 THEN now() END)",
    )
    .bind(id)
    .bind(slug)
    .bind(deleted)
    .execute(pool)
    .await?;
    Ok(id)
}

async fn seed_user(pool: &PgPool, email: &str) -> Result<Uuid, TestError> {
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO users (id, email, display_name) VALUES ($1, $2, $2)")
        .bind(id)
        .bind(email)
        .execute(pool)
        .await?;
    Ok(id)
}

/// Insert a legacy membership with a controlled `created_at` offset (so
/// earliest-membership promotion is deterministic) and optional
/// tombstone.
async fn seed_membership(
    pool: &PgPool,
    user: Uuid,
    org: Uuid,
    basic_role: &str,
    minutes_ago: i32,
    deleted: bool,
) -> Result<Uuid, TestError> {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO user_org_memberships
             (id, user_id, org_id, basic_role, joined_via, created_at, deleted_at)
         VALUES ($1, $2, $3, $4, 'manual',
                 now() - make_interval(mins => $5),
                 CASE WHEN $6 THEN now() END)",
    )
    .bind(id)
    .bind(user)
    .bind(org)
    .bind(basic_role)
    .bind(minutes_ago)
    .bind(deleted)
    .execute(pool)
    .await?;
    Ok(id)
}

/// Live org-root assignment roles for `(org, user)`, sorted.
async fn root_roles_for(pool: &PgPool, org: Uuid, user: Uuid) -> Result<Vec<String>, TestError> {
    let mut roles: Vec<String> = sqlx::query_scalar(
        "SELECT ra.builtin_role FROM role_assignments ra
         JOIN resource_nodes rn ON rn.id = ra.node_id
         WHERE ra.org_id = $1 AND ra.user_id = $2
           AND rn.scope_type = 'org' AND ra.deleted_at IS NULL",
    )
    .bind(org)
    .bind(user)
    .fetch_all(pool)
    .await?;
    roles.sort();
    Ok(roles)
}

#[tokio::test]
#[serial]
async fn backfill_maps_promotes_and_asserts_exactly_one_owner() -> TestResult {
    let db = TestDb::new_unmigrated().await?;
    let pool = db.migrate_pool();
    run_identity_migrations(pool).await?;

    // Legacy world: orgs + memberships exist, rbac does not.
    // org_mapped covers the fixed mapping (owner/admin/member/unknown)
    // plus a soft-deleted membership.
    let org_mapped = seed_org(pool, "bf-mapped", false).await?;
    let owner = seed_user(pool, "bf-owner@example.test").await?;
    let admin = seed_user(pool, "bf-admin@example.test").await?;
    let plain = seed_user(pool, "bf-member@example.test").await?;
    let unknown = seed_user(pool, "bf-unknown@example.test").await?;
    let ghost = seed_user(pool, "bf-ghost@example.test").await?;
    seed_membership(pool, owner, org_mapped, "owner", 50, false).await?;
    seed_membership(pool, admin, org_mapped, "admin", 40, false).await?;
    seed_membership(pool, plain, org_mapped, "member", 30, false).await?;
    seed_membership(pool, unknown, org_mapped, "viewer", 20, false).await?;
    seed_membership(pool, ghost, org_mapped, "member", 10, true).await?;

    // org_promoted has zero owner-valued memberships: the earliest live
    // membership must be promoted.
    let org_promoted = seed_org(pool, "bf-promoted", false).await?;
    let earliest = seed_user(pool, "bf-earliest@example.test").await?;
    let later = seed_user(pool, "bf-later@example.test").await?;
    seed_membership(pool, earliest, org_promoted, "member", 90, false).await?;
    seed_membership(pool, later, org_promoted, "member", 60, false).await?;

    // Soft-deleted org: nothing is backfilled for it.
    let org_dead = seed_org(pool, "bf-dead", true).await?;
    let dead_member = seed_user(pool, "bf-dead-member@example.test").await?;
    seed_membership(pool, dead_member, org_dead, "owner", 30, false).await?;

    run_rbac_migrations(pool).await?;

    // Pre-existing live orgs got root nodes + version rows.
    for org in [org_mapped, org_promoted] {
        let roots: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM resource_nodes
             WHERE org_id = $1 AND scope_type = 'org' AND deleted_at IS NULL",
        )
        .bind(org)
        .fetch_one(pool)
        .await?;
        assert_eq!(roots, 1, "org {org}: backfilled root");
        let version: i64 =
            sqlx::query_scalar("SELECT version FROM org_permission_versions WHERE org_id = $1")
                .bind(org)
                .fetch_one(pool)
                .await?;
        assert_eq!(version, 1, "org {org}: backfilled version row");
    }

    // Fixed mapping (org_mapped has an owner, so no promotion there).
    assert_eq!(
        root_roles_for(pool, org_mapped, owner).await?,
        ["org_owner"]
    );
    assert_eq!(
        root_roles_for(pool, org_mapped, admin).await?,
        ["org_admin"]
    );
    assert_eq!(root_roles_for(pool, org_mapped, plain).await?, ["member"]);
    assert_eq!(
        root_roles_for(pool, org_mapped, unknown).await?,
        ["member"],
        "unknown basic_role maps to member"
    );
    assert_eq!(
        root_roles_for(pool, org_mapped, ghost).await?,
        Vec::<String>::new(),
        "soft-deleted membership gets no assignment"
    );

    // Promotion: earliest live membership gains org_owner IN ADDITION
    // to its mapped member binding.
    assert_eq!(
        root_roles_for(pool, org_promoted, earliest).await?,
        ["member", "org_owner"]
    );
    assert_eq!(root_roles_for(pool, org_promoted, later).await?, ["member"]);

    // Soft-deleted org: no root, no version row, no assignments.
    let dead_rows: i64 = sqlx::query_scalar(
        "SELECT (SELECT count(*) FROM resource_nodes WHERE org_id = $1)
              + (SELECT count(*) FROM org_permission_versions WHERE org_id = $1)
              + (SELECT count(*) FROM role_assignments WHERE org_id = $1)",
    )
    .bind(org_dead)
    .fetch_one(pool)
    .await?;
    assert_eq!(dead_rows, 0, "soft-deleted org must be untouched");

    // The migration-level invariant, re-asserted from the test side:
    // exactly one live org-root org_owner per live org.
    let owner_counts: Vec<(Uuid, i64)> = sqlx::query_as(
        "SELECT o.id, count(ra.id)
         FROM orgs o
         JOIN resource_nodes rn
             ON rn.org_id = o.id AND rn.scope_type = 'org' AND rn.deleted_at IS NULL
         LEFT JOIN role_assignments ra
             ON ra.node_id = rn.id AND ra.builtin_role = 'org_owner' AND ra.deleted_at IS NULL
         WHERE o.deleted_at IS NULL
         GROUP BY o.id",
    )
    .fetch_all(pool)
    .await?;
    assert_eq!(owner_counts.len(), 2, "two live orgs");
    for (org, owners) in owner_counts {
        assert_eq!(owners, 1, "org {org}: exactly one live org_owner");
    }
    Ok(())
}
