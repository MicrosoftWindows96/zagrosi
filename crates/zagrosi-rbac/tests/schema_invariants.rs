// SPDX-License-Identifier: AGPL-3.0-or-later

//! Constraint-level invariants, exercised as `zagrosi_app` under tenant
//! transactions (the role real traffic uses): scope-tree shape rules,
//! the org-root partial unique, assignment XOR + binding uniqueness,
//! case-insensitive role names, and the entries' composite-FK org pin.

use serial_test::serial;
use sqlx::PgPool;
use uuid::Uuid;
use zagrosi_db::{TenantTx, begin_tenant_tx};
use zagrosi_test_support::{TestDb, seed_org, seed_user};

type TestError = Box<dyn std::error::Error + Send + Sync>;
type TestResult = Result<(), TestError>;

/// Live org-root node id (owner-level lookup).
async fn root_of(pool: &PgPool, org: Uuid) -> Result<Uuid, TestError> {
    Ok(sqlx::query_scalar(
        "SELECT id FROM resource_nodes
         WHERE org_id = $1 AND scope_type = 'org' AND deleted_at IS NULL",
    )
    .bind(org)
    .fetch_one(pool)
    .await?)
}

/// Insert a node as the current tenant; returns the generated id.
async fn try_insert_node(
    tx: &mut TenantTx<'_>,
    org: Uuid,
    scope: &str,
    parent: Option<Uuid>,
) -> Result<Uuid, sqlx::Error> {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO resource_nodes (id, org_id, scope_type, parent_id) VALUES ($1, $2, $3, $4)",
    )
    .bind(id)
    .bind(org)
    .bind(scope)
    .bind(parent)
    .execute(tx.as_executor())
    .await?;
    Ok(id)
}

#[tokio::test]
#[serial]
async fn scope_tree_shape_rules_hold() -> TestResult {
    let db = TestDb::new().await?;
    let org = seed_org(db.migrate_pool(), "inv-shape").await?;
    let root = root_of(db.migrate_pool(), org).await?;

    // CHECK pair: org scope with a parent; non-org scope without one.
    let mut tx = begin_tenant_tx(db.app_pool(), org).await?;
    assert!(
        try_insert_node(&mut tx, org, "org", Some(root))
            .await
            .is_err(),
        "org node with a parent must be rejected"
    );
    tx.rollback().await?;
    let mut tx = begin_tenant_tx(db.app_pool(), org).await?;
    assert!(
        try_insert_node(&mut tx, org, "project", None)
            .await
            .is_err(),
        "non-org node without a parent must be rejected"
    );
    tx.rollback().await?;

    // Strictly-higher parent rule, including level skips.
    let mut tx = begin_tenant_tx(db.app_pool(), org).await?;
    let project = try_insert_node(&mut tx, org, "project", Some(root)).await?;
    assert!(
        try_insert_node(&mut tx, org, "project", Some(project))
            .await
            .is_err(),
        "project under project (equal scope) must be rejected"
    );
    tx.rollback().await?;

    let mut tx = begin_tenant_tx(db.app_pool(), org).await?;
    let record = try_insert_node(&mut tx, org, "record", Some(root)).await?;
    assert!(
        try_insert_node(&mut tx, org, "workspace", Some(record))
            .await
            .is_err(),
        "workspace under record (lower scope parent) must be rejected"
    );
    tx.rollback().await?;

    // Accepted chains: workspace -> service, and skip-level project
    // directly under the org root (committed so later asserts see them).
    let mut tx = begin_tenant_tx(db.app_pool(), org).await?;
    let workspace = try_insert_node(&mut tx, org, "workspace", Some(root)).await?;
    let service = try_insert_node(&mut tx, org, "service", Some(workspace)).await?;
    let skip_project = try_insert_node(&mut tx, org, "project", Some(root)).await?;
    let deep_record = try_insert_node(&mut tx, org, "record", Some(service)).await?;
    tx.commit().await?;
    for id in [workspace, service, skip_project, deep_record] {
        let live: bool =
            sqlx::query_scalar("SELECT deleted_at IS NULL FROM resource_nodes WHERE id = $1")
                .bind(id)
                .fetch_one(db.migrate_pool())
                .await?;
        assert!(live, "accepted node {id} must exist live");
    }
    Ok(())
}

#[tokio::test]
#[serial]
async fn cross_org_and_dead_parents_are_rejected() -> TestResult {
    let db = TestDb::new().await?;
    let org_a = seed_org(db.migrate_pool(), "inv-parent-a").await?;
    let org_b = seed_org(db.migrate_pool(), "inv-parent-b").await?;
    let root_a = root_of(db.migrate_pool(), org_a).await?;

    // Under org-B context the org-A root is invisible (RLS) — the
    // SECURITY INVOKER trigger lookup fails closed.
    let mut tx = begin_tenant_tx(db.app_pool(), org_b).await?;
    assert!(
        try_insert_node(&mut tx, org_b, "workspace", Some(root_a))
            .await
            .is_err(),
        "cross-org parent must be rejected"
    );
    tx.rollback().await?;

    // Soft-deleted parent.
    let mut tx = begin_tenant_tx(db.app_pool(), org_a).await?;
    let workspace = try_insert_node(&mut tx, org_a, "workspace", Some(root_a)).await?;
    tx.commit().await?;
    sqlx::query("UPDATE resource_nodes SET deleted_at = now() WHERE id = $1")
        .bind(workspace)
        .execute(db.migrate_pool())
        .await?;
    let mut tx = begin_tenant_tx(db.app_pool(), org_a).await?;
    assert!(
        try_insert_node(&mut tx, org_a, "project", Some(workspace))
            .await
            .is_err(),
        "soft-deleted parent must be rejected"
    );
    tx.rollback().await?;
    Ok(())
}

#[tokio::test]
#[serial]
async fn org_root_partial_unique_allows_replacement_after_soft_delete() -> TestResult {
    let db = TestDb::new().await?;
    let org = seed_org(db.migrate_pool(), "inv-root").await?;
    let root = root_of(db.migrate_pool(), org).await?;

    let mut tx = begin_tenant_tx(db.app_pool(), org).await?;
    assert!(
        try_insert_node(&mut tx, org, "org", None).await.is_err(),
        "second live org root must hit the partial unique"
    );
    tx.rollback().await?;

    sqlx::query("UPDATE resource_nodes SET deleted_at = now() WHERE id = $1")
        .bind(root)
        .execute(db.migrate_pool())
        .await?;
    let mut tx = begin_tenant_tx(db.app_pool(), org).await?;
    let replacement = try_insert_node(&mut tx, org, "org", None).await?;
    tx.commit().await?;
    assert_ne!(replacement, root, "fresh root row after tombstoning");
    Ok(())
}

/// Bound-parameter assignment insert; returns the generated id.
async fn insert_assignment(
    tx: &mut TenantTx<'_>,
    org: Uuid,
    user: Uuid,
    node: Uuid,
    builtin: Option<&str>,
    custom: Option<Uuid>,
) -> (Uuid, Result<(), sqlx::Error>) {
    let id = Uuid::now_v7();
    let outcome = sqlx::query(
        "INSERT INTO role_assignments
             (id, org_id, user_id, builtin_role, custom_role_id, node_id, created_by)
         VALUES ($1, $2, $3, $4, $5, $6, $3)",
    )
    .bind(id)
    .bind(org)
    .bind(user)
    .bind(builtin)
    .bind(custom)
    .bind(node)
    .execute(tx.as_executor())
    .await
    .map(|_| ());
    (id, outcome)
}

#[tokio::test]
#[serial]
async fn assignment_xor_uniqueness_and_name_checks_hold() -> TestResult {
    let db = TestDb::new().await?;
    let org = seed_org(db.migrate_pool(), "inv-assign").await?;
    let user = seed_user(db.migrate_pool(), "inv-assign@example.test").await?;
    let root = root_of(db.migrate_pool(), org).await?;

    // A custom role to exercise the XOR's custom side.
    let custom_role = Uuid::now_v7();
    let mut tx = begin_tenant_tx(db.app_pool(), org).await?;
    sqlx::query("INSERT INTO custom_roles (id, org_id, name) VALUES ($1, $2, 'xor probe')")
        .bind(custom_role)
        .bind(org)
        .execute(tx.as_executor())
        .await?;
    tx.commit().await?;

    // XOR: both set / neither set. Unknown built-in name.
    for (label, builtin, custom) in [
        ("both", Some("member"), Some(custom_role)),
        ("neither", None, None),
        ("unknown name", Some("superadmin"), None),
    ] {
        let mut tx = begin_tenant_tx(db.app_pool(), org).await?;
        let (_, outcome) = insert_assignment(&mut tx, org, user, root, builtin, custom).await;
        tx.rollback().await?;
        assert!(outcome.is_err(), "case `{label}` must be rejected");
    }

    // Duplicate live binding; re-grant after soft-delete succeeds.
    let mut tx = begin_tenant_tx(db.app_pool(), org).await?;
    let (first_id, outcome) =
        insert_assignment(&mut tx, org, user, root, Some("member"), None).await;
    outcome?;
    tx.commit().await?;
    let mut tx = begin_tenant_tx(db.app_pool(), org).await?;
    let (_, dup) = insert_assignment(&mut tx, org, user, root, Some("member"), None).await;
    tx.rollback().await?;
    assert!(dup.is_err(), "duplicate live binding must be rejected");
    sqlx::query("UPDATE role_assignments SET deleted_at = now() WHERE id = $1")
        .bind(first_id)
        .execute(db.migrate_pool())
        .await?;
    let mut tx = begin_tenant_tx(db.app_pool(), org).await?;
    let (_, regrant) = insert_assignment(&mut tx, org, user, root, Some("member"), None).await;
    regrant?;
    tx.commit().await?;
    Ok(())
}

#[tokio::test]
#[serial]
async fn custom_role_names_unique_case_insensitively_among_live_rows() -> TestResult {
    let db = TestDb::new().await?;
    let org = seed_org(db.migrate_pool(), "inv-names").await?;

    let first = Uuid::now_v7();
    let mut tx = begin_tenant_tx(db.app_pool(), org).await?;
    sqlx::query("INSERT INTO custom_roles (id, org_id, name) VALUES ($1, $2, 'Admins')")
        .bind(first)
        .bind(org)
        .execute(tx.as_executor())
        .await?;
    tx.commit().await?;

    let mut tx = begin_tenant_tx(db.app_pool(), org).await?;
    let dup = sqlx::query("INSERT INTO custom_roles (id, org_id, name) VALUES ($1, $2, 'admins')")
        .bind(Uuid::now_v7())
        .bind(org)
        .execute(tx.as_executor())
        .await;
    tx.rollback().await?;
    assert!(dup.is_err(), "`admins` vs `Admins` must collide");

    sqlx::query("UPDATE custom_roles SET deleted_at = now() WHERE id = $1")
        .bind(first)
        .execute(db.migrate_pool())
        .await?;
    let mut tx = begin_tenant_tx(db.app_pool(), org).await?;
    sqlx::query("INSERT INTO custom_roles (id, org_id, name) VALUES ($1, $2, 'admins')")
        .bind(Uuid::now_v7())
        .bind(org)
        .execute(tx.as_executor())
        .await?;
    tx.commit().await?;
    Ok(())
}

#[tokio::test]
#[serial]
async fn entry_effect_check_and_composite_fk_org_pin_hold() -> TestResult {
    let db = TestDb::new().await?;
    let org_a = seed_org(db.migrate_pool(), "inv-entry-a").await?;
    let org_b = seed_org(db.migrate_pool(), "inv-entry-b").await?;

    let role_a = Uuid::now_v7();
    let mut tx = begin_tenant_tx(db.app_pool(), org_a).await?;
    sqlx::query("INSERT INTO custom_roles (id, org_id, name) VALUES ($1, $2, 'entry probe')")
        .bind(role_a)
        .bind(org_a)
        .execute(tx.as_executor())
        .await?;
    tx.commit().await?;

    // effect outside ('grant','deny').
    let mut tx = begin_tenant_tx(db.app_pool(), org_a).await?;
    let bad_effect = sqlx::query(
        "INSERT INTO custom_role_entries (id, custom_role_id, org_id, capability, effect)
         VALUES ($1, $2, $3, 'work_item.read', 'allow')",
    )
    .bind(Uuid::now_v7())
    .bind(role_a)
    .bind(org_a)
    .execute(tx.as_executor())
    .await;
    tx.rollback().await?;
    assert!(bad_effect.is_err(), "effect `allow` must be rejected");

    // Composite FK pins the denormalized org: an org-B entry pointing
    // at org-A's role has no (role_a, org_b) target.
    let mut tx = begin_tenant_tx(db.app_pool(), org_b).await?;
    let cross = sqlx::query(
        "INSERT INTO custom_role_entries (id, custom_role_id, org_id, capability, effect)
         VALUES ($1, $2, $3, 'work_item.read', 'grant')",
    )
    .bind(Uuid::now_v7())
    .bind(role_a)
    .bind(org_b)
    .execute(tx.as_executor())
    .await;
    tx.rollback().await?;
    assert!(
        cross.is_err(),
        "entry whose (custom_role_id, org_id) matches no role must be rejected"
    );

    // The straight case still works.
    let mut tx = begin_tenant_tx(db.app_pool(), org_a).await?;
    sqlx::query(
        "INSERT INTO custom_role_entries (id, custom_role_id, org_id, capability, effect)
         VALUES ($1, $2, $3, 'work_item.read', 'grant')",
    )
    .bind(Uuid::now_v7())
    .bind(role_a)
    .bind(org_a)
    .execute(tx.as_executor())
    .await?;
    tx.commit().await?;
    Ok(())
}
