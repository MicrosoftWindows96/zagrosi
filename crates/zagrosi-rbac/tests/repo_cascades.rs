// SPDX-License-Identifier: AGPL-3.0-or-later

//! Repo-layer round-trips on `&mut TenantTx`, application-level
//! soft-delete cascades, and the version counter's cross-transaction
//! visibility.

use serial_test::serial;
use uuid::Uuid;
use zagrosi_db::begin_tenant_tx;
use zagrosi_rbac::domain::{
    AssignmentRole, BuiltinRole, Effect, NewCustomRole, NewCustomRoleEntry, NewResourceNode,
    NewRoleAssignment, ScopeType,
};
use zagrosi_rbac::repo;
use zagrosi_test_support::{TestDb, seed_org, seed_user};

type TestError = Box<dyn std::error::Error + Send + Sync>;
type TestResult = Result<(), TestError>;

#[tokio::test]
#[serial]
async fn repo_round_trips_nodes_roles_entries_assignments() -> TestResult {
    let db = TestDb::new().await?;
    let org = seed_org(db.migrate_pool(), "repo-rt").await?;
    let user = seed_user(db.migrate_pool(), "repo-rt@example.test").await?;

    let mut tx = begin_tenant_tx(db.app_pool(), org).await?;

    // The trigger-provisioned root anchors everything.
    let root = repo::org_root(&mut tx).await?;
    assert_eq!(root.org_id, org);
    assert_eq!(root.scope_type, ScopeType::Org);
    assert_eq!(root.parent_id, None);

    // Org-root payloads are rejected at the repo boundary.
    let bad = repo::insert_node(
        &mut tx,
        &NewResourceNode {
            id: Uuid::now_v7(),
            scope_type: ScopeType::Org,
            parent_id: root.id,
            external_id: None,
        },
    )
    .await;
    assert!(bad.is_err(), "insert_node must reject org scope");

    let workspace = repo::insert_node(
        &mut tx,
        &NewResourceNode {
            id: Uuid::now_v7(),
            scope_type: ScopeType::Workspace,
            parent_id: root.id,
            external_id: Some(Uuid::now_v7()),
        },
    )
    .await?;
    let fetched = repo::find_node(&mut tx, workspace.id).await?;
    assert_eq!(fetched.as_ref(), Some(&workspace));
    assert_eq!(
        repo::find_node(&mut tx, Uuid::now_v7()).await?,
        None,
        "unknown node id reads as absent"
    );

    let role = repo::insert_custom_role(
        &mut tx,
        &NewCustomRole {
            id: Uuid::now_v7(),
            name: "Incident Commander".to_owned(),
            description: Some("runs incidents".to_owned()),
        },
    )
    .await?;
    assert_eq!(
        repo::find_custom_role(&mut tx, role.id).await?.as_ref(),
        Some(&role)
    );
    assert_eq!(repo::list_custom_roles(&mut tx).await?, vec![role.clone()]);

    let entry = |capability: &str, effect: Effect| NewCustomRoleEntry {
        id: Uuid::now_v7(),
        capability: capability.to_owned(),
        effect,
    };
    let (before, after) = repo::replace_entries(
        &mut tx,
        role.id,
        &[
            entry("work_item.read", Effect::Grant),
            entry("audit.read", Effect::Deny),
        ],
    )
    .await?;
    assert!(before.is_empty(), "fresh role starts with no entries");
    assert_eq!(after.len(), 2);
    assert!(
        after
            .iter()
            .all(|e| e.custom_role_id == role.id && e.org_id == org)
    );

    // Replace-on-write: the old set is hard-deleted and returned.
    let (before, after) =
        repo::replace_entries(&mut tx, role.id, &[entry("org.manage", Effect::Grant)]).await?;
    assert_eq!(before.len(), 2);
    assert_eq!(after.len(), 1);
    assert_eq!(after[0].capability, "org.manage");
    let missing = repo::replace_entries(&mut tx, Uuid::now_v7(), &[]).await;
    assert!(missing.is_err(), "replace_entries on a missing role errors");

    let assignment = repo::insert_assignment(
        &mut tx,
        &NewRoleAssignment {
            id: Uuid::now_v7(),
            user_id: user,
            role: AssignmentRole::Custom(role.id),
            node_id: workspace.id,
            created_by: user,
        },
    )
    .await?;
    let builtin = repo::insert_assignment(
        &mut tx,
        &NewRoleAssignment {
            id: Uuid::now_v7(),
            user_id: user,
            role: AssignmentRole::Builtin(BuiltinRole::Member),
            node_id: root.id,
            created_by: user,
        },
    )
    .await?;
    let listed = repo::list_assignments_for_user(&mut tx, user).await?;
    assert_eq!(listed, vec![assignment.clone(), builtin.clone()]);

    repo::soft_delete_assignment(&mut tx, assignment.id).await?;
    let listed = repo::list_assignments_for_user(&mut tx, user).await?;
    assert_eq!(listed, vec![builtin]);

    repo::soft_delete_custom_role(&mut tx, role.id).await?;
    assert_eq!(repo::find_custom_role(&mut tx, role.id).await?, None);
    assert!(
        repo::soft_delete_custom_role(&mut tx, role.id)
            .await
            .is_err(),
        "second soft-delete reads as NotFound"
    );

    tx.commit().await?;
    Ok(())
}

#[tokio::test]
#[serial]
async fn node_cascade_soft_deletes_bound_assignments() -> TestResult {
    let db = TestDb::new().await?;
    let org = seed_org(db.migrate_pool(), "repo-node-cascade").await?;
    let user = seed_user(db.migrate_pool(), "repo-node-cascade@example.test").await?;

    let mut tx = begin_tenant_tx(db.app_pool(), org).await?;
    let root = repo::org_root(&mut tx).await?;
    let workspace = repo::insert_node(
        &mut tx,
        &NewResourceNode {
            id: Uuid::now_v7(),
            scope_type: ScopeType::Workspace,
            parent_id: root.id,
            external_id: None,
        },
    )
    .await?;
    for (node, role) in [
        (workspace.id, BuiltinRole::WorkspaceAdmin),
        (root.id, BuiltinRole::Member),
    ] {
        repo::insert_assignment(
            &mut tx,
            &NewRoleAssignment {
                id: Uuid::now_v7(),
                user_id: user,
                role: AssignmentRole::Builtin(role),
                node_id: node,
                created_by: user,
            },
        )
        .await?;
    }

    repo::soft_delete_node_cascade(&mut tx, workspace.id).await?;
    assert_eq!(repo::find_node(&mut tx, workspace.id).await?, None);
    let remaining = repo::list_assignments_for_user(&mut tx, user).await?;
    assert_eq!(remaining.len(), 1, "only the root binding survives");
    assert_eq!(remaining[0].node_id, root.id);

    // The org root is immutable through the single-node primitive.
    assert!(
        repo::soft_delete_node_cascade(&mut tx, root.id)
            .await
            .is_err(),
        "node cascade must reject the org root"
    );
    tx.commit().await?;
    Ok(())
}

#[tokio::test]
#[serial]
async fn org_cascade_soft_deletes_all_nodes_and_assignments() -> TestResult {
    let db = TestDb::new().await?;
    let org = seed_org(db.migrate_pool(), "repo-org-cascade").await?;
    let user = seed_user(db.migrate_pool(), "repo-org-cascade@example.test").await?;

    let mut tx = begin_tenant_tx(db.app_pool(), org).await?;
    let root = repo::org_root(&mut tx).await?;
    let workspace = repo::insert_node(
        &mut tx,
        &NewResourceNode {
            id: Uuid::now_v7(),
            scope_type: ScopeType::Workspace,
            parent_id: root.id,
            external_id: None,
        },
    )
    .await?;
    repo::insert_assignment(
        &mut tx,
        &NewRoleAssignment {
            id: Uuid::now_v7(),
            user_id: user,
            role: AssignmentRole::Builtin(BuiltinRole::Member),
            node_id: workspace.id,
            created_by: user,
        },
    )
    .await?;
    repo::soft_delete_org_cascade(&mut tx).await?;
    tx.commit().await?;

    // Owner-level ground truth: zero live rows remain for the org.
    let live: i64 = sqlx::query_scalar(
        "SELECT (SELECT count(*) FROM resource_nodes
                 WHERE org_id = $1 AND deleted_at IS NULL)
              + (SELECT count(*) FROM role_assignments
                 WHERE org_id = $1 AND deleted_at IS NULL)",
    )
    .bind(org)
    .fetch_one(db.migrate_pool())
    .await?;
    assert_eq!(live, 0, "org cascade must tombstone nodes + assignments");
    Ok(())
}

#[tokio::test]
#[serial]
async fn version_bump_is_visible_from_a_later_transaction() -> TestResult {
    let db = TestDb::new().await?;
    let org = seed_org(db.migrate_pool(), "repo-version").await?;

    let mut tx = begin_tenant_tx(db.app_pool(), org).await?;
    assert_eq!(repo::current_version(&mut tx).await?, 1, "trigger seeds v1");
    assert_eq!(repo::bump_version(&mut tx).await?, 2);
    tx.commit().await?;

    let mut tx = begin_tenant_tx(db.app_pool(), org).await?;
    assert_eq!(
        repo::current_version(&mut tx).await?,
        2,
        "committed bump visible from a separate transaction"
    );
    tx.rollback().await?;
    Ok(())
}
