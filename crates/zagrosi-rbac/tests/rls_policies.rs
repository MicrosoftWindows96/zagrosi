// SPDX-License-Identifier: AGPL-3.0-or-later

//! Direct RLS spot checks on the five rbac tables, for fast failure —
//! the catalog-driven proptests in identity's `rls_isolation` suite
//! auto-cover these tables via the shared catalog; this file is the
//! crate-local early-warning version.

use serial_test::serial;
use sqlx::PgPool;
use uuid::Uuid;
use zagrosi_db::begin_tenant_tx;
use zagrosi_test_support::{TestDb, rls_catalog, seed_org, seed_user};

type TestError = Box<dyn std::error::Error + Send + Sync>;
type TestResult = Result<(), TestError>;

const RBAC_TABLES: [&str; 5] = [
    "resource_nodes",
    "org_permission_versions",
    "custom_roles",
    "custom_role_entries",
    "role_assignments",
];

/// Seed every rbac table for `org` via the shared catalog seeders
/// (BYPASSRLS pool).
async fn seed_rbac(pool: &PgPool, org: Uuid) -> TestResult {
    for entry in rls_catalog()
        .iter()
        .filter(|e| RBAC_TABLES.contains(&e.table))
    {
        let seed = entry.seed.ok_or("rbac entry without seeder")?;
        seed(pool, org).await?;
    }
    Ok(())
}

/// Anchor rows (owner-level lookups) for building per-table INSERT
/// probes attributed to `org`. Requires `seed_rbac(org)` to have run.
struct ProbeAnchors {
    root: Uuid,
    role: Uuid,
    user: Uuid,
}

async fn probe_anchors(db: &TestDb, org: Uuid) -> Result<ProbeAnchors, TestError> {
    let root: Uuid = sqlx::query_scalar(
        "SELECT id FROM resource_nodes
         WHERE org_id = $1 AND scope_type = 'org' AND deleted_at IS NULL",
    )
    .bind(org)
    .fetch_one(db.migrate_pool())
    .await?;
    let role: Uuid = sqlx::query_scalar("SELECT id FROM custom_roles WHERE org_id = $1 LIMIT 1")
        .bind(org)
        .fetch_one(db.migrate_pool())
        .await?;
    let user = seed_user(
        db.migrate_pool(),
        &format!("probe-{}@example.test", Uuid::now_v7().simple()),
    )
    .await?;
    Ok(ProbeAnchors { root, role, user })
}

/// Attempt an INSERT into `table` attributed to `org` over `exec`.
/// Every probe must FAIL when `org` is not the caller's tenant context —
/// via WITH CHECK, the invoker parent-validation trigger, or a missing
/// verb grant, whichever fires first.
async fn org_attributed_insert<'e, E>(
    exec: E,
    table: &str,
    org: Uuid,
    anchors: &ProbeAnchors,
) -> Result<(), sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    let id = Uuid::now_v7();
    let query = match table {
        "resource_nodes" => sqlx::query(
            "INSERT INTO resource_nodes (id, org_id, scope_type, parent_id)
             VALUES ($1, $2, 'workspace', $3)",
        )
        .bind(id)
        .bind(org)
        .bind(anchors.root),
        "org_permission_versions" => {
            sqlx::query("INSERT INTO org_permission_versions (org_id) VALUES ($1)").bind(org)
        }
        "custom_roles" => {
            sqlx::query("INSERT INTO custom_roles (id, org_id, name) VALUES ($1, $2, $3)")
                .bind(id)
                .bind(org)
                .bind(format!("probe {id}"))
        }
        "custom_role_entries" => sqlx::query(
            "INSERT INTO custom_role_entries (id, custom_role_id, org_id, capability, effect)
             VALUES ($1, $2, $3, 'work_item.read', 'grant')",
        )
        .bind(id)
        .bind(anchors.role)
        .bind(org),
        "role_assignments" => sqlx::query(
            "INSERT INTO role_assignments
                 (id, org_id, user_id, builtin_role, node_id, created_by)
             VALUES ($1, $2, $3, 'guest', $4, $3)",
        )
        .bind(id)
        .bind(org)
        .bind(anchors.user)
        .bind(anchors.root),
        other => {
            return Err(sqlx::Error::Protocol(format!(
                "unknown probe table {other}"
            )));
        }
    };
    query.execute(exec).await.map(|_| ())
}

#[tokio::test]
#[serial]
async fn org_a_context_sees_zero_org_b_rows_and_cannot_write_them() -> TestResult {
    let db = TestDb::new().await?;
    let org_a = seed_org(db.migrate_pool(), "rls-spot-a").await?;
    let org_b = seed_org(db.migrate_pool(), "rls-spot-b").await?;
    seed_rbac(db.migrate_pool(), org_a).await?;
    seed_rbac(db.migrate_pool(), org_b).await?;

    for table in RBAC_TABLES {
        let mut tx = begin_tenant_tx(db.app_pool(), org_a).await?;
        let foreign: i64 =
            sqlx::query_scalar(&format!("SELECT count(*) FROM {table} WHERE org_id = $1"))
                .bind(org_b)
                .fetch_one(tx.as_executor())
                .await?;
        let own: i64 =
            sqlx::query_scalar(&format!("SELECT count(*) FROM {table} WHERE org_id = $1"))
                .bind(org_a)
                .fetch_one(tx.as_executor())
                .await?;
        tx.commit().await?;
        assert_eq!(foreign, 0, "{table}: org-B rows visible under org-A");
        assert!(own > 0, "{table}: own rows must be visible");
    }

    // INSERT of an org-B-attributed row under org-A context must fail on
    // every rbac table (one transaction per probe — a 42501 verb denial
    // aborts the transaction it fires in).
    let anchors_b = probe_anchors(&db, org_b).await?;
    for table in RBAC_TABLES {
        let mut tx = begin_tenant_tx(db.app_pool(), org_a).await?;
        let outcome = org_attributed_insert(tx.as_executor(), table, org_b, &anchors_b).await;
        tx.rollback().await?;
        assert!(
            outcome.is_err(),
            "{table}: org-B INSERT under org-A context must fail"
        );
    }
    Ok(())
}

#[tokio::test]
#[serial]
async fn no_guc_fails_closed_on_every_rbac_table() -> TestResult {
    let db = TestDb::new().await?;
    let org = seed_org(db.migrate_pool(), "rls-spot-noguc").await?;
    seed_rbac(db.migrate_pool(), org).await?;

    for table in RBAC_TABLES {
        // Plain pool connection: no GUC at all.
        let visible: i64 = sqlx::query_scalar(&format!("SELECT count(*) FROM {table}"))
            .fetch_one(db.app_pool())
            .await?;
        assert_eq!(visible, 0, "{table}: no-GUC SELECT must see zero rows");
    }

    // INSERT without tenant context must fail on every rbac table.
    let anchors = probe_anchors(&db, org).await?;
    for table in RBAC_TABLES {
        let outcome = org_attributed_insert(db.app_pool(), table, org, &anchors).await;
        assert!(
            outcome.is_err(),
            "{table}: INSERT without GUC must fail closed"
        );
    }
    Ok(())
}
