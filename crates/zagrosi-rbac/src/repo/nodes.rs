// SPDX-License-Identifier: AGPL-3.0-or-later

//! `resource_nodes` persistence.

use uuid::Uuid;
use zagrosi_db::TenantTx;

use crate::domain::{NewResourceNode, ResourceNode, ScopeType};
use crate::error::{Error, Result};

fn map_row(
    id: Uuid,
    org_id: Uuid,
    scope_type: &str,
    parent_id: Option<Uuid>,
    external_id: Option<Uuid>,
    created_at: chrono::DateTime<chrono::Utc>,
    deleted_at: Option<chrono::DateTime<chrono::Utc>>,
) -> Result<ResourceNode> {
    Ok(ResourceNode {
        id,
        org_id,
        scope_type: ScopeType::parse(scope_type)?,
        parent_id,
        external_id,
        created_at,
        deleted_at,
    })
}

/// Insert a non-org node. Org roots come only from the provisioning
/// trigger / backfill — [`ScopeType::Org`] payloads are rejected before
/// touching the database.
///
/// # Errors
///
/// [`Error::OrgRootMutationRejected`] for org-scope payloads;
/// [`Error::Sqlx`] for parent-validation trigger rejections (missing /
/// soft-deleted / cross-org / non-higher-scope parent) and constraint
/// violations.
pub async fn insert_node(tx: &mut TenantTx<'_>, node: &NewResourceNode) -> Result<ResourceNode> {
    if node.scope_type == ScopeType::Org {
        return Err(Error::OrgRootMutationRejected);
    }
    let org_id = tx.org_id();
    let row = sqlx::query!(
        r#"
        INSERT INTO resource_nodes (id, org_id, scope_type, parent_id, external_id)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING id, org_id, scope_type, parent_id, external_id, created_at, deleted_at
        "#,
        node.id,
        org_id,
        node.scope_type.as_str(),
        node.parent_id,
        node.external_id,
    )
    .fetch_one(tx.as_executor())
    .await?;
    map_row(
        row.id,
        row.org_id,
        &row.scope_type,
        row.parent_id,
        row.external_id,
        row.created_at,
        row.deleted_at,
    )
}

/// Fetch a live node by id. `None` covers absent, soft-deleted, and
/// foreign-org rows alike — the explicit `org_id` bind keeps that true
/// even on a BYPASSRLS connection (defense-in-depth alongside RLS).
///
/// # Errors
///
/// [`Error::Sqlx`] for database failures;
/// [`Error::InvalidStoredValue`] for unparseable stored rows.
pub async fn find_node(tx: &mut TenantTx<'_>, node_id: Uuid) -> Result<Option<ResourceNode>> {
    let org_id = tx.org_id();
    let row = sqlx::query!(
        r#"
        SELECT id, org_id, scope_type, parent_id, external_id, created_at, deleted_at
        FROM resource_nodes
        WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL
        "#,
        node_id,
        org_id,
    )
    .fetch_optional(tx.as_executor())
    .await?;
    row.map(|r| {
        map_row(
            r.id,
            r.org_id,
            &r.scope_type,
            r.parent_id,
            r.external_id,
            r.created_at,
            r.deleted_at,
        )
    })
    .transpose()
}

/// The org's live root node (exactly one, by the partial unique).
///
/// # Errors
///
/// [`Error::OrgRootMissing`] when the provisioning invariant is broken;
/// [`Error::Sqlx`] for database failures.
pub async fn org_root(tx: &mut TenantTx<'_>) -> Result<ResourceNode> {
    let org_id = tx.org_id();
    let row = sqlx::query!(
        r#"
        SELECT id, org_id, scope_type, parent_id, external_id, created_at, deleted_at
        FROM resource_nodes
        WHERE org_id = $1 AND scope_type = 'org' AND deleted_at IS NULL
        "#,
        org_id,
    )
    .fetch_optional(tx.as_executor())
    .await?
    .ok_or(Error::OrgRootMissing)?;
    map_row(
        row.id,
        row.org_id,
        &row.scope_type,
        row.parent_id,
        row.external_id,
        row.created_at,
        row.deleted_at,
    )
}
