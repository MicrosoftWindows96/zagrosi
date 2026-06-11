// SPDX-License-Identifier: AGPL-3.0-or-later

//! Application-level soft-delete cascade helpers.
//!
//! Extends identity's `repo/cascade.rs` convention: Postgres
//! `FK CASCADE` is incompatible with soft-delete, so the cascade is
//! enforced here, atomically inside the caller's tenant transaction.

use uuid::Uuid;
use zagrosi_db::TenantTx;

use crate::domain::ScopeType;
use crate::error::{Error, Result};

/// Soft-delete a node and every live assignment bound to it (same
/// transaction).
///
/// Descendant nodes are the service layer's concern (section-09 walks
/// the tree); this helper is the single-node primitive. Org roots are
/// rejected — tombstoning the root of a live org would orphan its whole
/// lineage; org teardown goes through [`soft_delete_org_cascade`].
///
/// # Errors
///
/// [`Error::NotFound`] when the node is absent / already deleted /
/// foreign-org; [`Error::OrgRootMutationRejected`] for the org root;
/// [`Error::Sqlx`] for database failures.
pub async fn soft_delete_node_cascade(tx: &mut TenantTx<'_>, node_id: Uuid) -> Result<()> {
    match super::find_node(tx, node_id).await? {
        None => return Err(Error::NotFound { id: node_id }),
        Some(node) if node.scope_type == ScopeType::Org => {
            return Err(Error::OrgRootMutationRejected);
        }
        Some(_) => {}
    }
    let org_id = tx.org_id();
    sqlx::query!(
        r#"
        UPDATE resource_nodes
        SET deleted_at = now()
        WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL
        "#,
        node_id,
        org_id,
    )
    .execute(tx.as_executor())
    .await?;
    sqlx::query!(
        r#"
        UPDATE role_assignments
        SET deleted_at = now()
        WHERE node_id = $1 AND org_id = $2 AND deleted_at IS NULL
        "#,
        node_id,
        org_id,
    )
    .execute(tx.as_executor())
    .await?;
    Ok(())
}

/// Soft-delete all of the org's nodes (root included) and their
/// assignments.
///
/// Invoked from org soft-delete flows at composition time — identity
/// never links rbac directly. Idempotent: zero live rows is not an
/// error. `custom_roles` / `custom_role_entries` are deliberately left
/// untouched (the plan scopes this helper to nodes + assignments); the
/// composition-time org-teardown flow owns role cleanup if the
/// name-uniqueness slot or storage ever matters for dead orgs.
///
/// # Errors
///
/// [`Error::Sqlx`] for database failures.
pub async fn soft_delete_org_cascade(tx: &mut TenantTx<'_>) -> Result<()> {
    let org_id = tx.org_id();
    sqlx::query!(
        r#"
        UPDATE role_assignments
        SET deleted_at = now()
        WHERE org_id = $1 AND deleted_at IS NULL
        "#,
        org_id,
    )
    .execute(tx.as_executor())
    .await?;
    sqlx::query!(
        r#"
        UPDATE resource_nodes
        SET deleted_at = now()
        WHERE org_id = $1 AND deleted_at IS NULL
        "#,
        org_id,
    )
    .execute(tx.as_executor())
    .await?;
    Ok(())
}
