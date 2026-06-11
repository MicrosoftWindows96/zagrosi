// SPDX-License-Identifier: AGPL-3.0-or-later

//! `role_assignments` persistence.

use uuid::Uuid;
use zagrosi_db::TenantTx;

use crate::domain::{AssignmentRole, NewRoleAssignment, RoleAssignment};
use crate::error::{Error, Result};

/// Insert a role binding. Hits the live-binding partial unique on a
/// duplicate `(user, node, role)`, and the FK / XOR constraints on bad
/// references.
///
/// # Errors
///
/// [`Error::Sqlx`] for constraint violations and database failures.
pub async fn insert_assignment(
    tx: &mut TenantTx<'_>,
    a: &NewRoleAssignment,
) -> Result<RoleAssignment> {
    let org_id = tx.org_id();
    let (builtin_role, custom_role_id) = a.role.columns();
    let row = sqlx::query!(
        r#"
        INSERT INTO role_assignments
            (id, org_id, user_id, builtin_role, custom_role_id, node_id, created_by)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING id, org_id, user_id, builtin_role, custom_role_id, node_id,
                  created_by, created_at, deleted_at
        "#,
        a.id,
        org_id,
        a.user_id,
        builtin_role,
        custom_role_id,
        a.node_id,
        a.created_by,
    )
    .fetch_one(tx.as_executor())
    .await?;
    Ok(RoleAssignment {
        id: row.id,
        org_id: row.org_id,
        user_id: row.user_id,
        role: AssignmentRole::from_columns(row.builtin_role.as_deref(), row.custom_role_id)?,
        node_id: row.node_id,
        created_by: row.created_by,
        created_at: row.created_at,
        deleted_at: row.deleted_at,
    })
}

/// Soft-delete a live assignment.
///
/// # Errors
///
/// [`Error::NotFound`] when no live row matched (absent, already
/// deleted, or foreign-org); [`Error::Sqlx`] for database failures.
pub async fn soft_delete_assignment(tx: &mut TenantTx<'_>, assignment_id: Uuid) -> Result<()> {
    let org_id = tx.org_id();
    let affected = sqlx::query!(
        r#"
        UPDATE role_assignments
        SET deleted_at = now()
        WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL
        "#,
        assignment_id,
        org_id,
    )
    .execute(tx.as_executor())
    .await?
    .rows_affected();
    if affected == 0 {
        return Err(Error::NotFound { id: assignment_id });
    }
    Ok(())
}

/// All live assignments for a user in the current org — the entry-set
/// source section-07 expands.
///
/// # Errors
///
/// [`Error::Sqlx`] for database failures;
/// [`Error::InvalidStoredValue`] for unparseable stored rows.
pub async fn list_assignments_for_user(
    tx: &mut TenantTx<'_>,
    user_id: Uuid,
) -> Result<Vec<RoleAssignment>> {
    let org_id = tx.org_id();
    let rows = sqlx::query!(
        r#"
        SELECT id, org_id, user_id, builtin_role, custom_role_id, node_id,
               created_by, created_at, deleted_at
        FROM role_assignments
        WHERE org_id = $1 AND user_id = $2 AND deleted_at IS NULL
        ORDER BY created_at, id
        "#,
        org_id,
        user_id,
    )
    .fetch_all(tx.as_executor())
    .await?;
    rows.into_iter()
        .map(|r| {
            Ok(RoleAssignment {
                id: r.id,
                org_id: r.org_id,
                user_id: r.user_id,
                role: AssignmentRole::from_columns(r.builtin_role.as_deref(), r.custom_role_id)?,
                node_id: r.node_id,
                created_by: r.created_by,
                created_at: r.created_at,
                deleted_at: r.deleted_at,
            })
        })
        .collect()
}
