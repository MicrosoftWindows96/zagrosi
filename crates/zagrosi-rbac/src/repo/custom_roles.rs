// SPDX-License-Identifier: AGPL-3.0-or-later

//! `custom_roles` + `custom_role_entries` persistence.

use uuid::Uuid;
use zagrosi_db::TenantTx;

use crate::domain::{CustomRole, CustomRoleEntry, Effect, NewCustomRole, NewCustomRoleEntry};
use crate::error::{Error, Result};

/// Insert a custom role. Hits the case-insensitive partial unique on
/// `(org_id, lower(name))` when a live role of the same name exists.
///
/// # Errors
///
/// [`Error::Sqlx`] for constraint violations and database failures.
pub async fn insert_custom_role(tx: &mut TenantTx<'_>, role: &NewCustomRole) -> Result<CustomRole> {
    let org_id = tx.org_id();
    let row = sqlx::query!(
        r#"
        INSERT INTO custom_roles (id, org_id, name, description)
        VALUES ($1, $2, $3, $4)
        RETURNING id, org_id, name, description, created_at, updated_at, deleted_at
        "#,
        role.id,
        org_id,
        role.name,
        role.description.as_deref(),
    )
    .fetch_one(tx.as_executor())
    .await?;
    Ok(CustomRole {
        id: row.id,
        org_id: row.org_id,
        name: row.name,
        description: row.description,
        created_at: row.created_at,
        updated_at: row.updated_at,
        deleted_at: row.deleted_at,
    })
}

/// Fetch a live custom role by id.
///
/// `None` covers absent, soft-deleted, and foreign-org rows alike — the
/// explicit `org_id` bind keeps that true even on a BYPASSRLS
/// connection (defense-in-depth alongside RLS).
///
/// # Errors
///
/// [`Error::Sqlx`] for database failures.
pub async fn find_custom_role(tx: &mut TenantTx<'_>, role_id: Uuid) -> Result<Option<CustomRole>> {
    let org_id = tx.org_id();
    let row = sqlx::query!(
        r#"
        SELECT id, org_id, name, description, created_at, updated_at, deleted_at
        FROM custom_roles
        WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL
        "#,
        role_id,
        org_id,
    )
    .fetch_optional(tx.as_executor())
    .await?;
    Ok(row.map(|r| CustomRole {
        id: r.id,
        org_id: r.org_id,
        name: r.name,
        description: r.description,
        created_at: r.created_at,
        updated_at: r.updated_at,
        deleted_at: r.deleted_at,
    }))
}

/// All live custom roles of the current org, name-ordered.
///
/// # Errors
///
/// [`Error::Sqlx`] for database failures.
pub async fn list_custom_roles(tx: &mut TenantTx<'_>) -> Result<Vec<CustomRole>> {
    let org_id = tx.org_id();
    let rows = sqlx::query!(
        r#"
        SELECT id, org_id, name, description, created_at, updated_at, deleted_at
        FROM custom_roles
        WHERE org_id = $1 AND deleted_at IS NULL
        ORDER BY lower(name), id
        "#,
        org_id,
    )
    .fetch_all(tx.as_executor())
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| CustomRole {
            id: r.id,
            org_id: r.org_id,
            name: r.name,
            description: r.description,
            created_at: r.created_at,
            updated_at: r.updated_at,
            deleted_at: r.deleted_at,
        })
        .collect())
}

/// Hard-delete the role's existing entries and insert the new set
/// (replace-on-write PUT semantics; entries have no `deleted_at`).
/// Returns `(before, after)` for audit payloads, both id-ordered.
///
/// # Errors
///
/// [`Error::NotFound`] when the role is absent / soft-deleted /
/// foreign-org; [`Error::Sqlx`] for database failures (including
/// `effect` CHECK and composite-FK violations).
pub async fn replace_entries(
    tx: &mut TenantTx<'_>,
    role_id: Uuid,
    entries: &[NewCustomRoleEntry],
) -> Result<(Vec<CustomRoleEntry>, Vec<CustomRoleEntry>)> {
    // Existence gate: an empty `entries` set would otherwise silently
    // no-op on a missing role (the composite FK only fires on INSERT).
    if find_custom_role(tx, role_id).await?.is_none() {
        return Err(Error::NotFound { id: role_id });
    }
    let org_id = tx.org_id();
    let deleted = sqlx::query!(
        r#"
        DELETE FROM custom_role_entries
        WHERE custom_role_id = $1 AND org_id = $2
        RETURNING id, custom_role_id, org_id, capability, effect, created_at
        "#,
        role_id,
        org_id,
    )
    .fetch_all(tx.as_executor())
    .await?;
    let mut before = deleted
        .into_iter()
        .map(|r| {
            Ok(CustomRoleEntry {
                id: r.id,
                custom_role_id: r.custom_role_id,
                org_id: r.org_id,
                capability: r.capability,
                effect: Effect::parse(&r.effect)?,
                created_at: r.created_at,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    before.sort_by_key(|e| e.id);

    let mut after = Vec::with_capacity(entries.len());
    for entry in entries {
        let row = sqlx::query!(
            r#"
            INSERT INTO custom_role_entries (id, custom_role_id, org_id, capability, effect)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id, custom_role_id, org_id, capability, effect, created_at
            "#,
            entry.id,
            role_id,
            org_id,
            entry.capability,
            entry.effect.as_str(),
        )
        .fetch_one(tx.as_executor())
        .await?;
        after.push(CustomRoleEntry {
            id: row.id,
            custom_role_id: row.custom_role_id,
            org_id: row.org_id,
            capability: row.capability,
            effect: Effect::parse(&row.effect)?,
            created_at: row.created_at,
        });
    }
    after.sort_by_key(|e| e.id);
    Ok((before, after))
}

/// Soft-delete a live custom role. Its entries stay in place (the role
/// is dead, so resolution never loads them); bindings referencing the
/// role are the caller's concern at composition time.
///
/// # Errors
///
/// [`Error::NotFound`] when no live row matched (absent, already
/// deleted, or foreign-org); [`Error::Sqlx`] for database failures.
pub async fn soft_delete_custom_role(tx: &mut TenantTx<'_>, role_id: Uuid) -> Result<()> {
    let org_id = tx.org_id();
    let affected = sqlx::query!(
        r#"
        UPDATE custom_roles
        SET deleted_at = now(), updated_at = now()
        WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL
        "#,
        role_id,
        org_id,
    )
    .execute(tx.as_executor())
    .await?
    .rows_affected();
    if affected == 0 {
        return Err(Error::NotFound { id: role_id });
    }
    Ok(())
}
