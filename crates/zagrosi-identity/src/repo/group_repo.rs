// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! `GroupRepo` — SCIM 2.0 `Group` persistence (multi-tenant).
//!
//! Groups belong to exactly one org. Every method is reached through
//! [`super::OrgScoped`] so the `WHERE org_id = $1` predicate is
//! provably present on every multi-tenant query (see the SCIM
//! tenant-isolation invariant in section-12).

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use sqlx::Postgres;
use sqlx::Row;
use sqlx::postgres::PgRow;
use uuid::Uuid;

use crate::domain::{Group, GroupMembership};
use crate::error::{IdentityError, Result, map_sqlx_error};

use super::OrgScoped;

/// Re-construct a [`Group`] from an arbitrary `sqlx::PgRow`.
/// Mirror of `super::user_repo::user_from_row` for the Groups
/// SCIM list handler.
///
/// # Errors
///
/// Returns [`IdentityError::Database`] for any column-extraction
/// failure.
pub fn group_from_row(row: &PgRow) -> Result<Group> {
    fn boxed(err: sqlx::Error) -> IdentityError {
        IdentityError::Database(Box::new(err))
    }
    Ok(Group {
        id: row.try_get("id").map_err(boxed)?,
        org_id: row.try_get("org_id").map_err(boxed)?,
        display_name: row.try_get("display_name").map_err(boxed)?,
        external_id: row.try_get("external_id").map_err(boxed)?,
        row_version: row.try_get("row_version").map_err(boxed)?,
        created_at: row.try_get("created_at").map_err(boxed)?,
        updated_at: row.try_get("updated_at").map_err(boxed)?,
        deleted_at: row.try_get("deleted_at").map_err(boxed)?,
    })
}

/// Repository for `groups` + `group_memberships`. Multi-tenant —
/// callers MUST go through [`OrgScoped`].
#[derive(Clone)]
pub struct GroupRepo {
    pool: PgPool,
}

impl GroupRepo {
    /// Wrap a connection pool.
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Pool accessor for `OrgScoped` impls.
    #[must_use]
    pub const fn pool(&self) -> &PgPool {
        &self.pool
    }
}

/// Argument bundle for [`OrgScoped::<GroupRepo>::create`].
#[derive(Debug, Clone, Copy)]
pub struct NewGroup<'a> {
    /// Application-generated UUID v7.
    pub id: Uuid,
    /// SCIM `displayName`.
    pub display_name: &'a str,
    /// SCIM `externalId` (IdP-assigned).
    pub external_id: Option<&'a str>,
}

impl OrgScoped<'_, GroupRepo> {
    /// Insert a new group within this org.
    pub async fn create_group(&self, new: NewGroup<'_>) -> Result<Group> {
        self.create_group_in_pool(new, self.inner().pool()).await
    }

    /// Insert a new group within a caller-supplied transaction.
    pub async fn create_group_in_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, Postgres>,
        new: NewGroup<'_>,
    ) -> Result<Group> {
        let row = sqlx::query!(
            r#"
            INSERT INTO groups (id, org_id, display_name, external_id)
            VALUES ($1, $2, $3, $4)
            RETURNING id, org_id, display_name, external_id, row_version,
                      created_at, updated_at, deleted_at
            "#,
            new.id,
            self.org_id(),
            new.display_name,
            new.external_id,
        )
        .fetch_one(&mut **tx)
        .await
        .map_err(|e| {
            map_sqlx_error(
                e,
                IdentityError::GroupNotFound,
                IdentityError::GroupDisplayNameExists,
                Some("groups_org_display_name_unique_live"),
            )
        })?;
        Ok(Group {
            id: row.id,
            org_id: row.org_id,
            display_name: row.display_name,
            external_id: row.external_id,
            row_version: row.row_version,
            created_at: row.created_at,
            updated_at: row.updated_at,
            deleted_at: row.deleted_at,
        })
    }

    async fn create_group_in_pool(&self, new: NewGroup<'_>, pool: &PgPool) -> Result<Group> {
        let row = sqlx::query!(
            r#"
            INSERT INTO groups (id, org_id, display_name, external_id)
            VALUES ($1, $2, $3, $4)
            RETURNING id, org_id, display_name, external_id, row_version,
                      created_at, updated_at, deleted_at
            "#,
            new.id,
            self.org_id(),
            new.display_name,
            new.external_id,
        )
        .fetch_one(pool)
        .await
        .map_err(|e| {
            map_sqlx_error(
                e,
                IdentityError::GroupNotFound,
                IdentityError::GroupDisplayNameExists,
                Some("groups_org_display_name_unique_live"),
            )
        })?;
        Ok(Group {
            id: row.id,
            org_id: row.org_id,
            display_name: row.display_name,
            external_id: row.external_id,
            row_version: row.row_version,
            created_at: row.created_at,
            updated_at: row.updated_at,
            deleted_at: row.deleted_at,
        })
    }

    /// Lookup a live group by id, scoped to this org. Cross-org IDs
    /// resolve to `None` so the SCIM handler can return `404` without
    /// the response status leaking existence.
    pub async fn find_group(&self, id: Uuid) -> Result<Option<Group>> {
        let row = sqlx::query!(
            r#"
            SELECT id, org_id, display_name, external_id, row_version,
                   created_at, updated_at, deleted_at
            FROM groups
            WHERE org_id = $1 AND id = $2 AND deleted_at IS NULL
            "#,
            self.org_id(),
            id,
        )
        .fetch_optional(self.inner().pool())
        .await?;
        Ok(row.map(|r| Group {
            id: r.id,
            org_id: r.org_id,
            display_name: r.display_name,
            external_id: r.external_id,
            row_version: r.row_version,
            created_at: r.created_at,
            updated_at: r.updated_at,
            deleted_at: r.deleted_at,
        }))
    }

    /// Lookup a live group by id within a caller-supplied transaction.
    pub async fn find_group_in_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, Postgres>,
        id: Uuid,
    ) -> Result<Option<Group>> {
        let row = sqlx::query!(
            r#"
            SELECT id, org_id, display_name, external_id, row_version,
                   created_at, updated_at, deleted_at
            FROM groups
            WHERE org_id = $1 AND id = $2 AND deleted_at IS NULL
            "#,
            self.org_id(),
            id,
        )
        .fetch_optional(&mut **tx)
        .await?;
        Ok(row.map(|r| Group {
            id: r.id,
            org_id: r.org_id,
            display_name: r.display_name,
            external_id: r.external_id,
            row_version: r.row_version,
            created_at: r.created_at,
            updated_at: r.updated_at,
            deleted_at: r.deleted_at,
        }))
    }

    /// Update a group's `display_name` / `external_id`. Bumps
    /// `row_version` by 1 and updates `updated_at`. Returns the row
    /// post-update so the caller can derive the new ETag without a
    /// re-read.
    pub async fn update_group_in_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, Postgres>,
        id: Uuid,
        display_name: &str,
        external_id: Option<&str>,
        if_match_version: Option<i64>,
    ) -> Result<Group> {
        let row_opt = sqlx::query!(
            r#"
            UPDATE groups
            SET display_name = $3,
                external_id = $4,
                row_version = row_version + 1,
                updated_at = now()
            WHERE org_id = $1
              AND id = $2
              AND deleted_at IS NULL
              AND ($5::BIGINT IS NULL OR row_version = $5)
            RETURNING id, org_id, display_name, external_id, row_version,
                      created_at, updated_at, deleted_at
            "#,
            self.org_id(),
            id,
            display_name,
            external_id,
            if_match_version,
        )
        .fetch_optional(&mut **tx)
        .await
        .map_err(|e| {
            map_sqlx_error(
                e,
                IdentityError::GroupNotFound,
                IdentityError::GroupDisplayNameExists,
                Some("groups_org_display_name_unique_live"),
            )
        })?;

        let Some(row) = row_opt else {
            if if_match_version.is_some() {
                return Err(IdentityError::ScimPreconditionFailed);
            }
            return Err(IdentityError::GroupNotFound);
        };
        Ok(Group {
            id: row.id,
            org_id: row.org_id,
            display_name: row.display_name,
            external_id: row.external_id,
            row_version: row.row_version,
            created_at: row.created_at,
            updated_at: row.updated_at,
            deleted_at: row.deleted_at,
        })
    }

    /// Soft-delete a group + all live memberships within the same
    /// transaction.
    pub async fn soft_delete_group_in_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, Postgres>,
        id: Uuid,
    ) -> Result<()> {
        let res = sqlx::query!(
            r#"
            UPDATE groups
            SET deleted_at = now(), updated_at = now()
            WHERE org_id = $1 AND id = $2 AND deleted_at IS NULL
            "#,
            self.org_id(),
            id,
        )
        .execute(&mut **tx)
        .await?;
        if res.rows_affected() == 0 {
            return Err(IdentityError::GroupNotFound);
        }
        sqlx::query!(
            r#"
            UPDATE group_memberships
            SET deleted_at = now()
            WHERE group_id = $1 AND deleted_at IS NULL
            "#,
            id,
        )
        .execute(&mut **tx)
        .await?;
        Ok(())
    }

    /// List live group memberships for `group_id` (org-scoped sanity
    /// check joined through `groups`).
    pub async fn list_members_in_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, Postgres>,
        group_id: Uuid,
    ) -> Result<Vec<GroupMembership>> {
        let rows = sqlx::query!(
            r#"
            SELECT m.id, m.group_id, m.user_id, m.created_at, m.deleted_at
            FROM group_memberships m
            JOIN groups g ON g.id = m.group_id
            WHERE g.org_id = $1
              AND m.group_id = $2
              AND m.deleted_at IS NULL
              AND g.deleted_at IS NULL
            "#,
            self.org_id(),
            group_id,
        )
        .fetch_all(&mut **tx)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| GroupMembership {
                id: r.id,
                group_id: r.group_id,
                user_id: r.user_id,
                created_at: r.created_at,
                deleted_at: r.deleted_at,
            })
            .collect())
    }

    /// List live group memberships for `group_id` against the pool
    /// (read-only path used by GET handler).
    pub async fn list_members(&self, group_id: Uuid) -> Result<Vec<GroupMembership>> {
        let rows = sqlx::query!(
            r#"
            SELECT m.id, m.group_id, m.user_id, m.created_at, m.deleted_at
            FROM group_memberships m
            JOIN groups g ON g.id = m.group_id
            WHERE g.org_id = $1
              AND m.group_id = $2
              AND m.deleted_at IS NULL
              AND g.deleted_at IS NULL
            "#,
            self.org_id(),
            group_id,
        )
        .fetch_all(self.inner().pool())
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| GroupMembership {
                id: r.id,
                group_id: r.group_id,
                user_id: r.user_id,
                created_at: r.created_at,
                deleted_at: r.deleted_at,
            })
            .collect())
    }

    /// Add `user_id` to `group_id` if not already a live member.
    /// `user_id` MUST be live in the org (caller checks via
    /// `MembershipRepo`).
    pub async fn add_member_in_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, Postgres>,
        group_id: Uuid,
        user_id: Uuid,
    ) -> Result<()> {
        sqlx::query!(
            r#"
            INSERT INTO group_memberships (id, group_id, user_id)
            VALUES ($1, $2, $3)
            ON CONFLICT (group_id, user_id)
                WHERE deleted_at IS NULL
                DO NOTHING
            "#,
            Uuid::now_v7(),
            group_id,
            user_id,
        )
        .execute(&mut **tx)
        .await?;
        Ok(())
    }

    /// Remove `user_id` from `group_id` (soft-delete the row).
    pub async fn remove_member_in_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, Postgres>,
        group_id: Uuid,
        user_id: Uuid,
    ) -> Result<()> {
        sqlx::query!(
            r#"
            UPDATE group_memberships
            SET deleted_at = now()
            WHERE group_id = $1
              AND user_id = $2
              AND deleted_at IS NULL
            "#,
            group_id,
            user_id,
        )
        .execute(&mut **tx)
        .await?;
        Ok(())
    }

    /// Bump `row_version` + `updated_at` on `group_id`. Returns the
    /// new (`row_version`, `updated_at`) so the handler can derive
    /// the new ETag.
    pub async fn bump_group_version_in_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, Postgres>,
        group_id: Uuid,
    ) -> Result<(i64, DateTime<Utc>)> {
        let row = sqlx::query!(
            r#"
            UPDATE groups
            SET row_version = row_version + 1,
                updated_at = now()
            WHERE org_id = $1 AND id = $2 AND deleted_at IS NULL
            RETURNING row_version, updated_at
            "#,
            self.org_id(),
            group_id,
        )
        .fetch_optional(&mut **tx)
        .await?
        .ok_or(IdentityError::GroupNotFound)?;
        Ok((row.row_version, row.updated_at))
    }

    /// Count live groups in this org (used by list-response totals).
    pub async fn count_groups(&self) -> Result<i64> {
        let row = sqlx::query!(
            r#"
            SELECT COUNT(*) AS "count!"
            FROM groups
            WHERE org_id = $1 AND deleted_at IS NULL
            "#,
            self.org_id(),
        )
        .fetch_one(self.inner().pool())
        .await?;
        Ok(row.count)
    }

    /// List a page of groups in this org (no filter — caller layers
    /// filter predicates separately via `QueryBuilder`).
    pub async fn list_groups_page(&self, offset: i64, limit: i64) -> Result<Vec<Group>> {
        let rows = sqlx::query!(
            r#"
            SELECT id, org_id, display_name, external_id, row_version,
                   created_at, updated_at, deleted_at
            FROM groups
            WHERE org_id = $1 AND deleted_at IS NULL
            ORDER BY id ASC
            OFFSET $2 LIMIT $3
            "#,
            self.org_id(),
            offset,
            limit,
        )
        .fetch_all(self.inner().pool())
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| Group {
                id: r.id,
                org_id: r.org_id,
                display_name: r.display_name,
                external_id: r.external_id,
                row_version: r.row_version,
                created_at: r.created_at,
                updated_at: r.updated_at,
                deleted_at: r.deleted_at,
            })
            .collect())
    }
}
