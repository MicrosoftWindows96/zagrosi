// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! `MembershipRepo` — user ↔ org link persistence.

use sqlx::PgPool;
use sqlx::Postgres;
use uuid::Uuid;

use crate::domain::Membership;
use crate::error::{IdentityError, Result, map_sqlx_error};

/// Repository for `user_org_memberships`. Single-tenant per row but
/// the table itself spans every org, so this repo is used without a
/// tenant wrapper — callers filter by `user_id` or `org_id` as
/// appropriate.
#[derive(Clone)]
pub struct MembershipRepo {
    pool: PgPool,
}

impl MembershipRepo {
    /// Wrap a connection pool.
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Insert a new membership. Hits the partial unique on
    /// `(user_id, org_id) WHERE deleted_at IS NULL` if the user is
    /// already a live member of the org.
    ///
    /// Runs in a short self-managed transaction with the `app.org_id`
    /// GUC set to `new.org_id` so the P2 WITH CHECK admits the write
    /// under RLS.
    pub async fn create(&self, new: NewMembership<'_>) -> Result<Membership> {
        let mut tx = self.pool.begin().await?;
        super::with_org_context(&mut tx, new.org_id).await?;
        let row = sqlx::query!(
            r#"
            INSERT INTO user_org_memberships (
                id, user_id, org_id, basic_role, joined_via,
                jit_provisioned_at
            )
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id, user_id, org_id, basic_role, joined_via,
                      jit_provisioned_at, created_at, deleted_at
            "#,
            new.id,
            new.user_id,
            new.org_id,
            new.basic_role,
            new.joined_via,
            new.jit_provisioned_at,
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| {
            map_sqlx_error(
                e,
                IdentityError::UserNotFound,
                IdentityError::MembershipAlreadyExists,
                Some("user_org_memberships_user_org_unique_live"),
            )
        })?;
        tx.commit().await?;

        Ok(Membership {
            id: row.id,
            user_id: row.user_id,
            org_id: row.org_id,
            basic_role: row.basic_role,
            joined_via: row.joined_via,
            jit_provisioned_at: row.jit_provisioned_at,
            created_at: row.created_at,
            deleted_at: row.deleted_at,
        })
    }

    /// Insert a new membership inside a caller-supplied transaction.
    /// Wired by the OIDC / SAML JIT paths.
    pub async fn create_in_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, Postgres>,
        new: NewMembership<'_>,
    ) -> Result<Membership> {
        let row = sqlx::query!(
            r#"
            INSERT INTO user_org_memberships (
                id, user_id, org_id, basic_role, joined_via,
                jit_provisioned_at
            )
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id, user_id, org_id, basic_role, joined_via,
                      jit_provisioned_at, created_at, deleted_at
            "#,
            new.id,
            new.user_id,
            new.org_id,
            new.basic_role,
            new.joined_via,
            new.jit_provisioned_at,
        )
        .fetch_one(&mut **tx)
        .await
        .map_err(|e| {
            map_sqlx_error(
                e,
                IdentityError::UserNotFound,
                IdentityError::MembershipAlreadyExists,
                Some("user_org_memberships_user_org_unique_live"),
            )
        })?;

        Ok(Membership {
            id: row.id,
            user_id: row.user_id,
            org_id: row.org_id,
            basic_role: row.basic_role,
            joined_via: row.joined_via,
            jit_provisioned_at: row.jit_provisioned_at,
            created_at: row.created_at,
            deleted_at: row.deleted_at,
        })
    }

    /// Lookup the live membership for `(user_id, org_id)` inside the
    /// caller-supplied transaction. Used by the OIDC anchor-hit path
    /// so the membership read shares a consistency horizon with the
    /// pending mark-used + JIT writes.
    pub async fn find_for_user_org_in_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, Postgres>,
        user_id: Uuid,
        org_id: Uuid,
    ) -> Result<Option<Membership>> {
        let row = sqlx::query!(
            r#"
            SELECT id, user_id, org_id, basic_role, joined_via,
                   jit_provisioned_at, created_at, deleted_at
            FROM user_org_memberships
            WHERE user_id = $1 AND org_id = $2 AND deleted_at IS NULL
            "#,
            user_id,
            org_id,
        )
        .fetch_optional(&mut **tx)
        .await?;

        Ok(row.map(|r| Membership {
            id: r.id,
            user_id: r.user_id,
            org_id: r.org_id,
            basic_role: r.basic_role,
            joined_via: r.joined_via,
            jit_provisioned_at: r.jit_provisioned_at,
            created_at: r.created_at,
            deleted_at: r.deleted_at,
        }))
    }

    /// List live memberships for a user. Orders by `created_at` so
    /// the canonical "first membership" can be taken as the default
    /// active org for new sessions.
    ///
    /// Runs inside a short self-managed transaction with the
    /// `app.user_id` GUC set ([`super::with_user_context`]): this read
    /// is inherently user-scoped with no org context (the org-switcher
    /// lists memberships across orgs before any org is chosen), so
    /// section-05's org-or-self SELECT policy needs the user GUC. A
    /// `find_for_user_in_tx` variant was deliberately not added — no
    /// caller composes this listing into a larger transaction today;
    /// the self-managed txn gives every caller the GUC for free.
    pub async fn find_for_user(&self, user_id: Uuid) -> Result<Vec<Membership>> {
        let mut tx = self.pool.begin().await?;
        super::with_user_context(&mut tx, user_id).await?;
        let rows = sqlx::query!(
            r#"
            SELECT id, user_id, org_id, basic_role, joined_via,
                   jit_provisioned_at, created_at, deleted_at
            FROM user_org_memberships
            WHERE user_id = $1 AND deleted_at IS NULL
            ORDER BY created_at ASC
            "#,
            user_id,
        )
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;

        Ok(rows
            .into_iter()
            .map(|r| Membership {
                id: r.id,
                user_id: r.user_id,
                org_id: r.org_id,
                basic_role: r.basic_role,
                joined_via: r.joined_via,
                jit_provisioned_at: r.jit_provisioned_at,
                created_at: r.created_at,
                deleted_at: r.deleted_at,
            })
            .collect())
    }
}

/// Argument bundle for [`MembershipRepo::create`].
#[derive(Debug, Clone, Copy)]
pub struct NewMembership<'a> {
    /// Application-generated UUID v7.
    pub id: Uuid,
    /// Member.
    pub user_id: Uuid,
    /// Joined org.
    pub org_id: Uuid,
    /// Coarse role placeholder (the tenant-isolation layer's RBAC supersedes).
    pub basic_role: &'a str,
    /// Auth path: `password`, `oidc`, `saml`, `scim`, `manual`.
    pub joined_via: &'a str,
    /// `Some(now)` when JIT-provisioned via SSO/SCIM.
    pub jit_provisioned_at: Option<chrono::DateTime<chrono::Utc>>,
}
