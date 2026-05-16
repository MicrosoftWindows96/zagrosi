// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! `OrgRepo` — tenant-root persistence.

use sqlx::PgPool;
use uuid::Uuid;

use crate::domain::Org;
use crate::error::{IdentityError, Result, map_sqlx_error};

/// Repository for the `orgs` table. Used directly (no [`super::OrgScoped`]
/// wrapper) because this table is the tenant root itself and predicates
/// would degenerate into `WHERE id = $1 AND id = $1`.
#[derive(Clone)]
pub struct OrgRepo {
    pool: PgPool,
}

impl OrgRepo {
    /// Wrap a connection pool.
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Insert a new org. Hits the `slug` partial unique on
    /// `deleted_at IS NULL`; conflicts return
    /// [`IdentityError::OrgSlugAlreadyExists`].
    pub async fn create(&self, new: NewOrg<'_>) -> Result<Org> {
        let row = sqlx::query!(
            r#"
            INSERT INTO orgs (id, slug, display_name, primary_domain)
            VALUES ($1, $2, $3, $4)
            RETURNING id, slug, display_name, primary_domain,
                      created_at, updated_at, deleted_at
            "#,
            new.id,
            new.slug,
            new.display_name,
            new.primary_domain,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            map_sqlx_error(
                e,
                IdentityError::OrgNotFound,
                IdentityError::OrgSlugAlreadyExists,
                Some("orgs_slug_unique_live"),
            )
        })?;

        Ok(Org {
            id: row.id,
            slug: row.slug,
            display_name: row.display_name,
            primary_domain: row.primary_domain,
            created_at: row.created_at,
            updated_at: row.updated_at,
            deleted_at: row.deleted_at,
        })
    }

    /// Find a live org by primary key.
    pub async fn find_by_id(&self, id: Uuid) -> Result<Option<Org>> {
        let row = sqlx::query!(
            r#"
            SELECT id, slug, display_name, primary_domain,
                   created_at, updated_at, deleted_at
            FROM orgs
            WHERE id = $1 AND deleted_at IS NULL
            "#,
            id,
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| Org {
            id: r.id,
            slug: r.slug,
            display_name: r.display_name,
            primary_domain: r.primary_domain,
            created_at: r.created_at,
            updated_at: r.updated_at,
            deleted_at: r.deleted_at,
        }))
    }

    /// Find a live org by slug.
    pub async fn find_by_slug(&self, slug: &str) -> Result<Option<Org>> {
        let row = sqlx::query!(
            r#"
            SELECT id, slug, display_name, primary_domain,
                   created_at, updated_at, deleted_at
            FROM orgs
            WHERE slug = $1 AND deleted_at IS NULL
            "#,
            slug,
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| Org {
            id: r.id,
            slug: r.slug,
            display_name: r.display_name,
            primary_domain: r.primary_domain,
            created_at: r.created_at,
            updated_at: r.updated_at,
            deleted_at: r.deleted_at,
        }))
    }

    // Soft-delete is intentionally absent from this surface. All org
    // soft-deletes go through [`crate::repo::cascade::soft_delete_org`]
    // inside a caller-supplied transaction so the parent flip and the
    // child cascade are atomic. Exposing a parent-only `soft_delete`
    // here would create a trap where callers run two separate
    // operations (parent flip outside a txn, cascade inside one) and a
    // crash between them leaves the row deleted but the children live.
}

/// Argument bundle for [`OrgRepo::create`].
#[derive(Debug, Clone, Copy)]
pub struct NewOrg<'a> {
    /// Application-generated UUID v7.
    pub id: Uuid,
    /// URL-safe slug.
    pub slug: &'a str,
    /// Human-readable display name.
    pub display_name: &'a str,
    /// Optional primary email-domain claim.
    pub primary_domain: Option<&'a str>,
}
