// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! `OrgIdpRepo` — per-org IdP configuration persistence.

use serde_json::Value as JsonValue;
use sqlx::PgPool;
use uuid::Uuid;

use crate::domain::OrgIdp;
use crate::error::{IdentityError, Result, map_sqlx_error};

use super::OrgScoped;

/// Repository for `org_idps`. Multi-tenant: callers MUST go through
/// [`OrgScoped`]. Encryption of secret material inside `config` is
/// the responsibility of the application layer (the secrets shim); the
/// repo signature accepts already-encrypted blobs verbatim.
#[derive(Clone)]
pub struct OrgIdpRepo {
    pool: PgPool,
}

impl OrgIdpRepo {
    /// Wrap a connection pool.
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Pool accessor.
    #[must_use]
    pub const fn pool(&self) -> &PgPool {
        &self.pool
    }
}

impl super::org_scoped::HasPool for OrgIdpRepo {
    fn pool(&self) -> &sqlx::PgPool {
        &self.pool
    }
}

impl OrgScoped<'_, OrgIdpRepo> {
    /// Insert a new IdP for this org.
    pub async fn create(&self, new: NewOrgIdp<'_>) -> Result<OrgIdp> {
        let mut tx = self.begin_org_tx().await?;
        let row = sqlx::query!(
            r#"
            INSERT INTO org_idps (
                id, org_id, protocol, display_name,
                config, config_version, jit_provisioning,
                is_default, enabled
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING id, org_id, protocol, display_name, config,
                      config_version, jit_provisioning, is_default,
                      enabled, created_at, updated_at, deleted_at
            "#,
            new.id,
            self.org_id(),
            new.protocol,
            new.display_name,
            new.config,
            new.config_version,
            new.jit_provisioning,
            new.is_default,
            new.enabled,
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| {
            map_sqlx_error(
                e,
                IdentityError::OrgNotFound,
                IdentityError::OrgNotFound,
                None,
            )
        })?;
        tx.commit().await?;

        Ok(OrgIdp {
            id: row.id,
            org_id: row.org_id,
            protocol: row.protocol,
            display_name: row.display_name,
            config: row.config,
            config_version: row.config_version,
            jit_provisioning: row.jit_provisioning,
            is_default: row.is_default,
            enabled: row.enabled,
            created_at: row.created_at,
            updated_at: row.updated_at,
            deleted_at: row.deleted_at,
        })
    }

    /// Find a live IdP by id, scoped to this org.
    pub async fn find_by_id(&self, id: Uuid) -> Result<Option<OrgIdp>> {
        let mut tx = self.begin_org_tx().await?;
        let row = sqlx::query!(
            r#"
            SELECT id, org_id, protocol, display_name, config,
                   config_version, jit_provisioning, is_default,
                   enabled, created_at, updated_at, deleted_at
            FROM org_idps
            WHERE org_id = $1 AND id = $2 AND deleted_at IS NULL
            "#,
            self.org_id(),
            id,
        )
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;

        Ok(row.map(|r| OrgIdp {
            id: r.id,
            org_id: r.org_id,
            protocol: r.protocol,
            display_name: r.display_name,
            config: r.config,
            config_version: r.config_version,
            jit_provisioning: r.jit_provisioning,
            is_default: r.is_default,
            enabled: r.enabled,
            created_at: r.created_at,
            updated_at: r.updated_at,
            deleted_at: r.deleted_at,
        }))
    }

    /// List live IdPs for this org. Ordered by `display_name` for UI
    /// stability.
    pub async fn list_for_org(&self) -> Result<Vec<OrgIdp>> {
        let mut tx = self.begin_org_tx().await?;
        let rows = sqlx::query!(
            r#"
            SELECT id, org_id, protocol, display_name, config,
                   config_version, jit_provisioning, is_default,
                   enabled, created_at, updated_at, deleted_at
            FROM org_idps
            WHERE org_id = $1 AND deleted_at IS NULL
            ORDER BY display_name ASC
            "#,
            self.org_id(),
        )
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;

        Ok(rows
            .into_iter()
            .map(|r| OrgIdp {
                id: r.id,
                org_id: r.org_id,
                protocol: r.protocol,
                display_name: r.display_name,
                config: r.config,
                config_version: r.config_version,
                jit_provisioning: r.jit_provisioning,
                is_default: r.is_default,
                enabled: r.enabled,
                created_at: r.created_at,
                updated_at: r.updated_at,
                deleted_at: r.deleted_at,
            })
            .collect())
    }

    /// Replace `config` under an optimistic-concurrency guard.
    ///
    /// `expected_version` is the `config_version` value the caller
    /// last observed; the UPDATE applies ONLY when the persisted row
    /// still matches that value, and the bump goes to
    /// `expected_version + 1` atomically. Returns the new version on
    /// success.
    ///
    /// # Errors
    ///
    /// - [`IdentityError::OrgNotFound`] when the row does not exist
    ///   (or has been soft-deleted).
    /// - [`IdentityError::OptimisticLockConflict`] when the persisted
    ///   `config_version` no longer matches `expected_version` — a
    ///   concurrent writer beat us. Callers MUST re-load the row,
    ///   reconcile, and retry (or return the persisted state to the
    ///   user verbatim).
    pub async fn update_config(
        &self,
        id: Uuid,
        config: JsonValue,
        expected_version: i16,
    ) -> Result<i16> {
        // 1. Try CAS update.
        let mut tx = self.begin_org_tx().await?;
        let updated = sqlx::query!(
            r#"
            UPDATE org_idps
            SET config = $3,
                config_version = $4 + 1,
                updated_at = now()
            WHERE org_id = $1
              AND id = $2
              AND config_version = $4
              AND deleted_at IS NULL
            RETURNING config_version
            "#,
            self.org_id(),
            id,
            config,
            expected_version,
        )
        .fetch_optional(&mut *tx)
        .await?;

        if let Some(row) = updated {
            tx.commit().await?;
            return Ok(row.config_version);
        }

        // 2. CAS missed. Distinguish row-missing from version-stale
        //    so the caller can pick the right retry path.
        let exists = sqlx::query!(
            r#"
            SELECT 1 AS sentinel
            FROM org_idps
            WHERE org_id = $1 AND id = $2 AND deleted_at IS NULL
            "#,
            self.org_id(),
            id,
        )
        .fetch_optional(&mut *tx)
        .await?
        .is_some();
        tx.commit().await?;

        if exists {
            Err(IdentityError::OptimisticLockConflict)
        } else {
            Err(IdentityError::OrgNotFound)
        }
    }

    /// Soft-delete an IdP. The org cascade calls this for every IdP
    /// of the org; callers outside the cascade should generally
    /// prefer the cascade helper.
    pub async fn soft_delete(&self, id: Uuid) -> Result<()> {
        let mut tx = self.begin_org_tx().await?;
        sqlx::query!(
            r#"
            UPDATE org_idps
            SET deleted_at = now(), updated_at = now()
            WHERE org_id = $1 AND id = $2 AND deleted_at IS NULL
            "#,
            self.org_id(),
            id,
        )
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }
}

/// Argument bundle for [`OrgScoped::<OrgIdpRepo>::create`].
#[derive(Debug)]
pub struct NewOrgIdp<'a> {
    /// Application-generated UUID v7.
    pub id: Uuid,
    /// `oidc` or `saml`.
    pub protocol: &'a str,
    /// Display name.
    pub display_name: &'a str,
    /// Versioned JSONB config blob.
    pub config: JsonValue,
    /// Config schema version.
    pub config_version: i16,
    /// Whether SCIM/SSO JIT provisioning is allowed.
    pub jit_provisioning: bool,
    /// Whether this IdP handles unrouted traffic.
    pub is_default: bool,
    /// Kill-switch.
    pub enabled: bool,
}
