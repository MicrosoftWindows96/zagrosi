// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! `ScimResourceRepo` — SCIM bearer token persistence.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use sqlx::types::ipnetwork::IpNetwork;
use uuid::Uuid;

use crate::domain::ScimResource;
use crate::error::{IdentityError, Result, map_sqlx_error};

use super::OrgScoped;

/// Repository for `scim_tokens`. Multi-tenant: callers MUST go
/// through [`OrgScoped`].
#[derive(Clone)]
pub struct ScimResourceRepo {
    pool: PgPool,
}

impl ScimResourceRepo {
    /// Wrap a connection pool.
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Pool accessor (used by `OrgScoped` impls).
    #[must_use]
    pub const fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Global lookup by SCIM-token hash. Bypasses
    /// [`super::OrgScoped`] because the bearer-token IS the tenant
    /// key — auth fires before tenancy is established. Mirrors the
    /// `SessionRepo::find_by_token_hash` pattern documented at the
    /// repo-module entry point. Cross-tenant probing remains
    /// impossible at the resource layer because every resource repo
    /// (Users, Groups) reads through `OrgScoped` with the org_id
    /// returned by this method.
    pub async fn find_global_by_token_hash(
        &self,
        token_hash: &[u8; 32],
    ) -> Result<Option<ScimResource>> {
        let row = sqlx::query!(
            r#"
            SELECT id, org_id, display_name, token_hash, scopes,
                   allowed_cidrs, tolerant_mode, last_used_at,
                   last_used_ip, created_at, expires_at,
                   revoked_at, deleted_at
            FROM scim_tokens
            WHERE token_hash = $1
              AND revoked_at IS NULL
              AND deleted_at IS NULL
              AND (expires_at IS NULL OR expires_at > now())
            "#,
            &token_hash[..],
        )
        .fetch_optional(&self.pool)
        .await?;
        let Some(r) = row else { return Ok(None) };
        let token_hash_arr: [u8; 32] = r
            .token_hash
            .as_slice()
            .try_into()
            .map_err(|_| IdentityError::MalformedToken("scim token_hash is not 32 bytes"))?;
        Ok(Some(ScimResource {
            id: r.id,
            org_id: r.org_id,
            display_name: r.display_name,
            token_hash: token_hash_arr,
            scopes: r.scopes,
            allowed_cidrs: r.allowed_cidrs,
            tolerant_mode: r.tolerant_mode,
            last_used_at: r.last_used_at,
            last_used_ip: r.last_used_ip.map(|n| n.ip()),
            created_at: r.created_at,
            expires_at: r.expires_at,
            revoked_at: r.revoked_at,
            deleted_at: r.deleted_at,
        }))
    }

    /// Update `last_used_at` / `last_used_ip` on the SCIM token.
    /// Best-effort: errors are absorbed by the caller — telemetry
    /// breakage MUST NOT short-circuit a successful auth.
    pub async fn touch_last_used(
        &self,
        token_id: Uuid,
        ip: Option<std::net::IpAddr>,
    ) -> Result<()> {
        let ip_net: Option<sqlx::types::ipnetwork::IpNetwork> = ip.map(Into::into);
        sqlx::query!(
            r#"
            UPDATE scim_tokens
            SET last_used_at = now(),
                last_used_ip = $2
            WHERE id = $1
            "#,
            token_id,
            ip_net,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

impl OrgScoped<'_, ScimResourceRepo> {
    /// Insert a new SCIM bearer.
    pub async fn create(&self, new: NewScimResource<'_>) -> Result<ScimResource> {
        let scopes_owned: Vec<String> = new.scopes.iter().map(|s| (*s).to_string()).collect();
        let row = sqlx::query!(
            r#"
            INSERT INTO scim_tokens (
                id, org_id, display_name, token_hash, scopes,
                allowed_cidrs, tolerant_mode, expires_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING id, org_id, display_name, token_hash, scopes,
                      allowed_cidrs, tolerant_mode, last_used_at,
                      last_used_ip, created_at, expires_at,
                      revoked_at, deleted_at
            "#,
            new.id,
            self.org_id(),
            new.display_name,
            new.token_hash,
            &scopes_owned,
            new.allowed_cidrs,
            new.tolerant_mode,
            new.expires_at,
        )
        .fetch_one(self.inner().pool())
        .await
        .map_err(|e| {
            map_sqlx_error(
                e,
                IdentityError::TokenNotFound,
                IdentityError::TokenNotFound,
                Some("scim_tokens_token_hash_unique_live"),
            )
        })?;

        let token_hash: [u8; 32] = row
            .token_hash
            .as_slice()
            .try_into()
            .map_err(|_| IdentityError::MalformedToken("scim token_hash is not 32 bytes"))?;
        Ok(ScimResource {
            id: row.id,
            org_id: row.org_id,
            display_name: row.display_name,
            token_hash,
            scopes: row.scopes,
            allowed_cidrs: row.allowed_cidrs,
            tolerant_mode: row.tolerant_mode,
            last_used_at: row.last_used_at,
            last_used_ip: row.last_used_ip.map(|n| n.ip()),
            created_at: row.created_at,
            expires_at: row.expires_at,
            revoked_at: row.revoked_at,
            deleted_at: row.deleted_at,
        })
    }

    /// Lookup a live SCIM token by hash, scoped to this org.
    pub async fn find_by_token_hash(&self, token_hash: &[u8; 32]) -> Result<Option<ScimResource>> {
        let row = sqlx::query!(
            r#"
            SELECT id, org_id, display_name, token_hash, scopes,
                   allowed_cidrs, tolerant_mode, last_used_at,
                   last_used_ip, created_at, expires_at,
                   revoked_at, deleted_at
            FROM scim_tokens
            WHERE org_id = $1
              AND token_hash = $2
              AND revoked_at IS NULL
              AND deleted_at IS NULL
              AND (expires_at IS NULL OR expires_at > now())
            "#,
            self.org_id(),
            &token_hash[..],
        )
        .fetch_optional(self.inner().pool())
        .await?;

        let Some(r) = row else { return Ok(None) };
        let token_hash_arr: [u8; 32] = r
            .token_hash
            .as_slice()
            .try_into()
            .map_err(|_| IdentityError::MalformedToken("scim token_hash is not 32 bytes"))?;
        Ok(Some(ScimResource {
            id: r.id,
            org_id: r.org_id,
            display_name: r.display_name,
            token_hash: token_hash_arr,
            scopes: r.scopes,
            allowed_cidrs: r.allowed_cidrs,
            tolerant_mode: r.tolerant_mode,
            last_used_at: r.last_used_at,
            last_used_ip: r.last_used_ip.map(|n| n.ip()),
            created_at: r.created_at,
            expires_at: r.expires_at,
            revoked_at: r.revoked_at,
            deleted_at: r.deleted_at,
        }))
    }

    /// Revoke a SCIM token scoped to this org.
    pub async fn revoke(&self, id: Uuid) -> Result<()> {
        sqlx::query!(
            r#"
            UPDATE scim_tokens
            SET revoked_at = now()
            WHERE org_id = $1 AND id = $2 AND revoked_at IS NULL
            "#,
            self.org_id(),
            id,
        )
        .execute(self.inner().pool())
        .await?;
        Ok(())
    }
}

/// Argument bundle for [`OrgScoped::<ScimResourceRepo>::create`].
#[derive(Debug)]
pub struct NewScimResource<'a> {
    /// Application-generated UUID v7.
    pub id: Uuid,
    /// Display name shown in admin UI.
    pub display_name: &'a str,
    /// SHA-256 of the raw `scim_*` token.
    pub token_hash: &'a [u8],
    /// SCIM scope set.
    pub scopes: &'a [&'a str],
    /// Source-IP allow-list. Empty means unrestricted.
    pub allowed_cidrs: &'a [IpNetwork],
    /// Toggles SCIM-server Entra ID workarounds.
    pub tolerant_mode: bool,
    /// Optional hard expiry timestamp.
    pub expires_at: Option<DateTime<Utc>>,
}
