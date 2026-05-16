// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! `ServiceTokenRepo` — internal service-to-service bearer
//! persistence.

use sqlx::PgPool;
use uuid::Uuid;

use crate::domain::ServiceToken;
use crate::error::{IdentityError, Result, map_sqlx_error};

/// Repository for `service_tokens`. Org-agnostic — service tokens
/// authorise platform-wide internal callers, so [`super::OrgScoped`]
/// does not apply. The tenant-isolation layer's RLS will whitelist this table for the
/// service / migration roles rather than gating it by tenant.
#[derive(Clone)]
pub struct ServiceTokenRepo {
    pool: PgPool,
}

impl ServiceTokenRepo {
    /// Wrap a connection pool.
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Insert a new service token.
    pub async fn create(&self, new: NewServiceToken<'_>) -> Result<ServiceToken> {
        let subjects_owned: Vec<String> = new
            .allowed_subjects
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        let row = sqlx::query!(
            r#"
            INSERT INTO service_tokens (
                id, service_name, token_hash, allowed_subjects, display_name
            )
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id, service_name, token_hash, allowed_subjects,
                      display_name, created_at, revoked_at, deleted_at
            "#,
            new.id,
            new.service_name,
            new.token_hash,
            &subjects_owned,
            new.display_name,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            map_sqlx_error(
                e,
                IdentityError::TokenNotFound,
                IdentityError::TokenNotFound,
                Some("service_tokens_token_hash_unique_live"),
            )
        })?;

        let token_hash: [u8; 32] = row
            .token_hash
            .as_slice()
            .try_into()
            .map_err(|_| IdentityError::MalformedToken("service token_hash is not 32 bytes"))?;
        Ok(ServiceToken {
            id: row.id,
            service_name: row.service_name,
            token_hash,
            allowed_subjects: row.allowed_subjects,
            display_name: row.display_name,
            created_at: row.created_at,
            revoked_at: row.revoked_at,
            deleted_at: row.deleted_at,
        })
    }

    /// Lookup a live service token by hash.
    pub async fn find_by_token_hash(&self, token_hash: &[u8; 32]) -> Result<Option<ServiceToken>> {
        let row = sqlx::query!(
            r#"
            SELECT id, service_name, token_hash, allowed_subjects,
                   display_name, created_at, revoked_at, deleted_at
            FROM service_tokens
            WHERE token_hash = $1
              AND revoked_at IS NULL
              AND deleted_at IS NULL
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
            .map_err(|_| IdentityError::MalformedToken("service token_hash is not 32 bytes"))?;
        Ok(Some(ServiceToken {
            id: r.id,
            service_name: r.service_name,
            token_hash: token_hash_arr,
            allowed_subjects: r.allowed_subjects,
            display_name: r.display_name,
            created_at: r.created_at,
            revoked_at: r.revoked_at,
            deleted_at: r.deleted_at,
        }))
    }

    /// Revoke a service token. Returns the number of rows mutated:
    /// `1` on the first revoke, `0` if the row was missing or already
    /// revoked. The service layer uses the count to suppress a
    /// duplicate `ServiceTokenRevoked` audit emission under a
    /// concurrent-revoke race (mirrors the `ApiTokenRepo::revoke`
    /// contract).
    pub async fn revoke(&self, id: Uuid) -> Result<u64> {
        let result = sqlx::query!(
            r#"
            UPDATE service_tokens
            SET revoked_at = now()
            WHERE id = $1 AND revoked_at IS NULL AND deleted_at IS NULL
            "#,
            id,
        )
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    /// Fetch one service token by id regardless of revocation state
    /// (so the admin UI can surface a `revoked_at` timestamp on a
    /// previously-revoked row). Soft-deleted rows are excluded.
    pub async fn find_by_id(&self, id: Uuid) -> Result<Option<ServiceToken>> {
        let row = sqlx::query!(
            r#"
            SELECT id, service_name, token_hash, allowed_subjects,
                   display_name, created_at, revoked_at, deleted_at
            FROM service_tokens
            WHERE id = $1 AND deleted_at IS NULL
            "#,
            id,
        )
        .fetch_optional(&self.pool)
        .await?;
        let Some(r) = row else { return Ok(None) };
        let token_hash: [u8; 32] = r
            .token_hash
            .as_slice()
            .try_into()
            .map_err(|_| IdentityError::MalformedToken("service token_hash is not 32 bytes"))?;
        Ok(Some(ServiceToken {
            id: r.id,
            service_name: r.service_name,
            token_hash,
            allowed_subjects: r.allowed_subjects,
            display_name: r.display_name,
            created_at: r.created_at,
            revoked_at: r.revoked_at,
            deleted_at: r.deleted_at,
        }))
    }

    /// List every live (non-revoked, non-deleted) service token,
    /// newest first. Platform-level surface — no org scoping.
    pub async fn list(&self) -> Result<Vec<ServiceToken>> {
        let rows = sqlx::query!(
            r#"
            SELECT id, service_name, token_hash, allowed_subjects,
                   display_name, created_at, revoked_at, deleted_at
            FROM service_tokens
            WHERE revoked_at IS NULL AND deleted_at IS NULL
            ORDER BY created_at DESC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let token_hash: [u8; 32] =
                r.token_hash.as_slice().try_into().map_err(|_| {
                    IdentityError::MalformedToken("service token_hash is not 32 bytes")
                })?;
            out.push(ServiceToken {
                id: r.id,
                service_name: r.service_name,
                token_hash,
                allowed_subjects: r.allowed_subjects,
                display_name: r.display_name,
                created_at: r.created_at,
                revoked_at: r.revoked_at,
                deleted_at: r.deleted_at,
            });
        }
        Ok(out)
    }
}

/// Argument bundle for [`ServiceTokenRepo::create`].
#[derive(Debug)]
pub struct NewServiceToken<'a> {
    /// Application-generated UUID v7.
    pub id: Uuid,
    /// Caller name.
    pub service_name: &'a str,
    /// SHA-256 of the raw `svc_*` token.
    pub token_hash: &'a [u8],
    /// NATS subject allow-list.
    pub allowed_subjects: &'a [&'a str],
    /// Display name shown in admin UI.
    pub display_name: &'a str,
}
