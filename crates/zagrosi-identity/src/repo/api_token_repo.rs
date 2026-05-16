// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! `ApiTokenRepo` — personal access token persistence.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use std::net::IpAddr;
use uuid::Uuid;

use crate::domain::ApiToken;
use crate::error::{IdentityError, Result, map_sqlx_error};

use super::OrgScoped;

/// Repository for `api_tokens`. Multi-tenant: every method goes
/// through [`OrgScoped`] so the `WHERE org_id = $1` predicate is
/// inseparable from the query.
#[derive(Clone)]
pub struct ApiTokenRepo {
    pool: PgPool,
}

impl ApiTokenRepo {
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

    /// Lookup a live PAT row by token hash, scanning across orgs.
    ///
    /// **Caller contract**: this is the only top-level method on
    /// [`ApiTokenRepo`] that bypasses the `OrgScoped` wrapper. It
    /// exists for the bearer-token resolution fast path: the resolver
    /// receives a raw `pat_*` token *before* knowing the caller's
    /// org, so the lookup must derive `(org_id, user_id)` from the
    /// row itself. The partial-unique index
    /// `api_tokens_token_hash_unique_live` guarantees at most one
    /// live row per hash so cross-org collision is impossible.
    ///
    /// Every other read / write path against `api_tokens` MUST go
    /// through [`OrgScoped`] so the tenant-isolation invariant holds.
    pub async fn find_live_by_token_hash(
        &self,
        token_hash: &[u8; 32],
    ) -> Result<Option<crate::domain::ApiToken>> {
        let row = sqlx::query!(
            r#"
            SELECT id, token_hash, user_id, org_id, display_name,
                   scopes, last_used_at, last_used_ip,
                   created_at, expires_at, revoked_at
            FROM api_tokens
            WHERE token_hash = $1
              AND revoked_at IS NULL
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
            .map_err(|_| IdentityError::MalformedToken("api_token hash is not 32 bytes"))?;
        Ok(Some(crate::domain::ApiToken {
            id: r.id,
            token_hash: token_hash_arr,
            user_id: r.user_id,
            org_id: r.org_id,
            display_name: r.display_name,
            scopes: r.scopes,
            last_used_at: r.last_used_at,
            last_used_ip: r.last_used_ip.map(|n| n.ip()),
            created_at: r.created_at,
            expires_at: r.expires_at,
            revoked_at: r.revoked_at,
        }))
    }
}

impl OrgScoped<'_, ApiTokenRepo> {
    /// Insert a new PAT bound to this wrapper's org. `token_hash`
    /// MUST be the SHA-256 over the full raw `pat_<43>` token.
    pub async fn create(&self, new: NewApiToken<'_>) -> Result<ApiToken> {
        let scopes_owned: Vec<String> = new.scopes.iter().map(|s| (*s).to_string()).collect();
        let row = sqlx::query!(
            r#"
            INSERT INTO api_tokens (
                id, token_hash, user_id, org_id, display_name,
                scopes, expires_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING id, token_hash, user_id, org_id, display_name,
                      scopes, last_used_at, last_used_ip,
                      created_at, expires_at, revoked_at
            "#,
            new.id,
            new.token_hash,
            new.user_id,
            self.org_id(),
            new.display_name,
            &scopes_owned,
            new.expires_at,
        )
        .fetch_one(self.inner().pool())
        .await
        .map_err(|e| {
            map_sqlx_error(
                e,
                IdentityError::TokenNotFound,
                IdentityError::TokenNotFound,
                Some("api_tokens_token_hash_unique_live"),
            )
        })?;

        let token_hash: [u8; 32] = row
            .token_hash
            .as_slice()
            .try_into()
            .map_err(|_| IdentityError::MalformedToken("api_token hash is not 32 bytes"))?;
        Ok(ApiToken {
            id: row.id,
            token_hash,
            user_id: row.user_id,
            org_id: row.org_id,
            display_name: row.display_name,
            scopes: row.scopes,
            last_used_at: row.last_used_at,
            last_used_ip: row.last_used_ip.map(|n| n.ip()),
            created_at: row.created_at,
            expires_at: row.expires_at,
            revoked_at: row.revoked_at,
        })
    }

    /// Lookup a live PAT by token hash, scoped to this org.
    pub async fn find_by_token_hash(&self, token_hash: &[u8; 32]) -> Result<Option<ApiToken>> {
        let row = sqlx::query!(
            r#"
            SELECT id, token_hash, user_id, org_id, display_name,
                   scopes, last_used_at, last_used_ip,
                   created_at, expires_at, revoked_at
            FROM api_tokens
            WHERE org_id = $1
              AND token_hash = $2
              AND revoked_at IS NULL
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
            .map_err(|_| IdentityError::MalformedToken("api_token hash is not 32 bytes"))?;
        Ok(Some(ApiToken {
            id: r.id,
            token_hash: token_hash_arr,
            user_id: r.user_id,
            org_id: r.org_id,
            display_name: r.display_name,
            scopes: r.scopes,
            last_used_at: r.last_used_at,
            last_used_ip: r.last_used_ip.map(|n| n.ip()),
            created_at: r.created_at,
            expires_at: r.expires_at,
            revoked_at: r.revoked_at,
        }))
    }

    /// Lookup a single PAT by id, scoped to `(user_id, org_id)`.
    /// Returns the row whether or not it is revoked so the
    /// owner-visible token-management UI can surface revoked tokens
    /// with their `revoked_at` timestamp set (audit trail).
    pub async fn find_by_id_for_user(
        &self,
        user_id: Uuid,
        token_id: Uuid,
    ) -> Result<Option<ApiToken>> {
        let row = sqlx::query!(
            r#"
            SELECT id, token_hash, user_id, org_id, display_name,
                   scopes, last_used_at, last_used_ip,
                   created_at, expires_at, revoked_at
            FROM api_tokens
            WHERE org_id = $1 AND user_id = $2 AND id = $3
            "#,
            self.org_id(),
            user_id,
            token_id,
        )
        .fetch_optional(self.inner().pool())
        .await?;

        let Some(r) = row else { return Ok(None) };
        let token_hash: [u8; 32] = r
            .token_hash
            .as_slice()
            .try_into()
            .map_err(|_| IdentityError::MalformedToken("api_token hash is not 32 bytes"))?;
        Ok(Some(ApiToken {
            id: r.id,
            token_hash,
            user_id: r.user_id,
            org_id: r.org_id,
            display_name: r.display_name,
            scopes: r.scopes,
            last_used_at: r.last_used_at,
            last_used_ip: r.last_used_ip.map(|n| n.ip()),
            created_at: r.created_at,
            expires_at: r.expires_at,
            revoked_at: r.revoked_at,
        }))
    }

    /// List live PATs for `user_id` in this org. Best-effort
    /// observability ordering.
    pub async fn list_for_user(&self, user_id: Uuid) -> Result<Vec<ApiToken>> {
        let rows = sqlx::query!(
            r#"
            SELECT id, token_hash, user_id, org_id, display_name,
                   scopes, last_used_at, last_used_ip,
                   created_at, expires_at, revoked_at
            FROM api_tokens
            WHERE org_id = $1
              AND user_id = $2
              AND revoked_at IS NULL
            ORDER BY created_at DESC
            "#,
            self.org_id(),
            user_id,
        )
        .fetch_all(self.inner().pool())
        .await?;

        rows.into_iter()
            .map(|r| {
                let token_hash: [u8; 32] =
                    r.token_hash.as_slice().try_into().map_err(|_| {
                        IdentityError::MalformedToken("api_token hash is not 32 bytes")
                    })?;
                Ok(ApiToken {
                    id: r.id,
                    token_hash,
                    user_id: r.user_id,
                    org_id: r.org_id,
                    display_name: r.display_name,
                    scopes: r.scopes,
                    last_used_at: r.last_used_at,
                    last_used_ip: r.last_used_ip.map(|n| n.ip()),
                    created_at: r.created_at,
                    expires_at: r.expires_at,
                    revoked_at: r.revoked_at,
                })
            })
            .collect()
    }

    /// Update best-effort `last_used_*` columns.
    ///
    /// `last_used_at` is monotonic via `GREATEST(COALESCE(...), $3)`
    /// so a late-delivered older write-behind event cannot move the
    /// timestamp backward; `last_used_ip` only updates when the
    /// caller's `last_used_at` wins the comparison so the IP stays
    /// in sync with the most-recent observation. Concurrent updates
    /// targeting the same token MAY lose the IP update without
    /// consequence (best-effort metadata).
    pub async fn update_last_used(
        &self,
        token_id: Uuid,
        last_used_at: DateTime<Utc>,
        last_used_ip: Option<IpAddr>,
    ) -> Result<()> {
        let ip_value: Option<sqlx::types::ipnetwork::IpNetwork> = last_used_ip.map(Into::into);
        sqlx::query!(
            r#"
            UPDATE api_tokens
            SET
                last_used_at = GREATEST(COALESCE(last_used_at, $3), $3),
                last_used_ip = CASE
                    WHEN last_used_at IS NULL OR last_used_at < $3 THEN $4
                    ELSE last_used_ip
                END
            WHERE org_id = $1 AND id = $2 AND revoked_at IS NULL
            "#,
            self.org_id(),
            token_id,
            last_used_at,
            ip_value,
        )
        .execute(self.inner().pool())
        .await?;
        Ok(())
    }

    /// Revoke a PAT scoped to this org. Returns the number of rows
    /// the UPDATE actually mutated so the caller can distinguish
    /// "this caller did the revoke" (`1`) from "already revoked or
    /// missing" (`0`) and emit audit events only for the former,
    /// preventing duplicate audit emission under concurrent revokes.
    pub async fn revoke(&self, token_id: Uuid) -> Result<u64> {
        let result = sqlx::query!(
            r#"
            UPDATE api_tokens
            SET revoked_at = now()
            WHERE org_id = $1 AND id = $2 AND revoked_at IS NULL
            "#,
            self.org_id(),
            token_id,
        )
        .execute(self.inner().pool())
        .await?;
        Ok(result.rows_affected())
    }

    /// Revoke every live PAT for `user_id` in this org. Used by the
    /// user soft-delete cascade.
    pub async fn revoke_all_for_user(&self, user_id: Uuid) -> Result<u64> {
        let result = sqlx::query!(
            r#"
            UPDATE api_tokens
            SET revoked_at = now()
            WHERE org_id = $1 AND user_id = $2 AND revoked_at IS NULL
            "#,
            self.org_id(),
            user_id,
        )
        .execute(self.inner().pool())
        .await?;
        Ok(result.rows_affected())
    }
}

/// Argument bundle for [`OrgScoped::<ApiTokenRepo>::create`].
#[derive(Debug)]
pub struct NewApiToken<'a> {
    /// Application-generated UUID v7.
    pub id: Uuid,
    /// SHA-256 of the raw `pat_<43>` token.
    pub token_hash: &'a [u8],
    /// Owning user.
    pub user_id: Uuid,
    /// Display name.
    pub display_name: &'a str,
    /// Scope list.
    pub scopes: &'a [&'a str],
    /// Optional hard expiry; `None` means never.
    pub expires_at: Option<DateTime<Utc>>,
}
