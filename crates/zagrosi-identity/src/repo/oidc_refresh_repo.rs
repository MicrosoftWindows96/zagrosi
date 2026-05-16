// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! `OidcRefreshRepo` — refresh-token chain persistence.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use sqlx::Postgres;
use uuid::Uuid;

use crate::domain::OidcRefreshToken;
use crate::error::{IdentityError, Result, map_sqlx_error};

/// Repository for `oidc_refresh_tokens`. Refresh-token rotation is
/// the security-critical path: the OIDC client inserts the new row,
/// `mark_used` the old, and detects replay by observing a `used_at`
/// re-flip. On replay, the entire chain MUST be revoked.
#[derive(Clone)]
pub struct OidcRefreshRepo {
    pool: PgPool,
}

impl OidcRefreshRepo {
    /// Wrap a connection pool.
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Insert a new refresh-token row.
    ///
    /// Used by the seed path ([`crate::oidc::RefreshChain::issue_initial`]).
    /// A unique-violation here surfaces as
    /// [`IdentityError::TokenNotFound`] because at seed time the
    /// caller is minting the very first row in the chain — a duplicate
    /// hash means a programming error or RNG collision, not a replay.
    pub async fn insert(&self, new: NewOidcRefresh<'_>) -> Result<OidcRefreshToken> {
        Self::insert_via_executor(&self.pool, new, IdentityError::TokenNotFound).await
    }

    /// Insert a refresh row inside a caller-supplied transaction. A
    /// unique-violation on the live-token index indicates the new
    /// token hash already exists for an active chain row, which is
    /// itself a replay or a programming bug; surface the typed
    /// [`IdentityError::RefreshChainReplay`] so the OIDC client's
    /// rotation path keeps the canonical signal.
    pub async fn insert_in_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, Postgres>,
        new: NewOidcRefresh<'_>,
    ) -> Result<OidcRefreshToken> {
        Self::insert_via_executor(&mut **tx, new, IdentityError::RefreshChainReplay).await
    }

    /// Single-source SQL + result mapping for the refresh-token
    /// INSERT. Both [`Self::insert`] (pool executor, seed path) and
    /// [`Self::insert_in_tx`] (transaction executor, rotation path)
    /// call this — sqlx's `Executor` trait abstracts both endpoints.
    /// `unique_violation_error` lets each caller pick the typed error
    /// that matches its semantic context (seed-time programming bug
    /// vs. rotation-time replay).
    async fn insert_via_executor<'e, E>(
        executor: E,
        new: NewOidcRefresh<'_>,
        unique_violation_error: IdentityError,
    ) -> Result<OidcRefreshToken>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        let row = sqlx::query!(
            r#"
            INSERT INTO oidc_refresh_tokens (
                id, session_id, token_hash, prev_id
            )
            VALUES ($1, $2, $3, $4)
            RETURNING id, session_id, token_hash, prev_id,
                      issued_at, used_at, revoked_at
            "#,
            new.id,
            new.session_id,
            new.token_hash,
            new.prev_id,
        )
        .fetch_one(executor)
        .await
        .map_err(move |e| {
            map_sqlx_error(
                e,
                IdentityError::TokenNotFound,
                unique_violation_error,
                Some("oidc_refresh_tokens_token_hash_unique_live"),
            )
        })?;

        let token_hash: [u8; 32] = row
            .token_hash
            .as_slice()
            .try_into()
            .map_err(|_| IdentityError::MalformedToken("refresh token_hash is not 32 bytes"))?;
        Ok(OidcRefreshToken {
            id: row.id,
            session_id: row.session_id,
            token_hash,
            prev_id: row.prev_id,
            issued_at: row.issued_at,
            used_at: row.used_at,
            revoked_at: row.revoked_at,
        })
    }

    /// Lookup a live refresh-token row by hash, regardless of
    /// `used_at`.
    ///
    /// Filters `revoked_at IS NULL` so a chain that has already been
    /// revoked stops returning rows altogether. The `used_at` column is
    /// surfaced verbatim so the caller can branch on it: a row whose
    /// `used_at IS NOT NULL` is a confirmed replay attempt (the same
    /// hash redeemed twice), and the OIDC client must revoke the
    /// chain + parent session before returning the typed
    /// [`IdentityError::RefreshChainReplay`].
    pub async fn find_by_token_hash(
        &self,
        token_hash: &[u8; 32],
    ) -> Result<Option<OidcRefreshToken>> {
        let row = sqlx::query!(
            r#"
            SELECT id, session_id, token_hash, prev_id,
                   issued_at, used_at, revoked_at
            FROM oidc_refresh_tokens
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
            .map_err(|_| IdentityError::MalformedToken("refresh token_hash is not 32 bytes"))?;
        Ok(Some(OidcRefreshToken {
            id: r.id,
            session_id: r.session_id,
            token_hash: token_hash_arr,
            prev_id: r.prev_id,
            issued_at: r.issued_at,
            used_at: r.used_at,
            revoked_at: r.revoked_at,
        }))
    }

    /// Mark the row consumed (`used_at = $2`). Returns
    /// [`IdentityError::RefreshChainReplay`] if the row was already
    /// marked; the OIDC client reacts by revoking the whole chain via
    /// [`OidcRefreshRepo::revoke_chain_for_session`].
    pub async fn mark_used(&self, id: Uuid, used_at: DateTime<Utc>) -> Result<()> {
        Self::mark_used_via_executor(&self.pool, id, used_at).await
    }

    /// Mark the row consumed inside a caller-supplied transaction. The
    /// rotation flow pairs this with [`Self::insert_in_tx`] so the
    /// parent flip and the child insert commit (or roll back) as one
    /// unit. Returns [`IdentityError::RefreshChainReplay`] when the row
    /// was concurrently consumed.
    pub async fn mark_used_in_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, Postgres>,
        id: Uuid,
        used_at: DateTime<Utc>,
    ) -> Result<()> {
        Self::mark_used_via_executor(&mut **tx, id, used_at).await
    }

    /// Single-source SQL for the `mark_used` UPDATE. Both
    /// [`Self::mark_used`] and [`Self::mark_used_in_tx`] delegate
    /// here so the `WHERE used_at IS NULL` race-detection predicate
    /// cannot drift between the two endpoints.
    async fn mark_used_via_executor<'e, E>(
        executor: E,
        id: Uuid,
        used_at: DateTime<Utc>,
    ) -> Result<()>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        let result = sqlx::query!(
            r#"
            UPDATE oidc_refresh_tokens
            SET used_at = $2
            WHERE id = $1 AND used_at IS NULL
            "#,
            id,
            used_at,
        )
        .execute(executor)
        .await?;

        if result.rows_affected() == 0 {
            return Err(IdentityError::RefreshChainReplay);
        }
        Ok(())
    }

    /// Revoke every live refresh-token row for `session_id`. The OIDC client
    /// invokes this on replay detection. Returns the number of rows
    /// revoked.
    pub async fn revoke_chain_for_session(&self, session_id: Uuid) -> Result<u64> {
        Self::revoke_chain_via_executor(&self.pool, session_id).await
    }

    /// In-tx variant of [`Self::revoke_chain_for_session`]. Used by
    /// the OIDC refresh-replay handler so chain revoke + parent
    /// session revoke share a commit unit.
    pub async fn revoke_chain_for_session_in_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, Postgres>,
        session_id: Uuid,
    ) -> Result<u64> {
        Self::revoke_chain_via_executor(&mut **tx, session_id).await
    }

    /// Single-source SQL for the chain-revoke UPDATE. Both
    /// [`Self::revoke_chain_for_session`] and
    /// [`Self::revoke_chain_for_session_in_tx`] delegate here so the
    /// `revoked_at IS NULL` idempotency filter cannot drift.
    async fn revoke_chain_via_executor<'e, E>(executor: E, session_id: Uuid) -> Result<u64>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        let result = sqlx::query!(
            r#"
            UPDATE oidc_refresh_tokens
            SET revoked_at = now()
            WHERE session_id = $1 AND revoked_at IS NULL
            "#,
            session_id,
        )
        .execute(executor)
        .await?;
        Ok(result.rows_affected())
    }
}

/// Argument bundle for [`OidcRefreshRepo::insert`].
#[derive(Debug)]
pub struct NewOidcRefresh<'a> {
    /// Application-generated UUID v7.
    pub id: Uuid,
    /// Owning session.
    pub session_id: Uuid,
    /// SHA-256 of the raw refresh token.
    pub token_hash: &'a [u8],
    /// Previous link in the chain; `None` for the first refresh.
    pub prev_id: Option<Uuid>,
}
