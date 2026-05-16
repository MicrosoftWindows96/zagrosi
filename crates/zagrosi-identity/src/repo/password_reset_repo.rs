// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! `PasswordResetRepo` — single-use password-reset token persistence.

use chrono::{DateTime, Utc};
use sqlx::Postgres;
use uuid::Uuid;

use crate::error::{IdentityError, Result};

/// Live (non-consumed) password-reset row materialised from a hash
/// lookup. Carries `id` + `user_id` so the password-auth reset-confirm flow can
/// flip `used_at` and update the user atomically.
#[derive(Debug, Clone)]
pub struct PasswordResetRow {
    /// Reset row primary key.
    pub id: Uuid,
    /// Owning user.
    pub user_id: Uuid,
    /// Hard expiry timestamp.
    pub expires_at: DateTime<Utc>,
    /// Single-use seal (`Some` after consumption).
    pub used_at: Option<DateTime<Utc>>,
}

/// Repository for `password_resets`. Single-tenant per row; the
/// canonical lookup is by SHA-256 of the raw `rst_*` token.
pub struct PasswordResetRepo {
    pool: sqlx::PgPool,
}

impl PasswordResetRepo {
    /// Wrap a connection pool.
    #[must_use]
    pub const fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }

    /// Insert a new reset-token row inside the caller's transaction.
    pub async fn insert(
        &self,
        tx: &mut sqlx::Transaction<'_, Postgres>,
        id: Uuid,
        user_id: Uuid,
        token_hash: &[u8],
        expires_at: DateTime<Utc>,
    ) -> Result<()> {
        sqlx::query!(
            r#"
            INSERT INTO password_resets (id, user_id, token_hash, expires_at)
            VALUES ($1, $2, $3, $4)
            "#,
            id,
            user_id,
            token_hash,
            expires_at,
        )
        .execute(&mut **tx)
        .await
        .map_err(IdentityError::from)?;
        Ok(())
    }

    /// Lookup an unused reset-token row by SHA-256 hash.
    /// Returns `None` for missing-or-already-used rows.
    pub async fn find_unused_by_hash(
        &self,
        token_hash: &[u8; 32],
    ) -> Result<Option<PasswordResetRow>> {
        let row = sqlx::query!(
            r#"
            SELECT id, user_id, expires_at, used_at
            FROM password_resets
            WHERE token_hash = $1 AND used_at IS NULL
            "#,
            &token_hash[..],
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| PasswordResetRow {
            id: r.id,
            user_id: r.user_id,
            expires_at: r.expires_at,
            used_at: r.used_at,
        }))
    }

    /// Atomically flip `used_at` inside the caller's transaction.
    /// Returns the number of rows updated; callers MUST treat zero
    /// as a lost-race + surface [`IdentityError::TokenAlreadyUsed`].
    pub async fn mark_used(
        &self,
        tx: &mut sqlx::Transaction<'_, Postgres>,
        id: Uuid,
    ) -> Result<u64> {
        let result = sqlx::query!(
            r#"
            UPDATE password_resets
            SET used_at = now()
            WHERE id = $1 AND used_at IS NULL
            "#,
            id,
        )
        .execute(&mut **tx)
        .await
        .map_err(IdentityError::from)?;
        Ok(result.rows_affected())
    }
}
