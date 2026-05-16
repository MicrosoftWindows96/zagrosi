// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! `EmailVerificationRepo` — single-use email-verification token persistence.

use chrono::{DateTime, Utc};
use sqlx::Postgres;
use uuid::Uuid;

use crate::error::{IdentityError, Result};

/// Live (non-consumed) email-verification row materialised from a
/// hash lookup.
#[derive(Debug, Clone)]
pub struct EmailVerificationRow {
    /// Verification row primary key.
    pub id: Uuid,
    /// Owning user.
    pub user_id: Uuid,
    /// Hard expiry timestamp.
    pub expires_at: DateTime<Utc>,
    /// Single-use seal (`Some` after consumption).
    pub used_at: Option<DateTime<Utc>>,
}

/// Repository for `email_verifications`.
pub struct EmailVerificationRepo {
    pool: sqlx::PgPool,
}

impl EmailVerificationRepo {
    /// Wrap a connection pool.
    #[must_use]
    pub const fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }

    /// Insert a new verification-token row inside the caller's
    /// transaction. `email` is the address the token was minted for —
    /// stored verbatim so the password-auth confirm path can verify the row's
    /// email matches the user's current email (defence against
    /// confirm-after-rotate races).
    pub async fn insert(
        &self,
        tx: &mut sqlx::Transaction<'_, Postgres>,
        id: Uuid,
        user_id: Uuid,
        email: &str,
        token_hash: &[u8],
        expires_at: DateTime<Utc>,
    ) -> Result<()> {
        sqlx::query!(
            r#"
            INSERT INTO email_verifications (id, user_id, email, token_hash, expires_at)
            VALUES ($1, $2, $3, $4, $5)
            "#,
            id,
            user_id,
            email,
            token_hash,
            expires_at,
        )
        .execute(&mut **tx)
        .await
        .map_err(IdentityError::from)?;
        Ok(())
    }

    /// Lookup an unused verification-token row by SHA-256 hash.
    pub async fn find_unused_by_hash(
        &self,
        token_hash: &[u8; 32],
    ) -> Result<Option<EmailVerificationRow>> {
        let row = sqlx::query!(
            r#"
            SELECT id, user_id, expires_at, used_at
            FROM email_verifications
            WHERE token_hash = $1 AND used_at IS NULL
            "#,
            &token_hash[..],
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| EmailVerificationRow {
            id: r.id,
            user_id: r.user_id,
            expires_at: r.expires_at,
            used_at: r.used_at,
        }))
    }

    /// Atomically flip `used_at` inside the caller's transaction.
    pub async fn mark_used(
        &self,
        tx: &mut sqlx::Transaction<'_, Postgres>,
        id: Uuid,
    ) -> Result<u64> {
        let result = sqlx::query!(
            r#"
            UPDATE email_verifications
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
