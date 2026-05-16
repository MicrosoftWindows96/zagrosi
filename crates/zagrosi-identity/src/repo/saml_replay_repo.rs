// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! `SamlReplayRepo` — assertion replay ledger persistence.

use chrono::{DateTime, Utc};
use sqlx::{PgPool, Postgres};
use uuid::Uuid;

use crate::domain::SamlAssertionRecord;
use crate::error::{IdentityError, Result, map_sqlx_error};

/// Repository for `saml_assertion_replay`. The composite primary
/// key `(org_idp_id, assertion_id)` IS the replay-rejection
/// mechanism: a duplicate insert raises a unique-violation, which
/// the SAML SP translates into an authentication failure.
#[derive(Clone)]
pub struct SamlReplayRepo {
    pool: PgPool,
}

impl SamlReplayRepo {
    /// Wrap a connection pool.
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Insert a replay-ledger row. A duplicate `(org_idp_id, assertion_id)`
    /// returns [`IdentityError::AssertionReplay`].
    pub async fn insert(&self, new: NewSamlAssertion<'_>) -> Result<SamlAssertionRecord> {
        let row = sqlx::query!(
            r#"
            INSERT INTO saml_assertion_replay (
                org_idp_id, assertion_id, not_on_or_after
            )
            VALUES ($1, $2, $3)
            RETURNING org_idp_id, assertion_id, not_on_or_after, created_at
            "#,
            new.org_idp_id,
            new.assertion_id,
            new.not_on_or_after,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            map_sqlx_error(
                e,
                IdentityError::TokenNotFound,
                IdentityError::AssertionReplay,
                Some("saml_assertion_replay_pkey"),
            )
        })?;

        Ok(SamlAssertionRecord {
            org_idp_id: row.org_idp_id,
            assertion_id: row.assertion_id,
            not_on_or_after: row.not_on_or_after,
            created_at: row.created_at,
        })
    }

    /// In-tx variant of [`Self::insert`]. The ACS handler runs the
    /// replay-ledger insert + the saml_pending_auth mark-used + the
    /// JIT/anchor-hit user-resolve in a single transaction so a crash
    /// mid-flow rolls everything back uniformly.
    pub async fn insert_in_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, Postgres>,
        new: NewSamlAssertion<'_>,
    ) -> Result<SamlAssertionRecord> {
        let row = sqlx::query!(
            r#"
            INSERT INTO saml_assertion_replay (
                org_idp_id, assertion_id, not_on_or_after
            )
            VALUES ($1, $2, $3)
            RETURNING org_idp_id, assertion_id, not_on_or_after, created_at
            "#,
            new.org_idp_id,
            new.assertion_id,
            new.not_on_or_after,
        )
        .fetch_one(&mut **tx)
        .await
        .map_err(|e| {
            map_sqlx_error(
                e,
                IdentityError::TokenNotFound,
                IdentityError::AssertionReplay,
                Some("saml_assertion_replay_pkey"),
            )
        })?;

        Ok(SamlAssertionRecord {
            org_idp_id: row.org_idp_id,
            assertion_id: row.assertion_id,
            not_on_or_after: row.not_on_or_after,
            created_at: row.created_at,
        })
    }

    /// Sweep rows whose validity window has elapsed. Returns the
    /// number of rows pruned. Run on a periodic worker (the SAML SP).
    pub async fn cleanup_expired_before(&self, cutoff: DateTime<Utc>) -> Result<u64> {
        let result = sqlx::query!(
            r#"
            DELETE FROM saml_assertion_replay
            WHERE not_on_or_after < $1
            "#,
            cutoff,
        )
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }
}

/// Argument bundle for [`SamlReplayRepo::insert`].
#[derive(Debug)]
pub struct NewSamlAssertion<'a> {
    /// Owning IdP.
    pub org_idp_id: Uuid,
    /// `<Assertion ID>` attribute.
    pub assertion_id: &'a str,
    /// `<Conditions NotOnOrAfter>` attribute.
    pub not_on_or_after: DateTime<Utc>,
}
