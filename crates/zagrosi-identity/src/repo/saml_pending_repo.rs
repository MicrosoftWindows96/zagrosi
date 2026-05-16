// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! `SamlPendingRepo` — pending SAML AuthnRequest persistence.

use chrono::{DateTime, Utc};
use sqlx::{PgPool, Postgres};
use uuid::Uuid;

use crate::domain::SamlPendingAuth;
use crate::error::{IdentityError, Result, map_sqlx_error};

/// Repository for `saml_pending_auth`.
///
/// Tenant scoping is by `org_idp_id` (the IdP carries the org).
/// Single-use is enforced by the partial unique index
/// `saml_pending_auth_request_id_unused`. The ACS handler runs
/// [`Self::find_by_relay_state_in_tx`] + [`Self::mark_used`] inside
/// the same transaction as the saml_assertion_replay INSERT and the
/// JIT/anchor-hit user-resolve so a crash mid-flow either commits
/// the entire ACS transaction or rolls everything back.
#[derive(Clone)]
pub struct SamlPendingRepo {
    pool: PgPool,
}

impl SamlPendingRepo {
    /// Wrap a connection pool.
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Insert a new pending-auth row. A duplicate
    /// `(org_idp_id, request_id)` while `used_at IS NULL` raises
    /// [`IdentityError::TokenNotFound`] (the partial unique index
    /// blocks reuse before any IdP round-trip).
    pub async fn insert(&self, new: NewSamlPending<'_>) -> Result<SamlPendingAuth> {
        let row = sqlx::query!(
            r#"
            INSERT INTO saml_pending_auth (
                id, request_id, relay_state, org_idp_id, expires_at
            )
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id, request_id, relay_state, org_idp_id,
                      created_at, expires_at, used_at
            "#,
            new.id,
            new.request_id,
            new.relay_state,
            new.org_idp_id,
            new.expires_at,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            map_sqlx_error(
                e,
                IdentityError::TokenNotFound,
                IdentityError::TokenNotFound,
                Some("saml_pending_auth_request_id_unused"),
            )
        })?;

        Ok(SamlPendingAuth {
            id: row.id,
            request_id: row.request_id,
            relay_state: row.relay_state,
            org_idp_id: row.org_idp_id,
            created_at: row.created_at,
            expires_at: row.expires_at,
            used_at: row.used_at,
        })
    }

    /// Look up a pending row by `relay_state` inside the caller's
    /// transaction. The ACS handler reads + marks the row in one
    /// transaction so the row's used-state is consistent with the
    /// downstream replay-ledger insert + session issue.
    ///
    /// Returns `Ok(None)` when no row matches; the row's `used_at`
    /// must be inspected by the caller to distinguish a fresh
    /// presentation from a replay.
    pub async fn find_by_relay_state_in_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, Postgres>,
        relay_state: &str,
    ) -> Result<Option<SamlPendingAuth>> {
        let row = sqlx::query!(
            r#"
            SELECT id, request_id, relay_state, org_idp_id,
                   created_at, expires_at, used_at
            FROM saml_pending_auth
            WHERE relay_state = $1
            "#,
            relay_state,
        )
        .fetch_optional(&mut **tx)
        .await?;

        Ok(row.map(|r| SamlPendingAuth {
            id: r.id,
            request_id: r.request_id,
            relay_state: r.relay_state,
            org_idp_id: r.org_idp_id,
            created_at: r.created_at,
            expires_at: r.expires_at,
            used_at: r.used_at,
        }))
    }

    /// Look up a pending row by `relay_state` and acquire a row-level
    /// lock for the duration of the caller's transaction.
    ///
    /// The ACS handler uses this variant to serialise concurrent
    /// presentations of the same `RelayState`: the first caller takes
    /// the lock, runs samael's signature + XSW + audience checks,
    /// inserts the replay-ledger row, marks the pending row used, and
    /// commits. Concurrent ACS calls block on the row lock; when they
    /// resume after the first commits, their re-read sees the
    /// committed `used_at IS NOT NULL` state and returns
    /// `RelayStateMismatch`.
    ///
    /// Without `FOR UPDATE`, two concurrent ACS posts with the same
    /// `RelayState` but distinct (forged) `assertion_id` values both
    /// pass samael (separate state) and both insert into
    /// `saml_assertion_replay` cleanly — issuing two sessions for one
    /// AuthnRequest. The lock closes that window.
    pub async fn find_by_relay_state_for_update_in_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, Postgres>,
        relay_state: &str,
    ) -> Result<Option<SamlPendingAuth>> {
        let row = sqlx::query!(
            r#"
            SELECT id, request_id, relay_state, org_idp_id,
                   created_at, expires_at, used_at
            FROM saml_pending_auth
            WHERE relay_state = $1
            FOR UPDATE
            "#,
            relay_state,
        )
        .fetch_optional(&mut **tx)
        .await?;

        Ok(row.map(|r| SamlPendingAuth {
            id: r.id,
            request_id: r.request_id,
            relay_state: r.relay_state,
            org_idp_id: r.org_idp_id,
            created_at: r.created_at,
            expires_at: r.expires_at,
            used_at: r.used_at,
        }))
    }

    /// Mark the row consumed inside the caller's transaction. Returns
    /// [`IdentityError::TokenNotFound`] if the row is missing or
    /// already used; the ACS handler re-raises this as
    /// `assertion_replay` (per spec the response surface is uniform).
    pub async fn mark_used(
        &self,
        tx: &mut sqlx::Transaction<'_, Postgres>,
        id: Uuid,
        used_at: DateTime<Utc>,
    ) -> Result<()> {
        let result = sqlx::query!(
            r#"
            UPDATE saml_pending_auth
            SET used_at = $2
            WHERE id = $1 AND used_at IS NULL
            "#,
            id,
            used_at,
        )
        .execute(&mut **tx)
        .await?;
        if result.rows_affected() == 0 {
            return Err(IdentityError::TokenNotFound);
        }
        Ok(())
    }

    /// Sweep rows whose expiry has elapsed AND used rows. Returns the
    /// number of rows pruned. Run on a periodic worker.
    pub async fn cleanup_expired_before(&self, cutoff: DateTime<Utc>) -> Result<u64> {
        let result = sqlx::query!(
            r#"
            DELETE FROM saml_pending_auth
            WHERE expires_at < $1 OR used_at IS NOT NULL
            "#,
            cutoff,
        )
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }
}

/// Argument bundle for [`SamlPendingRepo::insert`].
#[derive(Debug)]
pub struct NewSamlPending<'a> {
    /// Application-generated UUID v7.
    pub id: Uuid,
    /// SAML AuthnRequest id (CSPRNG, ASCII-safe; samael accepts any
    /// `xs:ID` value but the IdP echoes verbatim, so keep it short).
    pub request_id: &'a str,
    /// 256-bit base64url RelayState.
    pub relay_state: &'a str,
    /// IdP this transaction targets.
    pub org_idp_id: Uuid,
    /// Hard expiry timestamp (typically created_at + 10 minutes).
    pub expires_at: DateTime<Utc>,
}
