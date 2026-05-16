// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! `OidcPendingRepo` — pending OIDC authorisation persistence.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use sqlx::Postgres;
use uuid::Uuid;

use crate::domain::OidcPendingAuth;
use crate::error::{IdentityError, Result, map_sqlx_error};

/// Repository for `oidc_pending_auth`.
///
/// Tenant scoping is via `org_idp_id` (the IdP carries the org).
/// Single-use: the partial unique on `(state_hash) WHERE used_at IS NULL`
/// rejects duplicates while keeping the row queryable for audit.
/// `mark_used` is called inside the same transaction as the session
/// issue (the OIDC client), so the lookup + mark MUST be a transaction
/// pair from the caller's side.
#[derive(Clone)]
pub struct OidcPendingRepo {
    pool: PgPool,
}

impl OidcPendingRepo {
    /// Wrap a connection pool.
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Insert a new pending-auth row.
    pub async fn insert(&self, new: NewOidcPending<'_>) -> Result<OidcPendingAuth> {
        let row = sqlx::query!(
            r#"
            INSERT INTO oidc_pending_auth (
                id, org_idp_id, state_hash, nonce_hash, verifier_hash,
                csrf_cookie_hash, redirect_uri, expires_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING id, org_idp_id, state_hash, nonce_hash,
                      verifier_hash, csrf_cookie_hash, redirect_uri,
                      created_at, expires_at, used_at
            "#,
            new.id,
            new.org_idp_id,
            new.state_hash,
            new.nonce_hash,
            new.verifier_hash,
            new.csrf_cookie_hash,
            new.redirect_uri,
            new.expires_at,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            map_sqlx_error(
                e,
                IdentityError::TokenNotFound,
                IdentityError::TokenNotFound,
                Some("oidc_pending_auth_state_hash_unique_unused"),
            )
        })?;

        into_domain(
            row.id,
            row.org_idp_id,
            &row.state_hash,
            &row.nonce_hash,
            &row.verifier_hash,
            &row.csrf_cookie_hash,
            row.redirect_uri,
            row.created_at,
            row.expires_at,
            row.used_at,
        )
    }

    /// Lookup a pending-auth row by `state` SHA-256, regardless of
    /// `used_at`.
    ///
    /// The OIDC client distinguishes the "used row" replay from the
    /// "missing row" forgery in audit + telemetry; both surface as the
    /// same uniform `oidc_callback_failed` to the caller, but the
    /// audit dashboards distinguish them via the resolved row's
    /// `used_at` field. Callers that need the live-and-unused filter
    /// can compose [`Self::find_by_state`] with their own predicate.
    pub async fn find_by_state(&self, state_hash: &[u8; 32]) -> Result<Option<OidcPendingAuth>> {
        let row = sqlx::query!(
            r#"
            SELECT id, org_idp_id, state_hash, nonce_hash, verifier_hash,
                   csrf_cookie_hash, redirect_uri, created_at, expires_at, used_at
            FROM oidc_pending_auth
            WHERE state_hash = $1
            "#,
            &state_hash[..],
        )
        .fetch_optional(&self.pool)
        .await?;

        match row {
            None => Ok(None),
            Some(r) => Ok(Some(into_domain(
                r.id,
                r.org_idp_id,
                &r.state_hash,
                &r.nonce_hash,
                &r.verifier_hash,
                &r.csrf_cookie_hash,
                r.redirect_uri,
                r.created_at,
                r.expires_at,
                r.used_at,
            )?)),
        }
    }

    /// Mark the row consumed inside the caller's transaction. The OIDC client
    /// runs this immediately before issuing the session; `INSERT ...
    /// session ...` and this update share the txn so a crash either
    /// rolls both back or commits both.
    pub async fn mark_used(
        &self,
        tx: &mut sqlx::Transaction<'_, Postgres>,
        id: Uuid,
        used_at: DateTime<Utc>,
    ) -> Result<()> {
        let result = sqlx::query!(
            r#"
            UPDATE oidc_pending_auth
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
}

#[allow(clippy::too_many_arguments)]
fn into_domain(
    id: Uuid,
    org_idp_id: Uuid,
    state_hash: &[u8],
    nonce_hash: &[u8],
    verifier_hash: &[u8],
    csrf_cookie_hash: &[u8],
    redirect_uri: String,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    used_at: Option<DateTime<Utc>>,
) -> Result<OidcPendingAuth> {
    let to_arr = |b: &[u8]| -> Result<[u8; 32]> {
        b.try_into()
            .map_err(|_| IdentityError::MalformedToken("oidc_pending hash is not 32 bytes"))
    };
    Ok(OidcPendingAuth {
        id,
        org_idp_id,
        state_hash: to_arr(state_hash)?,
        nonce_hash: to_arr(nonce_hash)?,
        verifier_hash: to_arr(verifier_hash)?,
        csrf_cookie_hash: to_arr(csrf_cookie_hash)?,
        redirect_uri,
        created_at,
        expires_at,
        used_at,
    })
}

/// Argument bundle for [`OidcPendingRepo::insert`].
#[derive(Debug)]
pub struct NewOidcPending<'a> {
    /// Application-generated UUID v7.
    pub id: Uuid,
    /// IdP this transaction targets.
    pub org_idp_id: Uuid,
    /// SHA-256 of the `state` parameter.
    pub state_hash: &'a [u8],
    /// SHA-256 of the `nonce` value.
    pub nonce_hash: &'a [u8],
    /// SHA-256 of the PKCE code verifier.
    pub verifier_hash: &'a [u8],
    /// SHA-256 of the CSRF cookie value.
    pub csrf_cookie_hash: &'a [u8],
    /// Redirect URI registered with the IdP for this transaction.
    pub redirect_uri: &'a str,
    /// Hard expiry timestamp (typically created_at + 10 minutes).
    pub expires_at: DateTime<Utc>,
}
