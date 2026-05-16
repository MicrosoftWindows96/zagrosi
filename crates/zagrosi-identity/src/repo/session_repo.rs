// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! `SessionRepo` — browser session persistence.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use std::net::IpAddr;
use uuid::Uuid;

use crate::domain::Session;
use crate::error::{IdentityError, Result, map_sqlx_error};

/// Repository for `sessions`.
///
/// Sessions intentionally bypass the [`super::OrgScoped`] wrapper.
/// The model:
///
/// - `sessions.org_id` is `NULL`able and represents the *currently
///   selected* active org for a session, not a discriminator at
///   lookup time.
/// - Session-issue writes (`insert`) happen before the active org is
///   chosen, so an `OrgScoped` wrapper would have nothing to bind.
/// - The introspection path used by the gateway
///   (`SessionIntrospector` from `zagrosi-core`) receives only the
///   raw cookie/bearer token. The gateway has no org context yet —
///   the org is what comes back inside the introspection result.
///   Hash-only lookup is therefore the *only* feasible signature.
/// - The `sessions.token_hash` partial unique index guarantees at
///   most one live row per hash, so the lookup is unambiguous without
///   an `org_id` predicate.
///
/// **Caller contract for [`SessionRepo::find_by_token_hash`]**: when
/// the session is presented in a context that already knows the
/// expected org (e.g. a CSRF check that fingerprints the active org
/// from a prior request), the caller MUST verify
/// `session.org_id == expected_org_id` after lookup. The type system
/// does not enforce this — see `tests/tenant_isolation.rs` for the
/// canonical assertion that the lookup is hash-only by design.
///
/// Org-scoped helpers (`revoke_all_for_org`) live as inherent methods
/// because their `WHERE org_id = $1` filter is the whole query body
/// and an extra wrapper layer adds no safety.
#[derive(Clone)]
pub struct SessionRepo {
    pool: PgPool,
}

impl SessionRepo {
    /// Wrap a connection pool.
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Insert a freshly minted session. `token_hash` MUST be the
    /// SHA-256 of the raw `sid_*` cookie value (use
    /// [`crate::domain::token_format::hash_token`]).
    pub async fn insert(&self, new: NewSession<'_>) -> Result<Session> {
        Self::insert_via_executor(&self.pool, new).await
    }

    /// Insert a freshly minted session inside the caller's
    /// transaction. Identical to [`Self::insert`] but the row lands
    /// on the supplied transaction so the SAML / OIDC ACS handler
    /// can commit the session row atomically with the JIT user
    /// insert + replay-ledger insert + pending-row mark-used. Used
    /// by `saml::acs::handler` to close the session-issued-after-
    /// commit window where a downstream session insert failure left
    /// a JIT-provisioned user with a consumed replay row but no
    /// session, locking them out for that assertion.
    pub async fn insert_in_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        new: NewSession<'_>,
    ) -> Result<Session> {
        Self::insert_via_executor(&mut **tx, new).await
    }

    /// Single-source SQL + result mapping for the session INSERT.
    /// Both [`Self::insert`] (pool executor) and [`Self::insert_in_tx`]
    /// (transaction executor) call this — sqlx's `Executor` trait
    /// abstracts both endpoints. Removes the ~50 LOC duplication
    /// that would otherwise drift between the two callers.
    async fn insert_via_executor<'e, E>(executor: E, new: NewSession<'_>) -> Result<Session>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        let ip_value: Option<sqlx::types::ipnetwork::IpNetwork> = new.ip_addr.map(Into::into);
        let amr_owned: Vec<String> = new.amr.iter().map(|s| (*s).to_string()).collect();
        let row = sqlx::query!(
            r#"
            INSERT INTO sessions (
                id, token_hash, user_id, org_id,
                user_agent, ip_addr, amr, acr, expires_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING id, token_hash, user_id, org_id, user_agent,
                      ip_addr, version, amr, acr,
                      created_at, last_seen_at, expires_at,
                      revoked_at, deleted_at
            "#,
            new.id,
            new.token_hash,
            new.user_id,
            new.org_id,
            new.user_agent,
            ip_value,
            &amr_owned,
            new.acr,
            new.expires_at,
        )
        .fetch_one(executor)
        .await
        .map_err(|e| {
            map_sqlx_error(
                e,
                IdentityError::TokenNotFound,
                IdentityError::TokenNotFound,
                Some("sessions_token_hash_unique_live"),
            )
        })?;

        let token_hash: [u8; 32] = row
            .token_hash
            .as_slice()
            .try_into()
            .map_err(|_| IdentityError::MalformedToken("session token_hash is not 32 bytes"))?;
        Ok(Session {
            id: row.id,
            token_hash,
            user_id: row.user_id,
            org_id: row.org_id,
            user_agent: row.user_agent,
            ip_addr: row.ip_addr.map(|n| n.ip()),
            version: row.version,
            amr: row.amr,
            acr: row.acr,
            created_at: row.created_at,
            last_seen_at: row.last_seen_at,
            expires_at: row.expires_at,
            revoked_at: row.revoked_at,
            deleted_at: row.deleted_at,
        })
    }

    /// Lookup a live session by token hash. Returns `None` for
    /// expired, revoked, or tombstoned rows.
    pub async fn find_by_token_hash(&self, token_hash: &[u8; 32]) -> Result<Option<Session>> {
        let row = sqlx::query!(
            r#"
            SELECT id, token_hash, user_id, org_id, user_agent,
                   ip_addr, version, amr, acr,
                   created_at, last_seen_at, expires_at,
                   revoked_at, deleted_at
            FROM sessions
            WHERE token_hash = $1
              AND revoked_at IS NULL
              AND deleted_at IS NULL
              AND expires_at > now()
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
            .map_err(|_| IdentityError::MalformedToken("session token_hash is not 32 bytes"))?;
        Ok(Some(Session {
            id: r.id,
            token_hash: token_hash_arr,
            user_id: r.user_id,
            org_id: r.org_id,
            user_agent: r.user_agent,
            ip_addr: r.ip_addr.map(|n| n.ip()),
            version: r.version,
            amr: r.amr,
            acr: r.acr,
            created_at: r.created_at,
            last_seen_at: r.last_seen_at,
            expires_at: r.expires_at,
            revoked_at: r.revoked_at,
            deleted_at: r.deleted_at,
        }))
    }

    /// Lookup a live session by primary key. Returns `None` for
    /// rows that are revoked, tombstoned, or already past their
    /// `expires_at`.
    pub async fn find_by_id(&self, session_id: Uuid) -> Result<Option<Session>> {
        let row = sqlx::query!(
            r#"
            SELECT id, token_hash, user_id, org_id, user_agent,
                   ip_addr, version, amr, acr,
                   created_at, last_seen_at, expires_at,
                   revoked_at, deleted_at
            FROM sessions
            WHERE id = $1
              AND revoked_at IS NULL
              AND deleted_at IS NULL
              AND expires_at > now()
            "#,
            session_id,
        )
        .fetch_optional(&self.pool)
        .await?;

        let Some(r) = row else { return Ok(None) };
        let token_hash_arr: [u8; 32] = r
            .token_hash
            .as_slice()
            .try_into()
            .map_err(|_| IdentityError::MalformedToken("session token_hash is not 32 bytes"))?;
        Ok(Some(Session {
            id: r.id,
            token_hash: token_hash_arr,
            user_id: r.user_id,
            org_id: r.org_id,
            user_agent: r.user_agent,
            ip_addr: r.ip_addr.map(|n| n.ip()),
            version: r.version,
            amr: r.amr,
            acr: r.acr,
            created_at: r.created_at,
            last_seen_at: r.last_seen_at,
            expires_at: r.expires_at,
            revoked_at: r.revoked_at,
            deleted_at: r.deleted_at,
        }))
    }

    /// List the live sessions belonging to `user_id`. Used by the
    /// `GET /v1/sessions` self-listing route. Soft-deleted, revoked,
    /// or expired rows are excluded.
    pub async fn list_for_user(&self, user_id: Uuid) -> Result<Vec<Session>> {
        let rows = sqlx::query!(
            r#"
            SELECT id, token_hash, user_id, org_id, user_agent,
                   ip_addr, version, amr, acr,
                   created_at, last_seen_at, expires_at,
                   revoked_at, deleted_at
            FROM sessions
            WHERE user_id = $1
              AND revoked_at IS NULL
              AND deleted_at IS NULL
              AND expires_at > now()
            ORDER BY created_at DESC
            "#,
            user_id,
        )
        .fetch_all(&self.pool)
        .await?;

        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let token_hash_arr: [u8; 32] =
                r.token_hash.as_slice().try_into().map_err(|_| {
                    IdentityError::MalformedToken("session token_hash is not 32 bytes")
                })?;
            out.push(Session {
                id: r.id,
                token_hash: token_hash_arr,
                user_id: r.user_id,
                org_id: r.org_id,
                user_agent: r.user_agent,
                ip_addr: r.ip_addr.map(|n| n.ip()),
                version: r.version,
                amr: r.amr,
                acr: r.acr,
                created_at: r.created_at,
                last_seen_at: r.last_seen_at,
                expires_at: r.expires_at,
                revoked_at: r.revoked_at,
                deleted_at: r.deleted_at,
            });
        }
        Ok(out)
    }

    /// Switch the session's active org with optimistic locking.
    ///
    /// `expected_version` must match the row's current `version` for
    /// the update to succeed. On match, both `org_id` and `version`
    /// are updated atomically (`version := version + 1`). On mismatch,
    /// returns [`IdentityError::OptimisticLockConflict`].
    pub async fn update_active_org(
        &self,
        session_id: Uuid,
        new_org_id: Uuid,
        expected_version: i64,
    ) -> Result<i64> {
        assert!(
            !new_org_id.is_nil(),
            "new_org_id must not be nil — tenant-isolation invariant",
        );
        let row = sqlx::query!(
            r#"
            UPDATE sessions
            SET org_id = $2,
                version = version + 1,
                last_seen_at = now()
            WHERE id = $1
              AND version = $3
              AND revoked_at IS NULL
              AND deleted_at IS NULL
            RETURNING version
            "#,
            session_id,
            new_org_id,
            expected_version,
        )
        .fetch_optional(&self.pool)
        .await?;

        row.map(|r| r.version)
            .ok_or(IdentityError::OptimisticLockConflict)
    }

    /// Revoke a single session by id. Idempotent.
    pub async fn revoke(&self, session_id: Uuid) -> Result<()> {
        sqlx::query!(
            r#"
            UPDATE sessions
            SET revoked_at = now()
            WHERE id = $1 AND revoked_at IS NULL
            "#,
            session_id,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Revoke a single session inside a caller-supplied transaction.
    /// Used by the OIDC refresh-replay handler so chain revoke +
    /// session revoke share a commit unit.
    pub async fn revoke_in_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        session_id: Uuid,
    ) -> Result<()> {
        sqlx::query!(
            r#"
            UPDATE sessions
            SET revoked_at = now()
            WHERE id = $1 AND revoked_at IS NULL
            "#,
            session_id,
        )
        .execute(&mut **tx)
        .await?;
        Ok(())
    }

    /// Lookup the `(org_id, user_id)` of a session by id, restricted
    /// to live (non-soft-deleted) rows. Used by the OIDC refresh-replay
    /// handler so the audit event carries real tenant context AND the
    /// revoker has the user_id needed for the NATS event payload.
    /// `org_id` may still be `None` if the session never had an active
    /// org assigned. The query lives inside `tx` so it observes the
    /// same horizon as the chain-revoke + session-revoke that follow.
    pub async fn find_org_user_for_session_in_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        session_id: Uuid,
    ) -> Result<Option<(Option<Uuid>, Uuid)>> {
        let row = sqlx::query!(
            r#"
            SELECT org_id, user_id
            FROM sessions
            WHERE id = $1
              AND revoked_at IS NULL
            "#,
            session_id,
        )
        .fetch_optional(&mut **tx)
        .await?;
        Ok(row.map(|r| (r.org_id, r.user_id)))
    }

    /// Revoke every live session belonging to `user_id`. Used by
    /// password rotation, account deletion, and admin lockout.
    pub async fn revoke_all_for_user(&self, user_id: Uuid) -> Result<u64> {
        let result = sqlx::query!(
            r#"
            UPDATE sessions
            SET revoked_at = now()
            WHERE user_id = $1 AND revoked_at IS NULL
            "#,
            user_id,
        )
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    /// In-transaction variant of [`Self::revoke_all_for_user`].
    /// Used by SCIM `active=false` so the active-flip and the
    /// session revocation commit atomically.
    pub async fn revoke_all_for_user_in_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        user_id: Uuid,
    ) -> Result<u64> {
        let result = sqlx::query!(
            r#"
            UPDATE sessions
            SET revoked_at = now()
            WHERE user_id = $1 AND revoked_at IS NULL
            "#,
            user_id,
        )
        .execute(&mut **tx)
        .await?;
        Ok(result.rows_affected())
    }

    /// Revoke every live session belonging to `user_id` whose
    /// active org matches `org_id`. Used by the SCIM POST path
    /// when an existing user is re-onboarded as `active=false`
    /// in a NEW org — sessions in OTHER orgs MUST NOT be
    /// touched (cross-tenant blast radius bug fixed in
    /// section-12 round-2 review).
    pub async fn revoke_for_user_in_org_in_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        user_id: Uuid,
        org_id: Uuid,
    ) -> Result<u64> {
        let result = sqlx::query!(
            r#"
            UPDATE sessions
            SET revoked_at = now()
            WHERE user_id = $1
              AND org_id = $2
              AND revoked_at IS NULL
            "#,
            user_id,
            org_id,
        )
        .execute(&mut **tx)
        .await?;
        Ok(result.rows_affected())
    }

    /// Revoke every live session whose active org matches `org_id`.
    /// The persistence-layer cascade calls this from inside the org soft-delete
    /// transaction.
    pub async fn revoke_all_for_org(&self, org_id: Uuid) -> Result<u64> {
        let result = sqlx::query!(
            r#"
            UPDATE sessions
            SET revoked_at = now()
            WHERE org_id = $1 AND revoked_at IS NULL
            "#,
            org_id,
        )
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }
}

/// Argument bundle for [`SessionRepo::insert`].
#[derive(Debug)]
pub struct NewSession<'a> {
    /// Application-generated UUID v7.
    pub id: Uuid,
    /// SHA-256 of the raw cookie value.
    pub token_hash: &'a [u8],
    /// Owning user.
    pub user_id: Uuid,
    /// Initial active org; `None` lets the user pick on next request.
    pub org_id: Option<Uuid>,
    /// User agent at issue.
    pub user_agent: Option<&'a str>,
    /// Source IP at issue.
    pub ip_addr: Option<IpAddr>,
    /// RFC 8176 authentication-method-reference values.
    pub amr: &'a [&'a str],
    /// RFC 6711 authentication-context-class-reference.
    pub acr: Option<&'a str>,
    /// Hard expiry timestamp.
    pub expires_at: DateTime<Utc>,
}
