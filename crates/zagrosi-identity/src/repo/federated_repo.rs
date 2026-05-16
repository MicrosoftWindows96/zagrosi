// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! `FederatedIdentityRepo` — SSO anchor persistence.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use sqlx::Postgres;
use uuid::Uuid;

use crate::domain::FederatedIdentity;
use crate::error::{IdentityError, Result, map_sqlx_error};

/// Repository for `federated_identities`.
///
/// Anchor lookup by `(protocol, issuer_or_entity_id, subject_or_nameid)`
/// is org-implicit because that triple is globally unique. Writes
/// (create, tombstone) accept the `org_idp_id` directly: callers
/// resolve the IdP first and pass it in. Tombstoning sets
/// `user_id = NULL` while keeping the unique slot occupied — this
/// blocks silent re-attachment after soft-delete.
#[derive(Clone)]
pub struct FederatedIdentityRepo {
    pool: PgPool,
}

impl FederatedIdentityRepo {
    /// Wrap a connection pool.
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Insert a new anchor. The DB-level unique on
    /// `(protocol, iss, sub)` raises a `23505` conflict when the slot
    /// is already taken — including by a tombstone — which the repo
    /// translates into [`IdentityError::FederatedIdentityTombstoned`]
    /// when the conflicting row has `user_id IS NULL`. Callers that
    /// need to re-attach a tombstoned anchor must go through the
    /// admin merge flow (deferred to the admin layer).
    pub async fn create(&self, new: NewFederatedIdentity<'_>) -> Result<FederatedIdentity> {
        let row = sqlx::query!(
            r#"
            INSERT INTO federated_identities (
                id, protocol, issuer_or_entity_id, subject_or_nameid,
                org_idp_id, user_id, last_login_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING id, protocol, issuer_or_entity_id,
                      subject_or_nameid, org_idp_id, user_id,
                      created_at, last_login_at
            "#,
            new.id,
            new.protocol,
            new.issuer_or_entity_id,
            new.subject_or_nameid,
            new.org_idp_id,
            new.user_id,
            new.last_login_at,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            map_sqlx_error(
                e,
                IdentityError::TokenNotFound,
                IdentityError::FederatedIdentityTombstoned,
                Some("federated_identities_anchor_unique"),
            )
        })?;

        Ok(FederatedIdentity {
            id: row.id,
            protocol: row.protocol,
            issuer_or_entity_id: row.issuer_or_entity_id,
            subject_or_nameid: row.subject_or_nameid,
            org_idp_id: row.org_idp_id,
            user_id: row.user_id,
            created_at: row.created_at,
            last_login_at: row.last_login_at,
        })
    }

    /// Insert a new anchor inside a caller-supplied transaction.
    ///
    /// Wired by the OIDC / SAML JIT paths so the parent IdP-callback
    /// transaction (mark `oidc_pending_auth.used_at`, insert `users`,
    /// insert `user_org_memberships`) commits or rolls back as one
    /// unit.
    ///
    /// Cross-tenant defence: the unique index
    /// `federated_identities_anchor_unique` covers BOTH live and
    /// tombstoned rows. A conflict can mean:
    ///
    /// 1. The `(protocol, iss, sub)` slot is held by a tombstoned
    ///    row (`user_id IS NULL`) — admin merge required;
    ///    [`IdentityError::FederatedIdentityTombstoned`] (HTTP 409
    ///    `account_disabled`).
    /// 2. The slot is held by a LIVE anchor in another tenant
    ///    (different `org_idp_id`). Returning the tombstone error
    ///    here would tell the attacker their `(iss, sub)` exists
    ///    elsewhere — a cross-tenant existence oracle. Collapse onto
    ///    the uniform [`IdentityError::OidcStateMismatch`] family so
    ///    the public envelope is indistinguishable from a forged
    ///    state.
    /// 3. The slot is held by a LIVE anchor in this same IdP — race
    ///    between two concurrent JIT inserts. Same uniform collapse.
    ///
    /// The post-insert SELECT runs only on conflict so the happy
    /// path stays a single round-trip.
    pub async fn create_in_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, Postgres>,
        new: NewFederatedIdentity<'_>,
    ) -> Result<FederatedIdentity> {
        let insert = sqlx::query!(
            r#"
            INSERT INTO federated_identities (
                id, protocol, issuer_or_entity_id, subject_or_nameid,
                org_idp_id, user_id, last_login_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING id, protocol, issuer_or_entity_id,
                      subject_or_nameid, org_idp_id, user_id,
                      created_at, last_login_at
            "#,
            new.id,
            new.protocol,
            new.issuer_or_entity_id,
            new.subject_or_nameid,
            new.org_idp_id,
            new.user_id,
            new.last_login_at,
        )
        .fetch_one(&mut **tx)
        .await;

        let row = match insert {
            Ok(r) => r,
            Err(err) => {
                if let sqlx::Error::Database(ref db_err) = err
                    && db_err.code().as_deref() == Some("23505")
                    && db_err.constraint() == Some("federated_identities_anchor_unique")
                {
                    let colliding = sqlx::query!(
                        r#"
                        SELECT user_id, org_idp_id
                        FROM federated_identities
                        WHERE protocol = $1
                          AND issuer_or_entity_id = $2
                          AND subject_or_nameid = $3
                        "#,
                        new.protocol,
                        new.issuer_or_entity_id,
                        new.subject_or_nameid,
                    )
                    .fetch_optional(&mut **tx)
                    .await?;
                    return match colliding {
                        Some(c) if c.user_id.is_none() => {
                            Err(IdentityError::FederatedIdentityTombstoned)
                        }
                        _ => Err(IdentityError::OidcStateMismatch),
                    };
                }
                return Err(IdentityError::from(err));
            }
        };

        Ok(FederatedIdentity {
            id: row.id,
            protocol: row.protocol,
            issuer_or_entity_id: row.issuer_or_entity_id,
            subject_or_nameid: row.subject_or_nameid,
            org_idp_id: row.org_idp_id,
            user_id: row.user_id,
            created_at: row.created_at,
            last_login_at: row.last_login_at,
        })
    }

    /// Lookup the anchor by canonical `(protocol, iss, sub)` triple
    /// inside a caller-supplied transaction. The OIDC anchor-hit path
    /// uses this so the lookup races on the same consistency horizon
    /// as the pending mark-used + JIT writes.
    pub async fn find_by_protocol_iss_sub_in_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, Postgres>,
        protocol: &str,
        issuer_or_entity_id: &str,
        subject_or_nameid: &str,
    ) -> Result<Option<FederatedIdentity>> {
        let row = sqlx::query!(
            r#"
            SELECT id, protocol, issuer_or_entity_id, subject_or_nameid,
                   org_idp_id, user_id, created_at, last_login_at
            FROM federated_identities
            WHERE protocol = $1
              AND issuer_or_entity_id = $2
              AND subject_or_nameid = $3
            "#,
            protocol,
            issuer_or_entity_id,
            subject_or_nameid,
        )
        .fetch_optional(&mut **tx)
        .await?;

        Ok(row.map(|r| FederatedIdentity {
            id: r.id,
            protocol: r.protocol,
            issuer_or_entity_id: r.issuer_or_entity_id,
            subject_or_nameid: r.subject_or_nameid,
            org_idp_id: r.org_idp_id,
            user_id: r.user_id,
            created_at: r.created_at,
            last_login_at: r.last_login_at,
        }))
    }

    /// Lookup the anchor by canonical `(protocol, iss, sub)` triple.
    /// Returns tombstones too — callers MUST inspect `user_id` before
    /// minting a session.
    pub async fn find_by_protocol_iss_sub(
        &self,
        protocol: &str,
        issuer_or_entity_id: &str,
        subject_or_nameid: &str,
    ) -> Result<Option<FederatedIdentity>> {
        let row = sqlx::query!(
            r#"
            SELECT id, protocol, issuer_or_entity_id, subject_or_nameid,
                   org_idp_id, user_id, created_at, last_login_at
            FROM federated_identities
            WHERE protocol = $1
              AND issuer_or_entity_id = $2
              AND subject_or_nameid = $3
            "#,
            protocol,
            issuer_or_entity_id,
            subject_or_nameid,
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| FederatedIdentity {
            id: r.id,
            protocol: r.protocol,
            issuer_or_entity_id: r.issuer_or_entity_id,
            subject_or_nameid: r.subject_or_nameid,
            org_idp_id: r.org_idp_id,
            user_id: r.user_id,
            created_at: r.created_at,
            last_login_at: r.last_login_at,
        }))
    }

    /// Update `last_login_at` after a successful SSO sign-in.
    pub async fn update_last_login_at(&self, id: Uuid, last_login_at: DateTime<Utc>) -> Result<()> {
        sqlx::query!(
            r#"
            UPDATE federated_identities
            SET last_login_at = $2
            WHERE id = $1
            "#,
            id,
            last_login_at,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Update `last_login_at` inside a caller-supplied transaction.
    /// Wired by the OIDC callback so the bump is part of the same
    /// commit unit as the pending-row mark-used + JIT writes.
    pub async fn update_last_login_at_in_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, Postgres>,
        id: Uuid,
        last_login_at: DateTime<Utc>,
    ) -> Result<()> {
        sqlx::query!(
            r#"
            UPDATE federated_identities
            SET last_login_at = $2
            WHERE id = $1
            "#,
            id,
            last_login_at,
        )
        .execute(&mut **tx)
        .await?;
        Ok(())
    }

    /// Tombstone every anchor for `user_id` (set `user_id = NULL`).
    /// Returns the number of tombstoned rows.
    pub async fn tombstone_for_user(&self, user_id: Uuid) -> Result<u64> {
        let result = sqlx::query!(
            r#"
            UPDATE federated_identities
            SET user_id = NULL
            WHERE user_id = $1
            "#,
            user_id,
        )
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }
}

/// Argument bundle for [`FederatedIdentityRepo::create`].
#[derive(Debug)]
pub struct NewFederatedIdentity<'a> {
    /// Application-generated UUID v7.
    pub id: Uuid,
    /// `oidc` or `saml`.
    pub protocol: &'a str,
    /// OIDC `iss` or SAML `EntityID`.
    pub issuer_or_entity_id: &'a str,
    /// OIDC `sub` or SAML `NameID`.
    pub subject_or_nameid: &'a str,
    /// Owning IdP.
    pub org_idp_id: Uuid,
    /// Linked user.
    pub user_id: Option<Uuid>,
    /// `Some(now)` for first-time link; otherwise typically `None`.
    pub last_login_at: Option<DateTime<Utc>>,
}
