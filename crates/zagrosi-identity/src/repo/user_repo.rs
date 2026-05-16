// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! `UserRepo` — single-tenant user persistence.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use sqlx::Postgres;
use sqlx::Row;
use sqlx::postgres::PgRow;
use uuid::Uuid;

use crate::domain::User;
use crate::error::{IdentityError, Result, map_sqlx_error};

/// Single-tenant repository for the `users` table. Users are *not*
/// org-scoped — a user joins one or more orgs via
/// `user_org_memberships`. Cross-org probes happen at the membership
/// repo, not here.
#[derive(Clone)]
pub struct UserRepo {
    pool: PgPool,
}

impl UserRepo {
    /// Wrap a connection pool. Cheap (`PgPool` is `Clone`).
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Insert a new user. The caller supplies a freshly minted
    /// UUID v7 and the canonical email + display fields. `email_lower`
    /// is computed by the database generated column.
    pub async fn create(&self, new: NewUser<'_>) -> Result<User> {
        let row = sqlx::query!(
            r#"
            INSERT INTO users (
                id, email, display_name, password_hash,
                password_updated_at, password_hash_version,
                external_id
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING
                id, email, email_lower as "email_lower!",
                display_name, email_verified_at, password_hash,
                password_updated_at, password_hash_version,
                mfa_enrolled_at, active, external_id, row_version,
                created_at, updated_at, deleted_at
            "#,
            new.id,
            new.email,
            new.display_name,
            new.password_hash,
            new.password_updated_at,
            new.password_hash_version,
            new.external_id,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            map_sqlx_error(
                e,
                IdentityError::UserNotFound,
                IdentityError::EmailAlreadyExists,
                Some("users_email_lower_unique_live"),
            )
        })?;

        Ok(User {
            id: row.id,
            email: row.email,
            email_lower: row.email_lower,
            display_name: row.display_name,
            email_verified_at: row.email_verified_at,
            password_hash: row.password_hash,
            password_updated_at: row.password_updated_at,
            password_hash_version: row.password_hash_version,
            mfa_enrolled_at: row.mfa_enrolled_at,
            active: row.active,
            external_id: row.external_id,
            row_version: row.row_version,
            created_at: row.created_at,
            updated_at: row.updated_at,
            deleted_at: row.deleted_at,
        })
    }

    /// Insert a new user inside a caller-supplied transaction.
    ///
    /// Wired by the OIDC / SAML JIT paths so user-create + membership-create +
    /// federated_identities-create + `oidc_pending_auth.used_at` mark all
    /// commit or roll back together.
    pub async fn create_in_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, Postgres>,
        new: NewUser<'_>,
    ) -> Result<User> {
        let row = sqlx::query!(
            r#"
            INSERT INTO users (
                id, email, display_name, password_hash,
                password_updated_at, password_hash_version,
                external_id
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING
                id, email, email_lower as "email_lower!",
                display_name, email_verified_at, password_hash,
                password_updated_at, password_hash_version,
                mfa_enrolled_at, active, external_id, row_version,
                created_at, updated_at, deleted_at
            "#,
            new.id,
            new.email,
            new.display_name,
            new.password_hash,
            new.password_updated_at,
            new.password_hash_version,
            new.external_id,
        )
        .fetch_one(&mut **tx)
        .await
        .map_err(|e| {
            map_sqlx_error(
                e,
                IdentityError::UserNotFound,
                IdentityError::EmailAlreadyExists,
                Some("users_email_lower_unique_live"),
            )
        })?;

        Ok(User {
            id: row.id,
            email: row.email,
            email_lower: row.email_lower,
            display_name: row.display_name,
            email_verified_at: row.email_verified_at,
            password_hash: row.password_hash,
            password_updated_at: row.password_updated_at,
            password_hash_version: row.password_hash_version,
            mfa_enrolled_at: row.mfa_enrolled_at,
            active: row.active,
            external_id: row.external_id,
            row_version: row.row_version,
            created_at: row.created_at,
            updated_at: row.updated_at,
            deleted_at: row.deleted_at,
        })
    }

    /// Find a live user by email inside a caller-supplied transaction.
    /// The query lowers `$1` server-side via Postgres `lower()` so the
    /// canonical form ALWAYS matches the generated `email_lower`
    /// column, regardless of locale (`tr_TR.UTF-8` Turkish dotless-i,
    /// German ß, Cyrillic, etc.). Rust `String::to_lowercase` and
    /// Postgres `lower()` use different Unicode case-folding policies;
    /// running both sides of the compare through Postgres ensures
    /// they agree.
    ///
    /// The OIDC JIT path uses this so the in-tx pre-flight collision
    /// check actually matches the unique-index trap on the subsequent
    /// INSERT.
    pub async fn find_by_email_lower_in_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, Postgres>,
        email: &str,
    ) -> Result<Option<User>> {
        let row = sqlx::query!(
            r#"
            SELECT
                id, email, email_lower as "email_lower!",
                display_name, email_verified_at, password_hash,
                password_updated_at, password_hash_version,
                mfa_enrolled_at, active, external_id, row_version,
                created_at, updated_at, deleted_at
            FROM users
            WHERE email_lower = lower($1) AND deleted_at IS NULL
            "#,
            email,
        )
        .fetch_optional(&mut **tx)
        .await?;

        Ok(row.map(|r| User {
            id: r.id,
            email: r.email,
            email_lower: r.email_lower,
            display_name: r.display_name,
            email_verified_at: r.email_verified_at,
            password_hash: r.password_hash,
            password_updated_at: r.password_updated_at,
            password_hash_version: r.password_hash_version,
            mfa_enrolled_at: r.mfa_enrolled_at,
            active: r.active,
            external_id: r.external_id,
            row_version: r.row_version,
            created_at: r.created_at,
            updated_at: r.updated_at,
            deleted_at: r.deleted_at,
        }))
    }

    /// Mark `email_verified_at` inside a caller-supplied transaction.
    /// JIT path uses this so the verify-flip rides on the same commit
    /// as the user insert when `id_token.email_verified == true`.
    pub async fn mark_email_verified_in_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, Postgres>,
        user_id: Uuid,
        verified_at: DateTime<Utc>,
    ) -> Result<()> {
        sqlx::query!(
            r#"
            UPDATE users
            SET email_verified_at = $2,
                updated_at = now()
            WHERE id = $1
              AND deleted_at IS NULL
              AND email_verified_at IS NULL
            "#,
            user_id,
            verified_at,
        )
        .execute(&mut **tx)
        .await?;
        Ok(())
    }

    /// Find a live (non-tombstoned) user by primary key inside a
    /// caller-supplied transaction. The OIDC anchor-hit path uses
    /// this so a tombstone-flip racing the in-flight tx is observed
    /// against a single consistency horizon.
    pub async fn find_by_id_in_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, Postgres>,
        id: Uuid,
    ) -> Result<Option<User>> {
        let row = sqlx::query!(
            r#"
            SELECT
                id, email, email_lower as "email_lower!",
                display_name, email_verified_at, password_hash,
                password_updated_at, password_hash_version,
                mfa_enrolled_at, active, external_id, row_version,
                created_at, updated_at, deleted_at
            FROM users
            WHERE id = $1 AND deleted_at IS NULL
            "#,
            id,
        )
        .fetch_optional(&mut **tx)
        .await?;

        Ok(row.map(|r| User {
            id: r.id,
            email: r.email,
            email_lower: r.email_lower,
            display_name: r.display_name,
            email_verified_at: r.email_verified_at,
            password_hash: r.password_hash,
            password_updated_at: r.password_updated_at,
            password_hash_version: r.password_hash_version,
            mfa_enrolled_at: r.mfa_enrolled_at,
            active: r.active,
            external_id: r.external_id,
            row_version: r.row_version,
            created_at: r.created_at,
            updated_at: r.updated_at,
            deleted_at: r.deleted_at,
        }))
    }

    /// Find a live (non-tombstoned) user by primary key.
    pub async fn find_by_id(&self, id: Uuid) -> Result<Option<User>> {
        let row = sqlx::query!(
            r#"
            SELECT
                id, email, email_lower as "email_lower!",
                display_name, email_verified_at, password_hash,
                password_updated_at, password_hash_version,
                mfa_enrolled_at, active, external_id, row_version,
                created_at, updated_at, deleted_at
            FROM users
            WHERE id = $1 AND deleted_at IS NULL
            "#,
            id,
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| User {
            id: r.id,
            email: r.email,
            email_lower: r.email_lower,
            display_name: r.display_name,
            email_verified_at: r.email_verified_at,
            password_hash: r.password_hash,
            password_updated_at: r.password_updated_at,
            password_hash_version: r.password_hash_version,
            mfa_enrolled_at: r.mfa_enrolled_at,
            active: r.active,
            external_id: r.external_id,
            row_version: r.row_version,
            created_at: r.created_at,
            updated_at: r.updated_at,
            deleted_at: r.deleted_at,
        }))
    }

    /// Find a live user by canonical lowercased email.
    ///
    /// Callers MUST `lower()`-case the input themselves; this method
    /// passes the value through verbatim so a stray uppercase letter
    /// returns `None` rather than a partial match.
    pub async fn find_by_email_lower(&self, email_lower: &str) -> Result<Option<User>> {
        let row = sqlx::query!(
            r#"
            SELECT
                id, email, email_lower as "email_lower!",
                display_name, email_verified_at, password_hash,
                password_updated_at, password_hash_version,
                mfa_enrolled_at, active, external_id, row_version,
                created_at, updated_at, deleted_at
            FROM users
            WHERE email_lower = $1 AND deleted_at IS NULL
            "#,
            email_lower,
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| User {
            id: r.id,
            email: r.email,
            email_lower: r.email_lower,
            display_name: r.display_name,
            email_verified_at: r.email_verified_at,
            password_hash: r.password_hash,
            password_updated_at: r.password_updated_at,
            password_hash_version: r.password_hash_version,
            mfa_enrolled_at: r.mfa_enrolled_at,
            active: r.active,
            external_id: r.external_id,
            row_version: r.row_version,
            created_at: r.created_at,
            updated_at: r.updated_at,
            deleted_at: r.deleted_at,
        }))
    }

    /// Atomically rotate a user's password hash + version + timestamp.
    ///
    /// The session module rejects sessions whose `created_at` precedes
    /// `password_updated_at`, so rotating the password without
    /// updating the timestamp would leave stale sessions live; hence
    /// the single-statement update.
    pub async fn update_password(
        &self,
        user_id: Uuid,
        password_hash: &str,
        password_hash_version: i16,
        password_updated_at: DateTime<Utc>,
    ) -> Result<()> {
        let result = sqlx::query!(
            r#"
            UPDATE users
            SET password_hash = $2,
                password_hash_version = $3,
                password_updated_at = $4,
                updated_at = now()
            WHERE id = $1 AND deleted_at IS NULL
            "#,
            user_id,
            password_hash,
            password_hash_version,
            password_updated_at,
        )
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(IdentityError::UserNotFound);
        }
        Ok(())
    }

    /// Mark the user's email as verified at `verified_at`. Idempotent —
    /// re-marking has no effect on already-verified rows because the
    /// statement uses `COALESCE(email_verified_at, $2)` semantics via
    /// a `WHERE email_verified_at IS NULL` guard.
    pub async fn mark_email_verified(
        &self,
        user_id: Uuid,
        verified_at: DateTime<Utc>,
    ) -> Result<()> {
        sqlx::query!(
            r#"
            UPDATE users
            SET email_verified_at = $2,
                updated_at = now()
            WHERE id = $1
              AND deleted_at IS NULL
              AND email_verified_at IS NULL
            "#,
            user_id,
            verified_at,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// SCIM tenant-scoped read by id.
    ///
    /// Returns the user iff they hold a live `user_org_memberships`
    /// row in `org_id`. Cross-org IDs and unknown IDs both return
    /// `None` so the SCIM handler can return `404 not_found`
    /// without status-code probing leaking existence.
    pub async fn find_in_org(&self, org_id: Uuid, user_id: Uuid) -> Result<Option<User>> {
        let row = sqlx::query!(
            r#"
            SELECT
                u.id, u.email, u.email_lower as "email_lower!",
                u.display_name, u.email_verified_at, u.password_hash,
                u.password_updated_at, u.password_hash_version,
                u.mfa_enrolled_at, u.active, u.external_id, u.row_version,
                u.created_at, u.updated_at, u.deleted_at
            FROM users u
            JOIN user_org_memberships m
              ON m.user_id = u.id
            WHERE u.id = $2
              AND m.org_id = $1
              AND u.deleted_at IS NULL
              AND m.deleted_at IS NULL
            "#,
            org_id,
            user_id,
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| User {
            id: r.id,
            email: r.email,
            email_lower: r.email_lower,
            display_name: r.display_name,
            email_verified_at: r.email_verified_at,
            password_hash: r.password_hash,
            password_updated_at: r.password_updated_at,
            password_hash_version: r.password_hash_version,
            mfa_enrolled_at: r.mfa_enrolled_at,
            active: r.active,
            external_id: r.external_id,
            row_version: r.row_version,
            created_at: r.created_at,
            updated_at: r.updated_at,
            deleted_at: r.deleted_at,
        }))
    }

    /// Count live users with a live membership in `org_id`.
    pub async fn count_in_org(&self, org_id: Uuid) -> Result<i64> {
        let row = sqlx::query!(
            r#"
            SELECT COUNT(*) AS "count!"
            FROM users u
            JOIN user_org_memberships m ON m.user_id = u.id
            WHERE m.org_id = $1
              AND u.deleted_at IS NULL
              AND m.deleted_at IS NULL
            "#,
            org_id,
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(row.count)
    }

    /// List a page of users in `org_id`, ordered by id ascending.
    pub async fn list_in_org_page(
        &self,
        org_id: Uuid,
        offset: i64,
        limit: i64,
    ) -> Result<Vec<User>> {
        let rows = sqlx::query!(
            r#"
            SELECT
                u.id, u.email, u.email_lower as "email_lower!",
                u.display_name, u.email_verified_at, u.password_hash,
                u.password_updated_at, u.password_hash_version,
                u.mfa_enrolled_at, u.active, u.external_id, u.row_version,
                u.created_at, u.updated_at, u.deleted_at
            FROM users u
            JOIN user_org_memberships m ON m.user_id = u.id
            WHERE m.org_id = $1
              AND u.deleted_at IS NULL
              AND m.deleted_at IS NULL
            ORDER BY u.id ASC
            OFFSET $2 LIMIT $3
            "#,
            org_id,
            offset,
            limit,
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| User {
                id: r.id,
                email: r.email,
                email_lower: r.email_lower,
                display_name: r.display_name,
                email_verified_at: r.email_verified_at,
                password_hash: r.password_hash,
                password_updated_at: r.password_updated_at,
                password_hash_version: r.password_hash_version,
                mfa_enrolled_at: r.mfa_enrolled_at,
                active: r.active,
                external_id: r.external_id,
                row_version: r.row_version,
                created_at: r.created_at,
                updated_at: r.updated_at,
                deleted_at: r.deleted_at,
            })
            .collect())
    }

    /// SCIM tenant-scoped read by id, inside a caller-supplied
    /// transaction. Mirrors [`Self::find_in_org`] but reads under
    /// the same snapshot as the surrounding write so SCIM PATCH /
    /// PUT can ETag-check + update without a cross-connection
    /// race window.
    pub async fn find_in_org_in_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, Postgres>,
        org_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<User>> {
        let row = sqlx::query!(
            r#"
            SELECT
                u.id, u.email, u.email_lower as "email_lower!",
                u.display_name, u.email_verified_at, u.password_hash,
                u.password_updated_at, u.password_hash_version,
                u.mfa_enrolled_at, u.active, u.external_id, u.row_version,
                u.created_at, u.updated_at, u.deleted_at
            FROM users u
            JOIN user_org_memberships m
              ON m.user_id = u.id
            WHERE u.id = $2
              AND m.org_id = $1
              AND u.deleted_at IS NULL
              AND m.deleted_at IS NULL
            "#,
            org_id,
            user_id,
        )
        .fetch_optional(&mut **tx)
        .await?;
        Ok(row.map(|r| User {
            id: r.id,
            email: r.email,
            email_lower: r.email_lower,
            display_name: r.display_name,
            email_verified_at: r.email_verified_at,
            password_hash: r.password_hash,
            password_updated_at: r.password_updated_at,
            password_hash_version: r.password_hash_version,
            mfa_enrolled_at: r.mfa_enrolled_at,
            active: r.active,
            external_id: r.external_id,
            row_version: r.row_version,
            created_at: r.created_at,
            updated_at: r.updated_at,
            deleted_at: r.deleted_at,
        }))
    }

    /// SCIM PATCH/PUT update path.
    ///
    /// Bumps `row_version` by 1 and updates `updated_at`. Honours
    /// `if_match_version`: if non-`None` and the row's current
    /// `row_version` does not match, returns
    /// [`IdentityError::ScimPreconditionFailed`].
    ///
    /// Anchored on `org_id` via the membership join — defense in
    /// depth against future callers that bypass the
    /// `find_in_org_in_tx` preflight. The CAS predicate stays in
    /// place so concurrent writers still race correctly.
    ///
    /// Returns the row post-update so the SCIM handler can derive
    /// the new ETag without a re-read.
    #[allow(clippy::too_many_arguments)]
    pub async fn scim_update_in_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, Postgres>,
        org_id: Uuid,
        user_id: Uuid,
        display_name: &str,
        external_id: Option<&str>,
        active: bool,
        if_match_version: Option<i64>,
    ) -> Result<User> {
        let row_opt = sqlx::query!(
            r#"
            UPDATE users
            SET display_name = $3,
                external_id = $4,
                active = $5,
                row_version = row_version + 1,
                updated_at = now()
            WHERE id = $1
              AND deleted_at IS NULL
              AND EXISTS (
                  SELECT 1 FROM user_org_memberships m
                  WHERE m.user_id = users.id
                    AND m.org_id = $2
                    AND m.deleted_at IS NULL
              )
              AND ($6::BIGINT IS NULL OR row_version = $6)
            RETURNING
                id, email, email_lower as "email_lower!",
                display_name, email_verified_at, password_hash,
                password_updated_at, password_hash_version,
                mfa_enrolled_at, active, external_id, row_version,
                created_at, updated_at, deleted_at
            "#,
            user_id,
            org_id,
            display_name,
            external_id,
            active,
            if_match_version,
        )
        .fetch_optional(&mut **tx)
        .await?;

        let Some(r) = row_opt else {
            if if_match_version.is_some() {
                return Err(IdentityError::ScimPreconditionFailed);
            }
            return Err(IdentityError::UserNotFound);
        };
        Ok(User {
            id: r.id,
            email: r.email,
            email_lower: r.email_lower,
            display_name: r.display_name,
            email_verified_at: r.email_verified_at,
            password_hash: r.password_hash,
            password_updated_at: r.password_updated_at,
            password_hash_version: r.password_hash_version,
            mfa_enrolled_at: r.mfa_enrolled_at,
            active: r.active,
            external_id: r.external_id,
            row_version: r.row_version,
            created_at: r.created_at,
            updated_at: r.updated_at,
            deleted_at: r.deleted_at,
        })
    }

    /// Borrow the underlying pool. Used by the SCIM list handler
    /// which builds a dynamic `QueryBuilder` against the same
    /// `users JOIN user_org_memberships` shape this repo encodes
    /// in its static helpers.
    #[must_use]
    pub const fn pool(&self) -> &PgPool {
        &self.pool
    }

    // Soft-delete is intentionally absent from this surface. All user
    // soft-deletes go through [`crate::repo::cascade::soft_delete_user`]
    // inside a caller-supplied transaction so the parent flip and the
    // child cascade (sessions, api_tokens, federated tombstones,
    // membership soft-deletes) are atomic.
}

/// Re-construct a [`User`] domain aggregate from an arbitrary
/// `sqlx::PgRow` whose column names match the canonical
/// `users` projection used throughout this repo.
///
/// Exposed so the SCIM list handler can build a dynamic
/// `QueryBuilder` query (filter + sort + paginate) and map rows
/// without re-implementing the column extraction.
///
/// # Errors
///
/// Returns [`IdentityError::Database`] for any column-extraction
/// failure (column missing, type mismatch).
pub fn user_from_row(row: &PgRow) -> Result<User> {
    Ok(User {
        id: row.try_get("id").map_err(boxed_db)?,
        email: row.try_get("email").map_err(boxed_db)?,
        email_lower: row.try_get("email_lower").map_err(boxed_db)?,
        display_name: row.try_get("display_name").map_err(boxed_db)?,
        email_verified_at: row.try_get("email_verified_at").map_err(boxed_db)?,
        password_hash: row.try_get("password_hash").map_err(boxed_db)?,
        password_updated_at: row.try_get("password_updated_at").map_err(boxed_db)?,
        password_hash_version: row.try_get("password_hash_version").map_err(boxed_db)?,
        mfa_enrolled_at: row.try_get("mfa_enrolled_at").map_err(boxed_db)?,
        active: row.try_get("active").map_err(boxed_db)?,
        external_id: row.try_get("external_id").map_err(boxed_db)?,
        row_version: row.try_get("row_version").map_err(boxed_db)?,
        created_at: row.try_get("created_at").map_err(boxed_db)?,
        updated_at: row.try_get("updated_at").map_err(boxed_db)?,
        deleted_at: row.try_get("deleted_at").map_err(boxed_db)?,
    })
}

fn boxed_db(err: sqlx::Error) -> IdentityError {
    IdentityError::Database(Box::new(err))
}

/// Argument bundle for [`UserRepo::create`].
///
/// Bundling the call as a struct (rather than positional arguments)
/// keeps the call-site readable as the field count grows; field names
/// also defend against `email`/`display_name` swap mistakes that
/// positional `&str, &str` would silently accept.
#[derive(Debug, Clone, Copy)]
pub struct NewUser<'a> {
    /// Application-generated UUID v7.
    pub id: Uuid,
    /// Display-case email address.
    pub email: &'a str,
    /// Display name.
    pub display_name: &'a str,
    /// PHC password hash; `None` for SSO-only accounts.
    pub password_hash: Option<&'a str>,
    /// Initial `password_updated_at`. `Some(now)` for password sign-ups,
    /// `None` for SSO-only accounts (which have no password to age).
    pub password_updated_at: Option<DateTime<Utc>>,
    /// Argon2id profile version. Password-auth sets this to its current
    /// version constant.
    pub password_hash_version: i16,
    /// SCIM `externalId` (IdP-assigned identifier). `None` for users
    /// minted outside SCIM.
    pub external_id: Option<&'a str>,
}
