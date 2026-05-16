// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! Soft-delete cascade helpers.
//!
//! Postgres `FK CASCADE` is incompatible with soft-delete (the parent
//! row stays present with `deleted_at IS NOT NULL`), so the cascade
//! is enforced in the application layer. Both helpers take a
//! caller-supplied transaction so the parent flip and the child
//! updates land atomically. Audit-event emission is deliberately
//! left to the calling section: this module does pure DB work.

use sqlx::Postgres;
use uuid::Uuid;

use crate::error::Result;

/// Soft-delete an org and cascade per the design notes.
///
/// Within the caller's transaction:
///
/// - flip `deleted_at = now()` on the parent `orgs` row
/// - flip `deleted_at = now()` on every `org_idps`, `org_idp_domains`,
///   `scim_tokens`, `service_tokens` row owned by the org
/// - flip `deleted_at = now()` on every `user_org_memberships` row
///   joining the org
/// - revoke every live `sessions` row whose `org_id` matches
/// - revoke every live `api_tokens` row whose `org_id` matches
///   (the personal-access-token surface treats org soft-delete as
///   a tenant-scope teardown; see the api-token layer)
/// - leave `email_outbox` untouched; the worker reconciles in-flight
///   mail (the email-outbox layer)
///
/// `service_tokens` is org-agnostic at the table level but the
/// cascade rule treats org-owned platform integrations as part of
/// the tenant. Today there is no `service_tokens.org_id` column, so
/// this helper is a no-op for that table; once the tenant-isolation layer introduces
/// per-tenant service tokens the predicate will land here.
pub async fn soft_delete_org(tx: &mut sqlx::Transaction<'_, Postgres>, org_id: Uuid) -> Result<()> {
    sqlx::query!(
        r#"UPDATE orgs SET deleted_at = now(), updated_at = now()
           WHERE id = $1 AND deleted_at IS NULL"#,
        org_id,
    )
    .execute(&mut **tx)
    .await?;

    sqlx::query!(
        r#"UPDATE org_idps SET deleted_at = now(), updated_at = now()
           WHERE org_id = $1 AND deleted_at IS NULL"#,
        org_id,
    )
    .execute(&mut **tx)
    .await?;

    sqlx::query!(
        r#"UPDATE org_idp_domains SET deleted_at = now()
           WHERE org_idp_id IN (SELECT id FROM org_idps WHERE org_id = $1)
             AND deleted_at IS NULL"#,
        org_id,
    )
    .execute(&mut **tx)
    .await?;

    sqlx::query!(
        r#"UPDATE scim_tokens SET deleted_at = now()
           WHERE org_id = $1 AND deleted_at IS NULL"#,
        org_id,
    )
    .execute(&mut **tx)
    .await?;

    sqlx::query!(
        r#"UPDATE user_org_memberships SET deleted_at = now()
           WHERE org_id = $1 AND deleted_at IS NULL"#,
        org_id,
    )
    .execute(&mut **tx)
    .await?;

    sqlx::query!(
        r#"UPDATE sessions SET revoked_at = now()
           WHERE org_id = $1 AND revoked_at IS NULL"#,
        org_id,
    )
    .execute(&mut **tx)
    .await?;

    sqlx::query!(
        r#"UPDATE api_tokens SET revoked_at = now()
           WHERE org_id = $1 AND revoked_at IS NULL"#,
        org_id,
    )
    .execute(&mut **tx)
    .await?;

    Ok(())
}

/// Soft-delete a user and cascade.
///
/// Within the caller's transaction:
///
/// - flip `deleted_at = now()` on the parent `users` row
/// - revoke every live `sessions` row owned by the user
/// - revoke every live `api_tokens` row owned by the user
/// - tombstone every `federated_identities` row that points at the
///   user (`user_id := NULL`)
/// - flip `deleted_at = now()` on every `user_org_memberships` row
///   the user holds (so re-creation under a fresh `users` row is
///   unambiguous)
///
/// Tombstoned `federated_identities` rows still occupy the
/// `(protocol, iss, sub)` unique slot. Re-attaching the same SSO
/// anchor to a fresh user requires the admin merge flow (deferred
/// to the admin layer).
pub async fn soft_delete_user(
    tx: &mut sqlx::Transaction<'_, Postgres>,
    user_id: Uuid,
) -> Result<()> {
    sqlx::query!(
        r#"UPDATE users SET deleted_at = now(), updated_at = now()
           WHERE id = $1 AND deleted_at IS NULL"#,
        user_id,
    )
    .execute(&mut **tx)
    .await?;

    sqlx::query!(
        r#"UPDATE sessions SET revoked_at = now()
           WHERE user_id = $1 AND revoked_at IS NULL"#,
        user_id,
    )
    .execute(&mut **tx)
    .await?;

    sqlx::query!(
        r#"UPDATE api_tokens SET revoked_at = now()
           WHERE user_id = $1 AND revoked_at IS NULL"#,
        user_id,
    )
    .execute(&mut **tx)
    .await?;

    sqlx::query!(
        r#"UPDATE federated_identities SET user_id = NULL
           WHERE user_id = $1"#,
        user_id,
    )
    .execute(&mut **tx)
    .await?;

    sqlx::query!(
        r#"UPDATE user_org_memberships SET deleted_at = now()
           WHERE user_id = $1 AND deleted_at IS NULL"#,
        user_id,
    )
    .execute(&mut **tx)
    .await?;

    Ok(())
}
