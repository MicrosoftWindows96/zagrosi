// SPDX-License-Identifier: AGPL-3.0-or-later

//! `org_permission_versions` persistence — the per-org monotonic
//! counter the section-08 caches key their floors off.

use zagrosi_db::TenantTx;

use crate::error::{Error, Result};

/// Increment and return the org's permission version. Section-09
/// services call this in the same transaction as every rbac mutation.
///
/// # Errors
///
/// [`Error::OrgRootMissing`] when the org's version row is absent (a
/// provisioning invariant violation); [`Error::Sqlx`] for database
/// failures.
pub async fn bump_version(tx: &mut TenantTx<'_>) -> Result<i64> {
    let org_id = tx.org_id();
    sqlx::query_scalar!(
        r#"
        UPDATE org_permission_versions
        SET version = version + 1
        WHERE org_id = $1
        RETURNING version
        "#,
        org_id,
    )
    .fetch_optional(tx.as_executor())
    .await?
    .ok_or(Error::OrgRootMissing)
}

/// The org's current permission version.
///
/// # Errors
///
/// [`Error::OrgRootMissing`] when the org's version row is absent;
/// [`Error::Sqlx`] for database failures.
pub async fn current_version(tx: &mut TenantTx<'_>) -> Result<i64> {
    let org_id = tx.org_id();
    sqlx::query_scalar!(
        r#"
        SELECT version FROM org_permission_versions WHERE org_id = $1
        "#,
        org_id,
    )
    .fetch_optional(tx.as_executor())
    .await?
    .ok_or(Error::OrgRootMissing)
}
