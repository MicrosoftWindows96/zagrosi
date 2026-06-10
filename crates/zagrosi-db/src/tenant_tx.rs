// SPDX-License-Identifier: AGPL-3.0-or-later

//! [`TenantTx`] — a transaction that provably carries tenant context.
//!
//! Repositories in the RBAC / audit crates take `&mut TenantTx`, and the
//! only way to obtain one is [`begin_tenant_tx`] /
//! [`begin_tenant_tx_as_user`] — so "forgot the org filter" is
//! unrepresentable at the type level in new handler code. The GUC is set
//! with `set_config(..., /* is_local = */ true)` (`SET LOCAL` is a
//! top-level statement and cannot be parameterised), so it dies with the
//! transaction no matter how the transaction ends.
//!
//! Construction is deliberately cheap — `BEGIN` plus one `set_config`
//! statement in release builds — because the RBAC cold path and the
//! audit flusher open short tenant transactions on hot paths.

use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::error::Error;
use crate::{GUC_ORG_ID, GUC_USER_ID};

/// A transaction carrying verified tenant context.
///
/// The only way to obtain one is [`begin_tenant_tx`] /
/// [`begin_tenant_tx_as_user`], so a repo method taking `&mut TenantTx`
/// cannot run without `app.org_id` set — the type-level "you cannot
/// forget the org filter" mechanism.
#[derive(Debug)]
pub struct TenantTx<'a> {
    tx: Transaction<'a, Postgres>,
    org_id: Uuid,
    user_id: Option<Uuid>,
}

impl TenantTx<'_> {
    /// Executor access for repo queries (the `&mut **tx` pattern).
    pub fn as_executor(&mut self) -> &mut sqlx::PgConnection {
        &mut self.tx
    }

    /// Org scope this transaction was opened under.
    #[must_use]
    pub const fn org_id(&self) -> Uuid {
        self.org_id
    }

    /// User scope, when opened via [`begin_tenant_tx_as_user`].
    #[must_use]
    pub const fn user_id(&self) -> Option<Uuid> {
        self.user_id
    }

    /// Commit the transaction.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Sqlx`] when the commit fails.
    pub async fn commit(self) -> Result<(), Error> {
        self.tx.commit().await.map_err(Error::from)
    }

    /// Roll the transaction back. Dropping a [`TenantTx`] without
    /// calling either finisher also rolls back (inherited from
    /// `sqlx::Transaction`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Sqlx`] when the rollback fails.
    pub async fn rollback(self) -> Result<(), Error> {
        self.tx.rollback().await.map_err(Error::from)
    }
}

/// Begin a transaction and set `app.org_id` transaction-locally.
///
/// # Errors
///
/// Returns [`Error::NilOrgId`] for `Uuid::nil()` (error, not panic —
/// the nil sentinel must never become a tenant scope) and
/// [`Error::Sqlx`] for database failures.
pub async fn begin_tenant_tx(pool: &PgPool, org_id: Uuid) -> Result<TenantTx<'static>, Error> {
    begin_inner(pool, org_id, None).await
}

/// As [`begin_tenant_tx`], additionally setting `app.user_id` for the
/// org-or-self SELECT arm on `user_org_memberships`.
///
/// # Errors
///
/// Returns [`Error::NilOrgId`] / [`Error::NilUserId`] for nil ids and
/// [`Error::Sqlx`] for database failures.
pub async fn begin_tenant_tx_as_user(
    pool: &PgPool,
    org_id: Uuid,
    user_id: Uuid,
) -> Result<TenantTx<'static>, Error> {
    if user_id.is_nil() {
        return Err(Error::NilUserId);
    }
    begin_inner(pool, org_id, Some(user_id)).await
}

async fn begin_inner(
    pool: &PgPool,
    org_id: Uuid,
    user_id: Option<Uuid>,
) -> Result<TenantTx<'static>, Error> {
    if org_id.is_nil() {
        return Err(Error::NilOrgId);
    }
    let mut tx = pool.begin().await?;
    // One statement for both GUCs: construction stays at two round
    // trips (BEGIN + set_config) on the hot path.
    if let Some(user_id) = user_id {
        sqlx::query("SELECT set_config($1, $2, true), set_config($3, $4, true)")
            .bind(GUC_ORG_ID)
            .bind(org_id.to_string())
            .bind(GUC_USER_ID)
            .bind(user_id.to_string())
            .fetch_optional(&mut *tx)
            .await?;
    } else {
        sqlx::query("SELECT set_config($1, $2, true)")
            .bind(GUC_ORG_ID)
            .bind(org_id.to_string())
            .fetch_optional(&mut *tx)
            .await?;
    }
    #[cfg(debug_assertions)]
    {
        verify_guc(&mut tx, GUC_ORG_ID, &org_id.to_string()).await?;
        if let Some(user_id) = user_id {
            verify_guc(&mut tx, GUC_USER_ID, &user_id.to_string()).await?;
        }
    }
    Ok(TenantTx {
        tx,
        org_id,
        user_id,
    })
}

/// Debug-build read-back: catches plumbing regressions (wrong GUC name,
/// silently ignored `set_config`) before they reach an RLS policy.
/// Release builds skip the extra round trip.
#[cfg(debug_assertions)]
async fn verify_guc(
    tx: &mut Transaction<'_, Postgres>,
    guc: &'static str,
    expected: &str,
) -> Result<(), Error> {
    let actual: Option<String> = sqlx::query_scalar("SELECT current_setting($1, true)")
        .bind(guc)
        .fetch_one(&mut **tx)
        .await?;
    if actual.as_deref() == Some(expected) {
        Ok(())
    } else {
        Err(Error::GucVerificationFailed {
            guc,
            expected: expected.to_string(),
            actual,
        })
    }
}
