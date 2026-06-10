// SPDX-License-Identifier: AGPL-3.0-or-later

//! Role-pool builders for the four runtime DSNs.
//!
//! One generic builder — role-ness comes entirely from the DSN (the
//! four pools are otherwise identical). Every pool gets an
//! `after_release` hook issuing `RESET ALL`, defense-in-depth against
//! pooled-connection context leaks: production code only ever sets GUCs
//! transaction-locally (see the crate docs), so the hook should never
//! find anything to reset — but a single session-scoped `SET` slipping
//! through review must not leak tenant context to the next acquirer.
//!
//! This crate reads no environment: the `ENV_*` constants are *names
//! only*. Resolution and fallback policy live with consumers
//! (provisioning, test-support, app wiring).

use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;

use crate::error::Error;

/// DSN env key for the `zagrosi_app` role (the tenanted request path).
/// This unit repurposes the existing key: no longer a superuser DSN.
pub const ENV_DATABASE_URL: &str = "ZAGROSI_DATABASE_URL";

/// DSN env key for the `zagrosi_migrate` role (migrations / backfills
/// only).
pub const ENV_DATABASE_MIGRATE_URL: &str = "ZAGROSI_DATABASE_MIGRATE_URL";

/// DSN env key for the `zagrosi_auth` role (pre-tenant-context
/// token-hash lookups).
pub const ENV_DATABASE_AUTH_URL: &str = "ZAGROSI_DATABASE_AUTH_URL";

/// DSN env key for the `zagrosi_maintenance` role (retention /
/// archival / export jobs).
pub const ENV_DATABASE_MAINTENANCE_URL: &str = "ZAGROSI_DATABASE_MAINTENANCE_URL";

/// Build a `PgPool` for one of the runtime role DSNs, with the
/// `RESET ALL`-on-release hygiene hook attached.
///
/// # Errors
///
/// Returns [`Error::Sqlx`] when the pool cannot connect.
pub async fn connect_role_pool(dsn: &str) -> Result<PgPool, Error> {
    connect_role_pool_with(PgPoolOptions::new(), dsn).await
}

/// As [`connect_role_pool`], from caller-supplied [`PgPoolOptions`].
///
/// Use for pool sizing / timeouts. Note: sqlx stores a single
/// `after_release` callback, so this REPLACES any `after_release`
/// already configured on the supplied options — the `RESET ALL`
/// hygiene hook always wins.
///
/// # Errors
///
/// Returns [`Error::Sqlx`] when the pool cannot connect.
pub async fn connect_role_pool_with(options: PgPoolOptions, dsn: &str) -> Result<PgPool, Error> {
    options
        .after_release(|conn, _meta| {
            Box::pin(async move {
                sqlx::query("RESET ALL").execute(&mut *conn).await?;
                Ok(true)
            })
        })
        .connect(dsn)
        .await
        .map_err(Error::from)
}
