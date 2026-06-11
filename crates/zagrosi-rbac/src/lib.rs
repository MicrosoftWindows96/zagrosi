// SPDX-License-Identifier: AGPL-3.0-or-later

//! RBAC foundation crate for the Zagrosi platform.
//!
//! This crate owns the resource scope tree (`resource_nodes`), custom
//! roles and their capability entries, role assignments (bindings of
//! users to built-in role names or custom roles), and the per-org
//! permission version counter the caches key off.
//!
//! Layering follows the workspace convention: [`domain`] (pure value
//! types) → [`repo`] (sqlx on [`zagrosi_db::TenantTx`]); the resolution
//! engine, caches, services, and HTTP surface arrive in later sections.
//!
//! Coupling rule: this crate depends on `zagrosi-db` (and, from
//! section-07, `zagrosi-core`) — never on `zagrosi-identity`. SQL-level
//! foreign keys to identity-owned `orgs`/`users` are fine (single
//! database); only Rust-type coupling is forbidden.

#![deny(missing_docs)]

pub mod domain;
pub mod error;
pub mod repo;

pub use error::{Error, Result};

use sqlx::PgPool;
use sqlx::migrate::Migrator;

pub use sqlx::migrate::MigrateError;

/// Embedded forward-only migrations for the rbac schema.
///
/// Bookkeeping lands in the shared `_sqlx_migrations` history table —
/// the pinned sqlx 0.8.x has no per-`Migrator` table configuration (the
/// plan's `_sqlx_migrations_rbac` arrives with sqlx 0.9); the ordered
/// multi-set runner in `zagrosi-test-support::migrations` documents the
/// equivalent guarantees. Apply via that runner (tests, apps) or
/// [`run_migrations`] on an already-identity-migrated database.
pub static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

/// Apply every embedded rbac migration against `pool` in order.
///
/// The pool MUST be the `zagrosi_migrate` role (table ownership drives
/// `FORCE ROW LEVEL SECURITY` semantics) and identity's migration set
/// MUST already be applied (the rbac set references `orgs`, `users`,
/// and the `zagrosi_enable_rls` generator).
///
/// # Errors
///
/// Returns [`MigrateError`] verbatim: connection failures, checksum
/// mismatches, or DDL errors from the database.
pub async fn run_migrations(pool: &PgPool) -> std::result::Result<(), MigrateError> {
    MIGRATOR.run(pool).await
}
