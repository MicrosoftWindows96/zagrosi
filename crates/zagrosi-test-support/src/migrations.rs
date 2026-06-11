// SPDX-License-Identifier: AGPL-3.0-or-later

//! Ordered multi-crate migration runner.
//!
//! Each crate owns an embedded `sqlx::migrate!()` set; this module applies
//! them in dependency order (identity, then rbac, then audit as later
//! sections register them). The runner is the single migration entry point
//! for tests **and** future apps — it deliberately has no testcontainers
//! coupling.
//!
//! ## Shared history table (deviation from the unit plan, documented)
//!
//! The plan called for a distinct history table per set
//! (`_sqlx_migrations_rbac`, ...), but the pinned sqlx 0.8.6 hardcodes
//! `_sqlx_migrations` with no per-`Migrator` table configuration, and no
//! 0.8.x release ships one (the API arrives with sqlx 0.9, a
//! workspace-wide upgrade out of this unit's scope). Equivalent guarantees
//! are provided instead:
//!
//! - **Independent sets**: every set runs with `ignore_missing = true`, so
//!   one set's bookkeeping rows are invisible to another's validation.
//! - **No cross-set version collisions**: [`run_all_migrations`] fails fast
//!   if two registered sets share a version number (timestamped versions
//!   make collisions practically impossible; the check makes them loud,
//!   since the shared table would otherwise mask them).
//! - **Ordering**: sets are applied strictly in registry order.
//!
//! What is **lost** versus per-set tables: `ignore_missing = true` also
//! disables sqlx's `VersionMissing` drift detection (a migration file
//! deleted or renumbered after being applied goes unnoticed; checksum
//! validation still covers versions that remain). Irrelevant for the
//! ephemeral test databases this crate creates, but callers reusing
//! [`run_all_migrations`] against **persistent** databases (future apps,
//! units 09/11) inherit that blind spot. Revisit when the workspace moves
//! to sqlx 0.9 and per-set history tables become available.

use crate::error::HarnessError;
use sqlx::PgPool;
use sqlx::migrate::Migrator;
use std::borrow::Cow;
use std::collections::HashMap;

/// One embedded migration set.
pub struct MigrationSet {
    /// Stable set name: `"identity"` | `"rbac"` | `"audit"`.
    pub name: &'static str,
    /// The crate's embedded migrator.
    pub migrator: &'static Migrator,
}

/// Ordered registry — dependency order identity -> rbac -> audit.
/// Section 11 appends the audit entry here.
#[must_use]
pub fn migration_sets() -> &'static [MigrationSet] {
    static SETS: &[MigrationSet] = &[
        MigrationSet {
            name: "identity",
            migrator: &zagrosi_identity::MIGRATOR,
        },
        MigrationSet {
            name: "rbac",
            migrator: &zagrosi_rbac::MIGRATOR,
        },
    ];
    SETS
}

/// Apply every registered set in order. `pool` MUST be the
/// `zagrosi_migrate` pool so every created object is owned by that role
/// (section 05's `FORCE ROW LEVEL SECURITY` semantics depend on it).
///
/// Idempotent: re-running applies nothing new.
///
/// # Errors
///
/// Fails on cross-set version collisions, connection errors, or any
/// migration failure.
pub async fn run_all_migrations(pool: &PgPool) -> Result<(), HarnessError> {
    assert_disjoint_versions()?;
    for set in migration_sets() {
        run_set(pool, set).await?;
    }
    Ok(())
}

/// Apply the identity set alone. Staged-application tests (e.g. the
/// rbac backfill suite) seed legacy data between this and
/// [`run_rbac_migrations`].
///
/// # Errors
///
/// As [`run_all_migrations`], for this set only.
pub async fn run_identity_migrations(pool: &PgPool) -> Result<(), HarnessError> {
    run_named_set(pool, "identity").await
}

/// Apply the rbac set alone. The identity set MUST already be applied
/// (the rbac migrations reference `orgs`, `users`, and the
/// `zagrosi_enable_rls` generator).
///
/// # Errors
///
/// As [`run_all_migrations`], for this set only.
pub async fn run_rbac_migrations(pool: &PgPool) -> Result<(), HarnessError> {
    run_named_set(pool, "rbac").await
}

async fn run_named_set(pool: &PgPool, name: &'static str) -> Result<(), HarnessError> {
    let set = migration_sets()
        .iter()
        .find(|set| set.name == name)
        .ok_or_else(|| HarnessError::Config(format!("unknown migration set '{name}'")))?;
    run_set(pool, set).await
}

async fn run_set(pool: &PgPool, set: &MigrationSet) -> Result<(), HarnessError> {
    // Local copy with ignore_missing: other sets' rows in the shared
    // `_sqlx_migrations` table must not fail this set's validation.
    // The fields are public-but-doc-hidden (semver-exempt); this is a
    // non-published dev crate, and the alternative is hand-rolled
    // bookkeeping.
    let migrator = Migrator {
        migrations: Cow::Borrowed(set.migrator.migrations.as_ref()),
        ignore_missing: true,
        locking: set.migrator.locking,
        no_tx: set.migrator.no_tx,
    };
    migrator.run(pool).await?;
    tracing::debug!(set = set.name, "migration set applied");
    Ok(())
}

fn assert_disjoint_versions() -> Result<(), HarnessError> {
    let mut owner: HashMap<i64, &'static str> = HashMap::new();
    for set in migration_sets() {
        for migration in set.migrator.iter() {
            if let Some(other) = owner.insert(migration.version, set.name)
                && other != set.name
            {
                return Err(HarnessError::Config(format!(
                    "migration version {} exists in both '{other}' and '{}' — \
                         the shared _sqlx_migrations table cannot disambiguate; renumber one",
                    migration.version, set.name
                )));
            }
        }
    }
    Ok(())
}
