// SPDX-License-Identifier: AGPL-3.0-or-later

//! Superuser bootstrap — the only superuser code path in the harness.
//!
//! Runs once per container: creates the four runtime roles with the exact
//! attribute set section 05's migrations later assert, grants
//! database/schema access, pre-installs the untrusted extensions
//! (`pg_partman`, `pg_parquet`) the way section 01's compose initdb hook does
//! in dev, and applies the interim baseline grants that section 05 deletes.

// Private module: `pub(crate)` is technically redundant here but states the
// intent (these must never become part of the public API — M3 of the
// section-02 review); silence the nursery lint instead of widening to `pub`.
#![allow(clippy::redundant_pub_crate)]

use crate::error::HarnessError;
use sqlx::PgPool;

/// Test-only role passwords. Ephemeral containers — never production values.
pub(crate) const MIGRATE_PASSWORD: &str = "zagrosi-test-migrate";
/// Test-only password for `zagrosi_app`.
pub(crate) const APP_PASSWORD: &str = "zagrosi-test-app";
/// Test-only password for `zagrosi_auth`.
pub(crate) const AUTH_PASSWORD: &str = "zagrosi-test-auth";
/// Test-only password for `zagrosi_maintenance`.
pub(crate) const MAINTENANCE_PASSWORD: &str = "zagrosi-test-maintenance";

/// Create the four runtime roles idempotently.
///
/// Attributes match the exact section-05 catalog (the superuser context
/// makes BYPASSRLS creation unrestricted here; production provisioning
/// navigates that separately).
pub(crate) async fn create_roles(superuser: &PgPool) -> Result<(), HarnessError> {
    let sql = format!(
        r"
DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'zagrosi_migrate') THEN
    CREATE ROLE zagrosi_migrate LOGIN PASSWORD '{MIGRATE_PASSWORD}' NOSUPERUSER BYPASSRLS;
  END IF;
END $$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'zagrosi_app') THEN
    CREATE ROLE zagrosi_app LOGIN PASSWORD '{APP_PASSWORD}' NOSUPERUSER NOBYPASSRLS;
  END IF;
END $$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'zagrosi_auth') THEN
    CREATE ROLE zagrosi_auth LOGIN PASSWORD '{AUTH_PASSWORD}' NOSUPERUSER NOBYPASSRLS;
  END IF;
END $$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'zagrosi_maintenance') THEN
    CREATE ROLE zagrosi_maintenance LOGIN PASSWORD '{MAINTENANCE_PASSWORD}' NOSUPERUSER BYPASSRLS;
  END IF;
END $$;
"
    );
    sqlx::raw_sql(&sql).execute(superuser).await?;
    Ok(())
}

/// Database + schema grants.
///
/// `zagrosi_migrate` must own everything migrations create (CREATE on
/// schema + database); the runtime roles get CONNECT + USAGE only (PG 15+
/// removed PUBLIC's CREATE on `public`).
pub(crate) async fn grant_database_access(
    superuser: &PgPool,
    db: &str,
) -> Result<(), HarnessError> {
    let sql = format!(
        r#"
GRANT CONNECT ON DATABASE "{db}" TO zagrosi_migrate, zagrosi_app, zagrosi_auth, zagrosi_maintenance;
GRANT CREATE, TEMP ON DATABASE "{db}" TO zagrosi_migrate;
GRANT CREATE, USAGE ON SCHEMA public TO zagrosi_migrate;
GRANT USAGE ON SCHEMA public TO zagrosi_app, zagrosi_auth, zagrosi_maintenance;
"#
    );
    sqlx::raw_sql(&sql).execute(superuser).await?;
    Ok(())
}

/// Pre-install the untrusted extensions as superuser (idempotent).
///
/// Mirrors section 01's image/compose environment: `zagrosi_migrate`
/// cannot `CREATE EXTENSION` for untrusted extensions, so the rbac/audit
/// migration sets (sections 06/11) rely on this contract. Also
/// forward-provisions section 15: `pg_parquet`'s object-store roles are
/// granted to `zagrosi_maintenance` when present.
pub(crate) async fn install_extensions(superuser: &PgPool) -> Result<(), HarnessError> {
    sqlx::raw_sql(
        r"
CREATE SCHEMA IF NOT EXISTS partman;
CREATE EXTENSION IF NOT EXISTS pg_partman SCHEMA partman;
CREATE EXTENSION IF NOT EXISTS pg_parquet;
DO $$ BEGIN
  IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'parquet_object_store_read') THEN
    GRANT parquet_object_store_read TO zagrosi_maintenance;
  END IF;
  IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'parquet_object_store_write') THEN
    GRANT parquet_object_store_write TO zagrosi_maintenance;
  END IF;
END $$;
GRANT USAGE ON SCHEMA partman TO zagrosi_migrate;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA partman TO zagrosi_migrate;
GRANT EXECUTE ON ALL PROCEDURES IN SCHEMA partman TO zagrosi_migrate;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA partman TO zagrosi_migrate;
",
    )
    .execute(superuser)
    .await?;
    Ok(())
}

/// Interim baseline grants — **temporary shim, deleted by section 05**.
///
/// Until the identity role/grant migrations (section 05) land the explicit
/// per-table GRANT matrix, the role pools would get `permission denied` on
/// every table. Section 05 removes this call and its tests assert the exact
/// migration-defined GRANT matrix instead. Do not add grants anywhere else.
pub(crate) async fn apply_interim_grants(superuser: &PgPool) -> Result<(), HarnessError> {
    sqlx::raw_sql(
        r"
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public
  TO zagrosi_app, zagrosi_auth, zagrosi_maintenance;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public
  TO zagrosi_app, zagrosi_auth, zagrosi_maintenance;
ALTER DEFAULT PRIVILEGES FOR ROLE zagrosi_migrate IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES
  TO zagrosi_app, zagrosi_auth, zagrosi_maintenance;
ALTER DEFAULT PRIVILEGES FOR ROLE zagrosi_migrate IN SCHEMA public
  GRANT USAGE, SELECT ON SEQUENCES
  TO zagrosi_app, zagrosi_auth, zagrosi_maintenance;
",
    )
    .execute(superuser)
    .await?;
    Ok(())
}
