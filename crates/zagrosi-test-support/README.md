<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# zagrosi-test-support

Dev-only (`publish = false`) integration-test harness for the workspace.

## The rule this crate enforces

**Integration tests never connect as the Postgres superuser.** The
container superuser exists for bootstrap only (role creation, untrusted
extension installs, the interim grants below). All test traffic flows
through role-specific pools — `migrate_pool()`, `app_pool()`,
`auth_pool()`, `maintenance_pool()` — so RLS regressions surface as test
failures instead of being silently bypassed.

## What `TestDb::new()` does

1. Boots the custom Postgres image (`deploy/docker/postgres`; override with
   `ZAGROSI_TEST_PG_IMAGE`, e.g. for a locally built tag — pull or build it
   first, see `scripts/ensure-pg-image.sh`).
2. As superuser: creates the four runtime roles with the exact attribute
   catalog section 05's migrations assert, grants database/schema access,
   pre-installs pg_partman + pg_parquet (untrusted extensions — mirrors the
   compose initdb environment so rbac/audit migration sets can run as
   `zagrosi_migrate`), and grants pg_parquet's object-store roles to
   `zagrosi_maintenance`.
3. Applies every registered migration set as `zagrosi_migrate` via
   `run_all_migrations` (ordered: identity, then rbac/audit as later
   sections register them).
4. Applies **interim baseline grants** (`bootstrap::apply_interim_grants`)
   — a temporary shim until section 05 lands the explicit per-table GRANT
   matrix in identity migrations. Section 05 deletes exactly that one
   function call.

`TestDb::with_minio()` additionally starts MinIO on a shared per-test
network and wires the server-side S3 env (`AWS_*`, `AWS_ALLOW_HTTP=true`)
into Postgres for pg_parquet round-trips; section 15 reuses it for archival
end-to-end tests.

## Shared migration-history table

sqlx 0.8.6 (the workspace pin) hardcodes `_sqlx_migrations`; the
per-set-table API only exists from sqlx 0.9. The runner therefore applies
every set against the shared table with `ignore_missing = true` per set and
fails fast on cross-set version collisions. See `src/migrations.rs` for the
full rationale. Revisit when the workspace moves to sqlx 0.9.

## Dev-dep loop cost

`zagrosi-identity` dev-depends on this crate, which depends on
`zagrosi-identity` (for its `MIGRATOR`). Cargo-legal, but it roughly
doubles identity's test-build cost — keep identity-facing helpers thin
(fixtures grow only when a migrated suite already duplicates a helper).

## For later sections

- Sections 06/11: append your `MigrationSet` to
  `migrations::migration_sets()` (rbac before audit).
- Section 15: `with_minio()` + the pg_parquet object-store role grants are
  already in place.
- Section 18: this crate is the home for mock SIEM receivers (HEC/Datadog
  axum mocks, rsyslog container helpers).
