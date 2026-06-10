<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Zagrosi custom Postgres image

Stock `postgres:18-bookworm` plus two extensions the audit subsystem needs:

| Component | Pin | Purpose |
|---|---|---|
| pg_partman | 5.4.3 | month-partitioned `audit_events` maintenance, incl. the `pg_partman_bgw` background worker |
| pg_parquet | 0.5.1 | cold archival: `COPY ... TO 's3://...' (format 'parquet')` server-side |
| cargo-pgrx | 0.16.0 | build-time only (pg_parquet's pinned pgrx) |

Pins live in [`VERSIONS`](./VERSIONS) (single source of truth; `smoke.sh` and the
publish workflow read it). The published reference lives in
[`IMAGE_TAG`](./IMAGE_TAG).

`shared_preload_libraries = 'pg_partman_bgw,pg_parquet'` is configured at first
init by the baked-in hook (`initdb/01-partman-bgw.sh`). pg_parquet 0.5.x
hard-requires preload (it refuses to load otherwise), so both libraries are
always listed. `CREATE EXTENSION` is deliberately left to consumers
(migrations and tests); nothing is pre-created in `template1`.

## Env contract (initdb hook)

| Env var | Default | Purpose |
|---|---|---|
| `ZAGROSI_PARTMAN_DBNAME` | `$POSTGRES_DB`, else `postgres` | database the BGW runs maintenance in |
| `ZAGROSI_PARTMAN_ROLE` | `$POSTGRES_USER`, else `postgres` | role the BGW connects as |
| `ZAGROSI_PARTMAN_INTERVAL` | `3600` | seconds between BGW maintenance runs |

These only take effect on first init (the hook appends to `postgresql.conf`
inside the data volume). Recreate the volume to re-template.

**Upgrading an existing dev volume:** a `pg_data` volume created by the stock
`postgres:18-bookworm` image has no preload configuration, so `CREATE
EXTENSION pg_parquet` will refuse to load against it. Recreate the volume
(`docker compose down -v`) when switching to this image.

## Build and publish policy

- The image is **prebuilt** and published to `ghcr.io/zagrosi-code/zagrosi-postgres`
  by `.github/workflows/postgres-image.yml`. Per-PR CI elsewhere in the repo
  pulls the `IMAGE_TAG` reference and never rebuilds it (the pg_parquet stage
  compiles Rust via pgrx; a cold build takes 15-30 minutes).
- The workflow builds + smokes on PRs touching `deploy/docker/postgres/**`
  (no push), publishes on merge to `main`, and rebuilds weekly to pick up
  base-image security fixes (pushing a `-rYYYYMMDD` refresh tag and opening
  an issue when the primary tag already exists).
- **Tags are immutable, enforced.** Any change under `deploy/docker/postgres/**`
  must bump `IMAGE_TAG` (and `VERSIONS` when pins change) in the same commit;
  the publish step fails loudly when a main merge would re-publish an
  existing tag.
- Reproducibility caveat: the build stage installs the latest stable Rust
  toolchain at build time (cargo-pgrx and the extension versions are pinned
  exactly). The primary tag is built once; weekly `-rYYYYMMDD` refresh tags
  intentionally float on the current base image and toolchain.
- One-time ops step after the first publish: mark the GHCR package **public**
  so testcontainers and forks' CI can pull without credentials.

## Local build + smoke

```sh
docker build -t "$(cat deploy/docker/postgres/IMAGE_TAG)" deploy/docker/postgres
bash deploy/docker/postgres/smoke.sh "$(cat deploy/docker/postgres/IMAGE_TAG)"
```

## S3 / MinIO (server-side credentials)

pg_parquet's S3 access is entirely server-side: the application only issues
SQL `COPY`; credentials are Postgres-container env. Verified against
pg_parquet 0.5.1:

- `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_REGION`,
  `AWS_ENDPOINT_URL` — standard AWS config chain.
- `AWS_ALLOW_HTTP=true` — required for non-TLS endpoints (dev MinIO);
  env-only switch.
- Path-style addressing is pg_parquet's **default** (it never enables
  virtual-hosted style), so no extra variable is needed for MinIO.

The dev compose stack wires these to the bundled MinIO service and
provisions the `zagrosi-audit` bucket via a one-shot `minio-init` container.

## Managed Postgres requirements (RDS, Cloud SQL, ...)

If you cannot run this image:

- PostgreSQL **18 or newer**.
- **pg_partman >= 5.4** available and creatable
  (`CREATE EXTENSION pg_partman`). The `pg_partman_bgw` preload is usually
  unavailable on managed services — schedule partition maintenance externally
  by calling `partman.run_maintenance_proc()` via the provider's scheduler
  (e.g. pg_cron).
- **pg_parquet optional.** Without it, audit cold archival degrades to a
  documented manual export path (see `documentation/audit.md` once the
  archival unit lands); everything else works.
