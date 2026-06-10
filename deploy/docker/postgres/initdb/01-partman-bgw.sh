#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Initdb hook baked into the custom Postgres image. Runs once at first init
# (before the entrypoint restarts the real server), so the appended config
# governs the actual instance — required for shared_preload_libraries,
# which is a restart-only GUC.
#
# pg_parquet v0.5.x hard-requires preload (it panics when loaded without
# shared_preload_libraries), so both libraries are always listed.
#
# Env contract (see deploy/docker/postgres/README.md):
#   ZAGROSI_PARTMAN_DBNAME   default: $POSTGRES_DB, else 'postgres'
#   ZAGROSI_PARTMAN_ROLE     default: $POSTGRES_USER, else 'postgres'
#   ZAGROSI_PARTMAN_INTERVAL default: 3600 (seconds between BGW runs)

set -euo pipefail

partman_dbname="${ZAGROSI_PARTMAN_DBNAME:-${POSTGRES_DB:-postgres}}"
partman_role="${ZAGROSI_PARTMAN_ROLE:-${POSTGRES_USER:-postgres}}"
partman_interval="${ZAGROSI_PARTMAN_INTERVAL:-3600}"

case "${partman_interval}" in
    ''|*[!0-9]*)
        echo "zagrosi-postgres: ZAGROSI_PARTMAN_INTERVAL must be a positive integer, got '${partman_interval}'" >&2
        exit 1
        ;;
esac

# Escape single quotes for the postgresql.conf string literals (a ' in
# POSTGRES_DB/USER would otherwise break server start with an opaque error).
partman_dbname="${partman_dbname//\'/\'\'}"
partman_role="${partman_role//\'/\'\'}"

cat >> "${PGDATA}/postgresql.conf" <<EOF

# Appended by zagrosi-postgres initdb hook (01-partman-bgw.sh)
shared_preload_libraries = 'pg_partman_bgw,pg_parquet'
pg_partman_bgw.dbname = '${partman_dbname}'
pg_partman_bgw.role = '${partman_role}'
pg_partman_bgw.interval = ${partman_interval}
EOF

echo "zagrosi-postgres: BGW configured (dbname=${partman_dbname} role=${partman_role} interval=${partman_interval}s)"
