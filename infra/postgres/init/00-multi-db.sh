#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later

set -euo pipefail

if [ -z "${POSTGRES_MULTIPLE_DATABASES:-}" ]; then
    exit 0
fi

create_database() {
    local database="$1"
    psql -v ON_ERROR_STOP=1 --username "${POSTGRES_USER}" --dbname postgres <<-EOSQL
        SELECT 'CREATE DATABASE ${database}'
        WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = '${database}')\gexec
EOSQL
}

IFS=',' read -ra databases <<< "${POSTGRES_MULTIPLE_DATABASES}"
for database in "${databases[@]}"; do
    database="$(echo "${database}" | xargs)"
    if [ -n "${database}" ]; then
        create_database "${database}"
    fi
done
