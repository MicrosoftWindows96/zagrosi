#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Smoke-test the custom Postgres image before publish.
#
# Usage: smoke.sh <image-ref>
#
# Asserts, via docker run + psql:
#   1. container reaches ready state with POSTGRES_DB=smokedb
#   2. SHOW shared_preload_libraries contains pg_partman_bgw and pg_parquet
#      (pg_parquet v0.5.x hard-requires preload; it panics otherwise)
#   3. SHOW pg_partman_bgw.dbname = 'smokedb' (templated from env, not baked)
#   4. CREATE EXTENSION pg_partman SCHEMA partman succeeds and extversion
#      matches the VERSIONS pin
#   5. CREATE EXTENSION pg_parquet succeeds and extversion matches the pin
#   6. the pg_partman master BGW started (server log line; the idle master
#      does not hold a pg_stat_activity slot, so logs are the reliable signal)
#   7. re-run with ZAGROSI_PARTMAN_DBNAME=otherdb -> pg_partman_bgw.dbname
#      = 'otherdb' (explicit override beats the POSTGRES_DB default)

set -euo pipefail

if [ $# -ne 1 ]; then
    echo "usage: $0 <image-ref>" >&2
    exit 2
fi
IMAGE_REF="$1"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
# shellcheck source=deploy/docker/postgres/VERSIONS
source "${SCRIPT_DIR}/VERSIONS"

CONTAINER_A="zagrosi-pg-smoke-$$"
CONTAINER_B="zagrosi-pg-smoke-override-$$"

cleanup() {
    docker rm -f "${CONTAINER_A}" "${CONTAINER_B}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

fail() {
    echo "smoke FAILED: $1" >&2
    echo "=== container logs (${2:-$CONTAINER_A}) ===" >&2
    docker logs "${2:-$CONTAINER_A}" >&2 || true
    exit 1
}

psql_a() {
    docker exec "${CONTAINER_A}" psql -U postgres -d smokedb -v ON_ERROR_STOP=1 -tAc "$1"
}

# Wait until the *final* server (post-initdb restart) is up: the preload line
# is only visible after the entrypoint restarts with the templated config.
wait_ready() {
    local container="$1"
    local db="$2"
    local elapsed=0
    while [ "${elapsed}" -lt 120 ]; do
        if docker exec "${container}" psql -U postgres -d "${db}" -tAc \
            "SHOW shared_preload_libraries" 2>/dev/null | grep -q pg_partman_bgw; then
            return 0
        fi
        sleep 2
        elapsed=$((elapsed + 2))
    done
    return 1
}

echo "==> [1/7] starting container (POSTGRES_DB=smokedb)"
docker run -d --name "${CONTAINER_A}" \
    -e POSTGRES_PASSWORD=smoke-not-secret \
    -e POSTGRES_DB=smokedb \
    "${IMAGE_REF}" >/dev/null
wait_ready "${CONTAINER_A}" smokedb || fail "container did not become ready"

echo "==> [2/7] shared_preload_libraries contains both extensions"
preload="$(psql_a "SHOW shared_preload_libraries")"
echo "${preload}" | grep -q pg_partman_bgw || fail "pg_partman_bgw missing from shared_preload_libraries: ${preload}"
echo "${preload}" | grep -q pg_parquet || fail "pg_parquet missing from shared_preload_libraries: ${preload}"

echo "==> [3/7] pg_partman_bgw.dbname templated from POSTGRES_DB"
dbname="$(psql_a "SHOW pg_partman_bgw.dbname")"
[ "${dbname}" = "smokedb" ] || fail "pg_partman_bgw.dbname expected 'smokedb', got '${dbname}'"

echo "==> [4/7] pg_partman installs at pinned version ${PG_PARTMAN_VERSION}"
psql_a "CREATE SCHEMA partman" >/dev/null
psql_a "CREATE EXTENSION pg_partman SCHEMA partman" >/dev/null
partman_ver="$(psql_a "SELECT extversion FROM pg_extension WHERE extname = 'pg_partman'")"
[ "${partman_ver}" = "${PG_PARTMAN_VERSION}" ] || fail "pg_partman extversion expected '${PG_PARTMAN_VERSION}', got '${partman_ver}'"

echo "==> [5/7] pg_parquet installs at pinned version ${PG_PARQUET_VERSION}"
psql_a "CREATE EXTENSION pg_parquet" >/dev/null
parquet_ver="$(psql_a "SELECT extversion FROM pg_extension WHERE extname = 'pg_parquet'")"
[ "${parquet_ver}" = "${PG_PARQUET_VERSION}" ] || fail "pg_parquet extversion expected '${PG_PARQUET_VERSION}', got '${parquet_ver}'"

echo "==> [6/7] pg_partman master BGW started"
docker logs "${CONTAINER_A}" 2>&1 | grep -q "pg_partman master background worker" \
    || fail "no 'pg_partman master background worker' line in server log"

echo "==> [7/7] ZAGROSI_PARTMAN_DBNAME override beats POSTGRES_DB"
docker run -d --name "${CONTAINER_B}" \
    -e POSTGRES_PASSWORD=smoke-not-secret \
    -e POSTGRES_DB=smokedb \
    -e ZAGROSI_PARTMAN_DBNAME=otherdb \
    "${IMAGE_REF}" >/dev/null
wait_ready "${CONTAINER_B}" smokedb || fail "override container did not become ready" "${CONTAINER_B}"
override_dbname="$(docker exec "${CONTAINER_B}" psql -U postgres -d smokedb -tAc "SHOW pg_partman_bgw.dbname")"
[ "${override_dbname}" = "otherdb" ] || fail "pg_partman_bgw.dbname expected 'otherdb', got '${override_dbname}'" "${CONTAINER_B}"

echo "==> image smoke passed: ${IMAGE_REF}"
