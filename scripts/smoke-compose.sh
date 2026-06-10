#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Smoke test for the Zagrosi dev compose stack.
#
# Brings up Postgres + MinIO + Valkey + NATS, polls each service's
# healthcheck, runs minimal sanity probes, then tears the stack down. On any
# timeout or probe failure, prints `docker compose ps` and per-service logs
# before exiting non-zero. The trap cleanup runs on both success and failure
# paths.
#
# Designed to work without a checked-in .env: the script exports the minimum
# required env vars itself so CI can invoke it directly.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
REPO_ROOT="${SCRIPT_DIR}/.."
COMPOSE_FILE="${REPO_ROOT}/deploy/docker/compose.yaml"

export POSTGRES_USER="${POSTGRES_USER:-zagrosi}"
export POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-smoke-test-password-not-secret}"
export POSTGRES_DB="${POSTGRES_DB:-zagrosi}"
export MINIO_ROOT_USER="${MINIO_ROOT_USER:-zagrosi-minio}"
export MINIO_ROOT_PASSWORD="${MINIO_ROOT_PASSWORD:-smoke-minio-password-not-secret}"
# Non-standard host ports: the smoke must not collide with a developer's own
# MinIO on 9000/9001. All probes go over the compose network, so the host
# binding is irrelevant to the assertions.
export MINIO_PORT="${MINIO_PORT:-19000}"
export MINIO_CONSOLE_PORT="${MINIO_CONSOLE_PORT:-19001}"

# The stack runs the prebuilt custom Postgres image; the shared helper
# pulls it or falls back to a local build during the bootstrap window.
# shellcheck source=scripts/ensure-pg-image.sh
source "${SCRIPT_DIR}/ensure-pg-image.sh"

dump_diagnostics() {
    echo "=== docker compose ps ==="
    docker compose -f "${COMPOSE_FILE}" ps || true
    for svc in postgres minio minio-init valkey nats; do
        echo "=== docker compose logs ${svc} ==="
        docker compose -f "${COMPOSE_FILE}" logs --no-color "${svc}" || true
    done
}

cleanup() {
    docker compose -f "${COMPOSE_FILE}" down -v --remove-orphans || true
}
trap cleanup EXIT

wait_healthy() {
    local service="$1"
    local timeout_s="$2"
    local elapsed=0
    local interval=2
    local status=""
    while [ "${elapsed}" -lt "${timeout_s}" ]; do
        local cid
        cid="$(docker compose -f "${COMPOSE_FILE}" ps -q "${service}" || true)"
        if [ -n "${cid}" ]; then
            status="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "${cid}" 2>/dev/null || echo "")"
            if [ "${status}" = "healthy" ]; then
                return 0
            fi
        fi
        sleep "${interval}"
        elapsed=$((elapsed + interval))
    done
    echo "service ${service} did not become healthy within ${timeout_s}s (last status: ${status:-unknown})"
    dump_diagnostics
    return 1
}

probe() {
    local label="$1"
    shift
    if ! "$@"; then
        echo "probe failed: ${label}"
        dump_diagnostics
        return 1
    fi
}

psql_compose() {
    docker compose -f "${COMPOSE_FILE}" exec -T postgres \
        psql -U "${POSTGRES_USER}" -d "${POSTGRES_DB}" -v ON_ERROR_STOP=1 -tAc "$1"
}

echo "==> Ensuring custom Postgres image is available"
ensure_pg_image

echo "==> Bringing up dev compose stack"
docker compose -f "${COMPOSE_FILE}" up -d

echo "==> Waiting for services to become healthy"
wait_healthy postgres 60
wait_healthy minio 30
wait_healthy valkey 30
wait_healthy nats 30

echo "==> Running sanity probes"
probe "valkey ping" \
    docker compose -f "${COMPOSE_FILE}" exec -T valkey valkey-cli ping
probe "postgres pg_isready" \
    docker compose -f "${COMPOSE_FILE}" exec -T postgres \
    pg_isready -U "${POSTGRES_USER}" -d "${POSTGRES_DB}"
probe "nats healthz" \
    docker compose -f "${COMPOSE_FILE}" exec -T nats \
    wget -qO- http://localhost:8222/healthz

echo "==> Probing minio-init bucket provisioning"
# One-shot service: assert it exited 0 (bucket exists), not merely that it ran.
minio_init_probe() {
    local cid exit_code
    local elapsed=0
    while [ "${elapsed}" -lt 30 ]; do
        cid="$(docker compose -f "${COMPOSE_FILE}" ps -aq minio-init || true)"
        if [ -n "${cid}" ]; then
            if [ "$(docker inspect --format '{{.State.Status}}' "${cid}")" = "exited" ]; then
                exit_code="$(docker inspect --format '{{.State.ExitCode}}' "${cid}")"
                [ "${exit_code}" = "0" ]
                return $?
            fi
        fi
        sleep 2
        elapsed=$((elapsed + 2))
    done
    echo "minio-init did not finish within 30s"
    return 1
}
probe "minio-init exited 0 (zagrosi-audit bucket provisioned)" minio_init_probe

echo "==> Probing custom Postgres image extensions"
# Create then drop: the smoke must not leave state that migrations later own.
probe "pg_partman + pg_parquet installable" \
    psql_compose "CREATE SCHEMA IF NOT EXISTS partman;
                  CREATE EXTENSION IF NOT EXISTS pg_partman SCHEMA partman;
                  CREATE EXTENSION IF NOT EXISTS pg_parquet;
                  DROP EXTENSION pg_parquet;
                  DROP EXTENSION pg_partman;
                  DROP SCHEMA partman;"

echo "==> Probing pg_partman BGW heartbeat"
# The BGW master worker starts with the server (compose pins a low
# ZAGROSI_PARTMAN_INTERVAL); integration tests never depend on the BGW —
# they call partman.run_maintenance_proc() directly. This compose-level
# assertion is the one place the BGW itself is checked. The idle master
# holds no pg_stat_activity slot, so the server log is the reliable signal.
bgw_probe() {
    docker compose -f "${COMPOSE_FILE}" logs --no-color postgres \
        | grep -q "pg_partman master background worker"
}
probe "pg_partman master BGW started" bgw_probe

echo "==> Probing MinIO reachability from inside the Postgres container"
# pg_parquet's S3 access is server-side: the PG container must reach MinIO
# over the compose network. The postgres image ships no curl/wget, so use
# bash /dev/tcp for an HTTP-level check against the MinIO health endpoint.
minio_from_pg_probe() {
    docker compose -f "${COMPOSE_FILE}" exec -T postgres bash -c \
        'exec 3<>/dev/tcp/minio/9000 && printf "GET /minio/health/live HTTP/1.0\r\nHost: minio\r\n\r\n" >&3 && head -n1 <&3 | grep -q " 200 "'
}
probe "minio health endpoint reachable from postgres" minio_from_pg_probe

echo "==> Smoke test passed"
