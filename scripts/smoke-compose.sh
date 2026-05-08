#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Smoke test for the Zagrosi dev compose stack.
#
# Brings up Postgres + Valkey + NATS, polls each service's healthcheck, runs
# minimal sanity probes, then tears the stack down. On any timeout or probe
# failure, prints `docker compose ps` and per-service logs before exiting
# non-zero. The trap cleanup runs on both success and failure paths.
#
# Designed to work without a checked-in .env: the script exports the minimum
# required POSTGRES_* env vars itself so CI can invoke it directly.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
REPO_ROOT="${SCRIPT_DIR}/.."
COMPOSE_FILE="${REPO_ROOT}/deploy/docker/compose.yaml"

export POSTGRES_USER="${POSTGRES_USER:-zagrosi}"
export POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-smoke-test-password-not-secret}"
export POSTGRES_DB="${POSTGRES_DB:-zagrosi}"

dump_diagnostics() {
    echo "=== docker compose ps ==="
    docker compose -f "${COMPOSE_FILE}" ps || true
    for svc in postgres valkey nats; do
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

echo "==> Bringing up dev compose stack"
docker compose -f "${COMPOSE_FILE}" up -d

echo "==> Waiting for services to become healthy"
wait_healthy postgres 60
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

echo "==> Smoke test passed"
