#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
REPO_ROOT="${SCRIPT_DIR}/.."
BASE_COMPOSE="${REPO_ROOT}/deploy/docker/compose.yaml"
TEST_COMPOSE="${REPO_ROOT}/deploy/docker/compose.test.yaml"
COMPOSE=(docker compose -f "${BASE_COMPOSE}" -f "${TEST_COMPOSE}")

export POSTGRES_USER="${POSTGRES_USER:-zagrosi}"
export POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-smoke-test-password-not-secret}"
export POSTGRES_DB="${POSTGRES_DB:-zagrosi}"
export MINIO_ROOT_USER="${MINIO_ROOT_USER:-zagrosi-minio}"
export MINIO_ROOT_PASSWORD="${MINIO_ROOT_PASSWORD:-smoke-minio-password-not-secret}"
# Non-standard host ports: avoid colliding with a developer's own MinIO.
export MINIO_PORT="${MINIO_PORT:-19000}"
export MINIO_CONSOLE_PORT="${MINIO_CONSOLE_PORT:-19001}"
export AUTHENTIK_SECRET_KEY="${AUTHENTIK_SECRET_KEY:-$(openssl rand -hex 32)}"
export AUTHENTIK_BOOTSTRAP_PASSWORD="${AUTHENTIK_BOOTSTRAP_PASSWORD:-$(openssl rand -hex 16)}"
export AUTHENTIK_BOOTSTRAP_TOKEN="${AUTHENTIK_BOOTSTRAP_TOKEN:-$(openssl rand -hex 32)}"
export ZAGROSI_TEST_USER_PASSWORD="${ZAGROSI_TEST_USER_PASSWORD:-smoke-test-password-not-secret}"
export ZAGROSI_TEST_SCIM_BEARER="${ZAGROSI_TEST_SCIM_BEARER:-scim_smoke_test_not_secret}"

dump_diagnostics() {
    echo "=== docker compose ps ==="
    "${COMPOSE[@]}" ps || true
    for svc in postgres minio minio-init valkey nats authentik-server authentik-worker simplesamlphp mailpit; do
        echo "=== docker compose logs ${svc} ==="
        "${COMPOSE[@]}" logs --no-color "${svc}" || true
    done
}

cleanup() {
    "${COMPOSE[@]}" down -v --remove-orphans || true
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
        cid="$("${COMPOSE[@]}" ps -q "${service}" || true)"
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

echo "==> Ensuring custom Postgres image is available"
# shellcheck source=scripts/ensure-pg-image.sh
source "${SCRIPT_DIR}/ensure-pg-image.sh"
ensure_pg_image

echo "==> Bringing up SSO compose stack"
"${COMPOSE[@]}" up -d

echo "==> Waiting for services to become healthy"
wait_healthy postgres 90
wait_healthy valkey 30
wait_healthy nats 30
wait_healthy authentik-server 240
wait_healthy simplesamlphp 90
wait_healthy mailpit 30

echo "==> Applying Authentik bootstrap"
bash "${REPO_ROOT}/scripts/bootstrap-authentik.sh"

echo "==> Running sanity probes"
probe "valkey ping" "${COMPOSE[@]}" exec -T valkey valkey-cli ping
probe "postgres pg_isready" \
    "${COMPOSE[@]}" exec -T postgres pg_isready -U "${POSTGRES_USER}" -d "${POSTGRES_DB}"
probe "nats healthz" \
    "${COMPOSE[@]}" exec -T nats wget -qO- http://localhost:8222/healthz
probe "authentik health" curl -fsS http://localhost:9000/-/health/live/
probe "simplesamlphp metadata" curl -fsS http://localhost:8081/simplesaml/saml2/idp/metadata.php
probe "mailpit api" curl -fsS http://localhost:8025/api/v1/info

echo "==> SSO smoke test passed"
