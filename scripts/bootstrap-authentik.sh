#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later

set -euo pipefail

AUTHENTIK_URL="${ZAGROSI_TEST_AUTHENTIK_URL:-http://localhost:9000}"
TOKEN="${AUTHENTIK_BOOTSTRAP_TOKEN:-}"
BLUEPRINT_PATH="${AUTHENTIK_BLUEPRINT_PATH:-/blueprints/zagrosi/bootstrap.yaml}"

if [ -z "${TOKEN}" ]; then
    echo "AUTHENTIK_BOOTSTRAP_TOKEN is required" >&2
    exit 1
fi

api() {
    local method="$1"
    local path="$2"
    shift 2
    curl -fsS \
        -H "Authorization: Bearer ${TOKEN}" \
        -H "Accept: application/json" \
        -H "Content-Type: application/json" \
        -X "${method}" \
        "${AUTHENTIK_URL}${path}" \
        "$@"
}

echo "==> Waiting for Authentik API"
for _ in $(seq 1 60); do
    if curl -fsS "${AUTHENTIK_URL}/-/health/live/" >/dev/null; then
        break
    fi
    sleep 2
done

echo "==> Discovering Zagrosi blueprint"
blueprints="$(api GET "/api/v3/managed/blueprints/?path=${BLUEPRINT_PATH}" || true)"
pk="$(python3 -c '
import json, sys
try:
    data = json.load(sys.stdin)
except json.JSONDecodeError:
    sys.exit(0)
for item in data.get("results", []):
    if item.get("path") == sys.argv[1]:
        print(item.get("pk", ""))
        break
' "${BLUEPRINT_PATH}" <<< "${blueprints}")"

if [ -z "${pk}" ]; then
    echo "No Authentik blueprint instance found at ${BLUEPRINT_PATH}; relying on file watcher"
    exit 0
fi

echo "==> Applying Authentik blueprint ${pk}"
api POST "/api/v3/managed/blueprints/${pk}/apply/" >/dev/null
echo "==> Authentik bootstrap complete"
