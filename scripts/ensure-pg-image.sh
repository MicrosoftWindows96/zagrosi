#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Ensure the custom Postgres image (deploy/docker/postgres/IMAGE_TAG) is
# available locally: use the local image if present, else pull, else build.
#
# The build fallback exists for the bootstrap window (image not yet on GHCR:
# first PR of the image dir, forks without package access) and is the slow
# path (~25 min cold pgrx compile). It builds with --build-arg values from
# deploy/docker/postgres/VERSIONS — the single source of truth — so a
# fallback-built image can never carry pins that contradict its tag.
#
# Callable standalone or sourced; used by scripts/smoke-compose.sh,
# scripts/smoke-sso.sh, and CI jobs that bring up the compose stack.

set -euo pipefail

ENSURE_PG_SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
ENSURE_PG_IMAGE_DIR="${ENSURE_PG_SCRIPT_DIR}/../deploy/docker/postgres"

ensure_pg_image() {
    local image_tag pull_err
    image_tag="$(cat "${ENSURE_PG_IMAGE_DIR}/IMAGE_TAG")"
    if docker image inspect "${image_tag}" >/dev/null 2>&1; then
        return 0
    fi
    if pull_err="$(docker pull "${image_tag}" 2>&1 >/dev/null)"; then
        return 0
    fi
    echo "==> could not pull ${image_tag}:"
    echo "${pull_err}" | tail -3
    echo "==> building locally (slow path, ~25 min cold)"
    # shellcheck source=deploy/docker/postgres/VERSIONS
    source "${ENSURE_PG_IMAGE_DIR}/VERSIONS"
    docker build \
        --build-arg "PG_MAJOR=${PG_MAJOR}" \
        --build-arg "PG_PARTMAN_VERSION=${PG_PARTMAN_VERSION}" \
        --build-arg "PG_PARQUET_VERSION=${PG_PARQUET_VERSION}" \
        --build-arg "CARGO_PGRX_VERSION=${CARGO_PGRX_VERSION}" \
        -t "${image_tag}" "${ENSURE_PG_IMAGE_DIR}"
}

# Run directly (not sourced) -> execute.
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    ensure_pg_image
fi
