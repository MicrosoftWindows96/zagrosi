#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
REPO_ROOT="${SCRIPT_DIR}/.."
IDENTITY="${REPO_ROOT}/crates/zagrosi-identity"

mkdir -p \
    "${IDENTITY}/fuzz/corpus/saml_assertion" \
    "${IDENTITY}/fuzz/corpus/scim_filter" \
    "${IDENTITY}/fuzz/corpus/oidc_id_token"

cp "${IDENTITY}"/tests/fixtures/negative/saml/*.xml "${IDENTITY}/fuzz/corpus/saml_assertion/"
cp "${IDENTITY}"/tests/fixtures/negative/scim/*.txt "${IDENTITY}/fuzz/corpus/scim_filter/"
cp "${IDENTITY}"/tests/fixtures/negative/oidc/* "${IDENTITY}/fuzz/corpus/oidc_id_token/"
