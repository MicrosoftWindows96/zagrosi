// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::expect_used, clippy::unwrap_used, missing_docs)]

use std::collections::BTreeSet;
use std::path::PathBuf;

use serde_json::Value;

const REQUIRED_CHECKS: &[&str] = &[
    "rust / sso-integration",
    "rust / signin-bench",
    "rust / fuzz-smoke",
];

const DEFERRED_ITEMS: &[&str] = &[
    "KMS-backed envelope and Argon2 pepper",
    "Per-tenant SMTP transport",
    "Account-merge admin UX",
    "TOTP and WebAuthn MFA",
    "Idle-account Argon2 background rehash job",
    "Offline-mirror HIBP client",
    "SAML SP signing-key rotation flow",
    "SCIM Bulk support",
    "zxcvbn-style entropy estimator",
];

const REQUIRED_ROUTES: &[&str] = &[
    "/v1/auth/sign-up",
    "/v1/auth/sign-in",
    "/v1/auth/sign-out",
    "/v1/auth/email-verifications/request",
    "/v1/auth/email-verifications/confirm",
    "/v1/auth/password-reset/request",
    "/v1/auth/password-reset/confirm",
    "/v1/auth/discover",
    "/v1/sessions",
    "/v1/sessions/me",
    "/v1/sessions/{id}",
    "/v1/api-tokens",
    "/v1/api-tokens/{id}",
    "/v1/auth/oidc/{org_slug}/start",
    "/v1/auth/oidc/{org_slug}/callback",
    "/v1/auth/saml/{org_slug}/start",
    "/v1/auth/saml/{org_slug}/acs",
    "/v1/auth/saml/{org_slug}/metadata.xml",
    "/scim/v2/Users",
    "/scim/v2/Users/{id}",
    "/scim/v2/Groups",
    "/scim/v2/Groups/{id}",
    "/scim/v2/ServiceProviderConfig",
    "/scim/v2/ResourceTypes",
    "/scim/v2/Schemas",
    "/v1/orgs/{org_slug}/idps/{org_idp_id}/domains",
    "/v1/orgs/{org_slug}/idps/{org_idp_id}/domains/{domain_id}/verify",
    "/v1/orgs/{org_slug}/idps/{org_idp_id}/domains/{domain_id}",
    "/v1/orgs/{org_slug}/scim-tokens",
    "/v1/orgs/{org_slug}/scim-tokens/{id}",
    "/v1/service-tokens",
    "/v1/service-tokens/{id}",
    "/v1/admin/users/{id}/unlock",
];

#[test]
fn openapi_documents_required_routes() {
    let spec = read("documentation/api/identity.openapi.yaml");
    for route in REQUIRED_ROUTES {
        let key = format!("  {route}:");
        assert!(spec.contains(&key), "OpenAPI spec missing {route}");
    }
    assert!(spec.contains("application/scim+json"));
    assert!(spec.contains("RFC 9207"));
    assert!(spec.contains("__Host-zagrosi_sid"));
    assert!(spec.contains("RateLimit-Limit"));
}

#[test]
fn branch_protection_requires_identity_checks() {
    let raw = read(".github/branch-protection.json");
    let parsed: Value = serde_json::from_str(&raw).unwrap();
    let checks = parsed
        .pointer("/rules")
        .and_then(Value::as_array)
        .unwrap()
        .iter()
        .find(|rule| rule.get("type").and_then(Value::as_str) == Some("required_status_checks"))
        .and_then(|rule| rule.pointer("/parameters/required_status_checks"))
        .and_then(Value::as_array)
        .unwrap()
        .iter()
        .filter_map(|entry| entry.get("context").and_then(Value::as_str))
        .collect::<BTreeSet<_>>();

    for required in REQUIRED_CHECKS {
        assert!(
            checks.contains(*required),
            "missing required check {required}"
        );
    }
}

#[test]
fn changelog_unreleased_lists_every_deferred_item() {
    let changelog = read("CHANGELOG.md");
    let block = changelog
        .split_once("## [Unreleased]")
        .expect("missing Unreleased block")
        .1;
    for item in DEFERRED_ITEMS {
        assert!(block.contains(item), "missing deferred item {item}");
    }
}

#[test]
fn identity_docs_have_required_sections_and_style() {
    let identity = read("documentation/identity.md");
    let openapi = read("documentation/api/identity.openapi.yaml");
    for heading in [
        "## Architecture Overview",
        "## Threat Model",
        "## Deferred Items",
        "## Hardware Baseline",
        "## Environment Variables",
        "## Standards Conformance Map",
        "## Handoff Notes",
    ] {
        assert!(identity.contains(heading), "missing heading {heading}");
    }

    for (name, body) in [
        ("documentation/identity.md", identity.as_str()),
        ("documentation/api/identity.openapi.yaml", openapi.as_str()),
    ] {
        for mark in ['\u{2014}', '\u{2013}'] {
            assert!(
                !body.contains(mark),
                "{name} contains forbidden punctuation"
            );
        }
        for phrase in [
            ["Clau", "de"].concat(),
            ["Cod", "ex"].concat(),
            [" A", "I "].concat(),
        ] {
            assert!(
                !body.contains(&phrase),
                "{name} contains forbidden prose marker"
            );
        }
    }
}

fn read(path: &str) -> String {
    std::fs::read_to_string(repo_root().join(path)).expect("read repository file")
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .map_or_else(|| PathBuf::from("."), std::path::Path::to_path_buf)
}
