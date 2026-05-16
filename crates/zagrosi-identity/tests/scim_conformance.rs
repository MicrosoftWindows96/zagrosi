// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(
    clippy::doc_markdown,
    clippy::too_long_first_doc_paragraph,
    clippy::panic
)]
//! SCIM 2.0 conformance harness placeholders (section-12).
//!
//! Three sub-suites are wired here as `#[ignore]` integration tests
//! so the CI compose layer (section-16) can flip them on. Locally,
//! `cargo test --workspace` skips them because they require a
//! `scim-server`-mounted-on-an-ephemeral-port test compose:
//!
//! 1. **WSO2 SCIM 2.0 Compliance Test Suite** — hard CI gate.
//! 2. **verify.scim.dev validator binary** — hard CI gate.
//! 3. **Microsoft validator** — optional gate (warns on unreachable).
//!
//! The actual harness wiring lands in section-16 alongside the
//! `compose.test.yaml`. Until then, these stubs assert the contract
//! by erroring out with a deterministic message when run with
//! `--ignored`, so contributors who flip `#[ignore]` off without
//! the compose layer get a useful failure rather than a timeout.

#[tokio::test]
#[ignore = "requires section-16 compose stack (scim-server + WSO2 image)"]
async fn wso2_scim2_compliance_test_suite_passes_users_and_groups() {
    panic!(
        "section-16 compose harness not present yet — flip #[ignore] off only once \
         tests/compose.test.yaml ships the wso2/scim2-compliance-test-suite container"
    );
}

#[tokio::test]
#[ignore = "requires section-16 compose stack (scim-server + verify.scim.dev binary)"]
async fn verify_scim_dev_validator_passes() {
    panic!(
        "section-16 compose harness not present yet — flip #[ignore] off only once \
         tests/compose.test.yaml ships the verify-scim binary"
    );
}

#[tokio::test]
#[ignore = "optional gate — Microsoft validator probed at job start"]
async fn microsoft_scim_validator_runs_and_reports_when_reachable() {
    // Probe `https://scimvalidator.microsoft.com/` reachability. If
    // 200, run the validator + capture report as CI artefact. If
    // unreachable, log a warning + return Ok. Implementation lands
    // in section-16; this stub keeps the test name visible to
    // `cargo test --list` so the compose-test runner can reference
    // it by name.
    panic!(
        "section-16 compose harness not present yet — flip #[ignore] off only once \
         the conformance runner is wired"
    );
}
