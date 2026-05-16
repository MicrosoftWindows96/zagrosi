// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::missing_panics_doc,
    clippy::missing_errors_doc,
    clippy::missing_const_for_fn
)]
//! `docker compose` lifecycle helpers for the section-16 test stack.
//!
//! The canonical entry point for CI is `scripts/smoke-sso.sh`; these
//! helpers exist so an individual integration test can assert the
//! stack is reachable (and skip cleanly when it is not) without
//! shelling out by hand. Every helper is a thin, fail-soft wrapper
//! over `docker compose -f compose.yaml -f compose.test.yaml …`.

use std::path::PathBuf;
use std::process::Command;

use super::TestResult;

/// Repo root, derived from `CARGO_MANIFEST_DIR`
/// (`crates/zagrosi-identity` → two parents up).
#[must_use]
pub fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .map_or_else(|| PathBuf::from("."), std::path::Path::to_path_buf)
}

/// The `-f compose.yaml -f compose.test.yaml` argument pair.
#[must_use]
pub fn compose_files() -> [PathBuf; 2] {
    let root = repo_root();
    [
        root.join("deploy/docker/compose.yaml"),
        root.join("deploy/docker/compose.test.yaml"),
    ]
}

/// `true` when a `docker` binary is on `PATH` and the daemon
/// responds. Used by [`super::integration_enabled`] consumers as a
/// secondary belt-and-braces guard.
#[must_use]
pub fn docker_available() -> bool {
    Command::new("docker")
        .args(["info", "--format", "{{.ServerVersion}}"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn compose_command() -> Command {
    let [base, overlay] = compose_files();
    let mut cmd = Command::new("docker");
    cmd.arg("compose")
        .arg("-f")
        .arg(base)
        .arg("-f")
        .arg(overlay)
        .current_dir(repo_root());
    cmd
}

/// `docker compose … up -d --wait`. Fail-soft: returns the captured
/// stderr on non-zero exit so the caller can attach it to a skip /
/// diagnostic message rather than panicking mid-suite.
pub fn up() -> TestResult<()> {
    let out = compose_command().args(["up", "-d", "--wait"]).output()?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "compose up failed: {}",
            String::from_utf8_lossy(&out.stderr)
        )
        .into())
    }
}

/// `docker compose … down -v --remove-orphans`. Best-effort; never
/// errors (teardown must not mask a test failure).
pub fn down() {
    let _ = compose_command()
        .args(["down", "-v", "--remove-orphans"])
        .output();
}

/// `docker compose … ps` for diagnostics, returned verbatim.
#[must_use]
pub fn ps() -> String {
    compose_command()
        .arg("ps")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default()
}
