// SPDX-License-Identifier: AGPL-3.0-or-later

//! Integration test: the placeholder binary starts, emits the marker line,
//! and exits zero.
//!
//! Hermetic by design. Provides only `PATH` (so the OS loader can resolve
//! shared libraries on macOS and Linux), `ZAGROSI_SERVICE_NAME`, and
//! `RUST_LOG`. Does NOT set `ZAGROSI_PROMETHEUS_BIND` or
//! `ZAGROSI_OTEL_ENDPOINT` so no external sockets are touched.

use std::process::Command;

#[test]
fn placeholder_binary_runs_and_exits_zero() {
    let bin = env!("CARGO_BIN_EXE_zagrosi-api-gateway");

    let output = Command::new(bin)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("ZAGROSI_SERVICE_NAME", "test-gateway")
        .env("RUST_LOG", "info")
        .output()
        .expect("failed to spawn placeholder binary");

    assert!(
        output.status.success(),
        "binary exited non-zero: status={:?}\nstdout={}\nstderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");

    assert!(
        combined.contains("zagrosi: placeholder"),
        "marker substring not found in binary output\nstdout={stdout}\nstderr={stderr}",
    );
}
