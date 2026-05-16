// SPDX-License-Identifier: AGPL-3.0-or-later
//
// libFuzzer harness for `Secrets::open`.
//
// The target feeds arbitrary bytes as a candidate `Envelope` JSON payload
// under a fixed test key, then asserts:
//
// - `Secrets::open` never panics — the workspace `unwrap_used = deny` and
//   `panic = warn` lint posture is verified empirically by the harness.
// - `Secrets::open` never returns `Ok(_)` — the input space has negligible
//   probability of matching a valid AEAD authentication tag, so any `Ok`
//   indicates a real bug (constant-time check elision, mis-routed key_id,
//   etc.).
//
// The integration-test compose lights up the `rust / fuzz-smoke` CI job with
// `cargo +nightly fuzz run secrets_open -- -max_total_time=60`. Locally,
// the same command works once `cargo-fuzz` is installed
// (`cargo install cargo-fuzz`) on a nightly toolchain.

#![no_main]

use libfuzzer_sys::fuzz_target;
use zagrosi_identity::{Envelope, Secrets};

const FUZZ_KEY: [u8; 32] = [0x42; 32];

fuzz_target!(|data: &[u8]| {
    let secrets = Secrets::from_key(Box::new(FUZZ_KEY));
    if let Ok(envelope) = serde_json::from_slice::<Envelope>(data) {
        match secrets.open(&envelope) {
            Ok(_) => panic!(
                "fuzzer produced an envelope that authenticated under the fixed key",
            ),
            Err(_) => {
                // Any typed error variant is acceptable — the contract is
                // "no Ok, no panic". The harness exits with status 0 here
                // and libFuzzer continues mutating.
            }
        }
    }
});
