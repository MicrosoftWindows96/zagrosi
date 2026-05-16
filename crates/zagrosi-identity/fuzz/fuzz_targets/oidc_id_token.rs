// SPDX-License-Identifier: AGPL-3.0-or-later
//
// libFuzzer harness for the offline slice of the OIDC ID-token
// validation chain.
//
// Drives [`zagrosi_identity::oidc::verify_id_token_for_fuzz`] which
// exercises the attacker-controlled, network-free portion of
// `OidcClient::exchange_and_verify`:
//
// 1. UTF-8 validation of the raw token bytes.
// 2. Side-band `acr` / `amr` extraction from the JWT body.
// 3. Compact-JWS segmentation + base64url body decode.
// 4. JSON claim deserialisation into `openidconnect`'s
//    `CoreIdTokenClaims` (the same type the live verifier yields).
// 5. The explicit `iat`-skew / `azp`-shape post-checks the lib does
//    not enforce by default.
//
// The signature-verification + token-endpoint round-trip are NOT in
// scope here (they require a live JWKS + token endpoint); the
// `fuzzing` feature gate exposes the offline entry point precisely so
// this surface is reachable without a network.
//
// # Invariants the harness enforces
//
// - No panic on any input.
// - No network access (the entry point is network-free by
//   construction; the harness would hang/fail CI otherwise).
// - No `Ok`-shaped result a caller could mistake for a verified
//   token (the entry point returns `()`).
//
// The integration-test compose lights up the `rust / fuzz-smoke` CI
// job with `cargo +nightly fuzz run oidc_id_token -- -max_total_time=60`.
// Locally, install cargo-fuzz (`cargo install cargo-fuzz`) on a
// nightly toolchain and run the same command.

#![no_main]

use libfuzzer_sys::fuzz_target;
use zagrosi_identity::oidc::verify_id_token_for_fuzz;

fuzz_target!(|data: &[u8]| {
    verify_id_token_for_fuzz(data);
});
