// SPDX-License-Identifier: AGPL-3.0-or-later
//
// libFuzzer harness for the SAML ACS XML pre-flight + parser surface.
//
// Drives [`zagrosi_identity::saml::acs::fuzz_entry`] which exercises:
//
// 1. Base64 decode of the SAMLResponse form field (fail-soft).
// 2. UTF-8 validation.
// 3. DTD / external-entity pre-flight rejection.
// 4. samael's `parse_xml_response_with_mode` libxml2 + xmlsec XML
//    decoder + reducer (signature verification disabled by passing
//    an empty IdP metadata so the fuzz surface focuses on the XML
//    parser hardening, which is the XSW + XXE attack class.)
//
// # Invariants the harness enforces
//
// - No panic on any input.
// - No use-after-free / out-of-bounds (libxml2 wrapper safety).
// - No unbounded allocation.
//
// The integration-test compose lights up the `rust / fuzz-smoke` CI
// job with `cargo +nightly fuzz run saml_assertion -- -max_total_time=60`.
// Locally, install cargo-fuzz (`cargo install cargo-fuzz`) on a
// nightly toolchain and run the same command.

#![no_main]

use libfuzzer_sys::fuzz_target;
use zagrosi_identity::saml::acs::fuzz_entry;

fuzz_target!(|data: &[u8]| {
    fuzz_entry(data);
});
