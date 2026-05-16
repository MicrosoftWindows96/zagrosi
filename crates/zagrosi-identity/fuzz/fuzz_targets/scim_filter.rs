// SPDX-License-Identifier: AGPL-3.0-or-later

//! `cargo-fuzz` smoke harness for the SCIM 2.0 filter parser.
//!
//! The CI `rust / fuzz-smoke` job runs this for 60 seconds against
//! arbitrary byte sequences. The parser MUST never panic on
//! adversarial input — every parse failure should surface as
//! `ScimError::InvalidFilter` rather than an unwound stack.

#![no_main]

use libfuzzer_sys::fuzz_target;
use zagrosi_identity::http::scim::filter;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = filter::parse(s);
    }
});
