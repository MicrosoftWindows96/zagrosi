// SPDX-License-Identifier: AGPL-3.0-or-later

//! Golden-file round-trip for the v1 audit-event wire format.
//!
//! Owned by the tenant-isolation layer's `zagrosi-audit` consumers; breaking changes here
//! are a hard breaking change to the audit storage schema.

use zagrosi_core::AuditEvent;

#[test]
fn audit_event_v1_fixture_round_trips() {
    let raw = include_str!("fixtures/audit_event_v1.json");
    let event: AuditEvent = serde_json::from_str(raw).expect("fixture parses");
    let re = serde_json::to_value(&event).expect("re-serialise");
    let original: serde_json::Value = serde_json::from_str(raw).expect("original parses as value");
    assert_eq!(re, original, "AuditEvent round-trip is not lossless");
}
