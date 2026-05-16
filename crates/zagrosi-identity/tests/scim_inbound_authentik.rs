// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(
    clippy::doc_markdown,
    clippy::too_long_first_doc_paragraph,
    clippy::panic
)]
//! Authentik SCIM-push round-trip placeholders (section-12).
//!
//! Authentik is the canonical inbound SCIM producer in section-16's
//! compose stack. The three flows below are the integration-level
//! equivalent of the unit-level coverage in `tests/scim_server.rs`:
//!
//! - `authentik_push_user_creates_users_row_with_correct_attributes`
//! - `authentik_push_group_with_members_creates_group_with_matching_members`
//! - `authentik_active_false_revokes_sessions_and_soft_deletes_user`
//!
//! Locally, `cargo test --workspace` skips them because they require
//! the section-16 compose stack (`authentik/server:2026.2` +
//! worker). The unit-level coverage in `scim_server.rs` exercises
//! the same invariants (active=false → session revocation in same
//! tx, group member round-trip, ETag derivation) against an
//! in-process axum router.

#[tokio::test]
#[ignore = "requires section-16 compose stack (Authentik server + worker)"]
async fn authentik_push_user_creates_users_row_with_correct_attributes() {
    panic!(
        "section-16 compose harness not present yet — flip #[ignore] off only once \
         tests/compose.test.yaml ships authentik/server:2026.2"
    );
}

#[tokio::test]
#[ignore = "requires section-16 compose stack (Authentik server + worker)"]
async fn authentik_push_group_with_members_creates_group_with_matching_members() {
    panic!(
        "section-16 compose harness not present yet — flip #[ignore] off only once \
         tests/compose.test.yaml ships authentik/server:2026.2"
    );
}

#[tokio::test]
#[ignore = "requires section-16 compose stack (Authentik server + worker)"]
async fn authentik_active_false_revokes_sessions_and_soft_deletes_user() {
    panic!(
        "section-16 compose harness not present yet — flip #[ignore] off only once \
         tests/compose.test.yaml ships authentik/server:2026.2"
    );
}
