// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! Password-auth primitives.
//!
//! Splits cleanly into four sub-modules:
//!
//! - [`hasher`]: Argon2id hash + verify wrapped in a bounded
//!   `tokio::task::spawn_blocking` discipline. The async runtime never
//!   sees memory-hard work.
//! - [`policy`]: length-only policy checks per NIST SP 800-63B.
//! - [`breach`]: HIBP k-anonymity client + mode switch (online /
//!   disabled / offline-reserved).
//! - [`calibration`]: startup verify-bench guarding the Argon2id
//!   profile against brown-out under load.
//!
//! These primitives compose into the `IdentityService` password flows
//! (`service::signup`, `service::signin`, `service::password_reset`).
//! See `documentation/identity.md` for the cross-cutting invariants
//! (anti-enumeration, `password_updated_at` revocation source-of-truth,
//! HIBP fail-closed).

pub mod breach;
pub mod calibration;
pub mod hasher;
pub mod policy;

pub use breach::HibpBreachClient;
pub use calibration::calibrate;
pub use hasher::Argon2idHasher;
pub use policy::{DUMMY_VERIFY_PASSWORD, validate_password_length};
