// SPDX-License-Identifier: AGPL-3.0-or-later

//! Cryptographic shims for the identity crate.
//!
//! The secrets shim ships [`Secrets`], an AES-256-GCM envelope wrapper
//! for every persisted secret that downstream layers (OIDC
//! `client_secret`, SAML SP signing keys, future SMTP credentials) need
//! to hand to Postgres.
//!
//! The wire format `{key_id, nonce, ciphertext, tag}` is forward-compatible
//! with the future KMS layer's KMS-backed envelope rewrap: the KMS layer
//! will introduce additional `key_id` values (`v0.2-kms-<rotation>`),
//! and the v0.1 shim already returns
//! [`crate::error::IdentityError::UnknownKeyId`] for anything other than
//! [`KEY_ID_V0_1_STATIC`] so the rewrap can route by `key_id` without
//! breaking the public surface.

pub mod secrets;

pub use secrets::{Envelope, KEY_ID_V0_1_STATIC, NONCE_LEN, Secrets, TAG_LEN};
