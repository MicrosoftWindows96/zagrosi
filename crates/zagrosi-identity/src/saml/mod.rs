// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! SAML 2.0 Service Provider implementation.
//!
//! Feature-gated under the `saml` Cargo feature. The default build
//! does NOT pull `samael`, `libxmlsec1`, `libxml2`, `libc`, or
//! `openssl`; the SP only links the C stack when downstream binaries
//! opt in via `--features saml`.
//!
//! ## Module map
//!
//! * [`config`] — versioned [`config::SamlConfigV1`] for the
//!   `org_idps.config` JSONB column. Mirrors the contract of
//!   [`crate::oidc::config::OidcConfigV1`]: serialise on admin write,
//!   re-validate on every callback.
//! * [`errors`] — [`errors::SamlError`] enum exposing the audit-grade
//!   sub-reasons enumerated in section-11 spec lines 200-225.
//! * [`relay_state`] — 256-bit `RelayState` minting + constant-time
//!   compare. Spec line 23 invariant.
//! * [`request_id`] — `xs:ID`-safe AuthnRequest id minted from a
//!   256-bit CSPRNG draw. Overrides samael's default 32-bit
//!   `rand::random::<u32>()` so the id is unguessable in practice
//!   (samael's value is not part of its security claim, but the SP's
//!   pending-row correlation is, so we bump entropy).
//! * [`attribute`] — typed view over samael's [`samael::schema::Assertion`]
//!   attribute statements with the `attribute_mapping` overrides
//!   applied.
//! * [`authn`] — [`authn::start`] HTTP handler: builds the
//!   AuthnRequest, persists `saml_pending_auth`, returns the
//!   HTTP-Redirect-binding 302.
//! * [`acs`] — [`acs::handler`] HTTP handler: strict-order ACS
//!   validation, replay-ledger insert, JIT/anchor-hit user resolve,
//!   session issuance.
//! * [`metadata`] — [`metadata::handler`] HTTP handler: returns the
//!   SP `EntityDescriptor` XML, generating + envelope-encrypting the
//!   SP signing key on first call.
//!
//! ## XSW countermeasure (spec invariant 4)
//!
//! `samael::service_provider::ServiceProvider::parse_xml_response_with_mode`
//! invoked with `ReduceMode::ValidateAndMarkNoAncestors` reduces the
//! input XML to ONLY the subtree referenced by the verified
//! `Signature/Reference`. The SP layer then re-parses that reduced
//! XML, so attribute / Subject extraction can never read sibling
//! nodes outside the signed scope. This is the canonical XSW
//! defence.

pub mod acs;
pub mod attribute;
pub mod authn;
pub mod config;
pub mod errors;
pub mod jit;
pub mod metadata;
pub mod relay_state;
pub mod request_id;
pub mod service;

pub use acs::handler as acs_handler;
pub use authn::start as start_handler;
pub use config::{AttributeMapping, SamlConfigV1, SpSigningAlg};
pub use errors::SamlError;
pub use jit::{SamlJitInput, SamlJitOutcome, SamlJitProvisioner};
pub use metadata::handler as metadata_handler;
pub use service::{
    AcsCallbackInput, AcsCallbackOutcome, MetadataOutcome, SamlService, SamlServiceDeps,
    StartOutcome,
};
