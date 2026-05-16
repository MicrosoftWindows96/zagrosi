// SPDX-License-Identifier: AGPL-3.0-or-later

//! OIDC (Authorization Code + PKCE S256) sign-in surface.
//!
//! Hardens against state replay, mix-up attacks, refresh-token
//! replay, and email-as-key takeover. The module composes:
//!
//! - [`config::OidcConfigV1`] — versioned JSONB config persisted in
//!   `org_idps.config`.
//! - [`cookie`] — sealed callback cookie carrying raw CSRF / nonce /
//!   PKCE verifier between redirect and callback.
//! - [`discovery::DiscoveryCache`] — per-issuer in-process metadata
//!   cache with rate-limited refresh + optional JWKS thumbprint pin.
//! - [`pending::PendingService`] — façade over `oidc_pending_auth`
//!   carrying the hash derivation logic.
//! - [`refresh::RefreshChain`] — refresh-token rotation + chain replay
//!   detection.
//! - [`jit::JitProvisioner`] — atomic JIT (user + anchor + membership)
//!   inside the callback transaction.
//! - [`client::OidcClient`] — `openidconnect::CoreClient` wrapper for
//!   `exchange_code` + ID-token validation.
//! - [`service::OidcService`] — orchestrates `start` and `callback`.
//!
//! See `docs/02-identity-sso-scim/sections/section-10-oidc-client.md`
//! for the design notes (gitignored).

pub mod client;
pub mod config;
pub mod cookie;
pub mod discovery;
pub mod jit;
pub mod pending;
pub mod refresh;
pub mod service;

#[cfg(any(test, feature = "fuzzing"))]
pub use client::verify_id_token_for_fuzz;
pub use client::{AcrAmrClaims, OidcClient, PER_CALL_TIMEOUT, VerifiedIdToken};
pub use config::{
    AttributeMapping, OIDC_CONFIG_VERSION_V1, OidcConfigV1, SealedSecret, StoredOidcConfig,
    build_minimal_config, jwks_thumbprint_hex, seal_client_secret,
};
pub use cookie::{
    COOKIE_NAME, CallbackPayload, PKCE_VERIFIER_LEN, RANDOM_BYTES, build_set_cookie_header,
    open as open_callback_cookie, seal as seal_callback_cookie, sha256,
};
pub use discovery::{DEFAULT_REFRESH_RATE_LIMIT, DEFAULT_TTL, DiscoveryCache, DiscoverySnapshot};
pub use jit::{JitInput, JitOutcome, JitProvisioner};
pub use pending::{DEFAULT_PENDING_TTL, PendingService, StartContext};
pub use refresh::{RefreshChain, ReplayContext, RotatedRefresh};
pub use service::{
    CallbackInput, CallbackOutcome, OidcService, OidcServiceDeps, StartOutcome, build_clear_cookie,
};
