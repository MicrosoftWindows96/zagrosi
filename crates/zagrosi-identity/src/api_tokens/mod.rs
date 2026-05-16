// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! Personal access token (`pat_*`) surface.
//!
//! Five tightly-scoped sub-modules ship the public surface:
//!
//! - [`model`] holds the request / response DTOs the HTTP handlers
//!   serialise. `IssuedApiTokenResponse` is the only response shape
//!   that ever carries the raw token string and is returned at most
//!   once, on `POST /v1/api-tokens`.
//! - [`cache`] is the in-process LRU keyed on the token hash. It
//!   mirrors the [`crate::session::SessionCache`] shape (atomic-swap
//!   moka backend with healthy / fail-closed TTL flips) but stores
//!   `CachedApiToken` rather than `CachedSession` so the resolver
//!   does not re-key the session cache on PAT lookups.
//! - [`write_behind`] is the bounded mpsc channel that batches
//!   `last_used_*` updates off the resolve hot path. Coalesces
//!   updates per `(token_id)` within a 60-second window so a hot
//!   PAT issues at most one DB UPDATE per minute even under bursty
//!   load.
//! - [`resolver`] is the `pat_*` branch of the gateway-facing
//!   introspector pipeline. Validates the prefix + length pre-DB,
//!   probes the cache, falls back to a `find_by_token_hash` query,
//!   re-checks `(revoked_at IS NULL AND expires_at > now())` even on
//!   cache hits, and fires a write-behind event.
//! - [`service`] is the CRUD entry point: issue (mint + persist +
//!   audit), list, get, revoke.
//!
//! ## Scope catalogue v0.1
//!
//! See [`SCOPE_CATALOGUE_V0_1`]. The catalogue is extended in the
//! upcoming RBAC layer; this module's responsibility ends at
//! string-match validation against the constant set.

pub mod cache;
pub mod model;
pub mod resolver;
pub mod service;
pub mod write_behind;

pub use cache::{ApiTokenCache, CachedApiToken};
pub use model::{ApiTokenView, CreateApiTokenRequest, IssuedApiToken, IssuedApiTokenResponse};
pub use resolver::{ApiTokenResolver, PAT_RESOLVE_SCOPE};
pub use service::{ApiTokenService, IssueApiTokenInput};
pub use write_behind::{
    ApiTokenLastUsedReceiver, ApiTokenLastUsedSender, ApiTokenLastUsedUpdate,
    channel as api_token_last_used_channel,
};

/// Authorisation scopes accepted on PAT issuance in v0.1.
///
/// Every PAT-creation request whose `scopes` list contains a string
/// outside this set is rejected with
/// [`crate::error::IdentityError::InvalidScope`]. Catalogue extension
/// lands in the upcoming RBAC layer; until then the three-string set
/// here is the source of truth.
pub const SCOPE_CATALOGUE_V0_1: &[&str] = &["tokens:read", "tokens:write", "me:read"];

/// Required scope to mint or revoke personal access tokens.
pub const SCOPE_TOKENS_WRITE: &str = "tokens:write";

/// Required scope to list / get personal access tokens.
pub const SCOPE_TOKENS_READ: &str = "tokens:read";

/// Maximum length of the human-set `display_name` field in characters.
pub const DISPLAY_NAME_MAX_LEN: usize = 100;

/// Returns `true` when `scope` is a recognised v0.1 catalogue entry.
#[must_use]
pub fn is_known_scope(scope: &str) -> bool {
    SCOPE_CATALOGUE_V0_1.contains(&scope)
}
