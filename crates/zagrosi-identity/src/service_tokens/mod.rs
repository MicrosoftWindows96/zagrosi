// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! Service-token (`svc_*`) surface — platform-level internal
//! service-to-service bearer credentials.
//!
//! Out-of-process workers (split-11) boot with
//! `ZAGROSI_SERVICE_TOKEN=svc_…` and present
//! `Authorization: Bearer svc_…` on every callback to identity. The
//! gateway middleware calls [`zagrosi_core::SessionIntrospector::resolve`]
//! exactly as for every other bearer class — no special-casing.
//!
//! Sub-modules (mirror [`crate::api_tokens`], minus the write-behind
//! and expiry that the `service_tokens` schema does not have):
//!
//! - [`model`] — request / response DTOs. `IssuedServiceToken` is the
//!   only shape carrying the raw token, returned once on `POST`.
//! - [`cache`] — in-process LRU keyed on the token hash with the
//!   revocation-generation stale-write guard + TTL flip.
//! - [`resolver`] — the `svc_*` introspector branch. Builds an
//!   org-agnostic `AuthContext` (token-id sentinel, `scopes =
//!   allowed_subjects`).
//! - [`service`] — CRUD entry point (issue / list / get / revoke)
//!   with platform-admin-scoped audit.
//!
//! NATS-subject enforcement against `allowed_subjects` is the worker
//! pool's responsibility (split-11); this crate only validates +
//! persists + surfaces the list.

pub mod cache;
pub mod model;
pub mod resolver;
pub mod service;

pub use cache::{CachedServiceToken, ServiceTokenCache};
pub use model::{
    CreateServiceTokenRequest, IssuedServiceToken, IssuedServiceTokenResponse, ServiceTokenView,
};
pub use resolver::{SVC_RESOLVE_SCOPE, ServiceTokenResolver};
pub use service::{SERVICE_DISPLAY_NAME_MAX_LEN, ServiceTokenService};
