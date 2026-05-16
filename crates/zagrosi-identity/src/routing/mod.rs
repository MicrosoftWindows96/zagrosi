// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! Multi-IdP routing layer.
//!
//! Composes the email-domain → IdP routing decision used by
//! `POST /v1/auth/discover` together with the admin-facing domain-
//! ownership flow (`/v1/orgs/{org_slug}/idps/{id}/domains/...`).
//!
//! The module is split for clarity:
//!
//! - [`email_normalise`] — plus-tag stripping + IDNA punycode +
//!   lowercase folding.
//! - [`blocklist`] — Mozilla Public Suffix List + curated catch-all.
//! - [`dns`] — DNSSEC-validating dual-resolver TXT lookup port +
//!   `hickory-resolver`-backed production impl.
//! - [`cache`] — Moka cache short-circuit for repeat verify
//!   attempts within the configured TTL window.
//! - [`tombstone`] — federated-identity tombstone helper consumed
//!   by the OIDC + SAML callback paths.
//! - [`discover`] — `POST /v1/auth/discover` handler + response shape.
//! - [`domain_verify`] — admin domain CRUD handlers.
//! - [`state`] — composed [`RoutingState`] sub-state shared by
//!   every handler in this module.
//!
//! Two router builders are exported so the gateway-composition
//! root can mount the public discover endpoint and the admin
//! domain-CRUD endpoints behind separate middleware stacks:
//!
//! - [`router`] — public discover surface, no auth.
//! - [`admin_router`] — admin domain-CRUD surface; the mounter MUST
//!   gate this behind an authenticated admin middleware.

use axum::Router;
use axum::routing::{delete, post};

pub mod blocklist;
pub mod cache;
pub mod data;
pub mod discover;
pub mod dns;
pub mod domain_verify;
pub mod email_normalise;
pub mod state;
pub mod tombstone;

pub use cache::{DomainKey, DomainVerifyCache};
pub use discover::{
    DiscoverRequest, DiscoverResponse, PickerMethod, PickerOption, handle_discover,
};
pub use dns::{
    DnsResolverPort, HickoryDualResolver, VERIFY_TXT_PREFIX, VerifyFailure, VerifyOutcome,
    resolver_path_for,
};
pub use domain_verify::{
    CreateDomainRequest, CreateDomainResponse, VerifyDomainResponse, create_domain, delete_domain,
    verify_domain,
};
pub use email_normalise::{NormalisedEmail, normalise};
pub use state::RoutingState;
pub use tombstone::{FederatedLookup, lookup_federated_identity};

/// Build the public router (the discover endpoint only).
///
/// Caller composes this with the rest of the identity surface via
/// `axum::Router::merge`. No middleware is required — the discover
/// endpoint is public.
pub fn router(state: RoutingState) -> Router<()> {
    Router::new()
        .route("/v1/auth/discover", post(discover::handle_discover))
        .with_state(state)
}

/// Build the admin router (domain CRUD endpoints).
///
/// The mounter MUST gate this router behind authenticated admin
/// middleware before binding it to a public listener; the handlers
/// themselves accept `Extension<AuthContext>` and apply the v0.1
/// org-membership predicate, but they do NOT enforce admin role
/// claims (that lands with the RBAC layer).
pub fn admin_router(state: RoutingState) -> Router<()> {
    Router::new()
        .route(
            "/v1/orgs/{org_slug}/idps/{org_idp_id}/domains",
            post(domain_verify::create_domain),
        )
        .route(
            "/v1/orgs/{org_slug}/idps/{org_idp_id}/domains/{domain_id}/verify",
            post(domain_verify::verify_domain),
        )
        .route(
            "/v1/orgs/{org_slug}/idps/{org_idp_id}/domains/{domain_id}",
            delete(domain_verify::delete_domain),
        )
        .with_state(state)
}
