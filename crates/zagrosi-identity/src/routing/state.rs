// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! Composed state handle for the multi-IdP routing handlers.
//!
//! The discover endpoint and the domain-CRUD endpoints share a
//! single [`RoutingState`] so the gateway-composition root passes
//! one struct rather than threading dependencies through every
//! route. Mirrors the pattern used by [`crate::http::scim`] and
//! [`crate::oidc`].

use std::sync::Arc;

use zagrosi_core::Auditor;

use crate::repo::{OrgIdpDomainRepo, OrgIdpRepo, OrgRepo};

use super::cache::DomainVerifyCache;
use super::dns::DnsResolverPort;

/// Shared state for the routing layer's HTTP handlers.
///
/// Cheap to clone — every field is `Arc`-wrapped or already
/// `Clone`. The composition root constructs one [`RoutingState`]
/// at startup; axum hands a clone to every request.
#[derive(Clone)]
pub struct RoutingState {
    /// Cross-org routing-decision repo + per-org domain CRUD.
    pub org_idp_domain_repo: OrgIdpDomainRepo,
    /// Used by domain CRUD handlers to assert that the
    /// path-supplied `org_idp_id` belongs to the path-supplied
    /// org slug.
    pub org_idp_repo: OrgIdpRepo,
    /// Slug → org id resolution for the admin URL space.
    pub org_repo: OrgRepo,
    /// DNSSEC-validating resolver bound to the configured
    /// upstreams. Mocked in tests.
    pub dns_resolver: Arc<dyn DnsResolverPort>,
    /// Per-domain verify cache shared across handlers and
    /// requests. Cloning the `Arc` is the supported share
    /// pattern.
    pub domain_cache: Arc<DomainVerifyCache>,
    /// Audit sink. Discover does not audit; the domain CRUD
    /// handlers do.
    pub auditor: Arc<dyn Auditor>,
}

impl RoutingState {
    /// Wire dependencies. All fields are `Arc`-cheap so this
    /// constructor is the supported path; the composition root
    /// MUST NOT hand-roll the struct.
    #[must_use]
    pub fn new(
        org_idp_domain_repo: OrgIdpDomainRepo,
        org_idp_repo: OrgIdpRepo,
        org_repo: OrgRepo,
        dns_resolver: Arc<dyn DnsResolverPort>,
        domain_cache: Arc<DomainVerifyCache>,
        auditor: Arc<dyn Auditor>,
    ) -> Self {
        Self {
            org_idp_domain_repo,
            org_idp_repo,
            org_repo,
            dns_resolver,
            domain_cache,
            auditor,
        }
    }
}
