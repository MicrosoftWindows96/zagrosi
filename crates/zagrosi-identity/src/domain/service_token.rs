// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! `ServiceToken` (internal service-to-service bearer) aggregate.

use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Internal service-to-service bearer (`svc_*`) consumed by the
/// service-token surface. Intentionally org-agnostic; service tokens
/// authorise platform-wide internal callers. The tenant-isolation
/// layer's RLS will whitelist this table for the service / migration
/// roles rather than gate it by tenant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceToken {
    /// Application-generated UUID v7 primary key.
    pub id: Uuid,
    /// Caller name (e.g. `email-worker`, `scim-bridge`).
    pub service_name: String,
    /// SHA-256 of the raw `svc_*` token.
    pub token_hash: [u8; 32],
    /// NATS-subject allow-list the service may publish / subscribe on.
    /// Free-form patterns; the service-token surface enforces a `>` / `*`-aware match.
    pub allowed_subjects: Vec<String>,
    /// Display name shown in admin UI.
    pub display_name: String,
    /// Row creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Revocation timestamp.
    pub revoked_at: Option<DateTime<Utc>>,
    /// Soft-delete tombstone.
    pub deleted_at: Option<DateTime<Utc>>,
}
