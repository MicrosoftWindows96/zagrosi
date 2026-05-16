// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! `OidcPendingAuth` aggregate. State held between OIDC redirect and
//! callback.

use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Pending OIDC authorisation record. Every secret carried by the
/// browser between redirect and callback (`state`, `nonce`, the PKCE
/// verifier, the CSRF cookie value) is persisted only as a SHA-256
/// digest — the raw values stay client-side. The partial unique on
/// `(state_hash) WHERE used_at IS NULL` enforces single-use redemption.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcPendingAuth {
    /// Application-generated UUID v7 primary key.
    pub id: Uuid,
    /// IdP this request targets. Carries the org indirectly via
    /// `org_idps.org_id`.
    pub org_idp_id: Uuid,
    /// SHA-256 of the `state` parameter sent to the IdP.
    pub state_hash: [u8; 32],
    /// SHA-256 of the OIDC `nonce` echoed in the ID token.
    pub nonce_hash: [u8; 32],
    /// SHA-256 of the PKCE code-verifier (RFC 7636 S256).
    pub verifier_hash: [u8; 32],
    /// SHA-256 of the `__Host-zagrosi_oidc_csrf` cookie value.
    pub csrf_cookie_hash: [u8; 32],
    /// Redirect URI registered for this transaction.
    pub redirect_uri: String,
    /// Row creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Hard expiry timestamp (~10 minutes after creation per the design notes).
    pub expires_at: DateTime<Utc>,
    /// Single-use seal; `Some(now)` after the callback handler
    /// consumes the row.
    pub used_at: Option<DateTime<Utc>>,
}
