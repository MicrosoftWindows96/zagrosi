// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! `oidc_pending_auth` lifecycle helpers.
//!
//! Wraps [`crate::repo::OidcPendingRepo`] with the hash-derivation
//! logic the OIDC start handler needs (raw `state` → `state_hash`,
//! cookie payload → field hashes) and the lookup-and-mark sequence
//! the callback handler needs.

use chrono::{DateTime, Duration, Utc};
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::domain::OidcPendingAuth;
use crate::error::{IdentityError, Result};
use crate::oidc::cookie::{CallbackPayload, sha256};
use crate::repo::{NewOidcPending, OidcPendingRepo};

/// Default pending-auth row TTL. Section-10 hard-codes 10 minutes; a
/// future config lever can lower this on regulated deployments.
pub const DEFAULT_PENDING_TTL: Duration = Duration::minutes(10);

/// Argument bundle for [`PendingService::insert_for_start`].
///
/// Holds the IdP id + the redirect URI literal the start handler
/// passed to `set_redirect_uri` so the callback can verbatim-compare.
#[derive(Debug, Clone)]
pub struct StartContext<'a> {
    /// Owning IdP row id.
    pub org_idp_id: Uuid,
    /// Verbatim redirect URI passed to the IdP. The callback handler
    /// recomputes the same value and refuses to proceed on mismatch.
    pub redirect_uri: &'a str,
    /// Raw `state` value placed in the IdP authorization URL. Stored
    /// only as a SHA-256 hash on the row.
    pub state: &'a str,
    /// Raw cookie payload (CSRF / nonce / verifier). Hashed and stored
    /// on the row; the raw values travel between redirect and callback
    /// inside the sealed cookie envelope.
    pub cookie_payload: &'a CallbackPayload,
    /// Optional explicit expiry. When `None`, the start handler stamps
    /// `now + DEFAULT_PENDING_TTL`.
    pub expires_at: Option<DateTime<Utc>>,
}

/// Façade that combines the raw repo with the hash-derivation logic
/// the start / callback handlers need. Cheap to clone (single `Arc`
/// over the repo handle).
#[derive(Clone)]
pub struct PendingService {
    repo: OidcPendingRepo,
}

impl PendingService {
    /// Wire to the underlying repo.
    #[must_use]
    pub const fn new(repo: OidcPendingRepo) -> Self {
        Self { repo }
    }

    /// Insert a pending row for a fresh authorization request.
    #[tracing::instrument(skip_all, fields(org_idp_id = %ctx.org_idp_id, route = "oidc.pending.insert"))]
    pub async fn insert_for_start(&self, ctx: StartContext<'_>) -> Result<OidcPendingAuth> {
        let state_hash = sha256(ctx.state.as_bytes());
        let nonce_hash = ctx.cookie_payload.nonce_hash();
        let verifier_hash = ctx.cookie_payload.verifier_hash();
        let csrf_hash = ctx.cookie_payload.csrf_hash();
        let expires_at = ctx
            .expires_at
            .unwrap_or_else(|| Utc::now() + DEFAULT_PENDING_TTL);

        self.repo
            .insert(NewOidcPending {
                id: Uuid::now_v7(),
                org_idp_id: ctx.org_idp_id,
                state_hash: &state_hash,
                nonce_hash: &nonce_hash,
                verifier_hash: &verifier_hash,
                csrf_cookie_hash: &csrf_hash,
                redirect_uri: ctx.redirect_uri,
                expires_at,
            })
            .await
    }

    /// Lookup a pending row by `state` and reconcile every invariant
    /// the callback handler needs. The success branch returns the row
    /// ready for the caller to invoke [`PendingService::mark_used`]
    /// inside the JIT / session-issue transaction.
    ///
    /// # Errors
    ///
    /// - [`IdentityError::OidcStateMismatch`] when no row matches the
    ///   supplied `state` or any per-field hash differs from the
    ///   cookie payload (constant-time compared).
    /// - [`IdentityError::OidcReplay`] when the matching row was
    ///   already consumed (`used_at IS NOT NULL`). The lookup
    ///   intentionally returns used rows so this distinct audit
    ///   signal is reachable; the public HTTP envelope still collapses
    ///   to the uniform `oidc_callback_failed` surface.
    /// - [`IdentityError::OidcExpired`] when the row's `expires_at`
    ///   is past.
    #[tracing::instrument(skip_all, fields(route = "oidc.pending.resolve"))]
    pub async fn resolve_callback(
        &self,
        state: &str,
        cookie: &CallbackPayload,
    ) -> Result<OidcPendingAuth> {
        let state_hash = sha256(state.as_bytes());
        let row = self
            .repo
            .find_by_state(&state_hash)
            .await?
            .ok_or(IdentityError::OidcStateMismatch)?;

        if row.used_at.is_some() {
            return Err(IdentityError::OidcReplay);
        }

        if row.expires_at < Utc::now() {
            return Err(IdentityError::OidcExpired);
        }

        // Constant-time compare every cookie-derived hash against the
        // row's hashes. Failing any one collapses to the same
        // `OidcStateMismatch` so we don't disclose which field tripped.
        let csrf_ok: bool = row.csrf_cookie_hash.ct_eq(&cookie.csrf_hash()).into();
        let nonce_ok: bool = row.nonce_hash.ct_eq(&cookie.nonce_hash()).into();
        let verifier_ok: bool = row.verifier_hash.ct_eq(&cookie.verifier_hash()).into();
        if !(csrf_ok && nonce_ok && verifier_ok) {
            return Err(IdentityError::OidcStateMismatch);
        }
        Ok(row)
    }

    /// Mark a pending row consumed inside `tx`. Returns
    /// [`IdentityError::OidcReplay`] when the row was already consumed
    /// (race with a concurrent callback).
    #[tracing::instrument(skip_all, fields(pending_id = %id, route = "oidc.pending.mark_used"))]
    pub async fn mark_used(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        id: Uuid,
    ) -> Result<()> {
        match self.repo.mark_used(tx, id, Utc::now()).await {
            Ok(()) => Ok(()),
            Err(IdentityError::TokenNotFound) => Err(IdentityError::OidcReplay),
            Err(err) => Err(err),
        }
    }

    /// Borrow the underlying repo for tests / future paths that need
    /// finer-grained access.
    #[must_use]
    pub const fn repo(&self) -> &OidcPendingRepo {
        &self.repo
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_pending_ttl_is_ten_minutes() {
        assert_eq!(DEFAULT_PENDING_TTL.num_minutes(), 10);
    }

    #[test]
    fn start_context_holds_borrows() {
        // Compile-coverage assertion that `StartContext<'_>` round
        // trips through the borrow checker without requiring `'static`
        // values; the start handler stamps a stack-resident state /
        // payload pair.
        let payload = CallbackPayload::new_random();
        let _ = StartContext {
            org_idp_id: Uuid::now_v7(),
            redirect_uri: "https://example.test/callback",
            state: "borrowed-state",
            cookie_payload: &payload,
            expires_at: None,
        };
    }
}
