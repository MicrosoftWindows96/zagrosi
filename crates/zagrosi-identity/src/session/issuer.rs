// SPDX-License-Identifier: AGPL-3.0-or-later

//! Concrete implementation of [`crate::session::port::SessionIssuer`].
//!
//! Mints a fresh `sid_*` token via the canonical token-format
//! chokepoint, hashes the value (with prefix included so a future
//! cross-class collision is impossible), inserts the `sessions` row
//! through [`crate::repo::SessionRepo`], and produces a paired CSRF
//! token for browser callers. Also exposes the issued raw token to
//! the auth handler so it can decide between cookie and bearer
//! shaping.
//!
//! AuthN-state transitions (sign-in, password-reset confirm, IdP
//! callback) issue a fresh session token in the same code path so
//! pre-transition cookies can never be reused.

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Utc;
use rand_core::{OsRng, RngCore};
use std::sync::Arc;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::config::IdentityConfig;
use crate::domain::token_format::{TokenHash, TokenPrefix, hash_token, mint};
use crate::error::{IdentityError, Result};
use crate::repo::{NewSession, SessionRepo};
use crate::session::cookie::SessionAttachment;
use crate::session::port::{IssuedSession, SessionIssuer};

/// Number of random bytes that back the CSRF cookie value. 32 bytes
/// → 43 base64url-no-pad chars, matching the entropy budget the
/// session token uses so brute-force timing on either is identical.
const CSRF_BYTES: usize = 32;

/// Concrete `SessionIssuer` backed by [`SessionRepo`] +
/// [`IdentityConfig`].
#[derive(Clone)]
pub struct IdentitySessionIssuer {
    config: Arc<IdentityConfig>,
    sessions: SessionRepo,
}

impl IdentitySessionIssuer {
    /// Wrap the configured session repo + the loaded identity
    /// config. The config supplies `session.ttl_days` for the
    /// `sessions.expires_at` calculation.
    #[must_use]
    pub const fn new(config: Arc<IdentityConfig>, sessions: SessionRepo) -> Self {
        Self { config, sessions }
    }

    /// Issue a session and return the [`IssuedSession`] alongside
    /// the [`SessionAttachment`] cookie pair so callers driving a
    /// browser-shaped response do not need a second mint pass.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::Database`] for any sqlx failure on
    /// the `sessions` insert. Token generation is infallible (the
    /// `OsRng` source returns successfully on every supported
    /// platform).
    pub async fn issue_with_attachment(
        &self,
        user_id: Uuid,
        org_id: Option<Uuid>,
        amr: &[&str],
        acr: Option<&str>,
    ) -> Result<(IssuedSession, SessionAttachment)> {
        let inputs = self.build_issue_inputs(user_id, org_id, amr, acr);
        let amr_refs: Vec<&str> = inputs.amr_owned.iter().map(String::as_str).collect();
        let new = inputs.borrow_new_session(&amr_refs);
        let row = self
            .sessions
            .insert(new)
            .await
            .map_err(remap_database_error)?;
        Ok(inputs.into_issued(&row))
    }

    /// Same contract as [`Self::issue_with_attachment`] but the
    /// `sessions` row inserts on the caller-supplied transaction.
    /// Used by SSO callback paths (`saml::acs::handler`) that need
    /// the session-row insert to commit atomically with the
    /// upstream pending-row mark-used + replay-ledger insert + JIT
    /// user create. Without an in-tx variant the session insert
    /// runs after `tx.commit()` — a downstream session-insert
    /// failure leaves a JIT user with a consumed replay row but no
    /// session, locking the user out for that assertion.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::Database`] for any sqlx failure on
    /// the `sessions` insert.
    pub async fn issue_with_attachment_in_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        user_id: Uuid,
        org_id: Option<Uuid>,
        amr: &[&str],
        acr: Option<&str>,
    ) -> Result<(IssuedSession, SessionAttachment)> {
        let inputs = self.build_issue_inputs(user_id, org_id, amr, acr);
        let amr_refs: Vec<&str> = inputs.amr_owned.iter().map(String::as_str).collect();
        let new = inputs.borrow_new_session(&amr_refs);
        let row = self
            .sessions
            .insert_in_tx(tx, new)
            .await
            .map_err(remap_database_error)?;
        Ok(inputs.into_issued(&row))
    }

    /// Build the inputs (raw token + token hash + CSRF value +
    /// session id + expires_at) shared between the in-tx and
    /// non-tx issue paths. The raw secrets land inside
    /// [`Zeroizing`] wrappers immediately; on drop, the heap
    /// buffers are scrubbed before allocator reuse. Both issue
    /// paths consume the inputs via [`IssueInputs::new_session`]
    /// (borrows for the SQL insert) and [`IssueInputs::into_issued`]
    /// (moves the secrets into the returned `IssuedSession` +
    /// `SessionAttachment`).
    fn build_issue_inputs(
        &self,
        user_id: Uuid,
        org_id: Option<Uuid>,
        amr: &[&str],
        acr: Option<&str>,
    ) -> IssueInputs {
        let raw_token = Zeroizing::new(mint(TokenPrefix::Session));
        let token_hash = hash_token(&raw_token);
        let csrf_value = Zeroizing::new(generate_csrf_value());

        let issued_at = Utc::now();
        let ttl_days = i64::from(self.config.session.ttl_days);
        let expires_at = issued_at + chrono::TimeDelta::days(ttl_days);
        let session_id = Uuid::now_v7();

        IssueInputs {
            session_id,
            user_id,
            org_id,
            amr_owned: amr.iter().map(|s| (*s).to_owned()).collect(),
            acr: acr.map(str::to_owned),
            expires_at,
            raw_token,
            token_hash,
            csrf_value,
        }
    }
}

/// Shared mint output used by both `issue_with_attachment` and
/// `issue_with_attachment_in_tx`. The raw token + CSRF value are
/// stored inside [`Zeroizing`] so the heap buffers are scrubbed on
/// drop — a tx that aborts before the response is rendered will not
/// leave plaintext tokens lingering in heap memory until allocator
/// reuse.
///
/// `into_issued` moves the secrets into the returned
/// [`IssuedSession`] + [`SessionAttachment`]; the public-surface
/// types own plain `String` fields today (cookie crate API +
/// historical SessionAttachment shape). A future hardening pass
/// can promote those to `Zeroizing<String>` to extend the scrub
/// window through the response-render path; the issuer-side
/// scrubbing here covers the mint-to-handoff window.
struct IssueInputs {
    session_id: Uuid,
    user_id: Uuid,
    org_id: Option<Uuid>,
    amr_owned: Vec<String>,
    acr: Option<String>,
    expires_at: chrono::DateTime<Utc>,
    raw_token: Zeroizing<String>,
    token_hash: TokenHash,
    csrf_value: Zeroizing<String>,
}

impl IssueInputs {
    /// Build the borrow-shape `NewSession` that the SQL insert
    /// consumes. The caller materialises the `Vec<&str>` view of
    /// `amr_owned` so the slice's lifetime is tied to the caller's
    /// stack frame (and outlives the `.await`).
    fn borrow_new_session<'a>(&'a self, amr_refs: &'a [&'a str]) -> NewSession<'a> {
        NewSession {
            id: self.session_id,
            token_hash: self.token_hash.as_slice(),
            user_id: self.user_id,
            org_id: self.org_id,
            user_agent: None,
            ip_addr: None,
            amr: amr_refs,
            acr: self.acr.as_deref(),
            expires_at: self.expires_at,
        }
    }

    fn into_issued(mut self, row: &crate::domain::Session) -> (IssuedSession, SessionAttachment) {
        // Move the inner Strings out of their `Zeroizing` wrappers
        // via `mem::take`. The wrappers now hold empty Strings
        // (`String::default()` is heap-free); on drop the
        // `Zeroize` impl runs over zero bytes — no-op. The
        // moved-out Strings own the original heap allocations and
        // proceed to `SessionAttachment` / `IssuedSession`. The
        // issuer-side mint window (mint → SQL insert → handoff) is
        // therefore covered by zeroize-on-drop; the
        // post-handoff residue (cookie crate buffers,
        // `SessionAttachment::raw_session_token`) is a documented
        // follow-up.
        let raw_token = std::mem::take(&mut *self.raw_token);
        let csrf_value = std::mem::take(&mut *self.csrf_value);
        let issued = IssuedSession {
            id: row.id,
            user_id: row.user_id,
            org_id: row.org_id,
            expires_at: self.expires_at,
            raw_token: raw_token.clone(),
        };
        let attachment = SessionAttachment::new(raw_token, csrf_value);
        (issued, attachment)
    }
}

/// Identity passthrough used by both issue paths. Kept for parity
/// with the prior in-line shape; if a future variant family ever
/// needs remapping, this is the single chokepoint.
const fn remap_database_error(err: IdentityError) -> IdentityError {
    match err {
        IdentityError::Database(_) => err,
        other => other,
    }
}

#[async_trait]
impl SessionIssuer for IdentitySessionIssuer {
    async fn issue_password_session(
        &self,
        user_id: Uuid,
        org_id: Option<Uuid>,
        amr: &[&str],
    ) -> Result<IssuedSession> {
        let (issued, _attachment) = self
            .issue_with_attachment(user_id, org_id, amr, None)
            .await?;
        Ok(issued)
    }
}

/// Mint a 32-byte random value, base64url-no-pad encoded. Used as
/// the CSRF cookie payload.
#[must_use]
pub fn generate_csrf_value() -> String {
    let mut bytes = [0_u8; CSRF_BYTES];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csrf_value_is_43_base64url_no_pad_chars() {
        let value = generate_csrf_value();
        assert_eq!(
            value.len(),
            43,
            "32-byte payload renders to 43 chars no-pad"
        );
        assert!(
            value
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "value `{value}` contains non-base64url characters",
        );
    }

    #[test]
    fn csrf_value_does_not_collide_under_normal_load() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..1_000 {
            assert!(seen.insert(generate_csrf_value()), "csrf collision");
        }
    }
}
