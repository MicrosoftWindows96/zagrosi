// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! JIT (just-in-time) user provisioning for SAML sign-in.
//!
//! ## Trust gate
//!
//! `SamlConfigV1.trust_email_assertion == true` is the JIT
//! precondition. SAML assertions, unlike OIDC ID tokens, do not carry
//! an `email_verified` claim — the email value is whatever the IdP
//! chooses to assert. JIT is therefore admin-opt-in per IdP. With the
//! gate off we surface [`SamlError::EmailNotTrusted`] so the SPA can
//! hand off to the admin-provisioning flow.
//!
//! ## Cross-org email collision
//!
//! Email is **not** an SSO key (project-wide invariant — see
//! `documentation/identity.md`). When the assertion's `email_lower`
//! already matches a live `users` row, we refuse to auto-merge and
//! surface [`SamlError::AccountAlreadyExists`] so the SPA can hand
//! off to the admin-merge flow (deferred to the admin layer).
//!
//! ## Atomic JIT transaction
//!
//! The JIT path runs entirely inside the caller's transaction:
//!
//! 1. Insert the `users` row (`password_hash = NULL`).
//! 2. Insert the `federated_identities` row with the canonical
//!    `(protocol = 'saml', issuer = idp_entity_id, subject = NameID)`
//!    anchor.
//! 3. Insert the `user_org_memberships` row with `joined_via = 'saml'`
//!    + `jit_provisioned_at = now()`.
//!
//! All three steps share the same transaction so a crash midway rolls
//! everything back. The SAML service caller wraps the JIT call inside
//! the same transaction that performs the `saml_assertion_replay`
//! INSERT and the `saml_pending_auth` mark-used so the entire ACS path
//! commits atomically or rolls back atomically.

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::domain::{FederatedIdentity, User};
use crate::error::IdentityError;
use crate::repo::{
    FederatedIdentityRepo, MembershipRepo, NewFederatedIdentity, NewMembership, NewUser, UserRepo,
};

use super::errors::SamlError;

/// SAML protocol value persisted on the federated-identity anchor.
/// Mirrors the OIDC anchor's `protocol = "oidc"` constant.
pub const PROTOCOL: &str = "saml";

/// Membership join provenance used by the SAML JIT path.
pub const JOINED_VIA: &str = "saml";

/// SAML JIT input bundle.
#[derive(Debug, Clone)]
pub struct SamlJitInput {
    /// Org the SSO sign-in joins. Resolved upstream from `org_idps`.
    pub org_id: Uuid,
    /// IdP id (the `(protocol, iss, sub)` anchor's owning IdP).
    pub org_idp_id: Uuid,
    /// IdP entity id (canonical SSO anchor `iss` field — this is
    /// `Issuer/@Value` from the validated assertion, pinned against
    /// the IdP's stored `idp_entity_id`).
    pub issuer: String,
    /// `Subject/NameID/@Value` from the validated assertion. The
    /// canonical SSO anchor `sub` field.
    pub subject: String,
    /// Display-case email lifted from the assertion attribute set.
    pub email: String,
    /// Email value handed to the in-tx collision pre-flight read. The
    /// caller passes the display-case value verbatim; the underlying
    /// `find_by_email_lower_in_tx` query canonicalises both sides via
    /// Postgres `lower($1)`. Leaving canonicalisation server-side
    /// avoids a Rust `to_lowercase` vs Postgres `lower()` divergence
    /// on Turkish dotless-i, German ß, Cyrillic, etc.
    pub email_lower: String,
    /// Display name lifted from the assertion (given_name + family_name
    /// fallback chain — see [`super::attribute::MappedAttributes::display_name`]).
    pub display_name: String,
    /// Whether the per-IdP `trust_email_assertion` toggle is on.
    pub trust_email_assertion: bool,
    /// Membership role to assign on JIT (default `"member"`; the SAML
    /// config's `default_role` field carries the override).
    pub default_role: String,
}

/// SAML JIT provisioner. Cheap to clone — all repo handles wrap a
/// `PgPool` clone.
#[derive(Clone)]
pub struct SamlJitProvisioner {
    users: UserRepo,
    federated: FederatedIdentityRepo,
    memberships: MembershipRepo,
}

impl SamlJitProvisioner {
    /// Wire dependencies.
    #[must_use]
    pub const fn new(
        users: UserRepo,
        federated: FederatedIdentityRepo,
        memberships: MembershipRepo,
    ) -> Self {
        Self {
            users,
            federated,
            memberships,
        }
    }

    /// Borrow the underlying federated-identity repo. The SAML service
    /// uses this to look up the SSO anchor + update `last_login_at`
    /// without re-wrapping the repo in a separate composition root.
    #[must_use]
    pub const fn federated_repo(&self) -> &FederatedIdentityRepo {
        &self.federated
    }

    /// Borrow the underlying user repo for in-tx existence checks the
    /// orchestrator runs on the anchor-hit path.
    #[must_use]
    pub const fn user_repo(&self) -> &UserRepo {
        &self.users
    }

    /// Borrow the membership repo for in-tx existence checks on the
    /// anchor-hit path.
    #[must_use]
    pub const fn membership_repo(&self) -> &MembershipRepo {
        &self.memberships
    }

    /// Tx-scoped email lookup used by the JIT collision check.
    pub async fn find_user_by_email_lower_in_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        email_lower: &str,
    ) -> Result<Option<crate::domain::User>, SamlError> {
        self.users
            .find_by_email_lower_in_tx(tx, email_lower)
            .await
            .map_err(|err| map_repo_error(&err))
    }

    /// Update `last_login_at` on the federated-identity anchor inside
    /// the caller-supplied transaction.
    pub async fn federated_update_last_login_in_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        anchor_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<(), SamlError> {
        self.federated
            .update_last_login_at_in_tx(tx, anchor_id, now)
            .await
            .map_err(|err| map_repo_error(&err))
    }

    /// Run the JIT path inside `tx`. Returns the (user, anchor) pair
    /// on success.
    ///
    /// # Errors
    ///
    /// - [`SamlError::EmailNotTrusted`] when `trust_email_assertion`
    ///   is `false`.
    /// - [`SamlError::AccountAlreadyExists`] when a live user already
    ///   exists for `email_lower`.
    /// - [`SamlError::Internal`] for any database error from the
    ///   underlying repos.
    #[tracing::instrument(
        skip_all,
        fields(
            org_id = %input.org_id,
            org_idp_id = %input.org_idp_id,
            route = "saml.jit",
        )
    )]
    pub async fn run(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        input: SamlJitInput,
        now: DateTime<Utc>,
    ) -> Result<SamlJitOutcome, SamlError> {
        if !input.trust_email_assertion {
            return Err(SamlError::EmailNotTrusted);
        }

        // Email collision: an existing live row with the same
        // `email_lower` blocks JIT. Read against the in-flight
        // transaction so we observe any uncommitted insert from a
        // concurrent JIT path. READ COMMITTED still permits a race
        // with a tx that commits between our read and our write; the
        // `EmailAlreadyExists` remap on the `create_in_tx` path below
        // handles that residue.
        if self
            .users
            .find_by_email_lower_in_tx(tx, &input.email_lower)
            .await
            .map_err(|err| map_repo_error(&err))?
            .is_some()
        {
            return Err(SamlError::AccountAlreadyExists);
        }

        let user_id = Uuid::now_v7();
        let user = self
            .users
            .create_in_tx(
                tx,
                NewUser {
                    id: user_id,
                    email: &input.email,
                    display_name: &input.display_name,
                    password_hash: None,
                    password_updated_at: None,
                    // `0` flags an SSO-only account. Password-auth flows
                    // bump to the live argon2 profile version when (and
                    // if) the user later sets a password.
                    password_hash_version: 0,
                    external_id: None,
                },
            )
            .await
            .map_err(|err| match err {
                IdentityError::EmailAlreadyExists => SamlError::AccountAlreadyExists,
                other => map_repo_error(&other),
            })?;

        let anchor = self
            .federated
            .create_in_tx(
                tx,
                NewFederatedIdentity {
                    id: Uuid::now_v7(),
                    protocol: PROTOCOL,
                    issuer_or_entity_id: &input.issuer,
                    subject_or_nameid: &input.subject,
                    org_idp_id: input.org_idp_id,
                    user_id: Some(user_id),
                    last_login_at: Some(now),
                },
            )
            .await
            .map_err(|err| map_repo_error(&err))?;

        let _ = self
            .memberships
            .create_in_tx(
                tx,
                NewMembership {
                    id: Uuid::now_v7(),
                    user_id,
                    org_id: input.org_id,
                    basic_role: &input.default_role,
                    joined_via: JOINED_VIA,
                    jit_provisioned_at: Some(now),
                },
            )
            .await
            .map_err(|err| map_repo_error(&err))?;

        Ok(SamlJitOutcome { user, anchor })
    }
}

/// Map a repo-layer [`IdentityError`] onto the SAML error surface.
/// Every database fault collapses to [`SamlError::Internal`]; the
/// caller emits the underlying chain via `tracing::warn!` so the
/// audit dashboard still has the diagnostic.
fn map_repo_error(err: &IdentityError) -> SamlError {
    tracing::warn!(target: "zagrosi.identity.saml", error = %err, "saml jit: repo error");
    SamlError::Internal
}

/// SAML JIT result. The SAML service uses both the freshly minted
/// user and the federated-identity anchor when issuing the session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SamlJitOutcome {
    /// Newly minted user row.
    pub user: User,
    /// SSO anchor that links the user to `(protocol, iss, sub)`.
    pub anchor: FederatedIdentity,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn input_builder_compiles() {
        // Compile-coverage assertion. The full integration tests
        // exercise the actual `run` path against a live Postgres.
        let _ = SamlJitInput {
            org_id: Uuid::now_v7(),
            org_idp_id: Uuid::now_v7(),
            issuer: "https://idp.example.com".into(),
            subject: "alice@idp".into(),
            email: "Alice@Example.com".into(),
            email_lower: "alice@example.com".into(),
            display_name: "Alice".into(),
            trust_email_assertion: true,
            default_role: "member".into(),
        };
    }
}
