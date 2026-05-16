// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! JIT (just-in-time) user provisioning for OIDC sign-in.
//!
//! ## Trust gate
//!
//! `id_token.email_verified == true` is the JIT precondition unless
//! the per-IdP override `allow_unverified_email_jit` is `true`. A
//! misconfigured or rogue IdP can otherwise assert any email claim.
//!
//! ## Cross-org email collision
//!
//! Email is **not** an SSO key (project-wide invariant — see
//! `documentation/identity.md`). When the ID token's `email_lower` already
//! matches a live `users` row, we refuse to auto-merge and surface
//! [`IdentityError::OidcAccountAlreadyExists`] so the SPA can hand
//! off to the admin-merge flow (deferred to the admin layer).
//!
//! ## Atomic JIT transaction
//!
//! The JIT path runs entirely inside the caller's transaction:
//!
//! 1. Insert the `users` row (`password_hash = NULL`,
//!    `email_verified_at` populated when the gate passed).
//! 2. Insert the `federated_identities` row with the canonical
//!    `(protocol, iss, sub)` anchor.
//! 3. Insert the `user_org_memberships` row with `joined_via = 'oidc'`
//!    + `jit_provisioned_at = now()`.
//! 4. Mark the `oidc_pending_auth` row consumed (called by the
//!    OIDC service after the JIT step returns).
//!
//! All four steps share the same transaction so a crash midway rolls
//! everything back. Future RLS in the tenant-isolation layer relies on
//! [`crate::repo::with_org_context`] being set on the same `tx`; the
//! OIDC service sets it before calling [`JitProvisioner::run`].

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::domain::{FederatedIdentity, User};
use crate::error::{IdentityError, Result};
use crate::repo::{
    FederatedIdentityRepo, MembershipRepo, NewFederatedIdentity, NewMembership, NewUser, UserRepo,
};

/// OIDC JIT input bundle.
#[derive(Debug, Clone)]
pub struct JitInput {
    /// Org the SSO sign-in joins. Resolved upstream from `org_idps`.
    pub org_id: Uuid,
    /// IdP id (the `(protocol, iss, sub)` anchor's owning IdP).
    pub org_idp_id: Uuid,
    /// IdP `iss` claim (canonical SSO anchor field).
    pub issuer: String,
    /// IdP `sub` claim (canonical SSO anchor field).
    pub subject: String,
    /// Display-case email from the ID token.
    pub email: String,
    /// Email value handed to the in-tx collision pre-flight read. The
    /// caller passes a display-case value verbatim; the underlying
    /// `find_by_email_lower_in_tx` query canonicalises both sides via
    /// Postgres `lower($1)`. Leaving the canonicalisation server-side
    /// avoids a Rust `to_lowercase` vs Postgres `lower()` divergence
    /// on Turkish dotless-i, German ß, Cyrillic, etc.
    pub email_lower: String,
    /// Display name from the ID token (`name` claim or fallback).
    pub display_name: String,
    /// `id_token.email_verified` claim. `false` requires the per-IdP
    /// override (see [`JitInput::allow_unverified`]).
    pub email_verified: bool,
    /// Whether the per-IdP override permits unverified-email JIT.
    pub allow_unverified: bool,
    /// Membership role to assign on JIT (default `"member"` when
    /// `org_idps.config.default_role` is `None`).
    pub default_role: String,
}

/// JIT provisioner. Cheap to clone — all repo handles wrap a
/// `PgPool` clone.
#[derive(Clone)]
pub struct JitProvisioner {
    users: UserRepo,
    federated: FederatedIdentityRepo,
    memberships: MembershipRepo,
}

impl JitProvisioner {
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

    /// Borrow the underlying federated-identity repo. The OIDC service
    /// uses this to look up the SSO anchor + update `last_login_at`
    /// without re-wrapping the repo in a separate composition root.
    #[must_use]
    pub const fn federated_repo(&self) -> &FederatedIdentityRepo {
        &self.federated
    }

    /// Tx-scoped email lookup used by the JIT collision check. The
    /// helper sits on the JIT provisioner so the orchestrator does not
    /// need direct access to `UserRepo` for the in-tx variant.
    pub async fn find_user_by_email_lower_in_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        email_lower: &str,
    ) -> Result<Option<crate::domain::User>> {
        self.users.find_by_email_lower_in_tx(tx, email_lower).await
    }

    /// Run the JIT path inside `tx`. Returns the (user, anchor)
    /// pair on success.
    ///
    /// # Errors
    ///
    /// - [`IdentityError::OidcEmailNotVerified`] when
    ///   `email_verified == false && allow_unverified == false`.
    /// - [`IdentityError::OidcAccountAlreadyExists`] when a live user
    ///   already exists for `email_lower`. The lookup runs **before**
    ///   the user insert against the in-flight transaction so a
    ///   concurrent JIT cannot land between the read and the write.
    ///   If the unique partial index `users_email_lower_unique_live`
    ///   still surfaces the conflict (the lookup races against an
    ///   uncommitted insert in another tx, then that tx commits before
    ///   ours), the typed `EmailAlreadyExists` from the in-tx insert
    ///   is remapped to `OidcAccountAlreadyExists` here so the OIDC
    ///   public surface stays consistent.
    /// - Any database error from the underlying repos.
    #[tracing::instrument(
        skip_all,
        fields(
            org_id = %input.org_id,
            org_idp_id = %input.org_idp_id,
            route = "oidc.jit",
        )
    )]
    pub async fn run(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        input: JitInput,
        now: DateTime<Utc>,
    ) -> Result<JitOutcome> {
        if !input.email_verified && !input.allow_unverified {
            return Err(IdentityError::OidcEmailNotVerified);
        }

        // Email collision: an existing live row with the same
        // `email_lower` blocks JIT. Read against the in-flight
        // transaction so we observe any uncommitted insert from a
        // concurrent JIT path (READ COMMITTED still permits a race
        // with a tx that commits between our read and our write; the
        // remap on the create_in_tx path below handles that residue).
        if self
            .find_user_by_email_lower_in_tx(tx, &input.email_lower)
            .await?
            .is_some()
        {
            return Err(IdentityError::OidcAccountAlreadyExists);
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
                IdentityError::EmailAlreadyExists => IdentityError::OidcAccountAlreadyExists,
                other => other,
            })?;

        if input.email_verified {
            self.users
                .mark_email_verified_in_tx(tx, user_id, now)
                .await?;
        }

        let anchor = self
            .federated
            .create_in_tx(
                tx,
                NewFederatedIdentity {
                    id: Uuid::now_v7(),
                    protocol: "oidc",
                    issuer_or_entity_id: &input.issuer,
                    subject_or_nameid: &input.subject,
                    org_idp_id: input.org_idp_id,
                    user_id: Some(user_id),
                    last_login_at: Some(now),
                },
            )
            .await?;

        let _ = self
            .memberships
            .create_in_tx(
                tx,
                NewMembership {
                    id: Uuid::now_v7(),
                    user_id,
                    org_id: input.org_id,
                    basic_role: &input.default_role,
                    joined_via: "oidc",
                    jit_provisioned_at: Some(now),
                },
            )
            .await?;

        Ok(JitOutcome { user, anchor })
    }
}

/// JIT result. The OIDC service uses both the freshly minted user and
/// the federated-identity anchor when issuing the session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JitOutcome {
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
        let _ = JitInput {
            org_id: Uuid::now_v7(),
            org_idp_id: Uuid::now_v7(),
            issuer: "https://idp.example.com".into(),
            subject: "sub-123".into(),
            email: "Alice@Example.com".into(),
            email_lower: "alice@example.com".into(),
            display_name: "Alice".into(),
            email_verified: true,
            allow_unverified: false,
            default_role: "member".into(),
        };
    }
}
