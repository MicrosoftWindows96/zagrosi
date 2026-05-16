// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! Federated-identity tombstone enforcement helper.
//!
//! When a user is soft-deleted the cascade in
//! [`crate::repo::cascade::soft_delete_user`] flips every
//! `federated_identities` row owned by the user to
//! `user_id IS NULL` while leaving the unique
//! `(protocol, iss, sub)` slot occupied. The tombstone blocks
//! silent re-attachment of the same SSO anchor to a fresh user
//! without an explicit admin merge.
//!
//! The OIDC + SAML callback paths consume this helper to gate the
//! sign-in decision. Today the enforcement is also baked into
//! [`crate::repo::FederatedIdentityRepo::create_in_tx`] (which
//! raises [`crate::error::IdentityError::FederatedIdentityTombstoned`]
//! on conflict). Centralising the rule here means the lookup
//! pre-screens the callback with a single source of truth so
//! future audit-payload enrichment does not have to chase two
//! call-sites.

use uuid::Uuid;

use crate::error::Result;
use crate::repo::FederatedIdentityRepo;

/// Outcome of a tombstone-aware federated-identity lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FederatedLookup {
    /// No row exists for the `(protocol, iss, sub)` triple. The
    /// caller proceeds with JIT user creation (subject to the
    /// JIT-provisioning policy on the resolved IdP).
    Miss,
    /// A live anchor exists. The caller loads the named user and
    /// signs them in.
    Linked(Uuid),
    /// A tombstone exists (the slot is occupied with
    /// `user_id IS NULL`). The caller MUST reject the sign-in via
    /// [`crate::error::IdentityError::FederatedIdentityTombstoned`]
    /// and prompt the admin merge flow.
    Tombstoned,
}

/// Look up a federated-identity anchor with tombstone awareness.
///
/// Returns one of three outcomes — [`FederatedLookup::Miss`],
/// [`FederatedLookup::Linked`], or [`FederatedLookup::Tombstoned`].
/// The OIDC and SAML callback orchestrators map each onto the
/// appropriate downstream action.
///
/// # Errors
///
/// Propagates [`crate::error::IdentityError::Database`] from the
/// underlying repo lookup. Does not perform the tombstone-rejection
/// itself — that is the caller's responsibility (so audit emission
/// can include the resolved IdP context).
pub async fn lookup_federated_identity(
    repo: &FederatedIdentityRepo,
    protocol: &str,
    issuer_or_entity_id: &str,
    subject_or_nameid: &str,
) -> Result<FederatedLookup> {
    let row = repo
        .find_by_protocol_iss_sub(protocol, issuer_or_entity_id, subject_or_nameid)
        .await?;
    let Some(record) = row else {
        return Ok(FederatedLookup::Miss);
    };
    Ok(record
        .user_id
        .map_or(FederatedLookup::Tombstoned, FederatedLookup::Linked))
}

#[cfg(test)]
mod tests {
    use super::*;
    use static_assertions::assert_impl_all;

    assert_impl_all!(FederatedLookup: Send, Sync, Copy, PartialEq);

    #[test]
    fn lookup_variants_are_exhaustive() {
        // Drive the exhaustiveness check via match — adding a new
        // variant later breaks this test until the contributor
        // updates downstream callers.
        for v in [
            FederatedLookup::Miss,
            FederatedLookup::Linked(Uuid::nil()),
            FederatedLookup::Tombstoned,
        ] {
            match v {
                FederatedLookup::Miss
                | FederatedLookup::Linked(_)
                | FederatedLookup::Tombstoned => {}
            }
        }
    }
}
