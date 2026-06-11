// SPDX-License-Identifier: AGPL-3.0-or-later

//! Crate error type.

use uuid::Uuid;

/// Errors produced by the rbac persistence layer.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The referenced row does not exist in the caller's org. Under RLS
    /// a foreign org's row is indistinguishable from an absent one —
    /// cross-tenant probes surface here, never as a permission error.
    #[error("rbac row {id} not found in this org")]
    NotFound {
        /// Id the caller asked for.
        id: Uuid,
    },
    /// The org has no live root node / version row — a provisioning
    /// invariant violation (the org-root trigger and backfill guarantee
    /// both exist for every live org).
    #[error("org root or version row missing for the current org")]
    OrgRootMissing,
    /// Caller attempted to create or tombstone an org-root node through
    /// the repo. Roots come only from the provisioning trigger /
    /// backfill, and org teardown goes through `soft_delete_org_cascade`
    /// — never the single-node primitives.
    #[error(
        "org-root nodes are trigger-provisioned and immutable through the repo; \
         use soft_delete_org_cascade for org teardown"
    )]
    OrgRootMutationRejected,
    /// A stored string column did not parse into its domain enum
    /// (fail-closed: corrupted rows error, they never coerce).
    #[error("stored {column} value `{value}` is not a known {column}")]
    InvalidStoredValue {
        /// Column the value came from.
        column: &'static str,
        /// Offending stored value.
        value: String,
    },
    /// Underlying database failure.
    #[error("database error: {0}")]
    Sqlx(#[from] sqlx::Error),
}

/// Crate-wide result alias.
pub type Result<T, E = Error> = std::result::Result<T, E>;
