// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! Tenant-isolation invariant: the [`OrgScoped`] wrapper.
//!
//! Every multi-tenant SQL query in the identity surface is anchored
//! on `WHERE org_id = $1`. The wrapper carries the `org_id` and is
//! the only path through which a multi-tenant repo method may be
//! called: every multi-tenant repo `impl` block exists as
//! `impl<'a> OrgScoped<'a, R>` rather than `impl R`. Constructing
//! the wrapper requires a non-nil `org_id` (asserted at runtime in
//! [`OrgScoped::new`]); `Default` is intentionally not implemented
//! so accidental zero-value construction is impossible.
//!
//! Cross-org probing is rejected at the storage layer: a query
//! anchored on org B never returns a row owned by org A even if the
//! `(token_hash, org_id)` lookup is satisfied by org A's row,
//! because `WHERE org_id = $org_b AND token_hash = $h` filters out
//! org A's row before the partial unique index resolves it. This
//! matches the project-wide invariant that cross-tenant probes
//! return `404 Not Found`, never `403 Forbidden`.

use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::error::Result;

/// Pool access for the tenant-transaction helper. Every repo whose
/// multi-tenant surface lives on `OrgScoped<R>` implements this so
/// [`OrgScoped::begin_org_tx`] can open RLS-ready transactions.
pub(crate) trait HasPool {
    /// Borrow the repo's connection pool.
    fn pool(&self) -> &PgPool;
}

/// Tenant-bound view over a repo. See module docs.
///
/// Construction takes a non-nil `org_id` and a borrowed reference to
/// the wrapped repo. The lifetime parameter `'a` ties the wrapper to
/// the repo's borrow so callers cannot accidentally outlive the
/// underlying connection pool.
#[derive(Debug, Clone, Copy)]
pub struct OrgScoped<'a, R> {
    inner: &'a R,
    org_id: Uuid,
}

impl<'a, R> OrgScoped<'a, R> {
    /// Construct a wrapper bound to `org_id`. Panics if `org_id`
    /// is the nil UUID — that value is reserved as a sentinel and
    /// MUST NOT reach a tenant-isolated query.
    ///
    /// # Panics
    ///
    /// Panics with the message
    /// `"org_id must not be nil — tenant-isolation invariant"` when
    /// `org_id == Uuid::nil()`. The panic is intentional: a nil
    /// `org_id` reaching this function is a programmer error that
    /// would otherwise expose every tenant's rows to a query whose
    /// caller did not establish tenancy.
    #[must_use]
    pub fn new(inner: &'a R, org_id: Uuid) -> Self {
        assert!(
            !org_id.is_nil(),
            "org_id must not be nil — tenant-isolation invariant"
        );
        Self { inner, org_id }
    }

    /// Borrow the bound `org_id`.
    #[must_use]
    pub const fn org_id(&self) -> Uuid {
        self.org_id
    }

    /// Borrow the wrapped repo.
    #[must_use]
    pub const fn inner(&self) -> &'a R {
        self.inner
    }
}

impl<R> OrgScoped<'_, R> {
    /// Begin a transaction with the `app.org_id` GUC set to this
    /// wrapper's org. Every `OrgScoped` query runs through this so the
    /// RLS policies (identity migration 025) see tenant context — a
    /// pool-direct query would fail closed to zero rows.
    pub(crate) async fn begin_org_tx(&self) -> Result<Transaction<'static, Postgres>>
    where
        R: HasPool + Sync,
    {
        let mut tx = self.inner.pool().begin().await?;
        super::with_org_context(&mut tx, self.org_id).await?;
        Ok(tx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use static_assertions::assert_impl_all;

    #[derive(Copy, Clone)]
    struct DummyRepo;

    assert_impl_all!(OrgScoped<'static, DummyRepo>: Send, Sync, Copy);

    #[test]
    fn round_trips_org_id() {
        let repo = DummyRepo;
        let id = Uuid::now_v7();
        let scoped = OrgScoped::new(&repo, id);
        assert_eq!(scoped.org_id(), id);
    }

    #[test]
    #[should_panic(expected = "org_id must not be nil")]
    fn rejects_nil_org_id() {
        let repo = DummyRepo;
        let _ = OrgScoped::new(&repo, Uuid::nil());
    }
}
