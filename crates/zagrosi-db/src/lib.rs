// SPDX-License-Identifier: AGPL-3.0-or-later

//! Tenancy plumbing for the Zagrosi platform.
//!
//! This crate is the one shared home for the Postgres row-level-security
//! (RLS) transaction context: [`TenantTx`] (a transaction that provably
//! carries tenant context), the GUC constants the RLS policies read
//! ([`GUC_ORG_ID`], [`GUC_USER_ID`]), and the role-pool builders for the
//! four runtime DSNs ([`connect_role_pool`]).
//!
//! The crate is deliberately tiny: `[dependencies]` is **sqlx + uuid
//! only**. It never links `zagrosi-core` (which must stay sqlx-free), and
//! it reads no environment or configuration — the [`ENV_DATABASE_URL`]
//! family is exported as *names only*; resolution and fallback policy
//! live with consumers.
//!
//! # Non-negotiables
//!
//! - **GUCs are only ever set transaction-locally** via
//!   `set_config(name, value, /* is_local = */ true)`. Session-scoped
//!   `SET` is forbidden: a session-scoped GUC outlives its transaction on
//!   a pooled connection and leaks tenant context to the next acquirer.
//! - **Any future role switching is `SET LOCAL ROLE` only** — never
//!   session-scoped `SET ROLE`. Together these two rules make the
//!   `RESET ALL`-on-release hook attached by [`connect_role_pool`]
//!   *defense-in-depth* rather than a correctness requirement.
//!
//! # Fail-closed contract
//!
//! The RLS policies (section-05) compare every tenanted row against
//! `(SELECT NULLIF(current_setting('app.org_id', true), '')::uuid)`. A
//! missing or empty GUC yields `NULL`, which matches nothing — so a
//! query that runs outside a [`TenantTx`] sees zero tenanted rows rather
//! than all of them.

pub mod error;
pub mod pool;
pub mod tenant_tx;

pub use error::Error;
pub use pool::{
    ENV_DATABASE_AUTH_URL, ENV_DATABASE_MAINTENANCE_URL, ENV_DATABASE_MIGRATE_URL,
    ENV_DATABASE_URL, connect_role_pool, connect_role_pool_with,
};
pub use tenant_tx::{TenantTx, begin_tenant_tx, begin_tenant_tx_as_user};

/// Transaction-scoped GUC the RLS policies compare `org_id` against.
pub const GUC_ORG_ID: &str = "app.org_id";

/// Transaction-scoped GUC backing the org-or-self SELECT arm on
/// `user_org_memberships` (SELECT only, never writes — a forged user id
/// must never authorize a cross-org write).
pub const GUC_USER_ID: &str = "app.user_id";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guc_constants_are_locked() {
        // Section-05's policy generator hardcodes the same names in SQL;
        // this is the cross-crate drift guard on the Rust side.
        assert_eq!(GUC_ORG_ID, "app.org_id");
        assert_eq!(GUC_USER_ID, "app.user_id");
    }
}
