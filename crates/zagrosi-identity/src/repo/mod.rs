// SPDX-License-Identifier: AGPL-3.0-or-later

//! Repository layer for the identity crate.
//!
//! Every type in this module wraps a `sqlx::PgPool` (or accepts a
//! borrowed [`sqlx::Transaction`] for in-txn methods) and is the
//! **only** path through which the identity crate touches the
//! database. The wider identity surface (services, HTTP routes,
//! workers) consumes domain types from [`crate::domain`]; the repo
//! layer is the boundary where rows become aggregates.
//!
//! ## Tenant isolation
//!
//! Multi-tenant repos (`SessionRepo`, `ApiTokenRepo`, `OrgIdpRepo`,
//! `FederatedIdentityRepo`, `OidcPendingRepo`, `SamlReplayRepo`,
//! `ScimResourceRepo`) live as `impl<'a> OrgScoped<'a, R>`.
//! Constructing the wrapper requires a non-nil `org_id` (see
//! [`org_scoped::OrgScoped::new`]); the wrapped methods bind that
//! `org_id` into every multi-tenant query. Single-tenant repos
//! (`UserRepo`, `OrgRepo`, `MembershipRepo`, `ServiceTokenRepo`) are
//! used directly without the wrapper because their tables either
//! lack an `org_id` column or model the cross-org join itself.
//!
//! ## Soft-delete cascade
//!
//! Postgres `FK CASCADE` is incompatible with soft-delete (the parent
//! row stays present with `deleted_at IS NOT NULL`). Cascade is
//! enforced in the application layer via [`cascade`] helpers, all of
//! which run inside a caller-supplied transaction.
//!
//! ## Tenant-isolation GUCs
//!
//! [`with_org_context`] sets the `app.org_id` GUC for the duration of
//! a transaction; the tenant-isolation layer's RLS policies
//! (section-05) compare every tenanted row against it.
//! [`with_user_context`] sets `app.user_id`, backing the org-or-self
//! SELECT arm on `user_org_memberships`. Both are transaction-scoped
//! (`set_config(..., true)`); session-scoped `SET` is forbidden.

pub mod cascade;
pub mod org_scoped;
pub mod user_repo;

pub use cascade::{soft_delete_org, soft_delete_user};
pub use org_scoped::OrgScoped;
pub use user_repo::{NewUser, UserRepo, user_from_row};

// Forthcoming repo re-exports (added as each repo module lands).
pub use api_token_repo::{ApiTokenRepo, NewApiToken};
pub use email_verification_repo::{EmailVerificationRepo, EmailVerificationRow};
pub use failed_signin_repo::{FailedSigninRepo, FailedSigninUpsert};
pub use federated_repo::{FederatedIdentityRepo, NewFederatedIdentity};
pub use group_repo::{GroupRepo, NewGroup, group_from_row};
pub use membership_repo::{MembershipRepo, NewMembership};
pub use oidc_pending_repo::{NewOidcPending, OidcPendingRepo};
pub use oidc_refresh_repo::{NewOidcRefresh, OidcRefreshRepo};
pub use org_idp_domain_repo::{NewOrgIdpDomain, OrgIdpDomainRepo};
pub use org_idp_repo::{NewOrgIdp, OrgIdpRepo};
pub use org_repo::{NewOrg, OrgRepo};
pub use password_reset_repo::{PasswordResetRepo, PasswordResetRow};
pub use saml_pending_repo::{NewSamlPending, SamlPendingRepo};
pub use saml_replay_repo::{NewSamlAssertion, SamlReplayRepo};
pub use scim_resource_repo::{NewScimResource, ScimResourceRepo};
pub use service_token_repo::{NewServiceToken, ServiceTokenRepo};
pub use session_repo::{NewSession, SessionRepo};

pub mod api_token_repo;
pub mod email_verification_repo;
pub mod failed_signin_repo;
pub mod federated_repo;
pub mod group_repo;
pub mod membership_repo;
pub mod oidc_pending_repo;
pub mod oidc_refresh_repo;
pub mod org_idp_domain_repo;
pub mod org_idp_repo;
pub mod org_repo;
pub mod password_reset_repo;
pub mod saml_pending_repo;
pub mod saml_replay_repo;
pub mod scim_resource_repo;
pub mod service_token_repo;
pub mod session_repo;

use sqlx::Postgres;
use uuid::Uuid;

use crate::error::Result;

/// Set the per-transaction `app.org_id` GUC.
///
/// Section-05's RLS policies read this GUC: every multi-tenant query
/// in the identity surface must run inside a transaction that has
/// called this function; the policies refuse rows whose `org_id` does
/// not match the GUC (missing/empty GUC matches nothing — fail
/// closed).
///
/// Implemented via `set_config('app.org_id', $1, true)` so the call
/// composes inside a `query!` invocation without parser quirks
/// (`SET LOCAL` is a top-level statement and cannot be parameterised).
pub async fn with_org_context(
    tx: &mut sqlx::Transaction<'_, Postgres>,
    org_id: Uuid,
) -> Result<()> {
    sqlx::query!(
        "SELECT set_config('app.org_id', $1::text, true)",
        org_id.to_string(),
    )
    .fetch_optional(&mut **tx)
    .await?;
    Ok(())
}

/// Set the per-transaction `app.user_id` GUC.
///
/// Backs the org-or-self SELECT arm on `user_org_memberships` once RLS
/// lands (section-05). SELECT-only by design: the write policies
/// deliberately ignore this GUC (a forged user id must never authorize
/// a cross-org write).
///
/// Like [`with_org_context`], this identity-internal helper does not
/// guard against `Uuid::nil()` — callers hold non-nil invariants
/// upstream (`AuthContext` rejects nil ids at construction). The
/// public `zagrosi-db` API is the layer with typed nil errors; under
/// RLS a nil value matches no row anyway (fail closed).
pub async fn with_user_context(
    tx: &mut sqlx::Transaction<'_, Postgres>,
    user_id: Uuid,
) -> Result<()> {
    sqlx::query!(
        "SELECT set_config('app.user_id', $1::text, true)",
        user_id.to_string(),
    )
    .fetch_optional(&mut **tx)
    .await?;
    Ok(())
}
