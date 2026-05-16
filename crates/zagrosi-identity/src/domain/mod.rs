// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure domain types for the identity crate.
//!
//! Every type in this module is a value object: no `sqlx::FromRow`
//! derive, no axum extractors, no behaviour beyond the pure `Eq` /
//! `Clone` derives. Conversion to / from database rows lives in the
//! [`crate::repo`] layer; conversion to / from HTTP wire formats lives
//! in the route handlers (later sections). Keeping the boundary sharp
//! lets unit tests exercise these types without touching the database
//! or the network.
//!
//! `Send + Sync + 'static` is satisfied by every domain type because
//! every field is an owned scalar / `String` / `Vec<String>` / numeric
//! primitive. The assertions at the foot of this file freeze that
//! invariant — adding a non-`Send` field to any of these types will
//! break the build.

pub mod api_token;
pub mod federated;
pub mod group;
pub mod membership;
pub mod oidc_pending;
pub mod oidc_refresh;
pub mod org;
pub mod org_idp;
pub mod org_idp_domain;
pub mod saml_pending;
pub mod saml_replay;
pub mod scim_resource;
pub mod service_token;
pub mod session;
pub mod token_format;
pub mod user;

pub use api_token::ApiToken;
pub use federated::FederatedIdentity;
pub use group::{Group, GroupMembership};
pub use membership::Membership;
pub use oidc_pending::OidcPendingAuth;
pub use oidc_refresh::OidcRefreshToken;
pub use org::Org;
pub use org_idp::OrgIdp;
pub use org_idp_domain::{DomainRouteHit, OrgIdpDomain};
pub use saml_pending::SamlPendingAuth;
pub use saml_replay::SamlAssertionRecord;
pub use scim_resource::ScimResource;
pub use service_token::ServiceToken;
pub use session::Session;
pub use token_format::{
    HASH_LEN, TOKEN_BODY_LEN, TokenHash, TokenPrefix, hash_token, mint, parse_raw,
};
pub use user::User;

#[cfg(test)]
mod send_sync_assertions {
    use super::*;
    use static_assertions::assert_impl_all;

    // Every domain aggregate must be `Send + Sync + 'static` so it can
    // round-trip across tokio task boundaries (HTTP handlers, NATS
    // workers, SCIM batches). `'static` is implied by all fields being
    // owned (no borrowed slices).
    assert_impl_all!(User: Send, Sync);
    assert_impl_all!(Org: Send, Sync);
    assert_impl_all!(Membership: Send, Sync);
    assert_impl_all!(Session: Send, Sync);
    assert_impl_all!(ApiToken: Send, Sync);
    assert_impl_all!(OrgIdp: Send, Sync);
    assert_impl_all!(OrgIdpDomain: Send, Sync);
    assert_impl_all!(DomainRouteHit: Send, Sync);
    assert_impl_all!(FederatedIdentity: Send, Sync);
    assert_impl_all!(OidcPendingAuth: Send, Sync);
    assert_impl_all!(OidcRefreshToken: Send, Sync);
    assert_impl_all!(SamlPendingAuth: Send, Sync);
    assert_impl_all!(SamlAssertionRecord: Send, Sync);
    assert_impl_all!(ScimResource: Send, Sync);
    assert_impl_all!(ServiceToken: Send, Sync);
    assert_impl_all!(Group: Send, Sync);
    assert_impl_all!(GroupMembership: Send, Sync);
}
