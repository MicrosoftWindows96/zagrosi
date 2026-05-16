// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! Session-issuance + introspection + lifecycle.
//!
//! The submodules ship the gateway-facing fast path consumed by the
//! api-gateway middleware plus the in-process state the auth flows
//! (password sign-in, OIDC callback, SAML ACS) emit when a fresh
//! session is minted.
//!
//! - [`port`]: small `SessionIssuer` trait the auth flows call to
//!   issue a session without depending on the heavy
//!   [`introspector`] composition.
//! - [`issuer`]: concrete [`issuer::IdentitySessionIssuer`] that
//!   mints `sid_*` tokens via the canonical token-format chokepoint
//!   and inserts the `sessions` row through [`crate::repo::SessionRepo`].
//! - [`cookie`]: builds the `__Host-zagrosi_sid` + `__Host-zagrosi_csrf`
//!   browser cookies for the response shaping path.
//! - [`continuation`]: wraps issued sessions in
//!   [`zagrosi_core::AuthContinuation`] so future MFA factors can
//!   land without breaking the API shape.
//! - [`cache`]: in-process LRU + reverse-lookup index used by the
//!   introspector fast path.
//! - [`introspector`]: concrete [`introspector::IdentitySessionIntrospector`]
//!   implementation of [`zagrosi_core::SessionIntrospector`].
//! - [`revoke`]: explicit + bulk revocation paths plus NATS
//!   publishing for cross-replica eviction.
//! - [`switch_org`]: optimistic-lock active-org switch.
//! - [`events`]: NATS-backed cross-replica eviction bus shared by
//!   `revoke` and `switch_org`.
//! - [`write_behind`]: bounded mpsc channel for best-effort
//!   `last_seen_at` updates.

pub mod cache;
pub mod continuation;
pub mod cookie;
pub mod events;
pub mod introspector;
pub mod issuer;
pub mod port;
pub mod revoke;
pub mod switch_org;
pub mod write_behind;

pub use cache::{CachedSession, SessionCache};
pub use continuation::SessionView;
pub use cookie::{CSRF_COOKIE_NAME, CSRF_HEADER_NAME, SESSION_COOKIE_NAME, SessionAttachment};
pub use events::{BusError, SessionEventBus};
pub use introspector::IdentitySessionIntrospector;
pub use issuer::{IdentitySessionIssuer, generate_csrf_value};
pub use port::{IssuedSession, SessionIssuer};
pub use revoke::{
    REVOKE_SUBJECT_PREFIX, REVOKE_USER_SUBJECT_PREFIX, SessionRevokedEvent, SessionRevoker,
    UserSessionsRevokedEvent,
};
pub use switch_org::{
    SESSION_UPDATED_SUBJECT_PREFIX, SessionOrgSwitcher, SessionUpdatedEvent, SwitchError,
    SwitchOutcome,
};
pub use write_behind::{
    LastSeenReceiver, LastSeenSender, UpdateLastSeen, channel as last_seen_channel,
};
