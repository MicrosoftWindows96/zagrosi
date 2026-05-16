// SPDX-License-Identifier: AGPL-3.0-or-later

//! Concrete [`zagrosi_core::SessionIntrospector`] implementation.
//!
//! Resolution flow:
//!
//! 1. Validate the raw token's class prefix + body shape via
//!    [`zagrosi_core::RawTokenStr::parse`]. Reject malformed input
//!    before any DB or cache touch.
//! 2. Hash the token (prefix included) via the canonical
//!    [`crate::domain::token_format::hash_token`] chokepoint.
//! 3. Probe the in-process [`SessionCache`] keyed on the hash.
//!    Cache-hit replays the cached `password_updated_at` so a
//!    password-reset that landed after the cache fill rejects on
//!    the next miss; the cache hit itself does not re-read the
//!    user row (the cached `password_updated_at` is already as
//!    fresh as the cache TTL permits).
//! 4. On miss, look up the session row via
//!    [`SessionRepo::find_by_token_hash`] and the matching user row
//!    via [`UserRepo::find_by_id`] in parallel, validate every
//!    invariant, and prime the cache.
//! 5. Map the result onto a fresh [`AuthContext`].
//!
//! Best-effort `last_seen_at` updates are pushed onto the
//! write-behind channel from this module rather than synchronously
//! on the resolve hot path; the drain task issues coalesced
//! `UPDATE` statements.

use async_trait::async_trait;
use chrono::Utc;
use std::sync::Arc;
use uuid::Uuid;
use zagrosi_core::{
    AuthContext, AuthError, AuthMethod, RawTokenStr, SessionIntrospector, TokenClass,
};

use crate::api_tokens::ApiTokenResolver;
use crate::domain::token_format::hash_token;
use crate::repo::{SessionRepo, UserRepo};
use crate::service_tokens::ServiceTokenResolver;
use crate::session::cache::{CachedSession, SessionCache};
use crate::session::write_behind::{LastSeenSender, UpdateLastSeen};

/// Concrete introspector. Cheap to clone — every field is an
/// `Arc`-flavoured handle.
#[derive(Clone)]
pub struct IdentitySessionIntrospector {
    sessions: SessionRepo,
    users: UserRepo,
    cache: SessionCache,
    last_seen: Arc<LastSeenSender>,
    /// Optional PAT branch. When `None`, `pat_*` tokens reject as
    /// `MalformedPrefix` (the section-08-only deployment shape).
    /// When `Some`, the gateway dispatches `pat_*` tokens through
    /// the resolver — added in section-09.
    api_token_resolver: Option<Arc<ApiTokenResolver>>,
    /// Optional service-token branch. `None` → `svc_*` tokens reject
    /// as `MalformedPrefix` (deployments that have not wired the
    /// service-token plumbing). `Some` → `svc_*` dispatches here.
    /// Mirrors the PAT opt-in exactly so no deployment silently
    /// accepts a `svc_*` token through an unconfigured path.
    service_token_resolver: Option<Arc<ServiceTokenResolver>>,
}

impl IdentitySessionIntrospector {
    /// Wire dependencies. The `last_seen` sender is held inside an
    /// `Arc` so the introspector can be cheaply cloned across axum
    /// state without producing a new mpsc producer per clone.
    ///
    /// PAT support is opt-in via [`Self::with_api_token_resolver`];
    /// the bare constructor leaves `pat_*` tokens rejected as
    /// `MalformedPrefix` so a deployment that has not yet wired the
    /// PAT plumbing keeps the section-08 behaviour exactly.
    #[must_use]
    pub fn new(
        sessions: SessionRepo,
        users: UserRepo,
        cache: SessionCache,
        last_seen: LastSeenSender,
    ) -> Self {
        Self {
            sessions,
            users,
            cache,
            last_seen: Arc::new(last_seen),
            api_token_resolver: None,
            service_token_resolver: None,
        }
    }

    /// Attach a personal-access-token resolver so the introspector
    /// dispatches `pat_*` tokens through it.
    #[must_use]
    pub fn with_api_token_resolver(mut self, resolver: Arc<ApiTokenResolver>) -> Self {
        self.api_token_resolver = Some(resolver);
        self
    }

    /// Attach a service-token resolver so the introspector
    /// dispatches `svc_*` tokens through it. Opt-in, mirroring
    /// [`Self::with_api_token_resolver`]: an unconfigured deployment
    /// keeps `svc_*` rejected as `MalformedPrefix`.
    #[must_use]
    pub fn with_service_token_resolver(mut self, resolver: Arc<ServiceTokenResolver>) -> Self {
        self.service_token_resolver = Some(resolver);
        self
    }

    /// Borrow the underlying cache so the NATS subscriber can drive
    /// session-id-keyed evictions.
    #[must_use]
    pub const fn cache(&self) -> &SessionCache {
        &self.cache
    }
}

#[async_trait]
impl SessionIntrospector for IdentitySessionIntrospector {
    async fn resolve(&self, raw_token: &str) -> Result<AuthContext, AuthError> {
        // 1. Prefix + body shape. Rejects pre-cache, pre-DB.
        let parsed = RawTokenStr::parse(raw_token)?;
        // Dispatch by class. The session branch falls through to the
        // existing path below; the PAT branch delegates to the
        // section-09 resolver when wired (otherwise rejects as
        // malformed so an unconfigured deployment cannot accidentally
        // accept a `pat_*` token through the session table).
        match parsed.class() {
            TokenClass::Session => {}
            TokenClass::PersonalAccessToken => {
                return match self.api_token_resolver.as_ref() {
                    Some(r) => r.resolve_with_observation(raw_token, None).await,
                    None => Err(AuthError::MalformedPrefix),
                };
            }
            TokenClass::Service => {
                return match self.service_token_resolver.as_ref() {
                    Some(r) => r.resolve_with_observation(raw_token, None).await,
                    None => Err(AuthError::MalformedPrefix),
                };
            }
            // `Scim` + any future `#[non_exhaustive]` class: rejected
            // here (SCIM bearer auth runs through its own
            // `/scim/v2` middleware, not the session introspector).
            _ => return Err(AuthError::MalformedPrefix),
        }

        // 2. Hash with prefix included.
        let hash = hash_token(raw_token);

        // 3. Cache probe.
        if let Some(entry) = self.cache.get(&hash).await {
            return Self::context_from_cached(&entry).inspect(|ctx| {
                self.fire_last_seen(ctx.session_id());
            });
        }

        // 4. Cache miss: load session row + matching user row.
        let session = self
            .sessions
            .find_by_token_hash(&hash.0)
            .await
            .map_err(AuthError::internal)?
            .ok_or(AuthError::Unauthorized)?;
        let user = self
            .users
            .find_by_id(session.user_id)
            .await
            .map_err(AuthError::internal)?
            .ok_or(AuthError::Unauthorized)?;

        let now = Utc::now();
        if session.expires_at <= now {
            return Err(AuthError::Expired);
        }
        if session.revoked_at.is_some() {
            return Err(AuthError::Revoked);
        }
        if session.deleted_at.is_some() {
            return Err(AuthError::Unauthorized);
        }
        // Password-reset invariant: any session minted before the
        // current `password_updated_at` is implicitly revoked. The
        // user row's `password_updated_at` defaults to `created_at`
        // for sign-ups, so the comparison is well-defined for every
        // live row.
        let password_updated_at = user.password_updated_at;
        if let Some(pwd_updated) = password_updated_at
            && session.created_at < pwd_updated
        {
            return Err(AuthError::Revoked);
        }
        let Some(org_id) = session.org_id else {
            // A session whose active org was never picked still
            // resolves into an `AuthContext`, but the gateway needs
            // a concrete `org_id`. Surface the missing org as
            // `Unauthorized` — the SPA must steer the user through
            // the active-org chooser before issuing org-scoped
            // requests.
            return Err(AuthError::Unauthorized);
        };

        let cached = CachedSession {
            session_id: session.id,
            user_id: session.user_id,
            org_id,
            expires_at: session.expires_at,
            revoked_at: session.revoked_at,
            version: session.version,
            password_updated_at_at_resolve: password_updated_at.unwrap_or(session.created_at),
            amr: session.amr.clone(),
            acr: session.acr.clone(),
            created_at: session.created_at,
        };
        // 5. Prime cache, hydrate context, fire write-behind.
        self.cache.insert(hash, cached.clone()).await;
        let ctx = Self::context_from_cached(&cached)?;
        self.fire_last_seen(ctx.session_id());
        Ok(ctx)
    }
}

impl IdentitySessionIntrospector {
    fn context_from_cached(cached: &CachedSession) -> Result<AuthContext, AuthError> {
        let now = Utc::now();
        if cached.expires_at <= now {
            return Err(AuthError::Expired);
        }
        if cached.revoked_at.is_some() {
            return Err(AuthError::Revoked);
        }
        if cached.created_at < cached.password_updated_at_at_resolve {
            return Err(AuthError::Revoked);
        }
        let amr = if cached.amr.is_empty() {
            // RFC 8176 + AuthContext invariants both require at
            // least one AMR. A session row that landed pre-AMR (or
            // through a path that didn't tag) defaults to `pwd`
            // here so the AuthContext invariant holds; the canonical
            // tagging happens at issuance.
            vec!["pwd".to_string()]
        } else {
            cached.amr.clone()
        };
        let auth_method = auth_method_from_amr(&amr);
        AuthContext::new(
            cached.user_id,
            cached.session_id,
            cached.org_id,
            auth_method,
            TokenClass::Session,
            amr,
            cached.acr.clone(),
            cached.created_at,
            cached.expires_at,
            Uuid::now_v7(),
        )
        .map_err(|e| AuthError::internal(std::io::Error::other(e.to_string())))
    }

    fn fire_last_seen(&self, session_id: Uuid) {
        let _ = self.last_seen.try_send(UpdateLastSeen {
            session_id,
            seen_at: Utc::now(),
        });
    }
}

/// Map a session row's AMR (RFC 8176 authentication-method-reference
/// values) onto the [`zagrosi_core::AuthMethod`] enum.
///
/// The first AMR entry that matches a known method wins; legacy
/// password sessions default to [`AuthMethod::Password`] for
/// backward compatibility with rows that landed before the
/// canonical issuance path tagged AMR.
fn auth_method_from_amr(amr: &[String]) -> AuthMethod {
    for entry in amr {
        match entry.as_str() {
            // RFC 8176 baseline values.
            "oidc" | "iss" | "fed" => return AuthMethod::Oidc,
            "saml" => return AuthMethod::Saml,
            "scim" => return AuthMethod::ScimToken,
            "svc" | "service" => return AuthMethod::ServiceToken,
            "pat" | "api_token" => return AuthMethod::ApiToken,
            _ => {}
        }
    }
    AuthMethod::Password
}

#[cfg(test)]
mod tests {
    use super::*;
    use static_assertions::assert_impl_all;

    assert_impl_all!(IdentitySessionIntrospector: Send, Sync, Clone);

    #[test]
    fn auth_method_from_amr_pwd_default() {
        let amr = vec!["pwd".to_string()];
        assert_eq!(auth_method_from_amr(&amr), AuthMethod::Password);
    }

    #[test]
    fn auth_method_from_amr_oidc() {
        let amr = vec!["oidc".to_string()];
        assert_eq!(auth_method_from_amr(&amr), AuthMethod::Oidc);
    }

    #[test]
    fn auth_method_from_amr_saml() {
        let amr = vec!["saml".to_string()];
        assert_eq!(auth_method_from_amr(&amr), AuthMethod::Saml);
    }

    #[test]
    fn auth_method_from_amr_first_match_wins() {
        let amr = vec!["pwd".to_string(), "oidc".to_string()];
        assert_eq!(auth_method_from_amr(&amr), AuthMethod::Oidc);
    }

    #[test]
    fn auth_method_from_amr_unknown_falls_back_to_password() {
        let amr = vec!["mfa-totp".to_string()];
        assert_eq!(auth_method_from_amr(&amr), AuthMethod::Password);
    }

    // Behavioural tests against a live DB live in
    // `tests/session_lifecycle.rs` — the cache + DB plumbing in
    // this module needs both Postgres and an in-process channel
    // pair, which the integration harness provides.
}
