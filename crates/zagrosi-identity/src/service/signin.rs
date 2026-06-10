// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! `IdentityService::sign_in` — constant-time password sign-in.
//!
//! Constant-time discipline: every branch (unknown email, soft-deleted
//! user, unverified user, wrong password) runs an Argon2id verify (or
//! [`Argon2idHasher::dummy_verify`] when the user is missing) so the
//! caller cannot use wall-clock latency as an existence oracle.
//!
//! `password_updated_at` invariant: a successful sign-in that needs to
//! rehash updates `users.password_hash` + `password_updated_at` +
//! `password_hash_version` in one transaction. The timestamp bump
//! revokes every other live session for the user through the session
//! introspector's `created_at < password_updated_at` check.

use chrono::Utc;
use uuid::Uuid;
use zagrosi_core::{
    AuditActor, AuditEvent, AuditEventKind, AuditEventV1, AuditPayload, AuditResource,
    RateLimitDecision, RateLimitKey,
};

use super::{IdentityService, normalise_email, validate_email};
use crate::error::{IdentityError, Result};
use crate::password::Argon2idHasher;
use crate::session::IssuedSession;

/// Stable bucket scope for sign-in / sign-in-failure rate-limit and
/// lockout keys. Lives in core's [`RateLimitKey`] as a `&'static str`
/// so the Valkey limiter can format its storage keys without an
/// extra allocation.
pub(crate) const SIGNIN_SCOPE: &str = "signin";

/// Request bundle for [`IdentityService::sign_in`].
#[derive(Debug, Clone)]
pub struct SignInRequest {
    /// Display-case email submitted by the caller.
    pub email: String,
    /// Cleartext password — never logged.
    pub password: String,
    /// Source IP for audit + rate-limit aggregates.
    pub ip: std::net::IpAddr,
    /// Caller-controlled correlation id.
    pub correlation_id: Uuid,
}

impl IdentityService {
    /// Process a sign-in request. Returns the freshly issued session
    /// on success or a constant-time error on every failure branch.
    #[allow(clippy::too_many_lines, clippy::match_same_arms)]
    pub async fn sign_in(&self, req: SignInRequest) -> Result<IssuedSession> {
        // The per-IP gate runs *before* any Argon2id work so a
        // brute-force burst from one source IP fails fast at the
        // edge instead of saturating the password-verify pool.
        self.enforce_per_ip_check(req.ip, SIGNIN_SCOPE).await?;

        validate_email(&req.email)?;
        let email_lower = normalise_email(&req.email);

        let user = self.user_repo.find_by_email_lower(&email_lower).await?;

        match user {
            None => {
                // Unknown email — anti-enumeration dummy verify.
                self.hasher.dummy_verify().await?;
                self.record_failure(None, req.ip, req.correlation_id).await;
                Err(IdentityError::InvalidCredentials)
            }
            Some(user) if user.deleted_at.is_some() => {
                self.hasher.dummy_verify().await?;
                self.record_failure(Some(user.id), req.ip, req.correlation_id)
                    .await;
                Err(IdentityError::AccountDisabled)
            }
            Some(user) if user.email_verified_at.is_none() => {
                self.hasher.dummy_verify().await?;
                self.record_failure(Some(user.id), req.ip, req.correlation_id)
                    .await;
                Err(IdentityError::EmailNotVerified)
            }
            Some(user) => {
                let Some(phc) = user.password_hash.as_deref() else {
                    // SSO-only account; password sign-in not allowed.
                    self.hasher.dummy_verify().await?;
                    self.record_failure(Some(user.id), req.ip, req.correlation_id)
                        .await;
                    return Err(IdentityError::InvalidCredentials);
                };
                let matched = self.hasher.verify(&req.password, phc).await?;
                if !matched {
                    // Per-account exponential lockout: only known
                    // accounts increment here so the unknown-email
                    // branch above stays anti-enumeration. The Lua
                    // state machine returns LockedOut without
                    // incrementing once the lockout window opens.
                    if let Some(lock_err) = self.register_signin_breach(user.id).await {
                        self.record_failure(Some(user.id), req.ip, req.correlation_id)
                            .await;
                        return Err(lock_err);
                    }
                    self.record_failure(Some(user.id), req.ip, req.correlation_id)
                        .await;
                    return Err(IdentityError::InvalidCredentials);
                }

                // Transparent rehash on parameter drift.
                if self.hasher.needs_rehash(phc) {
                    transparent_rehash(self, &user.id, &req.password, &self.hasher).await?;
                }

                // Successful credentials clear any prior lockout
                // state — a successful sign-in resets the breach
                // counter so the next failure starts from zero.
                self.clear_signin_lockout(user.id).await;

                let session = self
                    .session_issuer
                    .issue_password_session(user.id, None, &["pwd"])
                    .await?;

                self.auditor
                    .record(AuditEvent::V1(
                        AuditEventV1::builder(
                            AuditEventKind::SigninSuccess,
                            AuditActor::User {
                                user_id: user.id,
                                ip: Some(req.ip),
                            },
                            None,
                            req.correlation_id,
                        )
                        .resource(AuditResource::Session {
                            session_id: session.id,
                        })
                        .metadata(AuditPayload::new(serde_json::json!({
                            "auth_method": "password",
                            "user_id": user.id,
                        })))
                        .build(),
                    ))
                    .await;
                Ok(session)
            }
        }
    }

    /// Run the sliding-window per-IP probe before any Argon2id
    /// work. Returns [`IdentityError::RateLimited`] on `Deny` and
    /// [`IdentityError::RateLimiterUnavailable`] on backend failure
    /// (fail-CLOSED).
    pub(crate) async fn enforce_per_ip_check(
        &self,
        ip: std::net::IpAddr,
        scope: &'static str,
    ) -> Result<()> {
        let key = RateLimitKey::PerIp { ip, scope };
        match self.rate_limiter.check(&key).await? {
            RateLimitDecision::Allow { .. } => Ok(()),
            RateLimitDecision::Deny { retry_after } => {
                Err(IdentityError::RateLimited { retry_after, scope })
            }
            RateLimitDecision::LockedOut {
                retry_after,
                attempts,
            } => Err(
                // Per-IP keys never produce LockedOut today, but the
                // enum is non-exhaustive — surface it as a rate-limit
                // failure rather than swallowing.
                IdentityError::LockedOut {
                    retry_after,
                    attempts,
                },
            ),
            _ => Err(IdentityError::RateLimited {
                retry_after: std::time::Duration::from_secs(60),
                scope,
            }),
        }
    }

    /// Register a known-account sign-in failure with the lockout
    /// state machine. Returns `Some(LockedOut)` when the breach
    /// transition (or an already-live lockout) blocks the caller, or
    /// `None` when the attempts counter is still below threshold.
    ///
    /// Backend failures are folded into `Some(RateLimiterUnavailable)`
    /// so the surrounding code path treats Valkey outages identically
    /// whether they hit the per-IP gate or the lockout state machine
    /// (both fail closed).
    pub(crate) async fn register_signin_breach(&self, user_id: Uuid) -> Option<IdentityError> {
        let key = RateLimitKey::PerAccount {
            user_id,
            scope: SIGNIN_SCOPE,
        };
        match self.rate_limiter.check(&key).await {
            Ok(RateLimitDecision::LockedOut {
                retry_after,
                attempts,
            }) => Some(IdentityError::LockedOut {
                retry_after,
                attempts,
            }),
            Ok(RateLimitDecision::Deny { retry_after }) => Some(IdentityError::RateLimited {
                retry_after,
                scope: SIGNIN_SCOPE,
            }),
            // `Allow` plus any future variant collapses to "permit"
            // here; a forward-compatible default keeps callers
            // shielded if `RateLimitDecision` grows new shapes that
            // the lockout path doesn't need to enforce.
            Ok(_) => None,
            Err(err) => Some(IdentityError::from(err)),
        }
    }

    /// Clear any live per-account lockout state on a successful
    /// sign-in. Errors are intentionally swallowed: a transient
    /// Valkey hiccup must not refuse the now-authenticated session,
    /// and the lockout key carries a TTL so the residual state will
    /// expire naturally if the unlock fails.
    pub(crate) async fn clear_signin_lockout(&self, user_id: Uuid) {
        let key = RateLimitKey::PerAccount {
            user_id,
            scope: SIGNIN_SCOPE,
        };
        let _ = self.rate_limiter.unlock(&key).await;
    }

    async fn record_failure(
        &self,
        user_id: Option<Uuid>,
        ip: std::net::IpAddr,
        correlation_id: Uuid,
    ) {
        let upsert = self
            .failed_signin_repo
            .record_failure(None, user_id, ip, Utc::now())
            .await;
        let Ok(upsert) = upsert else { return };
        if upsert.first_in_window {
            self.auditor
                .record(AuditEvent::V1(
                    AuditEventV1::builder(
                        AuditEventKind::SigninFailed,
                        user_id.map_or(AuditActor::Anonymous { ip: Some(ip) }, |uid| {
                            AuditActor::User {
                                user_id: uid,
                                ip: Some(ip),
                            }
                        }),
                        None,
                        correlation_id,
                    )
                    .metadata(AuditPayload::new(serde_json::json!({
                        "ip": ip.to_string(),
                        "count": upsert.count,
                    })))
                    .build(),
                ))
                .await;
        }
    }
}

async fn transparent_rehash(
    svc: &IdentityService,
    user_id: &Uuid,
    password: &str,
    hasher: &Argon2idHasher,
) -> Result<()> {
    let new_phc = hasher.hash(password).await?;
    svc.user_repo
        .update_password(*user_id, &new_phc, 1, Utc::now())
        .await
}
