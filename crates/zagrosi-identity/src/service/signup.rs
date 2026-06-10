// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! `IdentityService::sign_up` — anti-enumeration password sign-up.
//!
//! See `documentation/identity.md` (and the password-auth design notes) for the
//! canonical anti-enumeration contract: the response shape MUST be
//! byte-equivalent for new-email and collision paths, the audit
//! event MUST NOT disclose existence, and timing on the collision
//! path MUST stay close to the new-email path.

use chrono::Utc;
use uuid::Uuid;
use zagrosi_core::{
    AuditActor, AuditEvent, AuditEventKind, AuditEventV1, AuditPayload, AuditResource, BreachCheck,
};

use super::{IdentityService, normalise_email, validate_email};
use crate::domain::{TokenPrefix, hash_token, mint};
use crate::email::{EnqueueRequest, TemplateName};
use crate::error::{IdentityError, Result};
use crate::password::policy::validate_password_length;
use crate::repo::NewUser;

/// Request bundle for [`IdentityService::sign_up`].
#[derive(Debug, Clone)]
pub struct SignUpRequest {
    /// Display-case email the caller submitted.
    pub email: String,
    /// Display name for the new user.
    pub display_name: String,
    /// Cleartext password — never logged.
    pub password: String,
    /// Source IP for audit + rate-limit aggregates.
    pub ip: std::net::IpAddr,
    /// Caller-controlled correlation id (folded into idempotency keys).
    pub correlation_id: Uuid,
}

/// Response bundle for [`IdentityService::sign_up`].
///
/// Shape is intentionally identical for new-email and collision
/// paths so the response itself is not an enumeration oracle.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SignUpResponse {
    /// Always `"ok"`.
    pub status: &'static str,
    /// Always `"check_email"` — instructs the caller to wait for the
    /// verify-email message regardless of whether the address was
    /// new or pre-existing.
    pub action: &'static str,
}

const STABLE_RESPONSE: SignUpResponse = SignUpResponse {
    status: "ok",
    action: "check_email",
};

impl IdentityService {
    /// Process a sign-up request.
    #[allow(clippy::too_many_lines, clippy::match_same_arms)]
    ///
    /// Anti-enumeration guarantees:
    /// - Returns the same [`SignUpResponse`] regardless of whether
    ///   the email was new or already taken.
    /// - The new-user path mints a `vrf_*` token and enqueues a
    ///   `verify_email`; the collision path enqueues an
    ///   `account_already_exists` and skips the user mutation.
    /// - The collision path skips the Argon2id hash entirely so the
    ///   wall-clock cost stays close to the new-email path despite
    ///   not minting a new password.
    /// - The breach-list reject (`PasswordBreached`) and policy
    ///   reject (`PasswordTooShort` / `PasswordTooLong`) intentionally
    ///   surface BEFORE any DB lookup; these signals are independent
    ///   of email existence.
    pub async fn sign_up(&self, req: SignUpRequest) -> Result<SignUpResponse> {
        validate_email(&req.email)?;
        validate_password_length(&req.password, &self.config.password)?;

        let breach = self.breach_client.check(&req.password).await?;
        match breach {
            BreachCheck::Breached { .. } => return Err(IdentityError::PasswordBreached),
            BreachCheck::Unavailable => return Err(IdentityError::BreachlistUnavailable),
            BreachCheck::Clean => {}
            // `BreachCheck` is `non_exhaustive`; future variants
            // default to fail-closed (treat as breached) for safety.
            _ => return Err(IdentityError::BreachlistUnavailable),
        }

        let email_lower = normalise_email(&req.email);
        let existing = self.user_repo.find_by_email_lower(&email_lower).await?;

        if existing.is_some() {
            // Anti-enumeration collision path: enqueue the
            // `account_already_exists` template + emit the audit event
            // that carries the IP only (NEVER the existence answer).
            let mut tx = self.pool.begin().await?;
            self.outbox
                .enqueue(
                    &mut tx,
                    &EnqueueRequest {
                        user_id: Uuid::nil(),
                        org_id: None,
                        recipient: req.email.clone(),
                        from_address: self.outbound_from_address.clone(),
                        template: TemplateName::AccountAlreadyExists,
                        subject: "Sign-in attempt for an existing account".into(),
                        body_text: format!(
                            "Someone tried to create a new account with this email at {}. \
                             If that was you, please sign in or use the password-reset flow.",
                            self.base_url,
                        ),
                        body_html: None,
                        correlation_id: req.correlation_id,
                    },
                )
                .await?;
            tx.commit().await?;

            self.auditor
                .record(AuditEvent::V1(
                    AuditEventV1::builder(
                        AuditEventKind::SignupEmailCollisionAttempted,
                        AuditActor::Anonymous { ip: Some(req.ip) },
                        None,
                        req.correlation_id,
                    )
                    .metadata(AuditPayload::new(
                        serde_json::json!({"ip": req.ip.to_string()}),
                    ))
                    .build(),
                ))
                .await;
            return Ok(STABLE_RESPONSE);
        }

        // New-email path: hash + insert user + mint vrf token + enqueue
        // verify_email — all in one transaction so a failure between the
        // user insert and the outbox row rolls everything back.
        let phc = self.hasher.hash(&req.password).await?;
        let user_id = Uuid::now_v7();
        let now = Utc::now();
        let raw_token = mint(TokenPrefix::Verification);
        let token_hash = hash_token(&raw_token);
        let ttl_minutes = i64::from(self.config.email_token_ttl_minutes);
        let expires_at = now + chrono::Duration::minutes(ttl_minutes);

        let mut tx = self.pool.begin().await?;
        let user = self
            .user_repo
            .create_in_tx(
                &mut tx,
                NewUser {
                    id: user_id,
                    email: &req.email,
                    display_name: &req.display_name,
                    password_hash: Some(&phc),
                    password_updated_at: Some(now),
                    password_hash_version: 1,
                    external_id: None,
                },
            )
            .await?;
        self.email_verification_repo
            .insert(
                &mut tx,
                Uuid::now_v7(),
                user_id,
                &user.email,
                token_hash.as_slice(),
                expires_at,
            )
            .await?;
        self.outbox
            .enqueue(
                &mut tx,
                &EnqueueRequest {
                    user_id,
                    org_id: None,
                    recipient: req.email.clone(),
                    from_address: self.outbound_from_address.clone(),
                    template: TemplateName::VerifyEmail,
                    subject: "Confirm your email".into(),
                    body_text: format!(
                        "Confirm your email by visiting {}/v1/auth/email-verifications/landing?token={}",
                        self.base_url, raw_token,
                    ),
                    body_html: None,
                    correlation_id: req.correlation_id,
                },
            )
            .await?;
        tx.commit().await?;

        self.auditor
            .record(AuditEvent::V1(
                AuditEventV1::builder(
                    AuditEventKind::SignupCreated,
                    AuditActor::User {
                        user_id,
                        ip: Some(req.ip),
                    },
                    None,
                    req.correlation_id,
                )
                .resource(AuditResource::User { user_id })
                .metadata(AuditPayload::new(serde_json::json!({
                    "user_id": user_id,
                    "ip": req.ip.to_string(),
                })))
                .build(),
            ))
            .await;

        Ok(STABLE_RESPONSE)
    }
}
