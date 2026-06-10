// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! `IdentityService::password_reset_request` and
//! `password_reset_confirm`.

use chrono::Utc;
use uuid::Uuid;
use zagrosi_core::{
    AuditActor, AuditEvent, AuditEventKind, AuditEventV1, AuditPayload, AuditResource, BreachCheck,
};

use super::{IdentityService, normalise_email, validate_email};
use crate::domain::{TokenPrefix, hash_token, mint, parse_raw};
use crate::email::{EnqueueRequest, TemplateName};
use crate::error::{IdentityError, Result};
use crate::password::policy::validate_password_length;

/// Request bundle for [`IdentityService::password_reset_request`].
#[derive(Debug, Clone)]
pub struct PasswordResetRequestRequest {
    /// Submitted email.
    pub email: String,
    /// Source IP for the (optional) audit event.
    pub ip: std::net::IpAddr,
    /// Caller-controlled correlation id.
    pub correlation_id: Uuid,
}

/// Request bundle for [`IdentityService::password_reset_confirm`].
#[derive(Debug, Clone)]
pub struct PasswordResetConfirmRequest {
    /// Raw `rst_*` token (47 chars: prefix + 43 base64url body).
    pub raw_token: String,
    /// Cleartext new password.
    pub new_password: String,
    /// Caller-controlled correlation id.
    pub correlation_id: Uuid,
}

impl IdentityService {
    /// Issue a `rst_*` token for the address (if it matches a live
    /// user) or run a dummy verify for timing equality. Always
    /// returns `Ok(())` — the response itself is not an enumeration
    /// oracle.
    pub async fn password_reset_request(&self, req: PasswordResetRequestRequest) -> Result<()> {
        validate_email(&req.email)?;
        let email_lower = normalise_email(&req.email);
        let user = self.user_repo.find_by_email_lower(&email_lower).await?;

        let Some(user) = user.filter(|u| u.deleted_at.is_none()) else {
            // Anti-enumeration: dummy verify keeps wall-clock cost
            // close to the known-email path. NO audit event — the
            // audit log itself becomes an oracle if we emit only on
            // the known-email branch.
            self.hasher.dummy_verify().await?;
            return Ok(());
        };

        let raw = mint(TokenPrefix::Reset);
        let token_hash = hash_token(&raw);
        let now = Utc::now();
        let ttl_minutes = i64::from(self.config.email_token_ttl_minutes);
        let expires_at = now + chrono::Duration::minutes(ttl_minutes);

        let mut tx = self.pool.begin().await?;
        self.password_reset_repo
            .insert(
                &mut tx,
                Uuid::now_v7(),
                user.id,
                token_hash.as_slice(),
                expires_at,
            )
            .await?;
        self.outbox
            .enqueue(
                &mut tx,
                &EnqueueRequest {
                    user_id: user.id,
                    org_id: None,
                    recipient: req.email.clone(),
                    from_address: self.outbound_from_address.clone(),
                    template: TemplateName::PasswordReset,
                    subject: "Reset your password".into(),
                    body_text: format!(
                        "Reset your password by visiting {}/v1/auth/password-reset/landing?token={}",
                        self.base_url, raw,
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
                    AuditEventKind::PasswordResetRequested,
                    AuditActor::User {
                        user_id: user.id,
                        ip: Some(req.ip),
                    },
                    None,
                    req.correlation_id,
                )
                .resource(AuditResource::User { user_id: user.id })
                .metadata(AuditPayload::new(
                    serde_json::json!({"ip": req.ip.to_string()}),
                ))
                .build(),
            ))
            .await;
        Ok(())
    }

    /// Consume a `rst_*` token + rotate the user's password.
    #[allow(clippy::too_many_lines, clippy::match_same_arms)]
    ///
    /// Order of operations defends the user from the oracles:
    /// - Validates the token's prefix and the new password's length /
    ///   breach status BEFORE consuming the token (so a rejected
    ///   submission does not burn the row).
    /// - Wraps the `used_at` flip + `users.password_hash` update +
    ///   `users.password_updated_at` bump in one transaction so a
    ///   crash either retains the original password and unused token
    ///   or commits both updates.
    pub async fn password_reset_confirm(&self, req: PasswordResetConfirmRequest) -> Result<()> {
        let (prefix, _) = parse_raw(&req.raw_token)?;
        if prefix != TokenPrefix::Reset {
            return Err(IdentityError::TokenPrefixMismatch { expected: "rst_" });
        }
        validate_password_length(&req.new_password, &self.config.password)?;
        let breach = self.breach_client.check(&req.new_password).await?;
        match breach {
            BreachCheck::Breached { .. } => return Err(IdentityError::PasswordBreached),
            BreachCheck::Unavailable => return Err(IdentityError::BreachlistUnavailable),
            BreachCheck::Clean => {}
            _ => return Err(IdentityError::BreachlistUnavailable),
        }
        let token_hash = hash_token(&req.raw_token);
        let row = self
            .password_reset_repo
            .find_unused_by_hash(&token_hash.0)
            .await?
            .ok_or(IdentityError::TokenAlreadyUsed)?;
        if row.expires_at <= Utc::now() {
            return Err(IdentityError::TokenExpired);
        }

        let new_phc = self.hasher.hash(&req.new_password).await?;
        let mut tx = self.pool.begin().await?;
        let affected = self.password_reset_repo.mark_used(&mut tx, row.id).await?;
        if affected == 0 {
            tx.rollback().await?;
            return Err(IdentityError::TokenAlreadyUsed);
        }
        sqlx::query!(
            r#"UPDATE users
               SET password_hash = $2,
                   password_hash_version = 1,
                   password_updated_at = $3,
                   updated_at = now()
             WHERE id = $1 AND deleted_at IS NULL"#,
            row.user_id,
            new_phc,
            Utc::now(),
        )
        .execute(&mut *tx)
        .await
        .map_err(IdentityError::from)?;
        tx.commit().await?;

        self.auditor
            .record(AuditEvent::V1(
                AuditEventV1::builder(
                    AuditEventKind::PasswordChanged,
                    AuditActor::User {
                        user_id: row.user_id,
                        ip: None,
                    },
                    None,
                    req.correlation_id,
                )
                .resource(AuditResource::User {
                    user_id: row.user_id,
                })
                .metadata(AuditPayload::new(serde_json::json!({"flow": "reset"})))
                .build(),
            ))
            .await;
        Ok(())
    }
}
