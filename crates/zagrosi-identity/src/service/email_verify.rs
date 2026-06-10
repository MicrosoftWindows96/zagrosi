// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! `IdentityService::email_verify_confirm` — single-use email
//! verification.

use chrono::Utc;
use uuid::Uuid;
use zagrosi_core::{AuditActor, AuditEvent, AuditEventKind, AuditEventV1, AuditResource};

use super::IdentityService;
use crate::domain::{TokenPrefix, hash_token, parse_raw};
use crate::error::{IdentityError, Result};

/// Request bundle for [`IdentityService::email_verify_confirm`].
#[derive(Debug, Clone)]
pub struct EmailVerifyConfirmRequest {
    /// Raw `vrf_*` token.
    pub raw_token: String,
    /// Caller-controlled correlation id.
    pub correlation_id: Uuid,
}

impl IdentityService {
    /// Consume a `vrf_*` token + flip `users.email_verified_at`.
    pub async fn email_verify_confirm(&self, req: EmailVerifyConfirmRequest) -> Result<()> {
        let (prefix, _) = parse_raw(&req.raw_token)?;
        if prefix != TokenPrefix::Verification {
            return Err(IdentityError::TokenPrefixMismatch { expected: "vrf_" });
        }
        let token_hash = hash_token(&req.raw_token);
        let row = self
            .email_verification_repo
            .find_unused_by_hash(&token_hash.0)
            .await?
            .ok_or(IdentityError::TokenAlreadyUsed)?;
        if row.expires_at <= Utc::now() {
            return Err(IdentityError::TokenExpired);
        }

        let mut tx = self.pool.begin().await?;
        let affected = self
            .email_verification_repo
            .mark_used(&mut tx, row.id)
            .await?;
        if affected == 0 {
            tx.rollback().await?;
            return Err(IdentityError::TokenAlreadyUsed);
        }
        sqlx::query!(
            r#"UPDATE users
               SET email_verified_at = now(),
                   updated_at = now()
             WHERE id = $1 AND deleted_at IS NULL AND email_verified_at IS NULL"#,
            row.user_id,
        )
        .execute(&mut *tx)
        .await
        .map_err(IdentityError::from)?;
        tx.commit().await?;

        self.auditor
            .record(AuditEvent::V1(
                AuditEventV1::builder(
                    AuditEventKind::EmailVerified,
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
                .build(),
            ))
            .await;
        Ok(())
    }
}
