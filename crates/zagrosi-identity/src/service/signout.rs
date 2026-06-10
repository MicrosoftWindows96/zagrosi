// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! `IdentityService::sign_out` — session revocation.

use uuid::Uuid;
use zagrosi_core::{
    AuditActor, AuditEvent, AuditEventKind, AuditEventV1, AuditPayload, AuditResource,
};

use super::IdentityService;
use crate::error::Result;

impl IdentityService {
    /// Revoke `session_id`. Idempotent — already-revoked sessions
    /// return `Ok(())` so a double-tap on the sign-out button looks
    /// the same as the first.
    ///
    /// `actor_user_id` (when known) is recorded on the audit event so
    /// admin sign-outs can be distinguished from self-service ones.
    pub async fn sign_out(
        &self,
        session_id: Uuid,
        actor_user_id: Option<Uuid>,
        actor_ip: Option<std::net::IpAddr>,
        correlation_id: Uuid,
    ) -> Result<()> {
        self.session_repo.revoke(session_id).await?;

        let actor = actor_user_id.map_or(AuditActor::Anonymous { ip: actor_ip }, |user_id| {
            AuditActor::User {
                user_id,
                ip: actor_ip,
            }
        });
        self.auditor
            .record(AuditEvent::V1(
                AuditEventV1::builder(AuditEventKind::SessionRevoked, actor, None, correlation_id)
                    .resource(AuditResource::Session { session_id })
                    .metadata(AuditPayload::new(serde_json::json!({"reason": "sign_out"})))
                    .build(),
            ))
            .await;
        Ok(())
    }
}
