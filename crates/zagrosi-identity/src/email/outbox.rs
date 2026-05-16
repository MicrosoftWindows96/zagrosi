// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! Transactional outbox writer.
//!
//! The producer pattern (password-auth):
//!
//! 1. Open `sqlx::Transaction<'_, sqlx::Postgres>`.
//! 2. Mutate user state.
//! 3. Call [`EmailOutboxWriter::enqueue`] to write the outbox row
//!    inside the same transaction. Idempotency-keyed `INSERT ... ON
//!    CONFLICT DO NOTHING` guards against duplicate enqueues.
//! 4. Commit.
//! 5. Best-effort publish on `email.outbox.queue` via
//!    [`EmailOutboxWriter::notify`] AFTER commit. A publish failure
//!    is logged + ignored; the email-outbox worker drains the outbox on its
//!    next sweep, so no email is lost.
//!
//! The compile-time signature forbids passing a `&PgPool` instead of a
//! `&mut sqlx::Transaction<...>`; this defends against accidental
//! out-of-transaction enqueues that would break the atomic-with-user
//! -mutation contract.

use sha2::{Digest as _, Sha256};
use sqlx::Postgres;
use uuid::Uuid;

use crate::email::template::TemplateName;
use crate::error::{IdentityError, Result};

/// Outbox-row shape the producer hands to the writer.
///
/// `correlation_id` is folded into the idempotency key so a retry
/// path (e.g. a sign-up form double-submission) collapses to one
/// outbox row. The email-outbox worker uses `template_key` to resolve the
/// fluent template; `payload` is rendered into the template by the
/// worker.
#[derive(Debug, Clone)]
pub struct EnqueueRequest {
    /// Owning user.
    pub user_id: Uuid,
    /// Owning org. `None` for system mail (anti-enumeration sign-up
    /// collision is the canonical example).
    pub org_id: Option<Uuid>,
    /// Recipient email address. Display-case preserved.
    pub recipient: String,
    /// Sender address. Operators set this via outbound SMTP config.
    pub from_address: String,
    /// Template the email-outbox worker will render.
    pub template: TemplateName,
    /// Pre-rendered subject line.
    pub subject: String,
    /// Plain-text body (falls back when the recipient's MUA strips
    /// HTML).
    pub body_text: String,
    /// Optional HTML body.
    pub body_html: Option<String>,
    /// Free-form correlation id for tracing the outbox row back to
    /// the originating request. Folded into the idempotency key.
    pub correlation_id: Uuid,
}

impl EnqueueRequest {
    /// Compute the deterministic idempotency key.
    ///
    /// SHA-256 over `(user_id || event_kind || correlation_id)` — the
    /// same producer call site emits the same key, so a retried
    /// `enqueue` collapses on the partial unique index.
    #[must_use]
    pub fn idempotency_key(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.user_id.as_bytes());
        hasher.update(b":");
        hasher.update(self.template.as_key().as_bytes());
        hasher.update(b":");
        hasher.update(self.correlation_id.as_bytes());
        let digest = hasher.finalize();
        let mut hex = String::with_capacity(64);
        for byte in digest {
            use std::fmt::Write as _;
            let _ = write!(&mut hex, "{byte:02x}");
        }
        hex
    }
}

/// Outbox writer.
///
/// Construct with [`EmailOutboxWriter::new`]; `notify` is currently
/// a no-op that logs at `debug` because the NATS dependency lives in
/// the email-outbox layer. Once that layer lands, swap the body for an `async_nats` publish.
#[derive(Debug, Default, Clone, Copy)]
pub struct EmailOutboxWriter;

impl EmailOutboxWriter {
    /// Construct a new writer. Stateless today; once the email-outbox plugs in
    /// NATS, the writer will own the JetStream client.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Enqueue an outbox row inside the caller's transaction.
    ///
    /// Idempotency is enforced by the `email_outbox_org_idempotency_unique`
    /// partial unique index (NULLS NOT DISTINCT) introduced in the migration set.
    /// Repeat calls with the same `(org_id, idempotency_key)` collapse
    /// to one row via `ON CONFLICT DO NOTHING`.
    pub async fn enqueue(
        &self,
        tx: &mut sqlx::Transaction<'_, Postgres>,
        request: &EnqueueRequest,
    ) -> Result<()> {
        let idempotency_key = request.idempotency_key();
        sqlx::query!(
            r#"
            INSERT INTO email_outbox (
                id, org_id, to_address, from_address, subject,
                body_text, body_html, template_key, locale,
                idempotency_key, state, attempts, next_attempt_at
            )
            VALUES (
                $1, $2, $3, $4, $5,
                $6, $7, $8, 'en',
                $9, 'queued', 0, now()
            )
            ON CONFLICT (org_id, idempotency_key) DO NOTHING
            "#,
            Uuid::now_v7(),
            request.org_id,
            request.recipient,
            request.from_address,
            request.subject,
            request.body_text,
            request.body_html.as_deref(),
            request.template.as_key(),
            idempotency_key,
        )
        .execute(&mut **tx)
        .await
        .map_err(IdentityError::from)?;
        Ok(())
    }

    /// Publish a wake-up message on `email.outbox.queue`. Best-effort —
    /// must be called AFTER the producer commits the transaction.
    /// Failure is logged + ignored.
    ///
    /// Today this is a no-op (the email-outbox worker drains the outbox
    /// on its own schedule). The email-outbox layer wires it to NATS;
    /// at which point this becomes async.
    pub fn notify(&self, idempotency_key: &str) {
        tracing::debug!(
            target: "email.outbox.notify",
            idempotency_key,
            "outbox notify is a no-op until the email-outbox layer wires NATS",
        );
    }
}
