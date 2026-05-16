// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown)]
//! Consumer-side outbox dispatch.
//!
//! The producer ([`crate::email::EmailOutboxWriter`]) writes a
//! fully-rendered row (`subject` / `body_text` / `body_html` are
//! materialised at enqueue time — the worker does **not** render
//! templates). This module drains those rows.
//!
//! ## Locking model
//!
//! Each row is processed inside its own short transaction. The
//! dequeue `SELECT ... FOR UPDATE SKIP LOCKED LIMIT 1` row-locks
//! exactly one eligible row and skips rows another worker already
//! holds, so N worker replicas drain a backlog with no duplicate
//! sends and no skipped rows. The transaction stays open across the
//! transport call; commit (success or terminal failure) releases the
//! lock. A worker crash mid-send rolls the transaction back, leaving
//! the row `queued`/`failed` for the next sweep — no email is lost
//! and none is sent twice (the transport call is idempotent-keyed).
//!
//! ## Transport indirection
//!
//! [`OutboxDispatcher::process_one`] takes the send action as an
//! async closure rather than depending on a concrete transport. The
//! worker passes `|msg| transport.send(msg)`; tests pass a closure
//! that records calls and returns scripted outcomes, so the
//! dequeue / retry / dead-letter / SKIP-LOCKED logic is exercised
//! without an SMTP server.

use std::future::Future;

use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;
use zagrosi_core::{EmailMessage, EmailTransportError};

use crate::email::retry;
use crate::error::{IdentityError, Result};

/// Lifecycle states of an `email_outbox` row.
///
/// Wire values match the `CHECK (state IN (...))` constraint in
/// migration `010_email_outbox`. `Sending` is part of the schema
/// constraint for forward-compatibility but is intentionally unused
/// by this dispatcher: the per-row transaction lock already provides
/// mutual exclusion, so there is no committed intermediate state to
/// reap after a crash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboxState {
    /// Freshly enqueued, never attempted.
    Queued,
    /// Reserved by the schema; unused by this dispatcher (see type
    /// docs). Present only so the round-trip mapping is total.
    Sending,
    /// Delivered to the transport successfully; terminal.
    Sent,
    /// At least one transient failure; awaiting `next_attempt_at`.
    Failed,
    /// Retry cap reached or a permanent fault; terminal, never retried.
    Dead,
}

impl OutboxState {
    /// Wire string written to / read from `email_outbox.state`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Sending => "sending",
            Self::Sent => "sent",
            Self::Failed => "failed",
            Self::Dead => "dead",
        }
    }

    /// Parse a wire string. Returns `None` for an unrecognised value
    /// (a row that violates the migration `CHECK` — treated as a hard
    /// error by callers rather than silently coerced).
    ///
    /// Named `from_wire` (not `from_str`) deliberately: it is not a
    /// [`std::str::FromStr`] impl — the fallible-but-`Option` shape
    /// and "wire format" framing are intentional.
    #[must_use]
    pub fn from_wire(raw: &str) -> Option<Self> {
        match raw {
            "queued" => Some(Self::Queued),
            "sending" => Some(Self::Sending),
            "sent" => Some(Self::Sent),
            "failed" => Some(Self::Failed),
            "dead" => Some(Self::Dead),
            _ => None,
        }
    }
}

/// The columns the dispatcher reads to build an [`EmailMessage`].
///
/// `attempts` is the **pre-increment** value as stored; the dispatcher
/// bumps it on failure before consulting [`retry::next_attempt`].
#[derive(Clone)]
pub struct DispatchRow {
    /// `email_outbox.id`.
    pub id: Uuid,
    /// Owning org, `None` for system mail.
    pub org_id: Option<Uuid>,
    /// `To:` recipient.
    pub to_address: String,
    /// `From:` sender (producer copied this from outbound SMTP config).
    pub from_address: String,
    /// Pre-rendered subject line.
    pub subject: String,
    /// Pre-rendered plain-text body.
    pub body_text: String,
    /// Optional pre-rendered HTML body.
    pub body_html: Option<String>,
    /// Producer-computed idempotency key (carried into the transport).
    pub idempotency_key: String,
    /// Stored (pre-increment) attempt count.
    pub attempts: i32,
}

impl std::fmt::Debug for DispatchRow {
    /// `to_address` is recipient PII and `body_text`/`body_html`
    /// carry rendered single-use token URLs; all three render
    /// `<redacted>` so a `tracing::debug!(?row)` at any call site
    /// cannot leak them. `idempotency_key` is an opaque hash (safe,
    /// and the only correlation handle for ops) and survives, mirroring
    /// the `zagrosi_core::EmailMessage` redaction policy.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DispatchRow")
            .field("id", &self.id)
            .field("org_id", &self.org_id)
            .field("to_address", &"<redacted>")
            .field("from_address", &"<redacted>")
            .field("subject", &"<redacted>")
            .field("body_text", &"<redacted>")
            .field("body_html", &self.body_html.as_ref().map(|_| "<redacted>"))
            .field("idempotency_key", &self.idempotency_key)
            .field("attempts", &self.attempts)
            .finish()
    }
}

impl DispatchRow {
    fn to_message(&self) -> EmailMessage {
        EmailMessage {
            from: self.from_address.clone(),
            to: self.to_address.clone(),
            subject: self.subject.clone(),
            body_text: self.body_text.clone(),
            body_html: self.body_html.clone(),
            idempotency_key: self.idempotency_key.clone(),
        }
    }
}

/// What happened to one processed row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessOutcome {
    /// Transport accepted the message; row is `sent`.
    Sent {
        /// Processed row id.
        id: Uuid,
    },
    /// Transient failure; row is `failed`, eligible again at
    /// `next_attempt_at`.
    Retried {
        /// Processed row id.
        id: Uuid,
        /// Post-increment attempt count.
        attempts: i32,
    },
    /// Retry cap reached or permanent fault; row is `dead`.
    DeadLettered {
        /// Processed row id.
        id: Uuid,
        /// Post-increment attempt count.
        attempts: i32,
    },
}

/// The dequeue query. Held as a constant so a unit test can assert
/// the `FOR UPDATE SKIP LOCKED` clause is present without a database
/// (a regression guard: dropping it silently re-introduces
/// duplicate-send races under concurrent workers).
const DEQUEUE_SQL: &str = "\
SELECT id, org_id, to_address, from_address, subject, body_text, body_html, \
idempotency_key, attempts \
FROM email_outbox \
WHERE state IN ('queued','failed') \
  AND (next_attempt_at IS NULL OR next_attempt_at <= now()) \
ORDER BY next_attempt_at ASC NULLS FIRST \
FOR UPDATE SKIP LOCKED \
LIMIT 1";

/// Drains `email_outbox` one locked row per transaction.
#[derive(Debug, Clone)]
pub struct OutboxDispatcher {
    pool: PgPool,
}

impl OutboxDispatcher {
    /// Construct over a connection pool.
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Number of rows currently eligible for an immediate send. Used
    /// by the worker to publish the `email_outbox_pending_total`
    /// gauge on each sweep; not part of the dequeue critical path.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::Database`] if the count query fails.
    pub async fn pending_count(&self) -> Result<i64> {
        let row: (i64,) = sqlx::query_as(
            "SELECT count(*) FROM email_outbox \
             WHERE state IN ('queued','failed') \
               AND (next_attempt_at IS NULL OR next_attempt_at <= now())",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(IdentityError::from)?;
        Ok(row.0)
    }

    /// Claim, send, and finalise the single oldest eligible row.
    ///
    /// Returns `Ok(None)` when no row is eligible (the backlog is
    /// drained or every eligible row is locked by a peer worker).
    ///
    /// `send` is invoked at most once per call, inside the row's
    /// transaction. Its `Ok`/`Err` decides the terminal state:
    ///
    /// - `Ok(())` → `sent`.
    /// - `Err(Unavailable)` → `failed` with a backed-off
    ///   `next_attempt_at`, or `dead` once the attempt cap
    ///   ([`retry::MAX_ATTEMPTS`]) is hit.
    /// - `Err(Permanent { .. })` → `dead` immediately (a bad
    ///   recipient / rejected content will not become valid on retry).
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::Database`] on a SQL / transaction
    /// failure. A transport error is **not** propagated — it is
    /// recorded on the row and folded into the returned
    /// [`ProcessOutcome`].
    pub async fn process_one<F, Fut>(&self, send: F) -> Result<Option<ProcessOutcome>>
    where
        F: FnOnce(EmailMessage) -> Fut,
        Fut: Future<Output = std::result::Result<(), EmailTransportError>>,
    {
        let mut tx = self.pool.begin().await.map_err(IdentityError::from)?;

        let Some(row) = dequeue(&mut tx).await? else {
            // Nothing eligible. Roll the empty txn back explicitly so
            // the connection returns to the pool without a dangling
            // open transaction.
            tx.rollback().await.map_err(IdentityError::from)?;
            return Ok(None);
        };

        let send_result = send(row.to_message()).await;
        let outcome = match send_result {
            Ok(()) => {
                mark_sent(&mut tx, row.id).await?;
                ProcessOutcome::Sent { id: row.id }
            }
            Err(err) => mark_failure(&mut tx, &row, &err).await?,
        };

        tx.commit().await.map_err(IdentityError::from)?;
        Ok(Some(outcome))
    }
}

/// Column tuple returned by [`DEQUEUE_SQL`], in select order.
type RawOutboxRow = (
    Uuid,
    Option<Uuid>,
    String,
    String,
    String,
    String,
    Option<String>,
    String,
    i32,
);

/// Claim the oldest eligible row inside `tx` (row-locked via the
/// `FOR UPDATE SKIP LOCKED` in [`DEQUEUE_SQL`]).
async fn dequeue(tx: &mut sqlx::Transaction<'_, sqlx::Postgres>) -> Result<Option<DispatchRow>> {
    let raw = sqlx::query_as::<_, RawOutboxRow>(DEQUEUE_SQL)
        .fetch_optional(&mut **tx)
        .await
        .map_err(IdentityError::from)?;
    Ok(raw.map(|r| DispatchRow {
        id: r.0,
        org_id: r.1,
        to_address: r.2,
        from_address: r.3,
        subject: r.4,
        body_text: r.5,
        body_html: r.6,
        idempotency_key: r.7,
        attempts: r.8,
    }))
}

/// Mark the row delivered. Terminal; clears any prior `last_error`.
async fn mark_sent(tx: &mut sqlx::Transaction<'_, sqlx::Postgres>, id: Uuid) -> Result<()> {
    sqlx::query(
        "UPDATE email_outbox \
         SET state = 'sent', sent_at = now(), last_error = NULL \
         WHERE id = $1",
    )
    .bind(id)
    .execute(&mut **tx)
    .await
    .map_err(IdentityError::from)?;
    Ok(())
}

/// Apply a failed send: bump `attempts`, then either reschedule
/// (`failed` + backed-off `next_attempt_at`) or dead-letter (`dead`).
/// A permanent fault skips the retry schedule entirely.
async fn mark_failure(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    row: &DispatchRow,
    err: &EmailTransportError,
) -> Result<ProcessOutcome> {
    let next_attempts = row.attempts.saturating_add(1);
    let last_error = redacted_error(err);
    let permanent = matches!(err, EmailTransportError::Permanent { .. });
    let backoff = if permanent {
        None
    } else {
        retry::next_attempt(next_attempts)
    };

    if let Some(delay) = backoff {
        let next_at = Utc::now()
            + chrono::Duration::from_std(delay).unwrap_or_else(|_| {
                // `delay` is one of the fixed schedule constants
                // (<= 1h); the conversion cannot overflow. Fall back
                // to the smallest delay rather than panic if the
                // table ever changes.
                chrono::Duration::seconds(30)
            });
        sqlx::query(
            "UPDATE email_outbox \
             SET state = 'failed', attempts = $2, \
                 next_attempt_at = $3, last_error = $4 \
             WHERE id = $1",
        )
        .bind(row.id)
        .bind(next_attempts)
        .bind(next_at)
        .bind(&last_error)
        .execute(&mut **tx)
        .await
        .map_err(IdentityError::from)?;
        Ok(ProcessOutcome::Retried {
            id: row.id,
            attempts: next_attempts,
        })
    } else {
        sqlx::query(
            "UPDATE email_outbox \
             SET state = 'dead', attempts = $2, \
                 next_attempt_at = NULL, last_error = $3 \
             WHERE id = $1",
        )
        .bind(row.id)
        .bind(next_attempts)
        .bind(&last_error)
        .execute(&mut **tx)
        .await
        .map_err(IdentityError::from)?;
        Ok(ProcessOutcome::DeadLettered {
            id: row.id,
            attempts: next_attempts,
        })
    }
}

/// Render a transport error into the `last_error` column value.
///
/// [`EmailTransportError`]'s `Display` is redaction-safe by
/// construction (the permanent variant wraps detail in
/// `RedactedString`, the transient variant carries an
/// operator-scrubbed string). The result is length-capped so a
/// pathological upstream cannot bloat the row.
fn redacted_error(err: &EmailTransportError) -> String {
    /// Character cap (not byte cap): `String::truncate` panics if the
    /// byte offset splits a multi-byte UTF-8 sequence, and the error
    /// text can carry non-ASCII (IDN host, localized SMTP reply). A
    /// panic here would unwind the worker loop and wedge the queue.
    const MAX_CHARS: usize = 500;
    let s = err.to_string();
    if s.chars().count() <= MAX_CHARS {
        s
    } else {
        s.chars().take(MAX_CHARS).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_round_trips_through_wire_string() {
        for state in [
            OutboxState::Queued,
            OutboxState::Sending,
            OutboxState::Sent,
            OutboxState::Failed,
            OutboxState::Dead,
        ] {
            assert_eq!(OutboxState::from_wire(state.as_str()), Some(state));
        }
    }

    #[test]
    fn unknown_state_string_is_rejected() {
        assert_eq!(OutboxState::from_wire("bogus"), None);
        assert_eq!(OutboxState::from_wire(""), None);
    }

    #[test]
    fn dequeue_sql_uses_for_update_skip_locked() {
        // Regression guard: removing SKIP LOCKED silently
        // re-introduces duplicate-send races across worker replicas.
        assert!(
            DEQUEUE_SQL.contains("FOR UPDATE SKIP LOCKED"),
            "dequeue must row-lock with SKIP LOCKED; SQL was: {DEQUEUE_SQL}",
        );
        assert!(
            DEQUEUE_SQL.contains("state IN ('queued','failed')"),
            "dequeue must only consider retriable states",
        );
        assert!(
            DEQUEUE_SQL.contains("LIMIT 1"),
            "one row per locked transaction",
        );
    }

    #[test]
    fn redacted_error_caps_length_and_stays_safe() {
        use zagrosi_core::{EmailTransportFault, PermanentFaultCategory, RedactedString};

        let permanent = EmailTransportError::Permanent {
            fault: EmailTransportFault {
                category: PermanentFaultCategory::InvalidRecipient,
                smtp_code: Some(550),
                redacted_detail: RedactedString::new("bob@secret.example".into()),
            },
        };
        let rendered = redacted_error(&permanent);
        assert!(rendered.contains("invalid recipient"));
        assert!(!rendered.contains("bob@secret.example"));

        let long = EmailTransportError::Unavailable("x".repeat(5_000));
        assert!(redacted_error(&long).len() <= 500);
    }

    #[test]
    fn dispatch_row_builds_message_preserving_idempotency_key() {
        let row = DispatchRow {
            id: Uuid::nil(),
            org_id: None,
            to_address: "to@example.com".into(),
            from_address: "from@example.com".into(),
            subject: "Hi".into(),
            body_text: "Body".into(),
            body_html: Some("<p>Body</p>".into()),
            idempotency_key: "idem-123".into(),
            attempts: 0,
        };
        let msg = row.to_message();
        assert_eq!(msg.idempotency_key, "idem-123");
        assert_eq!(msg.to, "to@example.com");
        assert_eq!(msg.body_html.as_deref(), Some("<p>Body</p>"));
    }
}
