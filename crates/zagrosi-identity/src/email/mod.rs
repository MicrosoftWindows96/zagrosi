// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! Transactional email outbox — producer and consumer.
//!
//! The DB `email_outbox` table is authoritative: a row committed
//! alongside the user-state mutation IS the durable record that an
//! email must be delivered. NATS is only a wake-up hint; if the
//! publish fails the worker still drains the outbox on its next
//! periodic sweep, so no email is lost.
//!
//! ## Producer side ([`outbox`], [`template`])
//!
//! [`EmailOutboxWriter`] takes a borrowed transaction, forcing the
//! caller to fold the outbox insert into the same atomic unit as the
//! user-state mutation. The producer renders the subject + body at
//! enqueue time (so the worker performs no template rendering);
//! [`TemplateName`] records which template produced the row for
//! observability.
//!
//! ## Consumer side ([`dispatch`], [`transport`], [`retry`], [`worker`])
//!
//! [`worker::EmailWorker`] drains rows via
//! [`dispatch::OutboxDispatcher`] (one row per `FOR UPDATE SKIP
//! LOCKED` transaction → safe under N concurrent replicas), sends
//! through an [`zagrosi_core::EmailTransport`] (the default concrete
//! impl is [`transport::LettreTransport`]), and applies the
//! [`retry`] backoff schedule with dead-lettering at the attempt cap.

pub mod dispatch;
pub mod outbox;
pub mod retry;
pub mod template;
pub mod transport;
pub mod worker;

pub use dispatch::{DispatchRow, OutboxDispatcher, OutboxState, ProcessOutcome};
pub use outbox::{EmailOutboxWriter, EnqueueRequest};
pub use retry::{MAX_ATTEMPTS, next_attempt};
pub use template::TemplateName;
pub use transport::LettreTransport;
pub use worker::{DrainOutcome, EMAIL_OUTBOX_SUBJECT, EmailWorker};
