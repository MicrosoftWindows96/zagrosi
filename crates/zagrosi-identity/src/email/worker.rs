// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown)]
//! Email-outbox worker run-loop.
//!
//! [`EmailWorker`] drains `email_outbox` by repeatedly calling
//! [`OutboxDispatcher::process_one`]. Two things wake a drain:
//!
//! 1. A periodic sweep ([`EmailWorker::with_sweep_interval`],
//!    default 30 s) — the authoritative liveness mechanism. The DB
//!    outbox is the source of truth; even with NATS completely down
//!    every row is eventually delivered by the sweep.
//! 2. A NATS hint on `email.outbox.queue` — a latency optimisation
//!    only. The producer publishes (best-effort, post-commit) so a
//!    freshly enqueued mail is sent in well under a second instead of
//!    waiting up to one sweep interval. The hint payload is ignored;
//!    its arrival just triggers an immediate drain (the worker always
//!    re-reads from the DB).
//!
//! The NATS subscription feeds an internal [`tokio::sync::Notify`].
//! Tests poke that `Notify` directly via [`EmailWorker::waker`] to
//! exercise the wake path deterministically without a broker.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};
use zagrosi_core::EmailTransport;

use crate::email::dispatch::{OutboxDispatcher, ProcessOutcome};

/// NATS subject the producer publishes wake hints on and the worker
/// subscribes to. The payload is intentionally unused.
pub const EMAIL_OUTBOX_SUBJECT: &str = "email.outbox.queue";

/// Default periodic sweep cadence.
const DEFAULT_SWEEP: Duration = Duration::from_secs(30);
/// Default rows drained per wake before yielding back to the select.
const DEFAULT_BATCH: u32 = 50;

/// Tally of one [`EmailWorker::drain_once`] pass. Returned for test
/// assertions; the same numbers are emitted as metrics.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DrainOutcome {
    /// Rows delivered to the transport this pass.
    pub sent: u64,
    /// Rows that hit a transient failure and were rescheduled.
    pub retried: u64,
    /// Rows dead-lettered (retry cap reached or permanent fault).
    pub dead: u64,
}

impl DrainOutcome {
    /// Total rows processed (`sent + retried + dead`).
    #[must_use]
    pub const fn processed(&self) -> u64 {
        self.sent + self.retried + self.dead
    }
}

/// Drains `email_outbox`, sending via the injected transport.
pub struct EmailWorker {
    dispatcher: OutboxDispatcher,
    transport: Arc<dyn EmailTransport>,
    sweep_interval: Duration,
    batch_size: u32,
    waker: Arc<Notify>,
    shutdown: CancellationToken,
}

impl EmailWorker {
    /// Construct with default sweep (30 s) and batch (50).
    #[must_use]
    pub fn new(dispatcher: OutboxDispatcher, transport: Arc<dyn EmailTransport>) -> Self {
        Self {
            dispatcher,
            transport,
            sweep_interval: DEFAULT_SWEEP,
            batch_size: DEFAULT_BATCH,
            waker: Arc::new(Notify::new()),
            shutdown: CancellationToken::new(),
        }
    }

    /// Override the periodic sweep cadence.
    #[must_use]
    pub const fn with_sweep_interval(mut self, interval: Duration) -> Self {
        self.sweep_interval = interval;
        self
    }

    /// Override the per-wake drain batch size (floored at 1; a zero
    /// batch would make every drain a no-op and wedge the queue).
    #[must_use]
    pub const fn with_batch_size(mut self, batch: u32) -> Self {
        // `u32::max` routes through `Ord::max`, not const-stable on
        // the pinned toolchain; an explicit compare keeps this `const`.
        self.batch_size = if batch == 0 { 1 } else { batch };
        self
    }

    /// Supply an external cancellation token so the owning service
    /// can drive a clean shutdown.
    #[must_use]
    pub fn with_shutdown(mut self, token: CancellationToken) -> Self {
        self.shutdown = token;
        self
    }

    /// Handle used to wake an immediate drain. The NATS listener
    /// holds one; tests use it to exercise the wake path without a
    /// broker.
    #[must_use]
    pub fn waker(&self) -> Arc<Notify> {
        Arc::clone(&self.waker)
    }

    /// The shutdown token (clone-and-cancel to stop [`EmailWorker::run`]).
    #[must_use]
    pub fn shutdown_token(&self) -> CancellationToken {
        self.shutdown.clone()
    }

    /// Spawn the NATS wake-hint listener.
    ///
    /// Any message on [`EMAIL_OUTBOX_SUBJECT`] triggers an immediate
    /// drain. The loop re-arms the subscription on broker bounces with
    /// bounded backoff (mirrors the session-event subscriber). A
    /// dropped hint is harmless — the periodic sweep is the safety
    /// net — so subscription errors are logged, never fatal.
    ///
    /// Returns a [`tokio::task::JoinHandle`]; the owning service holds
    /// it so shutdown can abort the listener.
    #[must_use]
    pub fn spawn_nats_listener(&self, client: async_nats::Client) -> tokio::task::JoinHandle<()> {
        let waker = Arc::clone(&self.waker);
        let shutdown = self.shutdown.clone();
        tokio::spawn(async move {
            let mut backoff = Duration::from_millis(250);
            loop {
                if shutdown.is_cancelled() {
                    return;
                }
                tokio::select! {
                    () = shutdown.cancelled() => return,
                    result = run_nats_listener(&client, &waker) => {
                        match result {
                            Ok(()) => warn!(
                                "email-outbox NATS listener stream ended; restarting after backoff",
                            ),
                            Err(err) => error!(
                                %err,
                                "email-outbox NATS listener error; restarting after backoff",
                            ),
                        }
                    }
                }
                tokio::select! {
                    () = shutdown.cancelled() => return,
                    () = tokio::time::sleep(backoff) => {}
                }
                backoff = std::cmp::min(backoff * 2, Duration::from_secs(30));
            }
        })
    }

    /// Run until the shutdown token is cancelled.
    ///
    /// An initial drain runs immediately (the first interval tick
    /// fires at once), then on every sweep tick or wake hint. A DB
    /// error in a drain is logged and the loop continues — the next
    /// sweep retries; the worker never exits on a transient fault.
    pub async fn run(self) {
        let mut interval = tokio::time::interval(self.sweep_interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        info!(
            sweep_secs = self.sweep_interval.as_secs(),
            batch = self.batch_size,
            "email-outbox worker started",
        );
        loop {
            tokio::select! {
                () = self.shutdown.cancelled() => {
                    info!("email-outbox worker shutting down");
                    return;
                }
                _ = interval.tick() => {}
                () = self.waker.notified() => {
                    debug!("email-outbox worker woken by hint");
                }
            }
            self.drain_once().await;
        }
    }

    /// Drain up to `batch_size` rows. Logs and stops the pass on a DB
    /// error (the row stays eligible; the next sweep retries). Never
    /// panics, never propagates — a worker must not die on a bad row.
    pub async fn drain_once(&self) -> DrainOutcome {
        let mut outcome = DrainOutcome::default();
        for _ in 0..self.batch_size {
            let started = Instant::now();
            let transport = Arc::clone(&self.transport);
            let dispatcher = self.dispatcher.clone();
            // Process the row in a child task so a panic in a transport
            // impl (or anywhere in `process_one`) is caught as a
            // `JoinError` instead of unwinding the worker loop. A panic
            // drops the open transaction → Postgres rolls it back → the
            // row stays `queued`/`failed` and the next sweep retries.
            // No email lost, none double-sent. Honours the
            // "never panics, never propagates" contract above.
            let join = tokio::spawn(async move {
                dispatcher
                    .process_one(move |msg| async move { transport.send(msg).await })
                    .await
            })
            .await;
            let result = match join {
                Ok(r) => r,
                Err(panic) => {
                    metrics::counter!("email_outbox_dispatch_errors_total").increment(1);
                    error!(
                        %panic,
                        "email-outbox row processing panicked; isolated, ending sweep early",
                    );
                    break;
                }
            };
            match result {
                Ok(None) => break,
                Ok(Some(ProcessOutcome::Sent { id })) => {
                    record_send_duration(started.elapsed());
                    metrics::counter!("email_outbox_sent_total").increment(1);
                    debug!(outbox_id = %id, "email sent");
                    outcome.sent += 1;
                }
                Ok(Some(ProcessOutcome::Retried { id, attempts })) => {
                    record_send_duration(started.elapsed());
                    metrics::counter!("email_outbox_attempt_failures_total").increment(1);
                    warn!(outbox_id = %id, attempts, "email send failed; rescheduled");
                    outcome.retried += 1;
                }
                Ok(Some(ProcessOutcome::DeadLettered { id, attempts })) => {
                    record_send_duration(started.elapsed());
                    metrics::counter!("email_outbox_dead_total").increment(1);
                    error!(
                        outbox_id = %id,
                        attempts,
                        "email dead-lettered (retry cap or permanent fault)",
                    );
                    outcome.dead += 1;
                }
                Err(err) => {
                    metrics::counter!("email_outbox_dispatch_errors_total").increment(1);
                    warn!(%err, "email-outbox dispatch error; ending sweep early");
                    break;
                }
            }
        }
        match self.dispatcher.pending_count().await {
            Ok(pending) => {
                // The metrics gauge API is f64. A backlog never
                // approaches 2^52 rows, so the precision loss is
                // unreachable in practice; the lint is allowed
                // locally rather than papered over with a lossy cast.
                #[allow(clippy::cast_precision_loss)]
                let pending_f = pending as f64;
                metrics::gauge!("email_outbox_pending_total").set(pending_f);
            }
            Err(err) => debug!(%err, "email-outbox pending_count sample failed"),
        }
        outcome
    }
}

fn record_send_duration(elapsed: Duration) {
    metrics::histogram!("email_outbox_send_duration_seconds").record(elapsed.as_secs_f64());
}

async fn run_nats_listener(
    client: &async_nats::Client,
    waker: &Notify,
) -> Result<(), async_nats::SubscribeError> {
    use futures::StreamExt as _;

    let mut sub = client.subscribe(EMAIL_OUTBOX_SUBJECT).await?;
    info!(
        subject = EMAIL_OUTBOX_SUBJECT,
        "email-outbox NATS listener armed"
    );
    while sub.next().await.is_some() {
        // Payload ignored: the hint only means "drain now"; the
        // worker always re-reads the DB (the source of truth).
        waker.notify_one();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use static_assertions::assert_impl_all;

    assert_impl_all!(EmailWorker: Send, Sync);
    assert_impl_all!(DrainOutcome: Send, Sync, Copy);

    #[test]
    fn subject_is_stable() {
        assert_eq!(EMAIL_OUTBOX_SUBJECT, "email.outbox.queue");
    }

    #[test]
    fn drain_outcome_processed_sums_all_terminal_states() {
        let o = DrainOutcome {
            sent: 3,
            retried: 2,
            dead: 1,
        };
        assert_eq!(o.processed(), 6);
        assert_eq!(DrainOutcome::default().processed(), 0);
    }

    // `#[tokio::test]`: sqlx's lazy pool requires a Tokio context
    // even though it never connects here.
    #[tokio::test]
    async fn batch_size_floor_is_one() {
        // A zero batch would make every drain a no-op and silently
        // wedge the queue. Clamp to at least one.
        let pool = sqlx::postgres::PgPool::connect_lazy("postgres://invalid")
            .expect("lazy pool never connects here");
        let dispatcher = OutboxDispatcher::new(pool);
        let transport: Arc<dyn EmailTransport> = Arc::new(NoopTransport);
        let worker = EmailWorker::new(dispatcher, transport).with_batch_size(0);
        assert_eq!(worker.batch_size, 1);
    }

    struct NoopTransport;

    #[async_trait::async_trait]
    impl EmailTransport for NoopTransport {
        async fn send(
            &self,
            _message: zagrosi_core::EmailMessage,
        ) -> Result<(), zagrosi_core::EmailTransportError> {
            Ok(())
        }
    }
}
