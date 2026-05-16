// SPDX-License-Identifier: AGPL-3.0-or-later

//! Email-outbox worker integration tests.
//!
//! These exercise the consumer side ([`zagrosi_identity::email`])
//! against a real Postgres container (per the `tests/common` harness)
//! using a **mock transport**. The mock makes the dequeue / retry /
//! dead-letter / SKIP-LOCKED / idempotency / wake behaviour fully
//! deterministic without an SMTP server. Live SMTP-to-Mailpit
//! delivery is covered once the dev compose stack lands in
//! section-16; the trait seam is identical so the worker logic under
//! test here is the same code that runs in production.

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use sqlx::PgPool;
use sqlx::Row as _;
use tokio::sync::Mutex;
use uuid::Uuid;
use zagrosi_core::{
    EmailMessage, EmailTransport, EmailTransportError, EmailTransportFault, PermanentFaultCategory,
    RedactedString,
};
use zagrosi_identity::email::{EmailOutboxWriter, EnqueueRequest, TemplateName};
use zagrosi_identity::{EmailWorker, OutboxDispatcher};

use common::{TestResult, migrated_env};

/// Scripted transport behaviour.
#[derive(Clone, Copy)]
enum Mode {
    /// Always accept.
    Ok,
    /// Always transient-fail (drives the retry/cap path).
    Unavailable,
    /// Always permanent-fail (drives immediate dead-letter).
    Permanent,
}

/// Records every message the worker hands it.
struct MockTransport {
    mode: Mode,
    sent: Arc<Mutex<Vec<EmailMessage>>>,
    calls: Arc<AtomicUsize>,
}

impl MockTransport {
    fn new(mode: Mode) -> Self {
        Self {
            mode,
            sent: Arc::new(Mutex::new(Vec::new())),
            calls: Arc::new(AtomicUsize::new(0)),
        }
    }
}

#[async_trait::async_trait]
impl EmailTransport for MockTransport {
    async fn send(&self, message: EmailMessage) -> Result<(), EmailTransportError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        match self.mode {
            Mode::Ok => {
                self.sent.lock().await.push(message);
                Ok(())
            }
            Mode::Unavailable => Err(EmailTransportError::Unavailable("scripted blip".into())),
            Mode::Permanent => Err(EmailTransportError::Permanent {
                fault: EmailTransportFault {
                    category: PermanentFaultCategory::InvalidRecipient,
                    smtp_code: Some(550),
                    redacted_detail: RedactedString::new("scripted".into()),
                },
            }),
        }
    }
}

/// Insert a `queued` outbox row directly (bypasses the producer for
/// bulk seeding). `org_id` is left NULL so no `orgs` FK row is needed.
async fn seed_queued(pool: &PgPool, to: &str, idem: &str) -> TestResult<Uuid> {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO email_outbox \
         (id, org_id, to_address, from_address, subject, body_text, body_html, \
          template_key, locale, idempotency_key, state, attempts, next_attempt_at) \
         VALUES ($1, NULL, $2, 'no-reply@zagrosi.test', 'Subject', 'Body', NULL, \
                 'verify_email', 'en', $3, 'queued', 0, now())",
    )
    .bind(id)
    .bind(to)
    .bind(idem)
    .execute(pool)
    .await?;
    Ok(id)
}

async fn state_of(pool: &PgPool, id: Uuid) -> TestResult<(String, i32)> {
    let row = sqlx::query("SELECT state, attempts FROM email_outbox WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await?;
    Ok((row.get::<String, _>("state"), row.get::<i32, _>("attempts")))
}

/// Make a `failed`/`queued` row immediately eligible again so the
/// retry-cap path can be driven without sleeping through the backoff.
async fn rearm(pool: &PgPool, id: Uuid) -> TestResult<()> {
    sqlx::query("UPDATE email_outbox SET next_attempt_at = now() WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

#[tokio::test]
async fn producer_enqueue_then_worker_sends_once() -> TestResult {
    let env = migrated_env().await?;
    let mock = Arc::new(MockTransport::new(Mode::Ok));
    let sent = Arc::clone(&mock.sent);

    // Producer side: write the row inside a transaction, commit, then
    // the (no-op) post-commit notify.
    let writer = EmailOutboxWriter::new();
    let mut tx = env.pool.begin().await?;
    let req = EnqueueRequest {
        user_id: Uuid::now_v7(),
        org_id: None,
        recipient: "alice@example.com".into(),
        from_address: "no-reply@zagrosi.test".into(),
        template: TemplateName::VerifyEmail,
        subject: "Confirm your email".into(),
        body_text: "Visit https://zagrosi.test/verify".into(),
        body_html: None,
        correlation_id: Uuid::now_v7(),
    };
    writer.enqueue(&mut tx, &req).await?;
    tx.commit().await?;

    let worker = EmailWorker::new(OutboxDispatcher::new(env.pool.clone()), mock.clone());
    let outcome = worker.drain_once().await;

    assert_eq!(outcome.sent, 1, "exactly one row sent");
    assert_eq!(outcome.processed(), 1);
    // Snapshot under the lock, release it, then assert — no guard
    // held across an assert temporary or the second drain's `.await`.
    let (count, first) = {
        let captured = sent.lock().await;
        (captured.len(), captured.first().cloned())
    };
    assert_eq!(count, 1);
    let first = first.expect("one message captured");
    assert_eq!(first.to, "alice@example.com");
    assert_eq!(first.subject, "Confirm your email");

    // A second drain has nothing to do (row is now `sent`).
    let again = worker.drain_once().await;
    assert_eq!(again.processed(), 0, "sent rows are not re-dequeued");
    Ok(())
}

#[tokio::test]
async fn concurrent_workers_no_duplicate_no_loss() -> TestResult {
    const N: usize = 60;
    let env = migrated_env().await?;
    for i in 0..N {
        seed_queued(
            &env.pool,
            &format!("user{i}@example.com"),
            &format!("idem-{i}"),
        )
        .await?;
    }

    let mock = Arc::new(MockTransport::new(Mode::Ok));
    let dispatcher = OutboxDispatcher::new(env.pool.clone());

    // Two independent drain loops racing the same backlog. SKIP
    // LOCKED must hand each row to exactly one of them.
    let drain = |disp: OutboxDispatcher, m: Arc<MockTransport>| async move {
        loop {
            let m2 = Arc::clone(&m);
            match disp
                .process_one(move |msg| async move { m2.send(msg).await })
                .await
                .expect("dispatch ok")
            {
                Some(_) => {}
                None => break,
            }
        }
    };
    let a = tokio::spawn(drain(dispatcher.clone(), mock.clone()));
    let b = tokio::spawn(drain(dispatcher.clone(), mock.clone()));
    a.await?;
    b.await?;

    // Snapshot counts under the lock, release it, then assert (no
    // guard held across an assert temporary or the DB `.await`).
    let (count, unique_count) = {
        let captured = mock.sent.lock().await;
        let unique: std::collections::HashSet<_> = captured.iter().map(|m| m.to.clone()).collect();
        (captured.len(), unique.len())
    };
    assert_eq!(count, N, "every row sent exactly once");
    assert_eq!(unique_count, N, "no duplicate sends across workers");

    let pending: i64 =
        sqlx::query_scalar("SELECT count(*) FROM email_outbox WHERE state <> 'sent'")
            .fetch_one(&env.pool)
            .await?;
    assert_eq!(pending, 0, "no row left unsent");
    Ok(())
}

#[tokio::test]
async fn transient_failure_retries_then_dead_letters_at_cap() -> TestResult {
    let env = migrated_env().await?;
    let id = seed_queued(&env.pool, "bob@example.com", "idem-cap").await?;

    let mock = Arc::new(MockTransport::new(Mode::Unavailable));
    let worker = EmailWorker::new(OutboxDispatcher::new(env.pool.clone()), mock.clone());

    // Five attempts: attempts 1..=4 reschedule (`failed`), the 5th
    // dead-letters. Re-arm between attempts to skip the backoff wait.
    for expected_attempt in 1..=5 {
        let out = worker.drain_once().await;
        assert_eq!(out.processed(), 1, "the one row was processed");
        let (state, attempts) = state_of(&env.pool, id).await?;
        assert_eq!(attempts, expected_attempt, "attempt counter increments");
        if expected_attempt < 5 {
            assert_eq!(state, "failed", "below cap → rescheduled");
            assert_eq!(out.retried, 1);
            rearm(&env.pool, id).await?;
        } else {
            assert_eq!(state, "dead", "cap reached → dead-lettered");
            assert_eq!(out.dead, 1);
        }
    }
    assert_eq!(
        mock.calls.load(Ordering::SeqCst),
        5,
        "exactly 5 send attempts"
    );

    // A dead row is never retried again.
    rearm(&env.pool, id).await?;
    let after = worker.drain_once().await;
    assert_eq!(after.processed(), 0, "dead rows are terminal");
    Ok(())
}

#[tokio::test]
async fn permanent_fault_dead_letters_immediately() -> TestResult {
    let env = migrated_env().await?;
    let id = seed_queued(&env.pool, "carol@example.com", "idem-perm").await?;

    let mock = Arc::new(MockTransport::new(Mode::Permanent));
    let worker = EmailWorker::new(OutboxDispatcher::new(env.pool.clone()), mock.clone());

    let out = worker.drain_once().await;
    assert_eq!(out.dead, 1, "permanent fault → dead on first attempt");
    let (state, attempts) = state_of(&env.pool, id).await?;
    assert_eq!(state, "dead");
    assert_eq!(attempts, 1, "no retry spin for a permanent fault");
    Ok(())
}

#[tokio::test]
async fn idempotency_key_prevents_duplicate_enqueue_and_send() -> TestResult {
    let env = migrated_env().await?;
    let mock = Arc::new(MockTransport::new(Mode::Ok));
    let writer = EmailOutboxWriter::new();

    // Same producer call (same user/template/correlation) twice — a
    // double-submitted sign-up form. The partial unique index
    // collapses it to one row via ON CONFLICT DO NOTHING.
    let req = EnqueueRequest {
        user_id: Uuid::from_u128(42),
        org_id: None,
        recipient: "dave@example.com".into(),
        from_address: "no-reply@zagrosi.test".into(),
        template: TemplateName::VerifyEmail,
        subject: "Confirm your email".into(),
        body_text: "verify".into(),
        body_html: None,
        correlation_id: Uuid::from_u128(99),
    };
    for _ in 0..2 {
        let mut tx = env.pool.begin().await?;
        writer.enqueue(&mut tx, &req).await?;
        tx.commit().await?;
    }
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM email_outbox")
        .fetch_one(&env.pool)
        .await?;
    assert_eq!(rows, 1, "duplicate enqueue collapsed to one row");

    let worker = EmailWorker::new(OutboxDispatcher::new(env.pool.clone()), mock.clone());
    worker.drain_once().await;
    assert_eq!(
        mock.calls.load(Ordering::SeqCst),
        1,
        "only one email delivered for the de-duplicated request",
    );
    Ok(())
}

#[tokio::test]
async fn nats_publish_failure_does_not_lose_email() -> TestResult {
    // The producer's `notify` is a best-effort no-op until the worker
    // process wires NATS; with no broker at all the periodic sweep is
    // the delivery guarantee. Enqueue, never publish, drain via the
    // sweep path → still delivered.
    let env = migrated_env().await?;
    let mock = Arc::new(MockTransport::new(Mode::Ok));
    let writer = EmailOutboxWriter::new();
    let mut tx = env.pool.begin().await?;
    let req = EnqueueRequest {
        user_id: Uuid::now_v7(),
        org_id: None,
        recipient: "erin@example.com".into(),
        from_address: "no-reply@zagrosi.test".into(),
        template: TemplateName::PasswordReset,
        subject: "Reset your password".into(),
        body_text: "reset".into(),
        body_html: None,
        correlation_id: Uuid::now_v7(),
    };
    writer.enqueue(&mut tx, &req).await?;
    tx.commit().await?;
    // Deliberately do NOT call writer.notify(...) — simulate a lost
    // wake hint.
    let worker = EmailWorker::new(OutboxDispatcher::new(env.pool.clone()), mock.clone());
    let out = worker.drain_once().await;
    assert_eq!(out.sent, 1, "sweep delivers even with no wake hint");
    Ok(())
}

#[tokio::test]
async fn waker_triggers_immediate_drain_well_under_one_second() -> TestResult {
    // A long sweep interval guarantees the row can only be delivered
    // via the wake path within the test window.
    let env = migrated_env().await?;
    let mock = Arc::new(MockTransport::new(Mode::Ok));
    let worker = EmailWorker::new(OutboxDispatcher::new(env.pool.clone()), mock.clone())
        .with_sweep_interval(Duration::from_secs(3_600));
    let waker = worker.waker();
    let shutdown = worker.shutdown_token();
    let calls = Arc::clone(&mock.calls);

    let handle = tokio::spawn(worker.run());

    // Let the worker reach its select! and consume the immediate
    // first interval tick (which finds an empty table).
    tokio::time::sleep(Duration::from_millis(150)).await;
    seed_queued(&env.pool, "frank@example.com", "idem-wake").await?;

    let start = Instant::now();
    waker.notify_one();

    // Poll for the delivery; assert it lands well under a second.
    loop {
        if calls.load(Ordering::SeqCst) >= 1 {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "wake hint must drain within 1s (elapsed {:?})",
            start.elapsed(),
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    shutdown.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
    Ok(())
}
