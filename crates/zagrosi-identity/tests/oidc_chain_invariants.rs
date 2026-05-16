// SPDX-License-Identifier: AGPL-3.0-or-later

//! Section-10 spec-mandated invariant tests.
//!
//! Covers the JIT + refresh-chain + pending-row replay invariants
//! enumerated in `docs/02-identity-sso-scim/sections/section-10-oidc-client.md`
//! that do not require a live IdP (Authentik integration lives in the
//! upcoming test-compose section). Each test runs against an
//! ephemeral Postgres container with the full identity migration set
//! applied, then exercises the OIDC repo + service surfaces directly.

#![allow(
    clippy::missing_panics_doc,
    clippy::too_many_lines,
    clippy::expect_used,
    clippy::needless_raw_string_hashes,
    clippy::doc_markdown,
    clippy::used_underscore_binding
)]

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use chrono::Utc;
use serial_test::serial;
use sqlx::PgPool;
use uuid::Uuid;
use zagrosi_core::{AuditEvent, AuditEventKind, AuditEventV1, Auditor};
use zagrosi_identity::oidc::{JitInput, JitProvisioner, RefreshChain, ReplayContext};
use zagrosi_identity::repo::{
    FederatedIdentityRepo, MembershipRepo, NewOidcPending, NewOidcRefresh, NewSession,
    OidcPendingRepo, OidcRefreshRepo, SessionRepo, UserRepo,
};
use zagrosi_identity::session::{SessionCache, SessionEventBus, SessionRevoker};

use common::{TestEnv, TestResult, migrated_env, seed_org, seed_user};

/// Capture-and-store auditor for assertion-based tests. Cheap to clone
/// (`Arc<Mutex<...>>`); every recorded event is appended verbatim.
#[derive(Clone, Default)]
struct CaptureAuditor {
    events: Arc<Mutex<Vec<AuditEvent>>>,
}

impl CaptureAuditor {
    fn new() -> Self {
        Self::default()
    }
    fn snapshot(&self) -> Vec<AuditEvent> {
        self.events.lock().expect("auditor mutex poisoned").clone()
    }
}

#[async_trait]
impl Auditor for CaptureAuditor {
    async fn record(&self, event: AuditEvent) {
        self.events
            .lock()
            .expect("auditor mutex poisoned")
            .push(event);
    }
}

/// Seed an `org_idps` row + a session row + a refresh chain. Returns
/// the (`session_id`, parent refresh-token id, parent token hash) tuple
/// the chain tests need.
async fn seed_session_and_refresh(
    pool: &PgPool,
    user_id: Uuid,
    org_id: Uuid,
    session_token_hash: &[u8; 32],
    refresh_token_hash: &[u8; 32],
) -> TestResult<(Uuid, Uuid)> {
    let session_id = Uuid::now_v7();
    sqlx::query(
        r#"
        INSERT INTO sessions (
            id, user_id, org_id, token_hash, expires_at, amr, acr
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        "#,
    )
    .bind(session_id)
    .bind(user_id)
    .bind(org_id)
    .bind(&session_token_hash[..])
    .bind(Utc::now() + chrono::Duration::days(7))
    .bind::<Vec<String>>(vec!["pwd".into()])
    .bind::<Option<String>>(None)
    .execute(pool)
    .await?;

    let parent_id = Uuid::now_v7();
    sqlx::query(
        r#"
        INSERT INTO oidc_refresh_tokens (id, session_id, token_hash, prev_id)
        VALUES ($1, $2, $3, $4)
        "#,
    )
    .bind(parent_id)
    .bind(session_id)
    .bind(&refresh_token_hash[..])
    .bind::<Option<Uuid>>(None)
    .execute(pool)
    .await?;

    Ok((session_id, parent_id))
}

async fn seed_idp(pool: &PgPool, org_id: Uuid) -> TestResult<Uuid> {
    let id = Uuid::now_v7();
    sqlx::query(
        r#"
        INSERT INTO org_idps (id, org_id, protocol, display_name, config, config_version)
        VALUES ($1, $2, 'oidc', 'Test IdP', '{"version":"1"}'::jsonb, 1)
        "#,
    )
    .bind(id)
    .bind(org_id)
    .execute(pool)
    .await?;
    Ok(id)
}

/// `test_refresh_insert_links_prev_id`
#[tokio::test]
#[serial]
async fn refresh_insert_links_prev_id() -> TestResult {
    let env: TestEnv = migrated_env().await?;
    let user_id = seed_user(&env.pool, "rl@example.com").await?;
    let org_id = seed_org(&env.pool, "rl-org").await?;
    let parent_hash = [0x11_u8; 32];
    let session_hash = [0x22_u8; 32];
    let (session_id, parent_id) =
        seed_session_and_refresh(&env.pool, user_id, org_id, &session_hash, &parent_hash).await?;

    let repo = OidcRefreshRepo::new(env.pool.clone());
    let child_hash = [0x33_u8; 32];
    let child = repo
        .insert(NewOidcRefresh {
            id: Uuid::now_v7(),
            session_id,
            token_hash: &child_hash,
            prev_id: Some(parent_id),
        })
        .await?;
    assert_eq!(
        child.prev_id,
        Some(parent_id),
        "child row must link back to the parent via prev_id",
    );
    Ok(())
}

/// `test_refresh_use_transitions_used_at`
#[tokio::test]
#[serial]
async fn refresh_use_transitions_used_at() -> TestResult {
    let env = migrated_env().await?;
    let user_id = seed_user(&env.pool, "ru@example.com").await?;
    let org_id = seed_org(&env.pool, "ru-org").await?;
    let parent_hash = [0x44_u8; 32];
    let session_hash = [0x55_u8; 32];
    let (_session_id, parent_id) =
        seed_session_and_refresh(&env.pool, user_id, org_id, &session_hash, &parent_hash).await?;
    let _ = _session_id;

    let repo = OidcRefreshRepo::new(env.pool.clone());
    repo.mark_used(parent_id, Utc::now()).await?;
    let row = repo
        .find_by_token_hash(&parent_hash)
        .await?
        .expect("row visible after mark_used; lookup no longer filters used_at");
    assert!(row.used_at.is_some(), "used_at must transition to now()");
    Ok(())
}

/// Build a `RefreshChain` wired to the test pool. The session revoker
/// runs against a disabled `SessionEventBus` so the publish call is
/// a no-op (no broker required) and the local cache is fresh per
/// test invocation.
fn build_refresh_chain(pool: PgPool, auditor: Arc<CaptureAuditor>) -> RefreshChain {
    let cache = SessionCache::new(64, Duration::from_secs(30));
    let bus = Arc::new(SessionEventBus::disabled());
    let revoker = Arc::new(SessionRevoker::new(
        SessionRepo::new(pool.clone()),
        cache,
        bus,
    ));
    RefreshChain::new(
        OidcRefreshRepo::new(pool.clone()),
        SessionRepo::new(pool.clone()),
        revoker,
        auditor,
        pool,
    )
}

/// Drive the seed + replay scenario shared by the three replay tests
/// below. Returns the (session_id, captured-event-list, expected
/// correlation id) tuple so individual tests can assert distinct
/// invariants without re-running the seed.
async fn drive_replay_scenario(env: &TestEnv) -> TestResult<(Uuid, Vec<AuditEventV1>, Uuid)> {
    let user_id = seed_user(&env.pool, &format!("rr-{}@example.com", Uuid::now_v7())).await?;
    let org_id = seed_org(&env.pool, &format!("rr-org-{}", Uuid::now_v7())).await?;
    let parent_raw = "rsk_parent_supersecret_value_for_test";
    let session_hash = [0x66_u8; 32];
    let parent_hash = sha256(parent_raw.as_bytes());
    let (session_id, _parent_id) =
        seed_session_and_refresh(&env.pool, user_id, org_id, &session_hash, &parent_hash).await?;

    let auditor = Arc::new(CaptureAuditor::new());
    let chain = build_refresh_chain(env.pool.clone(), auditor.clone());

    // Legitimate rotation seeds the chain so the replay below has a
    // child row to fall against.
    let new_raw = "rsk_child_supersecret_value_for_test";
    let correlation_id = Uuid::now_v7();
    let ctx = ReplayContext {
        correlation_id: Some(correlation_id),
    };
    let _ = chain.rotate(parent_raw, new_raw, ctx).await?;

    let replay = chain.rotate(parent_raw, "another_value", ctx).await;
    assert!(
        matches!(
            replay,
            Err(zagrosi_identity::IdentityError::RefreshChainReplay)
        ),
        "replay must surface typed RefreshChainReplay",
    );
    let events = auditor
        .snapshot()
        .into_iter()
        .filter_map(|e| match e {
            AuditEvent::V1(payload) => Some(payload),
            _ => None,
        })
        .collect();
    Ok((session_id, events, correlation_id))
}

/// `test_refresh_replay_revokes_chain` — chain rows must all be
/// revoked after replay.
#[tokio::test]
#[serial]
async fn refresh_replay_revokes_chain() -> TestResult {
    let env = migrated_env().await?;
    let (session_id, _events, _) = drive_replay_scenario(&env).await?;
    let live: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM oidc_refresh_tokens WHERE session_id = $1 AND revoked_at IS NULL",
    )
    .bind(session_id)
    .fetch_one(&env.pool)
    .await?;
    assert_eq!(live, 0, "every chain row must be revoked on replay");
    Ok(())
}

/// `test_refresh_replay_leaves_no_usable_session` — parent session row
/// must carry a `revoked_at` after replay.
#[tokio::test]
#[serial]
async fn refresh_replay_leaves_no_usable_session() -> TestResult {
    let env = migrated_env().await?;
    let (session_id, _, _) = drive_replay_scenario(&env).await?;
    let session_revoked: Option<chrono::DateTime<Utc>> =
        sqlx::query_scalar("SELECT revoked_at FROM sessions WHERE id = $1")
            .bind(session_id)
            .fetch_one(&env.pool)
            .await?;
    assert!(
        session_revoked.is_some(),
        "parent session must carry a revoked_at after replay",
    );
    Ok(())
}

/// `test_refresh_replay_emits_audit_event` — `OidcRefreshReplay` and
/// `SuspectedTokenReplay` audit pair must be emitted with a shared
/// `correlation_id` propagated from `ReplayContext`.
#[tokio::test]
#[serial]
async fn refresh_replay_emits_audit_event() -> TestResult {
    let env = migrated_env().await?;
    let (_session_id, events, expected_correlation) = drive_replay_scenario(&env).await?;
    let kinds: Vec<_> = events
        .iter()
        .map(zagrosi_core::AuditEventV1::event_kind)
        .collect();
    assert!(
        kinds.contains(&AuditEventKind::OidcRefreshReplay),
        "OidcRefreshReplay must be emitted: got {kinds:?}",
    );
    assert!(
        kinds.contains(&AuditEventKind::SuspectedTokenReplay),
        "SuspectedTokenReplay must be emitted: got {kinds:?}",
    );
    let replay_events: Vec<&AuditEventV1> = events
        .iter()
        .filter(|e| {
            matches!(
                e.event_kind(),
                AuditEventKind::OidcRefreshReplay | AuditEventKind::SuspectedTokenReplay
            )
        })
        .collect();
    for event in &replay_events {
        assert_eq!(
            event.correlation_id(),
            expected_correlation,
            "every replay-family audit must carry the originating correlation id, not a fresh now_v7"
        );
    }
    Ok(())
}

/// `test_jit_default_requires_email_verified`
#[tokio::test]
#[serial]
async fn jit_default_requires_email_verified() -> TestResult {
    let env = migrated_env().await?;
    let org_id = seed_org(&env.pool, "jit-rev-org").await?;
    let idp_id = seed_idp(&env.pool, org_id).await?;
    let jit = JitProvisioner::new(
        UserRepo::new(env.pool.clone()),
        FederatedIdentityRepo::new(env.pool.clone()),
        MembershipRepo::new(env.pool.clone()),
    );

    let mut tx = env.pool.begin().await?;
    let result = jit
        .run(
            &mut tx,
            JitInput {
                org_id,
                org_idp_id: idp_id,
                issuer: "https://idp.example.com".into(),
                subject: "user-abc".into(),
                email: "Alice@Example.com".into(),
                email_lower: "alice@example.com".into(),
                display_name: "Alice".into(),
                email_verified: false,
                allow_unverified: false,
                default_role: "member".into(),
            },
            Utc::now(),
        )
        .await;
    let _ = tx.rollback().await;
    assert!(
        matches!(
            result,
            Err(zagrosi_identity::IdentityError::OidcEmailNotVerified)
        ),
        "default JIT path must reject email_verified=false; got {result:?}",
    );
    Ok(())
}

/// `test_jit_override_allows_unverified`
#[tokio::test]
#[serial]
async fn jit_override_allows_unverified() -> TestResult {
    let env = migrated_env().await?;
    let org_id = seed_org(&env.pool, "jit-ovr-org").await?;
    let idp_id = seed_idp(&env.pool, org_id).await?;
    let jit = JitProvisioner::new(
        UserRepo::new(env.pool.clone()),
        FederatedIdentityRepo::new(env.pool.clone()),
        MembershipRepo::new(env.pool.clone()),
    );

    let mut tx = env.pool.begin().await?;
    let outcome = jit
        .run(
            &mut tx,
            JitInput {
                org_id,
                org_idp_id: idp_id,
                issuer: "https://idp.example.com".into(),
                subject: "user-ovr".into(),
                email: "ovr@example.com".into(),
                email_lower: "ovr@example.com".into(),
                display_name: "Override".into(),
                email_verified: false,
                allow_unverified: true,
                default_role: "member".into(),
            },
            Utc::now(),
        )
        .await?;
    tx.commit().await?;
    assert_eq!(outcome.user.email, "ovr@example.com");
    assert!(
        outcome.user.email_verified_at.is_none(),
        "override must NOT mark email_verified",
    );
    Ok(())
}

/// `test_jit_collision_rejects_no_auto_merge`
#[tokio::test]
#[serial]
async fn jit_collision_rejects_no_auto_merge() -> TestResult {
    let env = migrated_env().await?;
    let org_id = seed_org(&env.pool, "jit-col-org").await?;
    let idp_id = seed_idp(&env.pool, org_id).await?;
    seed_user(&env.pool, "collide@example.com").await?;

    let jit = JitProvisioner::new(
        UserRepo::new(env.pool.clone()),
        FederatedIdentityRepo::new(env.pool.clone()),
        MembershipRepo::new(env.pool.clone()),
    );

    let mut tx = env.pool.begin().await?;
    let result = jit
        .run(
            &mut tx,
            JitInput {
                org_id,
                org_idp_id: idp_id,
                issuer: "https://idp.example.com".into(),
                subject: "sub-collide".into(),
                email: "Collide@Example.com".into(),
                email_lower: "collide@example.com".into(),
                display_name: "Collide".into(),
                email_verified: true,
                allow_unverified: false,
                default_role: "member".into(),
            },
            Utc::now(),
        )
        .await;
    let _ = tx.rollback().await;
    assert!(
        matches!(
            result,
            Err(zagrosi_identity::IdentityError::OidcAccountAlreadyExists)
        ),
        "collision must surface OidcAccountAlreadyExists, not auto-merge: got {result:?}",
    );
    Ok(())
}

/// `test_jit_happy_path_atomic_inserts`
#[tokio::test]
#[serial]
async fn jit_happy_path_atomic_inserts() -> TestResult {
    let env = migrated_env().await?;
    let org_id = seed_org(&env.pool, "jit-hpy-org").await?;
    let idp_id = seed_idp(&env.pool, org_id).await?;
    let jit = JitProvisioner::new(
        UserRepo::new(env.pool.clone()),
        FederatedIdentityRepo::new(env.pool.clone()),
        MembershipRepo::new(env.pool.clone()),
    );

    let mut tx = env.pool.begin().await?;
    let outcome = jit
        .run(
            &mut tx,
            JitInput {
                org_id,
                org_idp_id: idp_id,
                issuer: "https://idp.example.com".into(),
                subject: "user-happy".into(),
                email: "Happy@Example.com".into(),
                email_lower: "happy@example.com".into(),
                display_name: "Happy".into(),
                email_verified: true,
                allow_unverified: false,
                default_role: "member".into(),
            },
            Utc::now(),
        )
        .await?;
    tx.commit().await?;

    // user row present + email_verified flipped.
    let user_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM users WHERE id = $1 AND email_verified_at IS NOT NULL",
    )
    .bind(outcome.user.id)
    .fetch_one(&env.pool)
    .await?;
    assert_eq!(
        user_count, 1,
        "JIT must insert user with email_verified set"
    );

    // anchor present.
    let anchor_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM federated_identities WHERE id = $1 AND user_id = $2",
    )
    .bind(outcome.anchor.id)
    .bind(outcome.user.id)
    .fetch_one(&env.pool)
    .await?;
    assert_eq!(anchor_count, 1);

    // membership present.
    let mem_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM user_org_memberships WHERE user_id = $1 AND org_id = $2 AND deleted_at IS NULL",
    )
    .bind(outcome.user.id)
    .bind(org_id)
    .fetch_one(&env.pool)
    .await?;
    assert_eq!(mem_count, 1);
    Ok(())
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

/// `test_callback_atomic_tx_rollback_on_session_insert_failure`
///
/// Regression for the lockout window the atomic-tx port closes: when
/// the session-row insert that runs at the tail of `OidcService::callback`
/// fails INSIDE the orchestration transaction, every earlier write in
/// that same transaction (JIT user, federated anchor, membership,
/// pending-row mark-used, anchor `last_login_at` bump) must roll back
/// uniformly.
///
/// Pre-fix the session insert ran AFTER `tx.commit()` so a session
/// insert failure left a JIT-provisioned user with a consumed pending
/// row but no session — the very next callback for the same `(iss,
/// sub)` would land on the orphaned anchor + user yet still fail to
/// mint a session, locking that user out.
///
/// The test forces the session insert to fail by colliding the
/// freshly minted `token_hash` with a pre-seeded live session row
/// (the partial unique `sessions_token_hash_unique_live` rejects the
/// duplicate). Then it verifies that ALL atomic-tx participants roll
/// back: JIT writes vanish AND the pending row's `used_at` stays
/// `NULL` AND the anchor `last_login_at` bump is gone (anchor itself
/// is gone).
#[tokio::test]
#[serial]
async fn callback_atomic_tx_rollback_on_session_insert_failure() -> TestResult {
    let env = migrated_env().await?;
    let pool = env.pool.clone();
    let org_id = seed_org(&pool, &format!("atom-{}", Uuid::now_v7())).await?;
    let idp_id = seed_idp(&pool, org_id).await?;

    // Seed a pre-existing user holding a live session whose
    // `token_hash` we pin. The partial unique
    // `sessions_token_hash_unique_live` will reject any second live
    // insert with the same hash — our mechanism for forcing the
    // in-tx session insert to fail.
    let pre_user = seed_user(&pool, &format!("pre-{}@example.com", Uuid::now_v7())).await?;
    let collision_hash = [0xCC_u8; 32];
    sqlx::query(
        r#"
        INSERT INTO sessions (id, user_id, token_hash, expires_at, amr)
        VALUES ($1, $2, $3, $4, $5)
        "#,
    )
    .bind(Uuid::now_v7())
    .bind(pre_user)
    .bind(&collision_hash[..])
    .bind(Utc::now() + chrono::Duration::days(7))
    .bind::<Vec<String>>(vec!["pwd".into()])
    .execute(&pool)
    .await?;

    // Seed the pending row that the callback orchestration would
    // mark used inside the tx. We pin known hashes so the post-
    // rollback assertion can re-fetch the row.
    let pending_repo = OidcPendingRepo::new(pool.clone());
    let state_hash = sha256(b"atomic-tx-test-state");
    let nonce_hash = sha256(b"atomic-tx-test-nonce");
    let verifier_hash = sha256(b"atomic-tx-test-verifier");
    let csrf_hash = sha256(b"atomic-tx-test-csrf");
    let pending = pending_repo
        .insert(NewOidcPending {
            id: Uuid::now_v7(),
            org_idp_id: idp_id,
            state_hash: &state_hash,
            nonce_hash: &nonce_hash,
            verifier_hash: &verifier_hash,
            csrf_cookie_hash: &csrf_hash,
            redirect_uri: "https://example.test/callback",
            expires_at: Utc::now() + chrono::Duration::minutes(10),
        })
        .await?;

    let jit = JitProvisioner::new(
        UserRepo::new(pool.clone()),
        FederatedIdentityRepo::new(pool.clone()),
        MembershipRepo::new(pool.clone()),
    );
    let session_repo = SessionRepo::new(pool.clone());

    // Open the orchestration tx and replay the production sequence:
    // JIT user provision → pending mark used → anchor last-login bump
    // → session insert (forced to fail). Production code propagates
    // the Err out of `callback_inner`; sqlx auto-rollbacks the dropped
    // tx. We mirror with an explicit rollback after the deliberate
    // failure for clarity.
    let mut tx = pool.begin().await?;

    // Use a single per-test email so the JIT path's collision check
    // does not race the seed user above.
    let email_local = Uuid::now_v7();
    let outcome = jit
        .run(
            &mut tx,
            JitInput {
                org_id,
                org_idp_id: idp_id,
                issuer: "https://idp.example.com".into(),
                subject: format!("sub-{email_local}"),
                email: format!("atom-{email_local}@example.com"),
                email_lower: format!("atom-{email_local}@example.com"),
                display_name: "Atom".into(),
                email_verified: true,
                allow_unverified: false,
                default_role: "member".into(),
            },
            Utc::now(),
        )
        .await?;

    pending_repo
        .mark_used(&mut tx, pending.id, Utc::now())
        .await?;

    jit.federated_update_last_login_in_tx(&mut tx, outcome.anchor.id, Utc::now())
        .await?;

    let insert_result = session_repo
        .insert_in_tx(
            &mut tx,
            NewSession {
                id: Uuid::now_v7(),
                token_hash: &collision_hash,
                user_id: outcome.user.id,
                org_id: Some(org_id),
                user_agent: None,
                ip_addr: None,
                amr: &["oidc"],
                acr: None,
                expires_at: Utc::now() + chrono::Duration::days(7),
            },
        )
        .await;
    assert!(
        insert_result.is_err(),
        "session insert must fail on token_hash collision (got {insert_result:?})",
    );

    tx.rollback().await?;

    // Atomic-tx contract: every earlier write in the same tx must
    // have rolled back. JIT user gone.
    let user_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE id = $1")
        .bind(outcome.user.id)
        .fetch_one(&pool)
        .await?;
    assert_eq!(
        user_count, 0,
        "JIT-provisioned user must roll back when the in-tx session insert fails",
    );

    // Federated anchor (the OIDC analogue of the SAML replay row)
    // gone.
    let anchor_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM federated_identities WHERE id = $1")
            .bind(outcome.anchor.id)
            .fetch_one(&pool)
            .await?;
    assert_eq!(
        anchor_count, 0,
        "federated anchor must roll back when the in-tx session insert fails",
    );

    // Membership gone.
    let mem_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM user_org_memberships WHERE user_id = $1 AND org_id = $2",
    )
    .bind(outcome.user.id)
    .bind(org_id)
    .fetch_one(&pool)
    .await?;
    assert_eq!(
        mem_count, 0,
        "membership must roll back when the in-tx session insert fails",
    );

    // Pending row's `used_at` still NULL — the mark-used flip in step
    // 8 of the callback orchestration rolled back with the tx.
    let pending_used_at: Option<chrono::DateTime<Utc>> =
        sqlx::query_scalar("SELECT used_at FROM oidc_pending_auth WHERE id = $1")
            .bind(pending.id)
            .fetch_one(&pool)
            .await?;
    assert!(
        pending_used_at.is_none(),
        "pending row used_at must remain NULL after tx rollback (got {pending_used_at:?})",
    );

    // Session row absent for the JIT user (the failed insert never
    // committed; no orphan rows).
    let session_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sessions WHERE user_id = $1")
        .bind(outcome.user.id)
        .fetch_one(&pool)
        .await?;
    assert_eq!(
        session_count, 0,
        "no session row must exist for the rolled-back JIT user",
    );

    Ok(())
}
