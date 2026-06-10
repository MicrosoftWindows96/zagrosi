// SPDX-License-Identifier: AGPL-3.0-or-later

//! Migration smoke + invariants for identity.
//!
//! These tests boot the `zagrosi-test-support` harness (custom Postgres 18
//! image, four runtime roles, ordered migration runner) per test and verify
//! the invariants documented in the migration set. Schema-level probes run
//! over the `zagrosi_migrate` pool — this file asserts owner-level DDL
//! invariants, not tenant traffic.
//!
//! Running these tests requires a Docker daemon. `PostgreSQL` 18 is the
//! platform floor (the custom image bundles `pg_partman`/`pg_parquet`; see
//! `deploy/docker/postgres/README.md` "Managed Postgres requirements"), so
//! the former PG-17 matrix variant is gone.

use serial_test::serial;
use sqlx::PgPool;
use std::error::Error;
use std::time::Duration;
use uuid::Uuid;
use zagrosi_test_support::TestDb;

/// Expected migration version timestamps (filename leading numeric
/// prefix). Used to assert manifest fidelity in the smoke test rather
/// than asserting that a `SELECT ... ORDER BY version` result is
/// already sorted (a tautology).
const EXPECTED_VERSIONS: [i64; 20] = [
    20_260_508_120_000,
    20_260_508_120_100,
    20_260_508_120_200,
    20_260_508_120_300,
    20_260_508_120_400,
    20_260_508_120_500,
    20_260_508_120_600,
    20_260_508_120_700,
    20_260_508_120_800,
    20_260_508_120_900,
    20_260_508_121_000,
    20_260_508_121_100,
    20_260_508_121_200,
    20_260_508_121_300,
    20_260_508_121_400,
    20_260_508_121_500,
    20_260_509_191_612,
    20_260_510_000_100,
    20_260_510_000_200,
    20_260_510_000_300,
];

/// Boxed dynamic error type used by the integration tests so any
/// failure (`testcontainers`, `sqlx`, parse errors) lifts via `?`.
type TestError = Box<dyn Error + Send + Sync>;
type TestResult = Result<(), TestError>;

/// Per-test fixture. Field declaration order *is* drop order: the pool
/// clone closes before the harness (and its container) stops. Callers
/// borrow `pool` directly and let `_db` keep the container alive.
struct TestEnv {
    pool: PgPool,
    _db: TestDb,
}

/// Boot the harness (custom image, roles, all migrations applied) and
/// yield the `zagrosi_migrate` pool — the owner-level connection this
/// schema-smoke file asserts against.
async fn migrated_env() -> Result<TestEnv, TestError> {
    let db = TestDb::new().await?;
    Ok(TestEnv {
        pool: db.migrate_pool().clone(),
        _db: db,
    })
}

/// Build a 32-byte BYTEA literal where every byte equals `byte`.
/// The migrations' `*_hash` columns expect 32-byte SHA-256 outputs but
/// the smoke tests only need fixed, distinguishable byte patterns —
/// using `digest()` would pull `pgcrypto`'s hashing path into the test
/// surface, which is out of scope for the migration set.
fn fixed_hash(byte: u8) -> Vec<u8> {
    vec![byte; 32]
}

/// Insert a minimal valid `orgs` row and return its UUID v7.
async fn seed_org(pool: &PgPool, slug: &str) -> Result<Uuid, TestError> {
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO orgs (id, slug, display_name) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(slug)
        .bind(slug)
        .execute(pool)
        .await?;
    Ok(id)
}

/// Insert a minimal valid `users` row and return its UUID v7.
async fn seed_user(pool: &PgPool, email: &str) -> Result<Uuid, TestError> {
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO users (id, email, display_name) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(email)
        .bind(email)
        .execute(pool)
        .await?;
    Ok(id)
}

/// Insert a minimal valid `org_idps` row and return its UUID v7.
async fn seed_org_idp(pool: &PgPool, org_id: Uuid, protocol: &str) -> Result<Uuid, TestError> {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO org_idps (id, org_id, protocol, display_name, config) \
         VALUES ($1, $2, $3, $4, '{}'::jsonb)",
    )
    .bind(id)
    .bind(org_id)
    .bind(protocol)
    .bind(format!("{protocol}-test"))
    .execute(pool)
    .await?;
    Ok(id)
}

#[tokio::test]
#[serial]
async fn identity_manifest_matches_expected_versions() -> TestResult {
    // The harness itself proves the clean apply (it migrates a fresh
    // container); this test pins the identity manifest fidelity. The
    // history table is shared across migration sets (see test-support's
    // migrations module), so filter to identity's versions.
    let env = migrated_env().await?;
    let pool = env.pool.clone();
    let versions: Vec<i64> = sqlx::query_scalar(
        "SELECT version FROM _sqlx_migrations WHERE version = ANY($1) ORDER BY version",
    )
    .bind(EXPECTED_VERSIONS.to_vec())
    .fetch_all(&pool)
    .await?;
    assert_eq!(
        versions,
        EXPECTED_VERSIONS.to_vec(),
        "applied migration versions must match the manifest timestamps verbatim"
    );
    assert!(
        versions.windows(2).all(|w| w[0] < w[1]),
        "migration versions must be strictly increasing"
    );
    Ok(())
}

#[tokio::test]
#[serial]
async fn migrate_is_idempotent() -> TestResult {
    let env = migrated_env().await?;
    let pool = env.pool.clone();
    zagrosi_test_support::run_all_migrations(&pool).await?;
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*)::BIGINT FROM _sqlx_migrations WHERE version = ANY($1)")
            .bind(EXPECTED_VERSIONS.to_vec())
            .fetch_one(&pool)
            .await?;
    assert_eq!(count, 20);
    Ok(())
}

#[tokio::test]
#[serial]
async fn each_table_is_independently_droppable_and_reapplies() -> TestResult {
    let env = migrated_env().await?;
    let pool = env.pool.clone();
    let tables = [
        "group_memberships",
        "groups",
        "saml_pending_auth",
        "service_tokens",
        "failed_signin_aggregates",
        "federated_identities",
        "saml_assertion_replay",
        "oidc_refresh_tokens",
        "oidc_pending_auth",
        "email_outbox",
        "scim_tokens",
        "org_idp_domains",
        "org_idps",
        "password_resets",
        "email_verifications",
        "api_tokens",
        "sessions",
        "user_org_memberships",
        "users",
        "orgs",
    ];
    for table in tables {
        let stmt = format!("DROP TABLE {table} CASCADE");
        sqlx::query(&stmt).execute(&pool).await?;
    }
    // Also clear the IDENTITY rows from the migrations bookkeeping so the
    // runner re-applies every identity migration end-to-end, proving the
    // bisect-friendly smoke check from the spec. Scoped DELETE (not DROP):
    // the history table is shared across migration sets, and dropping it
    // would erase rbac/audit bookkeeping while their schema objects
    // persist. The pool is the zagrosi_migrate role, so recreated objects
    // keep the correct owner.
    sqlx::query("DELETE FROM _sqlx_migrations WHERE version = ANY($1)")
        .bind(EXPECTED_VERSIONS.to_vec())
        .execute(&pool)
        .await?;
    zagrosi_test_support::run_all_migrations(&pool).await?;
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*)::BIGINT FROM _sqlx_migrations WHERE version = ANY($1)")
            .bind(EXPECTED_VERSIONS.to_vec())
            .fetch_one(&pool)
            .await?;
    assert_eq!(count, 20, "re-application should replay all 20 migrations");
    Ok(())
}

#[tokio::test]
#[serial]
async fn uuid_v7_sortable_by_creation_order() -> TestResult {
    let env = migrated_env().await?;
    let pool = env.pool.clone();
    let mut inserted_ids: Vec<Uuid> = Vec::with_capacity(8);
    for i in 0..8 {
        let id = Uuid::now_v7();
        sqlx::query("INSERT INTO users (id, email, display_name) VALUES ($1, $2, $3)")
            .bind(id)
            .bind(format!("user-{i}@example.com"))
            .bind(format!("User {i}"))
            .execute(&pool)
            .await?;
        inserted_ids.push(id);
        // 10 ms is well above kernel scheduler jitter so the host clock
        // advances strictly between successive `Uuid::now_v7()` calls,
        // even under noisy CI load.
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let by_id: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM users ORDER BY id")
        .fetch_all(&pool)
        .await?;
    // The strong assertion: the *order* of UUIDv7 IDs sorted by id matches
    // their creation order. We avoid the by-created-at equality assertion
    // because the host clock can theoretically step backwards within a
    // millisecond; the property under test is monotonic id ordering.
    assert!(
        inserted_ids.is_sorted(),
        "UUIDv7 sequence captured during the test should already be sorted by value"
    );
    assert_eq!(
        by_id, inserted_ids,
        "ORDER BY id must match insertion order for UUIDv7 PKs"
    );
    Ok(())
}

#[tokio::test]
#[serial]
async fn multi_tenant_tables_require_org_id() -> TestResult {
    let env = migrated_env().await?;
    let pool = env.pool.clone();
    let user_id = seed_user(&pool, "tenant@example.com").await?;
    let org_id = seed_org(&pool, "tenant-org").await?;
    // Each case is an INSERT that intentionally omits the tenant anchor
    // (`org_id` directly, OR `org_idp_id` for tables that anchor via an
    // FK chain through `org_idps`). The migration must reject every one
    // with a NOT NULL constraint violation.
    let cases: Vec<(&str, String)> = vec![
        (
            "user_org_memberships",
            format!(
                "INSERT INTO user_org_memberships (id, user_id, joined_via) \
                 VALUES ('{}'::uuid, '{user_id}'::uuid, 'manual')",
                Uuid::now_v7()
            ),
        ),
        (
            "api_tokens",
            format!(
                "INSERT INTO api_tokens (id, token_hash, user_id, display_name) \
                 VALUES ('{}'::uuid, decode('00','hex'), '{user_id}'::uuid, 'pat')",
                Uuid::now_v7()
            ),
        ),
        (
            "org_idps",
            format!(
                "INSERT INTO org_idps (id, protocol, display_name, config) \
                 VALUES ('{}'::uuid, 'oidc', 'idp', '{{}}'::jsonb)",
                Uuid::now_v7()
            ),
        ),
        (
            "scim_tokens",
            format!(
                "INSERT INTO scim_tokens (id, display_name, token_hash) \
                 VALUES ('{}'::uuid, 'scim', decode('00','hex'))",
                Uuid::now_v7()
            ),
        ),
        (
            "oidc_pending_auth",
            format!(
                "INSERT INTO oidc_pending_auth \
                 (id, state_hash, nonce_hash, verifier_hash, csrf_cookie_hash, redirect_uri, expires_at) \
                 VALUES ('{}'::uuid, decode(repeat('00', 32), 'hex'), decode(repeat('01', 32), 'hex'), \
                 decode(repeat('02', 32), 'hex'), decode(repeat('03', 32), 'hex'), \
                 'https://app/cb', now() + interval '5 min')",
                Uuid::now_v7()
            ),
        ),
        (
            "saml_assertion_replay",
            "INSERT INTO saml_assertion_replay (assertion_id, not_on_or_after) \
             VALUES ('aid', now() + interval '5 min')"
                .to_owned(),
        ),
        (
            "federated_identities",
            format!(
                "INSERT INTO federated_identities (id, protocol, issuer_or_entity_id, subject_or_nameid) \
                 VALUES ('{}'::uuid, 'oidc', 'iss', 'sub')",
                Uuid::now_v7()
            ),
        ),
    ];
    for (table, sql) in cases {
        let outcome = sqlx::query(&sql).execute(&pool).await;
        assert!(
            outcome.is_err(),
            "expected NOT NULL / FK violation for {table}, got success"
        );
    }
    // Sanity: filling in the tenant anchor lets the same shape succeed.
    let happy_membership = format!(
        "INSERT INTO user_org_memberships (id, user_id, org_id, joined_via) \
         VALUES ('{}'::uuid, '{user_id}'::uuid, '{org_id}'::uuid, 'manual')",
        Uuid::now_v7()
    );
    sqlx::query(&happy_membership).execute(&pool).await?;
    Ok(())
}

#[tokio::test]
#[serial]
async fn users_email_lower_is_auto_populated() -> TestResult {
    let env = migrated_env().await?;
    let pool = env.pool.clone();
    let user_id = Uuid::now_v7();
    sqlx::query("INSERT INTO users (id, email, display_name) VALUES ($1, $2, $3)")
        .bind(user_id)
        .bind("Alice@Example.COM")
        .bind("Alice")
        .execute(&pool)
        .await?;
    let lower: String = sqlx::query_scalar("SELECT email_lower FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(&pool)
        .await?;
    assert_eq!(lower, "alice@example.com");
    sqlx::query("UPDATE users SET email = $1 WHERE id = $2")
        .bind("Bob@Example.COM")
        .bind(user_id)
        .execute(&pool)
        .await?;
    let lower2: String = sqlx::query_scalar("SELECT email_lower FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(&pool)
        .await?;
    assert_eq!(lower2, "bob@example.com");
    Ok(())
}

#[tokio::test]
#[serial]
async fn users_password_hash_version_defaults_to_one() -> TestResult {
    let env = migrated_env().await?;
    let pool = env.pool.clone();
    let user_id = seed_user(&pool, "pwver@example.com").await?;
    let version: i16 = sqlx::query_scalar("SELECT password_hash_version FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(&pool)
        .await?;
    assert_eq!(version, 1_i16);
    Ok(())
}

#[tokio::test]
#[serial]
async fn oidc_pending_auth_rejects_duplicate_active_state() -> TestResult {
    let env = migrated_env().await?;
    let pool = env.pool.clone();
    let org_id = seed_org(&pool, "oidc-org").await?;
    let idp_id = seed_org_idp(&pool, org_id, "oidc").await?;
    let shared_state_hash = fixed_hash(0xAA);
    let first_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO oidc_pending_auth \
         (id, org_idp_id, state_hash, nonce_hash, verifier_hash, csrf_cookie_hash, redirect_uri, expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6, 'https://app/cb', now() + interval '10 min')",
    )
    .bind(first_id)
    .bind(idp_id)
    .bind(&shared_state_hash)
    .bind(fixed_hash(0xBB))
    .bind(fixed_hash(0xCC))
    .bind(fixed_hash(0xDD))
    .execute(&pool)
    .await?;
    let dup = sqlx::query(
        "INSERT INTO oidc_pending_auth \
         (id, org_idp_id, state_hash, nonce_hash, verifier_hash, csrf_cookie_hash, redirect_uri, expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6, 'https://app/cb', now() + interval '10 min')",
    )
    .bind(Uuid::now_v7())
    .bind(idp_id)
    .bind(&shared_state_hash)
    .bind(fixed_hash(0xBE))
    .bind(fixed_hash(0xCF))
    .bind(fixed_hash(0xDF))
    .execute(&pool)
    .await;
    assert!(dup.is_err(), "duplicate active state must be rejected");
    sqlx::query("UPDATE oidc_pending_auth SET used_at = now() WHERE id = $1")
        .bind(first_id)
        .execute(&pool)
        .await?;
    sqlx::query(
        "INSERT INTO oidc_pending_auth \
         (id, org_idp_id, state_hash, nonce_hash, verifier_hash, csrf_cookie_hash, redirect_uri, expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6, 'https://app/cb', now() + interval '10 min')",
    )
    .bind(Uuid::now_v7())
    .bind(idp_id)
    .bind(&shared_state_hash)
    .bind(fixed_hash(0xEE))
    .bind(fixed_hash(0xEF))
    .bind(fixed_hash(0xF0))
    .execute(&pool)
    .await?;
    Ok(())
}

#[tokio::test]
#[serial]
async fn oidc_refresh_tokens_chain_fk_holds() -> TestResult {
    let env = migrated_env().await?;
    let pool = env.pool.clone();
    let user_id = seed_user(&pool, "oidc-refresh@example.com").await?;
    let session_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO sessions (id, token_hash, user_id, expires_at) \
         VALUES ($1, decode('aa','hex'), $2, now() + interval '1 day')",
    )
    .bind(session_id)
    .bind(user_id)
    .execute(&pool)
    .await?;
    let first_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO oidc_refresh_tokens (id, session_id, token_hash) \
         VALUES ($1, $2, decode('01','hex'))",
    )
    .bind(first_id)
    .bind(session_id)
    .execute(&pool)
    .await?;
    let second_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO oidc_refresh_tokens (id, session_id, token_hash, prev_id) \
         VALUES ($1, $2, decode('02','hex'), $3)",
    )
    .bind(second_id)
    .bind(session_id)
    .bind(first_id)
    .execute(&pool)
    .await?;
    let dangling = sqlx::query(
        "INSERT INTO oidc_refresh_tokens (id, session_id, token_hash, prev_id) \
         VALUES ($1, $2, decode('03','hex'), $3)",
    )
    .bind(Uuid::now_v7())
    .bind(session_id)
    .bind(Uuid::now_v7())
    .execute(&pool)
    .await;
    assert!(dangling.is_err(), "FK must reject prev_id pointing nowhere");
    Ok(())
}

#[tokio::test]
#[serial]
async fn saml_assertion_replay_unique_per_idp_assertion_id() -> TestResult {
    let env = migrated_env().await?;
    let pool = env.pool.clone();
    let org_id = seed_org(&pool, "saml-org").await?;
    let idp_id = seed_org_idp(&pool, org_id, "saml").await?;
    sqlx::query(
        "INSERT INTO saml_assertion_replay (org_idp_id, assertion_id, not_on_or_after) \
         VALUES ($1, $2, now() + interval '5 min')",
    )
    .bind(idp_id)
    .bind("aid-1")
    .execute(&pool)
    .await?;
    let dup = sqlx::query(
        "INSERT INTO saml_assertion_replay (org_idp_id, assertion_id, not_on_or_after) \
         VALUES ($1, $2, now() + interval '5 min')",
    )
    .bind(idp_id)
    .bind("aid-1")
    .execute(&pool)
    .await;
    assert!(dup.is_err(), "duplicate assertion_id must be rejected");
    sqlx::query(
        "INSERT INTO saml_assertion_replay (org_idp_id, assertion_id, not_on_or_after) \
         VALUES ($1, $2, now() + interval '5 min')",
    )
    .bind(idp_id)
    .bind("aid-2")
    .execute(&pool)
    .await?;
    Ok(())
}

#[tokio::test]
#[serial]
async fn federated_identities_unique_anchor_with_tombstone() -> TestResult {
    let env = migrated_env().await?;
    let pool = env.pool.clone();
    let user_id = seed_user(&pool, "fed@example.com").await?;
    let org_id = seed_org(&pool, "fed-org").await?;
    let idp_id = seed_org_idp(&pool, org_id, "oidc").await?;
    let alive_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO federated_identities \
         (id, protocol, issuer_or_entity_id, subject_or_nameid, org_idp_id, user_id) \
         VALUES ($1, 'oidc', 'https://idp.example/iss', 'sub-1', $2, $3)",
    )
    .bind(alive_id)
    .bind(idp_id)
    .bind(user_id)
    .execute(&pool)
    .await?;
    let dup_alive = sqlx::query(
        "INSERT INTO federated_identities \
         (id, protocol, issuer_or_entity_id, subject_or_nameid, org_idp_id, user_id) \
         VALUES ($1, 'oidc', 'https://idp.example/iss', 'sub-1', $2, $3)",
    )
    .bind(Uuid::now_v7())
    .bind(idp_id)
    .bind(user_id)
    .execute(&pool)
    .await;
    assert!(
        dup_alive.is_err(),
        "duplicate anchor with same user must be rejected"
    );
    sqlx::query("UPDATE federated_identities SET user_id = NULL WHERE id = $1")
        .bind(alive_id)
        .execute(&pool)
        .await?;
    let dup_tombstone = sqlx::query(
        "INSERT INTO federated_identities \
         (id, protocol, issuer_or_entity_id, subject_or_nameid, org_idp_id) \
         VALUES ($1, 'oidc', 'https://idp.example/iss', 'sub-1', $2)",
    )
    .bind(Uuid::now_v7())
    .bind(idp_id)
    .execute(&pool)
    .await;
    assert!(
        dup_tombstone.is_err(),
        "tombstoned anchor must still occupy unique slot"
    );
    Ok(())
}

#[tokio::test]
#[serial]
async fn failed_signin_aggregates_upsert_keys() -> TestResult {
    let env = migrated_env().await?;
    let pool = env.pool.clone();
    // (a) NULL-user collapse: two NULL-user rows in the same window collide
    // because the (user_id, window_start) UNIQUE is NULLS NOT DISTINCT.
    sqlx::query(
        "INSERT INTO failed_signin_aggregates \
         (id, user_id, ip, window_start, count, first_attempt_at, last_attempt_at) \
         VALUES ($1, NULL, '10.0.0.1'::inet, '2026-01-01T00:00:00Z'::timestamptz, 1, now(), now())",
    )
    .bind(Uuid::now_v7())
    .execute(&pool)
    .await?;
    let dup_null = sqlx::query(
        "INSERT INTO failed_signin_aggregates \
         (id, user_id, ip, window_start, count, first_attempt_at, last_attempt_at) \
         VALUES ($1, NULL, '10.0.0.2'::inet, '2026-01-01T00:00:00Z'::timestamptz, 1, now(), now())",
    )
    .bind(Uuid::now_v7())
    .execute(&pool)
    .await;
    assert!(
        dup_null.is_err(),
        "NULLS NOT DISTINCT must collapse the (NULL, window_start) slot"
    );
    // (b) Real-user collapse: two rows for the SAME user in the SAME window
    // also collide via the (user_id, window_start) UNIQUE — even with a
    // different IP. This proves the user-window key is enforced
    // independently of the ip-window key.
    let user_id = seed_user(&pool, "fail@example.com").await?;
    sqlx::query(
        "INSERT INTO failed_signin_aggregates \
         (id, user_id, ip, window_start, count, first_attempt_at, last_attempt_at) \
         VALUES ($1, $2, '10.0.0.3'::inet, '2026-02-01T00:00:00Z'::timestamptz, 1, now(), now())",
    )
    .bind(Uuid::now_v7())
    .bind(user_id)
    .execute(&pool)
    .await?;
    let dup_user = sqlx::query(
        "INSERT INTO failed_signin_aggregates \
         (id, user_id, ip, window_start, count, first_attempt_at, last_attempt_at) \
         VALUES ($1, $2, '10.0.0.99'::inet, '2026-02-01T00:00:00Z'::timestamptz, 1, now(), now())",
    )
    .bind(Uuid::now_v7())
    .bind(user_id)
    .execute(&pool)
    .await;
    assert!(
        dup_user.is_err(),
        "(user_id, window_start) UNIQUE must reject same-user, same-window duplicate"
    );
    // (c) NAT-friendly behaviour: two DIFFERENT users hitting the SAME
    // IP in the SAME window must both succeed. The (ip, window_start)
    // index is intentionally non-unique so shared NAT / CGN traffic
    // does not collide. (The rate-limit module will sum across (ip, window)
    // for ip-pivot rate-limit decisions; uniqueness was a spec defect.)
    let other_user = seed_user(&pool, "fail-2@example.com").await?;
    sqlx::query(
        "INSERT INTO failed_signin_aggregates \
         (id, user_id, ip, window_start, count, first_attempt_at, last_attempt_at) \
         VALUES ($1, $2, '10.0.0.7'::inet, '2026-03-01T00:00:00Z'::timestamptz, 1, now(), now())",
    )
    .bind(Uuid::now_v7())
    .bind(other_user)
    .execute(&pool)
    .await?;
    sqlx::query(
        "INSERT INTO failed_signin_aggregates \
         (id, user_id, ip, window_start, count, first_attempt_at, last_attempt_at) \
         VALUES ($1, $2, '10.0.0.7'::inet, '2026-03-01T00:00:00Z'::timestamptz, 1, now(), now())",
    )
    .bind(Uuid::now_v7())
    .bind(user_id)
    .execute(&pool)
    .await?;
    Ok(())
}

#[tokio::test]
#[serial]
async fn service_tokens_token_hash_partial_unique() -> TestResult {
    let env = migrated_env().await?;
    let pool = env.pool.clone();
    let first_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO service_tokens (id, service_name, token_hash, display_name) \
         VALUES ($1, 'email-worker', decode('77','hex'), 'svc-1')",
    )
    .bind(first_id)
    .execute(&pool)
    .await?;
    let dup_alive = sqlx::query(
        "INSERT INTO service_tokens (id, service_name, token_hash, display_name) \
         VALUES ($1, 'email-worker', decode('77','hex'), 'svc-1-dup')",
    )
    .bind(Uuid::now_v7())
    .execute(&pool)
    .await;
    assert!(
        dup_alive.is_err(),
        "live duplicate token_hash must be rejected"
    );
    sqlx::query("UPDATE service_tokens SET revoked_at = now() WHERE id = $1")
        .bind(first_id)
        .execute(&pool)
        .await?;
    sqlx::query(
        "INSERT INTO service_tokens (id, service_name, token_hash, display_name) \
         VALUES ($1, 'email-worker', decode('77','hex'), 'svc-1-fresh')",
    )
    .bind(Uuid::now_v7())
    .execute(&pool)
    .await?;
    Ok(())
}

#[tokio::test]
#[serial]
async fn explain_session_lookup_uses_partial_index() -> TestResult {
    let env = migrated_env().await?;
    let pool = env.pool.clone();
    let user_id = seed_user(&pool, "session@example.com").await?;
    // Acquire a single connection so the session-level GUC change and the
    // EXPLAIN run against the same session. `SET LOCAL` is a no-op outside
    // an explicit transaction; using session-level `SET` keeps the change
    // alive for the subsequent EXPLAIN on the same conn.
    let mut conn = pool.acquire().await?;
    sqlx::query("SET enable_seqscan = OFF")
        .execute(&mut *conn)
        .await?;
    let lines: Vec<String> = sqlx::query_scalar::<_, String>(
        "EXPLAIN (FORMAT TEXT) \
         SELECT id FROM sessions \
         WHERE user_id = $1 AND expires_at > now() AND revoked_at IS NULL",
    )
    .bind(user_id)
    .fetch_all(&mut *conn)
    .await?;
    let plan = lines.join("\n");
    assert!(
        plan.contains("Index") && plan.contains("sessions_user_expires_active_idx"),
        "expected plan to use sessions_user_expires_active_idx, got:\n{plan}"
    );
    Ok(())
}

#[tokio::test]
#[serial]
async fn explain_users_email_lookup_uses_index() -> TestResult {
    let env = migrated_env().await?;
    let pool = env.pool.clone();
    let mut conn = pool.acquire().await?;
    sqlx::query("SET enable_seqscan = OFF")
        .execute(&mut *conn)
        .await?;
    let lines: Vec<String> = sqlx::query_scalar::<_, String>(
        "EXPLAIN (FORMAT TEXT) \
         SELECT id FROM users WHERE email_lower = $1 AND deleted_at IS NULL",
    )
    .bind("alice@example.com")
    .fetch_all(&mut *conn)
    .await?;
    let plan = lines.join("\n");
    assert!(
        plan.contains("Index") && plan.contains("users_email_lower_unique_live"),
        "expected plan to use users_email_lower_unique_live, got:\n{plan}"
    );
    Ok(())
}

// The former PG-17 matrix variant is intentionally gone: PostgreSQL 18 is
// the platform floor now that the custom image bundles pg_partman and
// pg_parquet. See deploy/docker/postgres/README.md ("Managed Postgres
// requirements").
