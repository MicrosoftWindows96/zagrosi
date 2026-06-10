// SPDX-License-Identifier: AGPL-3.0-or-later

//! `zagrosi_auth` mechanism: pre-tenant-context hash lookups succeed over
//! the auth pool with NO GUC; the same queries as `zagrosi_app` with no
//! GUC see zero rows (the exception is role-scoped, not table-wide).
//!
//! Mechanism (a) of the plan's §5.5: `USING (true)` SELECT policies
//! `TO zagrosi_auth` on the P1 token tables; `sessions` /
//! `oidc_refresh_tokens` / `service_tokens` are P5, where plain SELECT
//! grants suffice. The introspection repos are constructed over the auth
//! pool here exactly as the composition root will wire them.

use serial_test::serial;
use uuid::Uuid;
use zagrosi_identity::repo::{ApiTokenRepo, OidcRefreshRepo, SessionRepo};
use zagrosi_test_support::{TestDb, seed_org, seed_user};

type TestError = Box<dyn std::error::Error + Send + Sync>;
type TestResult = Result<(), TestError>;

const fn fixed_hash(byte: u8) -> [u8; 32] {
    [byte; 32]
}

#[allow(clippy::struct_field_names)]
struct Seeded {
    session_hash: [u8; 32],
    pat_hash: [u8; 32],
    scim_hash: [u8; 32],
    refresh_hash: [u8; 32],
}

async fn seed_lookup_rows(db: &TestDb) -> Result<Seeded, TestError> {
    let org = seed_org(db.migrate_pool(), "auth-role-org").await?;
    let user = seed_user(db.migrate_pool(), "auth-role@example.test").await?;
    let seeded = Seeded {
        session_hash: fixed_hash(0xA1),
        pat_hash: fixed_hash(0xA2),
        scim_hash: fixed_hash(0xA3),
        refresh_hash: fixed_hash(0xA4),
    };
    let session_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO sessions (id, user_id, org_id, token_hash, expires_at)
         VALUES ($1, $2, $3, $4, now() + interval '1 hour')",
    )
    .bind(session_id)
    .bind(user)
    .bind(org)
    .bind(&seeded.session_hash[..])
    .execute(db.migrate_pool())
    .await?;
    sqlx::query(
        "INSERT INTO api_tokens (id, token_hash, user_id, org_id, display_name)
         VALUES ($1, $2, $3, $4, 'auth-role pat')",
    )
    .bind(Uuid::now_v7())
    .bind(&seeded.pat_hash[..])
    .bind(user)
    .bind(org)
    .execute(db.migrate_pool())
    .await?;
    sqlx::query(
        "INSERT INTO scim_tokens (id, org_id, display_name, token_hash)
         VALUES ($1, $2, 'auth-role scim', $3)",
    )
    .bind(Uuid::now_v7())
    .bind(org)
    .bind(&seeded.scim_hash[..])
    .execute(db.migrate_pool())
    .await?;
    sqlx::query(
        "INSERT INTO oidc_refresh_tokens (id, session_id, token_hash)
         VALUES ($1, $2, $3)",
    )
    .bind(Uuid::now_v7())
    .bind(session_id)
    .bind(&seeded.refresh_hash[..])
    .execute(db.migrate_pool())
    .await?;
    Ok(seeded)
}

#[tokio::test]
#[serial]
async fn hash_lookups_work_as_auth_role_without_guc() -> TestResult {
    let db = TestDb::new().await?;
    let seeded = seed_lookup_rows(&db).await?;

    // The real introspection repos, constructed over the auth pool.
    let sessions = SessionRepo::new(db.auth_pool().clone());
    let session = sessions.find_by_token_hash(&seeded.session_hash).await?;
    assert!(session.is_some(), "session hash lookup over auth pool");

    let pats = ApiTokenRepo::new(db.auth_pool().clone());
    let pat = pats.find_live_by_token_hash(&seeded.pat_hash).await?;
    assert!(pat.is_some(), "PAT hash lookup over auth pool");

    let refresh = OidcRefreshRepo::new(db.auth_pool().clone());
    let row = refresh.find_by_token_hash(&seeded.refresh_hash).await?;
    assert!(row.is_some(), "refresh hash lookup over auth pool");

    // The real SCIM auth-middleware query over the auth pool.
    let scim = zagrosi_identity::repo::ScimResourceRepo::new(db.auth_pool().clone())
        .find_global_by_token_hash(&seeded.scim_hash)
        .await?;
    assert!(scim.is_some(), "scim hash lookup over auth pool");
    Ok(())
}

#[tokio::test]
#[serial]
async fn app_role_without_guc_sees_no_token_rows() -> TestResult {
    let db = TestDb::new().await?;
    let seeded = seed_lookup_rows(&db).await?;

    // The same P1-table hash queries over the APP pool with no GUC must
    // return nothing: the auth exception is role-scoped, fail-closed for
    // everyone else.
    let pats = ApiTokenRepo::new(db.app_pool().clone());
    let pat = pats.find_live_by_token_hash(&seeded.pat_hash).await?;
    assert!(pat.is_none(), "app role without GUC must see zero PAT rows");

    let scim = zagrosi_identity::repo::ScimResourceRepo::new(db.app_pool().clone())
        .find_global_by_token_hash(&seeded.scim_hash)
        .await?;
    assert!(
        scim.is_none(),
        "app role without GUC must see zero scim rows"
    );
    Ok(())
}
