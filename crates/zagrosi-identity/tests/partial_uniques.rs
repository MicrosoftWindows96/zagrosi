// SPDX-License-Identifier: AGPL-3.0-or-later

//! Partial-unique constraint coverage for the persistence layer.

mod common;

use chrono::{TimeZone, Utc};
use common::{TestResult, migrated_env, seed_org, seed_user};
use serial_test::serial;
use sqlx::Row;
use uuid::Uuid;
use zagrosi_identity::domain::{TokenPrefix, hash_token, mint};
use zagrosi_identity::repo::{
    NewOidcPending, NewOidcRefresh, NewSamlAssertion, NewServiceToken, OidcPendingRepo,
    OidcRefreshRepo, SamlReplayRepo, ServiceTokenRepo,
};

#[tokio::test]
#[serial]
async fn oidc_pending_state_unique_until_used() -> TestResult {
    let env = migrated_env().await?;
    let org = seed_org(&env.pool, "oup").await?;
    let idp = Uuid::now_v7();
    sqlx::query("INSERT INTO org_idps (id, org_id, protocol, display_name, config) VALUES ($1, $2, 'oidc', 'd', '{}'::jsonb)")
        .bind(idp)
        .bind(org)
        .execute(&env.pool)
        .await?;

    let repo = OidcPendingRepo::new(env.pool.clone());
    let state = hash_token("state-x").0;
    let nonce = hash_token("nonce-x").0;
    let verifier = hash_token("ver-x").0;
    let csrf = hash_token("csrf-x").0;

    let id1 = Uuid::now_v7();
    repo.insert(NewOidcPending {
        id: id1,
        org_idp_id: idp,
        state_hash: &state,
        nonce_hash: &nonce,
        verifier_hash: &verifier,
        csrf_cookie_hash: &csrf,
        redirect_uri: "https://app.example/cb",
        expires_at: Utc.with_ymd_and_hms(2099, 1, 1, 0, 0, 0).unwrap(),
    })
    .await?;

    // Duplicate state_hash while first row is still unused → must conflict.
    let dup = repo
        .insert(NewOidcPending {
            id: Uuid::now_v7(),
            org_idp_id: idp,
            state_hash: &state,
            nonce_hash: &nonce,
            verifier_hash: &verifier,
            csrf_cookie_hash: &csrf,
            redirect_uri: "https://app.example/cb",
            expires_at: Utc.with_ymd_and_hms(2099, 1, 1, 0, 0, 0).unwrap(),
        })
        .await;
    assert!(dup.is_err(), "duplicate state must conflict while unused");

    // Mark the first row used; same state must now be insertable again.
    let mut tx = env.pool.begin().await?;
    repo.mark_used(&mut tx, id1, Utc::now()).await?;
    tx.commit().await?;

    repo.insert(NewOidcPending {
        id: Uuid::now_v7(),
        org_idp_id: idp,
        state_hash: &state,
        nonce_hash: &nonce,
        verifier_hash: &verifier,
        csrf_cookie_hash: &csrf,
        redirect_uri: "https://app.example/cb",
        expires_at: Utc.with_ymd_and_hms(2099, 1, 1, 0, 0, 0).unwrap(),
    })
    .await?;
    Ok(())
}

#[tokio::test]
#[serial]
async fn oidc_refresh_chain_fk_validation() -> TestResult {
    let env = migrated_env().await?;
    let user = seed_user(&env.pool, "rc@example.com").await?;
    // Need a session FK target.
    let raw = mint(TokenPrefix::Session);
    let h = hash_token(&raw);
    let session_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO sessions (id, token_hash, user_id, expires_at) VALUES ($1, $2, $3, now() + interval '1 hour')",
    )
    .bind(session_id)
    .bind(&h.0[..])
    .bind(user)
    .execute(&env.pool)
    .await?;

    let refresh = OidcRefreshRepo::new(env.pool.clone());
    // First refresh — no prev.
    let r1_id = Uuid::now_v7();
    let r1_hash = hash_token("rt-1").0;
    refresh
        .insert(NewOidcRefresh {
            id: r1_id,
            session_id,
            token_hash: &r1_hash,
            prev_id: None,
        })
        .await?;
    // Second refresh — prev points to r1.
    let r2_hash = hash_token("rt-2").0;
    refresh
        .insert(NewOidcRefresh {
            id: Uuid::now_v7(),
            session_id,
            token_hash: &r2_hash,
            prev_id: Some(r1_id),
        })
        .await?;

    // Bogus prev_id MUST fail FK.
    let bogus_hash = hash_token("rt-bogus").0;
    let bogus = refresh
        .insert(NewOidcRefresh {
            id: Uuid::now_v7(),
            session_id,
            token_hash: &bogus_hash,
            prev_id: Some(Uuid::now_v7()),
        })
        .await;
    assert!(bogus.is_err(), "bogus prev_id must violate FK");
    Ok(())
}

#[tokio::test]
#[serial]
async fn saml_replay_unique_pair() -> TestResult {
    let env = migrated_env().await?;
    let org = seed_org(&env.pool, "sr-org").await?;
    let idp = Uuid::now_v7();
    sqlx::query("INSERT INTO org_idps (id, org_id, protocol, display_name, config) VALUES ($1, $2, 'saml', 'd', '{}'::jsonb)")
        .bind(idp)
        .bind(org)
        .execute(&env.pool)
        .await?;

    let repo = SamlReplayRepo::new(env.pool.clone());
    repo.insert(NewSamlAssertion {
        org_idp_id: idp,
        assertion_id: "aid-1",
        not_on_or_after: Utc.with_ymd_and_hms(2099, 1, 1, 0, 0, 0).unwrap(),
    })
    .await?;
    let dup = repo
        .insert(NewSamlAssertion {
            org_idp_id: idp,
            assertion_id: "aid-1",
            not_on_or_after: Utc.with_ymd_and_hms(2099, 1, 1, 0, 0, 0).unwrap(),
        })
        .await;
    assert!(matches!(
        dup,
        Err(zagrosi_identity::IdentityError::AssertionReplay)
    ));
    Ok(())
}

#[tokio::test]
#[serial]
async fn federated_identity_anchor_unique() -> TestResult {
    let env = migrated_env().await?;
    let org = seed_org(&env.pool, "fa-org").await?;
    let user = seed_user(&env.pool, "fa@example.com").await?;
    let idp = Uuid::now_v7();
    sqlx::query("INSERT INTO org_idps (id, org_id, protocol, display_name, config) VALUES ($1, $2, 'oidc', 'd', '{}'::jsonb)")
        .bind(idp)
        .bind(org)
        .execute(&env.pool)
        .await?;

    sqlx::query("INSERT INTO federated_identities (id, protocol, issuer_or_entity_id, subject_or_nameid, org_idp_id, user_id) VALUES ($1, 'oidc', 'https://i.example', 'sub-1', $2, $3)")
        .bind(Uuid::now_v7())
        .bind(idp)
        .bind(user)
        .execute(&env.pool)
        .await?;

    // Same triple → duplicate.
    let dup = sqlx::query("INSERT INTO federated_identities (id, protocol, issuer_or_entity_id, subject_or_nameid, org_idp_id, user_id) VALUES ($1, 'oidc', 'https://i.example', 'sub-1', $2, $3)")
        .bind(Uuid::now_v7())
        .bind(idp)
        .bind(user)
        .execute(&env.pool)
        .await;
    assert!(dup.is_err());
    Ok(())
}

#[tokio::test]
#[serial]
async fn failed_signin_aggregates_upsert_pair_unique() -> TestResult {
    let env = migrated_env().await?;
    let user = seed_user(&env.pool, "fs@example.com").await?;
    let window = Utc.with_ymd_and_hms(2025, 1, 1, 12, 0, 0).unwrap();
    sqlx::query("INSERT INTO failed_signin_aggregates (id, user_id, ip, window_start, count, first_attempt_at, last_attempt_at) VALUES ($1, $2, $3::inet, $4, 1, now(), now())")
        .bind(Uuid::now_v7())
        .bind(user)
        .bind("203.0.113.1")
        .bind(window)
        .execute(&env.pool)
        .await?;
    // Same (user_id, window_start) → uniqueness violation
    let dup = sqlx::query("INSERT INTO failed_signin_aggregates (id, user_id, ip, window_start, count, first_attempt_at, last_attempt_at) VALUES ($1, $2, $3::inet, $4, 1, now(), now())")
        .bind(Uuid::now_v7())
        .bind(user)
        .bind("203.0.113.2")
        .bind(window)
        .execute(&env.pool)
        .await;
    assert!(dup.is_err());

    // Two distinct user_ids in the same window → both succeed (NULLS NOT DISTINCT covers NULL but distinct user_ids are independent).
    let user2 = seed_user(&env.pool, "fs2@example.com").await?;
    sqlx::query("INSERT INTO failed_signin_aggregates (id, user_id, ip, window_start, count, first_attempt_at, last_attempt_at) VALUES ($1, $2, $3::inet, $4, 1, now(), now())")
        .bind(Uuid::now_v7())
        .bind(user2)
        .bind("203.0.113.3")
        .bind(window)
        .execute(&env.pool)
        .await?;

    let count: i64 =
        sqlx::query("SELECT COUNT(*) FROM failed_signin_aggregates WHERE window_start = $1")
            .bind(window)
            .fetch_one(&env.pool)
            .await?
            .get(0);
    assert_eq!(count, 2);
    Ok(())
}

#[tokio::test]
#[serial]
async fn service_tokens_partial_unique_after_revoke() -> TestResult {
    let env = migrated_env().await?;
    let repo = ServiceTokenRepo::new(env.pool.clone());
    let raw = mint(TokenPrefix::Service);
    let h = hash_token(&raw);
    let id1 = Uuid::now_v7();
    repo.create(NewServiceToken {
        id: id1,
        service_name: "worker-x",
        token_hash: h.as_slice(),
        allowed_subjects: &["x.>"],
        display_name: "x",
    })
    .await?;
    // Re-issue same hash without revoking first → conflict.
    let conflict = repo
        .create(NewServiceToken {
            id: Uuid::now_v7(),
            service_name: "worker-x",
            token_hash: h.as_slice(),
            allowed_subjects: &["x.>"],
            display_name: "x",
        })
        .await;
    assert!(conflict.is_err());

    // Revoke and re-issue → succeeds.
    repo.revoke(id1).await?;
    repo.create(NewServiceToken {
        id: Uuid::now_v7(),
        service_name: "worker-x",
        token_hash: h.as_slice(),
        allowed_subjects: &["x.>"],
        display_name: "x",
    })
    .await?;
    Ok(())
}
