// SPDX-License-Identifier: AGPL-3.0-or-later

//! Persistence-layer repo round-trip tests.
//!
//! Minimal happy-path round trip per repo. Tenant-isolation-specific
//! and cascade-specific behaviours live in dedicated test files.

mod common;

use chrono::{TimeZone, Utc};
use common::{TestResult, migrated_env, seed_org, seed_user};
use serial_test::serial;
use uuid::Uuid;
use zagrosi_identity::domain::{TokenPrefix, hash_token, mint};
use zagrosi_identity::repo::{
    ApiTokenRepo, FederatedIdentityRepo, MembershipRepo, NewApiToken, NewFederatedIdentity,
    NewMembership, NewOidcPending, NewOidcRefresh, NewOrg, NewOrgIdp, NewSamlAssertion,
    NewServiceToken, NewSession, NewUser, OidcPendingRepo, OidcRefreshRepo, OrgIdpRepo, OrgRepo,
    OrgScoped, SamlReplayRepo, ServiceTokenRepo, SessionRepo, UserRepo,
};

#[tokio::test]
#[serial]
async fn user_create_round_trip() -> TestResult {
    let env = migrated_env().await?;
    let users = UserRepo::new(env.pool.clone());

    let id = Uuid::now_v7();
    let created = users
        .create(NewUser {
            id,
            email: "Round.Trip@Example.COM",
            display_name: "Round Trip",
            password_hash: Some("$argon2id$placeholder"),
            password_updated_at: Some(Utc::now()),
            password_hash_version: 1,
            external_id: None,
        })
        .await?;
    assert_eq!(created.id, id);
    assert_eq!(created.email_lower, "round.trip@example.com");

    let by_id = users.find_by_id(id).await?.expect("by id");
    assert_eq!(by_id.id, id);

    let by_email = users
        .find_by_email_lower("round.trip@example.com")
        .await?
        .expect("by email");
    assert_eq!(by_email.id, id);

    Ok(())
}

#[tokio::test]
#[serial]
async fn org_create_round_trip() -> TestResult {
    let env = migrated_env().await?;
    let orgs = OrgRepo::new(env.pool.clone());

    let id = Uuid::now_v7();
    let created = orgs
        .create(NewOrg {
            id,
            slug: "round-trip-org",
            display_name: "Round Trip Org",
            primary_domain: Some("example.com"),
        })
        .await?;
    assert_eq!(created.id, id);

    let by_slug = orgs.find_by_slug("round-trip-org").await?.expect("by slug");
    assert_eq!(by_slug.id, id);
    Ok(())
}

#[tokio::test]
#[serial]
async fn membership_create_round_trip() -> TestResult {
    let env = migrated_env().await?;
    let user_id = seed_user(&env.pool, "m@example.com").await?;
    let org_id = seed_org(&env.pool, "m-org").await?;

    let memberships = MembershipRepo::new(env.pool.clone());
    let id = Uuid::now_v7();
    memberships
        .create(NewMembership {
            id,
            user_id,
            org_id,
            basic_role: "member",
            joined_via: "manual",
            jit_provisioned_at: None,
        })
        .await?;
    let listed = memberships.find_for_user(user_id).await?;
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].org_id, org_id);
    Ok(())
}

#[tokio::test]
#[serial]
async fn session_create_revoke_round_trip() -> TestResult {
    let env = migrated_env().await?;
    let user_id = seed_user(&env.pool, "s@example.com").await?;
    let sessions = SessionRepo::new(env.pool.clone());

    let raw = mint(TokenPrefix::Session);
    let token_hash = hash_token(&raw);
    let id = Uuid::now_v7();
    let expires = Utc.with_ymd_and_hms(2099, 1, 1, 0, 0, 0).unwrap();
    let inserted = sessions
        .insert(NewSession {
            id,
            token_hash: token_hash.as_slice(),
            user_id,
            org_id: None,
            user_agent: Some("test/1"),
            ip_addr: None,
            amr: &["pwd"],
            acr: Some("urn:zagrosi:acr:0"),
            expires_at: expires,
        })
        .await?;
    assert_eq!(inserted.id, id);

    let found = sessions.find_by_token_hash(&token_hash.0).await?;
    assert!(found.is_some());

    sessions.revoke(id).await?;
    let after = sessions.find_by_token_hash(&token_hash.0).await?;
    assert!(after.is_none(), "revoked session must not return");
    Ok(())
}

#[tokio::test]
#[serial]
async fn api_token_round_trip() -> TestResult {
    let env = migrated_env().await?;
    let user_id = seed_user(&env.pool, "p@example.com").await?;
    let org_id = seed_org(&env.pool, "p-org").await?;
    let pat_repo = ApiTokenRepo::new(env.pool.clone());
    let scoped = OrgScoped::new(&pat_repo, org_id);

    let raw = mint(TokenPrefix::Pat);
    let h = hash_token(&raw);
    let id = Uuid::now_v7();
    let token = scoped
        .create(NewApiToken {
            id,
            token_hash: h.as_slice(),
            user_id,
            display_name: "ci",
            scopes: &["work-items:read"],
            expires_at: None,
        })
        .await?;
    assert_eq!(token.id, id);

    let found = scoped.find_by_token_hash(&h.0).await?.expect("present");
    assert_eq!(found.id, id);
    let listed = scoped.list_for_user(user_id).await?;
    assert_eq!(listed.len(), 1);

    scoped.update_last_used(id, Utc::now(), None).await?;
    scoped.revoke(id).await?;
    assert!(scoped.find_by_token_hash(&h.0).await?.is_none());
    Ok(())
}

#[tokio::test]
#[serial]
async fn org_idp_create_list_round_trip() -> TestResult {
    let env = migrated_env().await?;
    let org_id = seed_org(&env.pool, "idp-org").await?;
    let idps = OrgIdpRepo::new(env.pool.clone());
    let scoped = OrgScoped::new(&idps, org_id);

    let id = Uuid::now_v7();
    let cfg = serde_json::json!({"issuer": "https://idp.example"});
    scoped
        .create(NewOrgIdp {
            id,
            protocol: "oidc",
            display_name: "Acme OIDC",
            config: cfg,
            config_version: 1,
            jit_provisioning: true,
            is_default: true,
            enabled: true,
        })
        .await?;
    let listed = scoped.list_for_org().await?;
    assert_eq!(listed.len(), 1);
    let new_cfg = serde_json::json!({"issuer": "https://idp2.example"});
    // CAS contract: pass the persisted `config_version` (== 1 from
    // the create above) and assert the bumped value comes back.
    // Earlier revisions of this test passed `expected_version=2`
    // which mismatched the persisted `1` and tripped the
    // optimistic-lock branch instead of exercising the happy path.
    let new_v = scoped.update_config(id, new_cfg, 1).await?;
    assert_eq!(new_v, 2);
    Ok(())
}

#[tokio::test]
#[serial]
async fn federated_identity_round_trip() -> TestResult {
    let env = migrated_env().await?;
    let org_id = seed_org(&env.pool, "fed-org").await?;
    let user_id = seed_user(&env.pool, "f@example.com").await?;
    // Need an org_idps row first.
    let idp_id = Uuid::now_v7();
    sqlx::query("INSERT INTO org_idps (id, org_id, protocol, display_name, config) VALUES ($1, $2, 'oidc', 'd', '{}'::jsonb)")
        .bind(idp_id)
        .bind(org_id)
        .execute(env.db.migrate_pool())
        .await?;

    let fed = FederatedIdentityRepo::new(env.pool.clone());
    let id = Uuid::now_v7();
    fed.create(NewFederatedIdentity {
        id,
        protocol: "oidc",
        issuer_or_entity_id: "https://idp.example",
        subject_or_nameid: "user-123",
        org_idp_id: idp_id,
        user_id: Some(user_id),
        last_login_at: Some(Utc::now()),
    })
    .await?;
    let found = fed
        .find_by_protocol_iss_sub("oidc", "https://idp.example", "user-123")
        .await?
        .expect("present");
    assert_eq!(found.id, id);

    fed.update_last_login_at(id, Utc::now()).await?;
    Ok(())
}

#[tokio::test]
#[serial]
async fn oidc_pending_round_trip() -> TestResult {
    let env = migrated_env().await?;
    let org_id = seed_org(&env.pool, "op-org").await?;
    let idp_id = Uuid::now_v7();
    sqlx::query("INSERT INTO org_idps (id, org_id, protocol, display_name, config) VALUES ($1, $2, 'oidc', 'd', '{}'::jsonb)")
        .bind(idp_id)
        .bind(org_id)
        .execute(env.db.migrate_pool())
        .await?;

    let repo = OidcPendingRepo::new(env.pool.clone());
    let h = |s: &str| {
        let v = hash_token(s);
        v.0
    };
    let id = Uuid::now_v7();
    let state = h("state-1");
    let nonce = h("nonce-1");
    let verifier = h("ver-1");
    let csrf = h("csrf-1");
    repo.insert(NewOidcPending {
        id,
        org_idp_id: idp_id,
        state_hash: &state,
        nonce_hash: &nonce,
        verifier_hash: &verifier,
        csrf_cookie_hash: &csrf,
        redirect_uri: "https://app.example/callback",
        expires_at: Utc.with_ymd_and_hms(2099, 1, 1, 0, 0, 0).unwrap(),
    })
    .await?;
    let unused = repo.find_by_state(&state).await?.expect("present");
    assert_eq!(unused.id, id);
    assert!(unused.used_at.is_none(), "fresh row must be unused");

    let mut tx = env.pool.begin().await?;
    repo.mark_used(&mut tx, id, Utc::now()).await?;
    tx.commit().await?;
    let after = repo
        .find_by_state(&state)
        .await?
        .expect("row still present");
    assert!(
        after.used_at.is_some(),
        "find_by_state surfaces used rows so the OIDC client can audit replay distinctly",
    );
    Ok(())
}

#[tokio::test]
#[serial]
async fn oidc_refresh_round_trip() -> TestResult {
    let env = migrated_env().await?;
    let user_id = seed_user(&env.pool, "or@example.com").await?;
    let sessions = SessionRepo::new(env.pool.clone());
    let raw = mint(TokenPrefix::Session);
    let h = hash_token(&raw);
    let session_id = Uuid::now_v7();
    sessions
        .insert(NewSession {
            id: session_id,
            token_hash: h.as_slice(),
            user_id,
            org_id: None,
            user_agent: None,
            ip_addr: None,
            amr: &["oidc"],
            acr: None,
            expires_at: Utc.with_ymd_and_hms(2099, 1, 1, 0, 0, 0).unwrap(),
        })
        .await?;

    let refresh = OidcRefreshRepo::new(env.pool.clone());
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
    assert!(refresh.find_by_token_hash(&r1_hash).await?.is_some());
    refresh.mark_used(r1_id, Utc::now()).await?;
    // Replay attempt
    assert!(refresh.mark_used(r1_id, Utc::now()).await.is_err());
    Ok(())
}

#[tokio::test]
#[serial]
async fn saml_replay_round_trip() -> TestResult {
    let env = migrated_env().await?;
    let org_id = seed_org(&env.pool, "saml-org").await?;
    let idp_id = Uuid::now_v7();
    sqlx::query("INSERT INTO org_idps (id, org_id, protocol, display_name, config) VALUES ($1, $2, 'saml', 'd', '{}'::jsonb)")
        .bind(idp_id)
        .bind(org_id)
        .execute(env.db.migrate_pool())
        .await?;

    let repo = SamlReplayRepo::new(env.pool.clone());
    repo.insert(NewSamlAssertion {
        org_idp_id: idp_id,
        assertion_id: "assertion-1",
        not_on_or_after: Utc.with_ymd_and_hms(2099, 1, 1, 0, 0, 0).unwrap(),
    })
    .await?;
    // Duplicate insert MUST raise replay.
    let dup = repo
        .insert(NewSamlAssertion {
            org_idp_id: idp_id,
            assertion_id: "assertion-1",
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
async fn service_token_round_trip() -> TestResult {
    let env = migrated_env().await?;
    let repo = ServiceTokenRepo::new(env.pool.clone());
    let raw = mint(TokenPrefix::Service);
    let h = hash_token(&raw);
    let id = Uuid::now_v7();
    repo.create(NewServiceToken {
        id,
        service_name: "email-worker",
        token_hash: h.as_slice(),
        allowed_subjects: &["email.>"],
        display_name: "email worker",
    })
    .await?;
    assert!(repo.find_by_token_hash(&h.0).await?.is_some());
    repo.revoke(id).await?;
    assert!(repo.find_by_token_hash(&h.0).await?.is_none());
    Ok(())
}
