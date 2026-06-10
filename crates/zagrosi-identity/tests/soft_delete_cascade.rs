// SPDX-License-Identifier: AGPL-3.0-or-later

//! Soft-delete cascade coverage: org and user.

mod common;

use chrono::{TimeZone, Utc};
use common::{TestResult, migrated_env, seed_org, seed_user};
use serial_test::serial;
use sqlx::Row;
use uuid::Uuid;
use zagrosi_identity::domain::{TokenPrefix, hash_token, mint};
use zagrosi_identity::repo::{
    ApiTokenRepo, FederatedIdentityRepo, MembershipRepo, NewApiToken, NewFederatedIdentity,
    NewMembership, NewScimResource, NewServiceToken, NewSession, OrgScoped, ScimResourceRepo,
    ServiceTokenRepo, SessionRepo, soft_delete_org, soft_delete_user,
};

#[tokio::test]
#[serial]
async fn org_soft_delete_cascade_flips_children() -> TestResult {
    let env = migrated_env().await?;
    let org = seed_org(&env.pool, "del-org").await?;
    let user = seed_user(&env.pool, "del-user@example.com").await?;

    // Add an IdP, an IdP domain, a SCIM token, a service token, a membership.
    let idp_id = Uuid::now_v7();
    sqlx::query("INSERT INTO org_idps (id, org_id, protocol, display_name, config) VALUES ($1, $2, 'oidc', 'd', '{}'::jsonb)")
        .bind(idp_id)
        .bind(org)
        .execute(env.db.migrate_pool())
        .await?;
    sqlx::query(
        "INSERT INTO org_idp_domains (id, org_idp_id, org_id, domain) \
         VALUES ($1, $2, $3, 'example.com')",
    )
    .bind(Uuid::now_v7())
    .bind(idp_id)
    .bind(org)
    .execute(env.db.migrate_pool())
    .await?;

    let scim = ScimResourceRepo::new(env.pool.clone());
    let raw_s = mint(TokenPrefix::Scim);
    let h_s = hash_token(&raw_s);
    let scim_id = Uuid::now_v7();
    OrgScoped::new(&scim, org)
        .create(NewScimResource {
            id: scim_id,
            display_name: "scim",
            token_hash: h_s.as_slice(),
            scopes: &["users:read"],
            allowed_cidrs: &[],
            tolerant_mode: false,
            expires_at: None,
        })
        .await?;
    let svc = ServiceTokenRepo::new(env.pool.clone());
    let raw_v = mint(TokenPrefix::Service);
    let h_v = hash_token(&raw_v);
    let svc_id = Uuid::now_v7();
    svc.create(NewServiceToken {
        id: svc_id,
        service_name: "w",
        token_hash: h_v.as_slice(),
        allowed_subjects: &["x.>"],
        display_name: "w",
    })
    .await?;

    // Add membership.
    let mem = MembershipRepo::new(env.pool.clone());
    mem.create(NewMembership {
        id: Uuid::now_v7(),
        user_id: user,
        org_id: org,
        basic_role: "member",
        joined_via: "manual",
        jit_provisioned_at: None,
    })
    .await?;
    // Add session with org set.
    let raw_sess = mint(TokenPrefix::Session);
    let h_sess = hash_token(&raw_sess);
    let sess_id = Uuid::now_v7();
    SessionRepo::new(env.pool.clone())
        .insert(NewSession {
            id: sess_id,
            token_hash: h_sess.as_slice(),
            user_id: user,
            org_id: Some(org),
            user_agent: None,
            ip_addr: None,
            amr: &["pwd"],
            acr: None,
            expires_at: Utc.with_ymd_and_hms(2099, 1, 1, 0, 0, 0).unwrap(),
        })
        .await?;

    let mut tx = env.pool.begin().await?;
    soft_delete_org(&mut tx, org).await?;
    tx.commit().await?;

    // org_idps and org_idp_domains soft-deleted.
    let idp_dead: bool = sqlx::query("SELECT deleted_at IS NOT NULL FROM org_idps WHERE id = $1")
        .bind(idp_id)
        .fetch_one(env.db.migrate_pool())
        .await?
        .get(0);
    assert!(idp_dead);

    let scim_dead: bool =
        sqlx::query("SELECT deleted_at IS NOT NULL FROM scim_tokens WHERE id = $1")
            .bind(scim_id)
            .fetch_one(env.db.migrate_pool())
            .await?
            .get(0);
    assert!(scim_dead);

    let mem_dead: bool = sqlx::query("SELECT deleted_at IS NOT NULL FROM user_org_memberships WHERE org_id = $1 AND user_id = $2")
        .bind(org)
        .bind(user)
        .fetch_one(env.db.migrate_pool())
        .await?
        .get(0);
    assert!(mem_dead);

    // Sessions revoked.
    let sess_dead: bool = sqlx::query("SELECT revoked_at IS NOT NULL FROM sessions WHERE id = $1")
        .bind(sess_id)
        .fetch_one(env.db.migrate_pool())
        .await?
        .get(0);
    assert!(sess_dead);

    // service_tokens stays — org-agnostic table, not part of cascade.
    let svc_alive: bool = sqlx::query(
        "SELECT revoked_at IS NULL AND deleted_at IS NULL FROM service_tokens WHERE id = $1",
    )
    .bind(svc_id)
    .fetch_one(env.db.migrate_pool())
    .await?
    .get(0);
    assert!(svc_alive);
    Ok(())
}

#[tokio::test]
#[serial]
async fn user_soft_delete_cascade_revokes_and_tombstones() -> TestResult {
    let env = migrated_env().await?;
    let org = seed_org(&env.pool, "ud-org").await?;
    let user = seed_user(&env.pool, "ud@example.com").await?;
    let idp_id = Uuid::now_v7();
    sqlx::query("INSERT INTO org_idps (id, org_id, protocol, display_name, config) VALUES ($1, $2, 'oidc', 'd', '{}'::jsonb)")
        .bind(idp_id)
        .bind(org)
        .execute(env.db.migrate_pool())
        .await?;

    // Session.
    let h_sess = hash_token(&mint(TokenPrefix::Session));
    let sess_id = Uuid::now_v7();
    SessionRepo::new(env.pool.clone())
        .insert(NewSession {
            id: sess_id,
            token_hash: h_sess.as_slice(),
            user_id: user,
            org_id: Some(org),
            user_agent: None,
            ip_addr: None,
            amr: &["pwd"],
            acr: None,
            expires_at: Utc.with_ymd_and_hms(2099, 1, 1, 0, 0, 0).unwrap(),
        })
        .await?;

    // PAT.
    let pat_repo = ApiTokenRepo::new(env.pool.clone());
    let h_pat = hash_token(&mint(TokenPrefix::Pat));
    let pat_id = Uuid::now_v7();
    OrgScoped::new(&pat_repo, org)
        .create(NewApiToken {
            id: pat_id,
            token_hash: h_pat.as_slice(),
            user_id: user,
            display_name: "ci",
            scopes: &[],
            expires_at: None,
        })
        .await?;

    // Federated identity.
    let fed = FederatedIdentityRepo::new(env.pool.clone());
    fed.create(NewFederatedIdentity {
        id: Uuid::now_v7(),
        protocol: "oidc",
        issuer_or_entity_id: "https://i",
        subject_or_nameid: "u-1",
        org_idp_id: idp_id,
        user_id: Some(user),
        last_login_at: None,
    })
    .await?;

    let mut tx = env.pool.begin().await?;
    // The user cascade touches tenanted rows; as zagrosi_app it needs
    // org context (cross-org purge is the maintenance role's job).
    zagrosi_identity::repo::with_org_context(&mut tx, org).await?;
    soft_delete_user(&mut tx, user).await?;
    tx.commit().await?;

    let sess_dead: bool = sqlx::query("SELECT revoked_at IS NOT NULL FROM sessions WHERE id = $1")
        .bind(sess_id)
        .fetch_one(env.db.migrate_pool())
        .await?
        .get(0);
    assert!(sess_dead);

    let pat_dead: bool = sqlx::query("SELECT revoked_at IS NOT NULL FROM api_tokens WHERE id = $1")
        .bind(pat_id)
        .fetch_one(env.db.migrate_pool())
        .await?
        .get(0);
    assert!(pat_dead);

    let tomb_count: i64 = sqlx::query("SELECT COUNT(*) FROM federated_identities WHERE user_id IS NULL AND issuer_or_entity_id = 'https://i' AND subject_or_nameid = 'u-1'")
        .fetch_one(env.db.migrate_pool())
        .await?
        .get(0);
    assert_eq!(tomb_count, 1, "federated identity must be tombstoned");
    Ok(())
}

#[tokio::test]
#[serial]
async fn federated_tombstone_blocks_re_attachment() -> TestResult {
    let env = migrated_env().await?;
    let org = seed_org(&env.pool, "fb-org").await?;
    let user1 = seed_user(&env.pool, "u1@example.com").await?;
    let user2 = seed_user(&env.pool, "u2@example.com").await?;
    let idp = Uuid::now_v7();
    sqlx::query("INSERT INTO org_idps (id, org_id, protocol, display_name, config) VALUES ($1, $2, 'oidc', 'd', '{}'::jsonb)")
        .bind(idp)
        .bind(org)
        .execute(env.db.migrate_pool())
        .await?;

    let fed = FederatedIdentityRepo::new(env.pool.clone());
    fed.create(NewFederatedIdentity {
        id: Uuid::now_v7(),
        protocol: "oidc",
        issuer_or_entity_id: "https://i.example",
        subject_or_nameid: "anchor",
        org_idp_id: idp,
        user_id: Some(user1),
        last_login_at: None,
    })
    .await?;

    let mut tx = env.pool.begin().await?;
    // The user cascade touches tenanted rows; as zagrosi_app it needs
    // org context (cross-org purge is the maintenance role's job).
    zagrosi_identity::repo::with_org_context(&mut tx, org).await?;
    soft_delete_user(&mut tx, user1).await?;
    tx.commit().await?;

    // Attempt to re-attach (p, iss, sub) under user2 — must fail with
    // FederatedIdentityTombstoned because the unique slot is held by
    // the tombstone.
    let res = fed
        .create(NewFederatedIdentity {
            id: Uuid::now_v7(),
            protocol: "oidc",
            issuer_or_entity_id: "https://i.example",
            subject_or_nameid: "anchor",
            org_idp_id: idp,
            user_id: Some(user2),
            last_login_at: None,
        })
        .await;
    assert!(matches!(
        res,
        Err(zagrosi_identity::IdentityError::FederatedIdentityTombstoned)
    ));
    Ok(())
}
