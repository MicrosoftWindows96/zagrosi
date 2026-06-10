// SPDX-License-Identifier: AGPL-3.0-or-later

//! Tenant-isolation invariant tests.
//!
//! Every multi-tenant repo MUST refuse to leak rows owned by org A
//! when invoked through an `OrgScoped` wrapper bound to org B. The
//! cross-org probe returns `None`, never an error — preserving the
//! project-wide rule that cross-tenant probes look like 404 not 403.

mod common;

use chrono::{TimeZone, Utc};
use common::{TestResult, migrated_env, seed_org, seed_user};
use serial_test::serial;
use uuid::Uuid;
use zagrosi_identity::domain::{TokenPrefix, hash_token, mint};
use zagrosi_identity::repo::{
    ApiTokenRepo, NewApiToken, NewOrgIdp, NewScimResource, OrgIdpRepo, OrgScoped, ScimResourceRepo,
};

#[tokio::test]
#[serial]
async fn api_token_lookup_rejects_other_org() -> TestResult {
    let env = migrated_env().await?;
    let user_a = seed_user(&env.pool, "a@example.com").await?;
    let org_a = seed_org(&env.pool, "org-a").await?;
    let org_b = seed_org(&env.pool, "org-b").await?;

    let pat_repo = ApiTokenRepo::new(env.pool.clone());
    let in_a = OrgScoped::new(&pat_repo, org_a);
    let raw = mint(TokenPrefix::Pat);
    let h = hash_token(&raw);
    in_a.create(NewApiToken {
        id: Uuid::now_v7(),
        token_hash: h.as_slice(),
        user_id: user_a,
        display_name: "ci",
        scopes: &[],
        expires_at: None,
    })
    .await?;

    // Same hash, different org wrapper — must miss.
    let in_b = OrgScoped::new(&pat_repo, org_b);
    let cross = in_b.find_by_token_hash(&h.0).await?;
    assert!(cross.is_none(), "cross-org PAT lookup must return None");
    Ok(())
}

#[tokio::test]
#[serial]
async fn scim_token_lookup_rejects_other_org() -> TestResult {
    let env = migrated_env().await?;
    let org_a = seed_org(&env.pool, "scim-a").await?;
    let org_b = seed_org(&env.pool, "scim-b").await?;
    let scim_repo = ScimResourceRepo::new(env.pool.clone());
    let in_a = OrgScoped::new(&scim_repo, org_a);
    let raw = mint(TokenPrefix::Scim);
    let h = hash_token(&raw);
    in_a.create(NewScimResource {
        id: Uuid::now_v7(),
        display_name: "scim",
        token_hash: h.as_slice(),
        scopes: &["users:read"],
        allowed_cidrs: &[],
        tolerant_mode: false,
        expires_at: Some(Utc.with_ymd_and_hms(2099, 1, 1, 0, 0, 0).unwrap()),
    })
    .await?;
    let in_b = OrgScoped::new(&scim_repo, org_b);
    let cross = in_b.find_by_token_hash(&h.0).await?;
    assert!(cross.is_none());
    Ok(())
}

#[tokio::test]
#[serial]
async fn org_idp_listing_partitions_by_org() -> TestResult {
    let env = migrated_env().await?;
    let org_a = seed_org(&env.pool, "idp-a").await?;
    let org_b = seed_org(&env.pool, "idp-b").await?;
    let idps = OrgIdpRepo::new(env.pool.clone());
    let scoped_a = OrgScoped::new(&idps, org_a);
    let scoped_b = OrgScoped::new(&idps, org_b);

    scoped_a
        .create(NewOrgIdp {
            id: Uuid::now_v7(),
            protocol: "oidc",
            display_name: "A's IdP",
            config: serde_json::json!({}),
            config_version: 1,
            jit_provisioning: true,
            is_default: true,
            enabled: true,
        })
        .await?;
    scoped_b
        .create(NewOrgIdp {
            id: Uuid::now_v7(),
            protocol: "saml",
            display_name: "B's IdP",
            config: serde_json::json!({}),
            config_version: 1,
            jit_provisioning: false,
            is_default: false,
            enabled: true,
        })
        .await?;

    let a_list = scoped_a.list_for_org().await?;
    let b_list = scoped_b.list_for_org().await?;
    assert_eq!(a_list.len(), 1);
    assert_eq!(b_list.len(), 1);
    assert_eq!(a_list[0].display_name, "A's IdP");
    assert_eq!(b_list[0].display_name, "B's IdP");
    Ok(())
}

#[tokio::test]
#[serial]
async fn org_scoped_with_org_context_round_trip() -> TestResult {
    let env = migrated_env().await?;
    let org = seed_org(&env.pool, "ctx-org").await?;

    // Inside a transaction, set the GUC and read it back.
    let mut tx = env.pool.begin().await?;
    zagrosi_identity::repo::with_org_context(&mut tx, org).await?;
    let value: Option<String> = sqlx::query_scalar("SELECT current_setting('app.org_id', true)")
        .fetch_one(&mut *tx)
        .await?;
    tx.commit().await?;
    assert_eq!(value.as_deref(), Some(org.to_string()).as_deref());
    Ok(())
}

#[tokio::test]
#[serial]
async fn with_user_context_round_trip() -> TestResult {
    let env = migrated_env().await?;
    let user = Uuid::now_v7();

    // Inside a transaction, set the user GUC and read it back.
    let mut tx = env.pool.begin().await?;
    zagrosi_identity::repo::with_user_context(&mut tx, user).await?;
    let value: Option<String> = sqlx::query_scalar("SELECT current_setting('app.user_id', true)")
        .fetch_one(&mut *tx)
        .await?;
    tx.commit().await?;
    assert_eq!(value.as_deref(), Some(user.to_string()).as_deref());

    // Transaction-local: gone after the txn ends, asserted in the
    // exact NULLIF(...) IS NULL shape the section-05 policies use.
    let unset: bool =
        sqlx::query_scalar("SELECT NULLIF(current_setting('app.user_id', true), '') IS NULL")
            .fetch_one(&env.pool)
            .await?;
    assert!(unset, "app.user_id must be unset outside the transaction");
    Ok(())
}

/// Confirms the documented hash-only design of `SessionRepo::find_by_token_hash`.
///
/// The session row carries `org_id` as data, not as a discriminator at lookup
/// time — the gateway introspector has no org context until the session itself
/// reveals it. The cross-org "probe" therefore returns the row regardless of
/// which org the caller thinks it belongs to. Callers MUST verify
/// `session.org_id` against any expected value AFTER the lookup. This test
/// freezes that contract.
#[tokio::test]
#[serial]
async fn session_find_is_hash_only_by_design() -> TestResult {
    use zagrosi_identity::repo::{NewSession, SessionRepo};

    let env = migrated_env().await?;
    let user = seed_user(&env.pool, "ho@example.com").await?;
    let org_a = seed_org(&env.pool, "ho-a").await?;
    let _org_b = seed_org(&env.pool, "ho-b").await?;
    let sessions = SessionRepo::new(env.pool.clone());

    let raw = mint(TokenPrefix::Session);
    let h = hash_token(&raw);
    let id = Uuid::now_v7();
    sessions
        .insert(NewSession {
            id,
            token_hash: h.as_slice(),
            user_id: user,
            org_id: Some(org_a),
            user_agent: None,
            ip_addr: None,
            amr: &["pwd"],
            acr: None,
            expires_at: Utc.with_ymd_and_hms(2099, 1, 1, 0, 0, 0).unwrap(),
        })
        .await?;

    // Hash-only lookup returns the row; caller is responsible for org check.
    let found = sessions.find_by_token_hash(&h.0).await?.expect("present");
    assert_eq!(found.id, id);
    assert_eq!(found.org_id, Some(org_a));
    // Caller-side org check is the only enforcement: ensure the test author's
    // discipline matches reality.
    let expected_org = org_a;
    assert_eq!(
        found.org_id,
        Some(expected_org),
        "documented contract: caller must verify session.org_id"
    );
    Ok(())
}

/// Federated-identity anchor lookup is by `(protocol, iss, sub)` triple,
/// which is globally unique. Org binding lives on the row's `org_idp_id`
/// FK chain; the lookup itself returns matching rows regardless of which
/// org the caller intended to probe. This is the documented design.
#[tokio::test]
#[serial]
async fn federated_anchor_lookup_is_globally_unique_by_design() -> TestResult {
    use zagrosi_identity::repo::{FederatedIdentityRepo, NewFederatedIdentity};

    let env = migrated_env().await?;
    let org_a = seed_org(&env.pool, "fa-a").await?;
    let _org_b = seed_org(&env.pool, "fa-b").await?;
    let user = seed_user(&env.pool, "fa@example.com").await?;
    let idp_a = Uuid::now_v7();
    sqlx::query("INSERT INTO org_idps (id, org_id, protocol, display_name, config) VALUES ($1, $2, 'oidc', 'd', '{}'::jsonb)")
        .bind(idp_a)
        .bind(org_a)
        .execute(&env.pool)
        .await?;

    let fed = FederatedIdentityRepo::new(env.pool.clone());
    fed.create(NewFederatedIdentity {
        id: Uuid::now_v7(),
        protocol: "oidc",
        issuer_or_entity_id: "https://i.example",
        subject_or_nameid: "sub-x",
        org_idp_id: idp_a,
        user_id: Some(user),
        last_login_at: None,
    })
    .await?;

    // Lookup by triple — globally unique. Caller resolves the org via
    // org_idp_id afterwards.
    let row = fed
        .find_by_protocol_iss_sub("oidc", "https://i.example", "sub-x")
        .await?
        .expect("present");
    assert_eq!(row.org_idp_id, idp_a);
    Ok(())
}

/// `oidc_pending_auth.state_hash` is globally unique (partial unique on
/// `WHERE used_at IS NULL`). The lookup is org-implicit via the row's
/// `org_idp_id`; the OIDC client verifies the `org_idp_id` matches the
/// expected `IdP` after redemption.
#[tokio::test]
#[serial]
async fn oidc_pending_state_lookup_is_globally_unique_by_design() -> TestResult {
    use zagrosi_identity::repo::{NewOidcPending, OidcPendingRepo};

    let env = migrated_env().await?;
    let org = seed_org(&env.pool, "op").await?;
    let idp = Uuid::now_v7();
    sqlx::query("INSERT INTO org_idps (id, org_id, protocol, display_name, config) VALUES ($1, $2, 'oidc', 'd', '{}'::jsonb)")
        .bind(idp)
        .bind(org)
        .execute(&env.pool)
        .await?;

    let repo = OidcPendingRepo::new(env.pool.clone());
    let state = hash_token("global-state").0;
    let nonce = hash_token("global-nonce").0;
    let verifier = hash_token("global-ver").0;
    let csrf = hash_token("global-csrf").0;
    let id = Uuid::now_v7();
    repo.insert(NewOidcPending {
        id,
        org_idp_id: idp,
        state_hash: &state,
        nonce_hash: &nonce,
        verifier_hash: &verifier,
        csrf_cookie_hash: &csrf,
        redirect_uri: "https://app.example/cb",
        expires_at: Utc.with_ymd_and_hms(2099, 1, 1, 0, 0, 0).unwrap(),
    })
    .await?;

    let row = repo.find_by_state(&state).await?.expect("present");
    // The row's org_idp_id is the only org binding. The OIDC client caller is
    // responsible for verifying it matches the expected IdP.
    assert_eq!(row.org_idp_id, idp);
    Ok(())
}
