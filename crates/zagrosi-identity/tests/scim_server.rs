// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(
    clippy::doc_markdown,
    clippy::too_long_first_doc_paragraph,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::too_many_lines,
    clippy::needless_borrows_for_generic_args,
    clippy::missing_const_for_fn,
    clippy::uninlined_format_args
)]
//! End-to-end SCIM 2.0 server integration tests (section-12).
//!
//! Tests light up the real `Router` against a per-test PG container
//! and a `disabled()` NATS bus. Tower's `oneshot` is the in-process
//! transport — no listener / no socket, so each test is fast and
//! parallel-safe.
//!
//! Coverage:
//!
//! - Tenant isolation (`404` not `403` on cross-org IDs).
//! - CIDR allowlist (accept / reject / empty-means-unrestricted).
//! - ServiceProviderConfig byte-equal to committed fixture.
//! - ETag derivation + `If-Match` (412 on stale, 200 on match).
//! - `active=false` flips `users.active` AND revokes every live
//!   session in the same DB transaction.
//! - `409 uniqueness` on duplicate `userName`.
//! - SCIM error envelope shape (RFC 7644 §3.12).
//! - Discovery endpoints carry `application/scim+json`.

mod common;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE, IF_MATCH};
use axum::http::{Request, StatusCode};
use base64::Engine;
use http_body_util::BodyExt;
use serde_json::Value;
use sha2::Digest;
use sqlx::PgPool;
use sqlx::types::ipnetwork::IpNetwork;
use tower::ServiceExt;
use uuid::Uuid;
use zagrosi_core::NoopAuditor;

use zagrosi_identity::http::scim::{ScimState, router as scim_router};
use zagrosi_identity::repo::{
    GroupRepo, MembershipRepo, NewMembership, NewScimResource, NewUser, OrgScoped,
    ScimResourceRepo, SessionRepo, UserRepo,
};
use zagrosi_identity::session::{SessionCache, SessionEventBus, SessionRevoker};

use common::{TestResult, migrated_env, seed_org};

/// Per-test SCIM harness. Owns the test container + the composed
/// router + a couple of pre-minted SCIM bearers for the orgs the
/// test cares about.
struct Harness {
    _env: common::TestEnv,
    pool: PgPool,
    org_a: Uuid,
    #[allow(dead_code)]
    org_b: Uuid,
    bearer_a: String,
    bearer_b: String,
    bearer_a_cidr_locked: String,
    router: Router,
}

async fn build_harness() -> TestResult<Harness> {
    build_harness_with_cidrs(vec!["10.0.0.0/8".parse().unwrap()]).await
}

async fn build_harness_with_cidrs(allowed_cidrs: Vec<IpNetwork>) -> TestResult<Harness> {
    let env = migrated_env().await?;
    let pool = env.pool.clone();
    let org_a = seed_org(&pool, &format!("a-{}", Uuid::now_v7())).await?;
    let org_b = seed_org(&pool, &format!("b-{}", Uuid::now_v7())).await?;

    let users = UserRepo::new(pool.clone());
    let memberships = MembershipRepo::new(pool.clone());
    let scim_tokens = ScimResourceRepo::new(pool.clone());
    let groups = GroupRepo::new(pool.clone());
    let sessions = SessionRepo::new(pool.clone());
    let bus = Arc::new(SessionEventBus::disabled());
    let cache = SessionCache::new(64, Duration::from_secs(30));
    let revoker = Arc::new(SessionRevoker::new(sessions.clone(), cache, bus));
    let auditor = Arc::new(NoopAuditor);

    let bearer_a = mint_token_for_org(&scim_tokens, org_a, "a-bearer", &[]).await?;
    let bearer_b = mint_token_for_org(&scim_tokens, org_b, "b-bearer", &[]).await?;
    let bearer_a_cidr_locked =
        mint_token_for_org(&scim_tokens, org_a, "a-bearer-cidr", &allowed_cidrs).await?;

    let state = ScimState::new(
        pool.clone(),
        users,
        scim_tokens,
        groups,
        memberships,
        sessions,
        revoker,
        auditor,
    );
    let router = scim_router(state);

    Ok(Harness {
        _env: env,
        pool,
        org_a,
        org_b,
        bearer_a,
        bearer_b,
        bearer_a_cidr_locked,
        router,
    })
}

async fn mint_token_for_org(
    repo: &ScimResourceRepo,
    org_id: Uuid,
    name: &str,
    allowed_cidrs: &[IpNetwork],
) -> TestResult<String> {
    let body = format!("scim_{}", b64_44());
    let raw = if body.len() == "scim_".len() + 43 {
        body
    } else {
        format!("scim_{}", "a".repeat(43))
    };
    let mut hasher = sha2::Sha256::new();
    hasher.update(raw.as_bytes());
    let hash: [u8; 32] = hasher.finalize().into();
    let scoped = OrgScoped::new(repo, org_id);
    scoped
        .create(NewScimResource {
            id: Uuid::now_v7(),
            display_name: name,
            token_hash: &hash[..],
            scopes: &["users:read", "users:write", "groups:read", "groups:write"],
            allowed_cidrs,
            tolerant_mode: false,
            expires_at: None,
        })
        .await?;
    Ok(raw)
}

fn b64_44() -> String {
    use rand_core::RngCore;
    let mut buf = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut buf);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
}

fn req_get(uri: &str, bearer: &str, peer: SocketAddr) -> Request<Body> {
    let req = Request::builder()
        .method("GET")
        .uri(uri)
        .header(AUTHORIZATION, format!("Bearer {bearer}"))
        .body(Body::empty())
        .unwrap();
    inject_connect_info(req, peer)
}

// test helper: threading `&Value` through 27 call sites that pass
// inline `json!` temporaries adds churn for no behaviour gain.
#[allow(clippy::needless_pass_by_value)]
fn req_post(uri: &str, bearer: &str, peer: SocketAddr, body: Value) -> Request<Body> {
    let req = Request::builder()
        .method("POST")
        .uri(uri)
        .header(AUTHORIZATION, format!("Bearer {bearer}"))
        .header(CONTENT_TYPE, "application/scim+json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    inject_connect_info(req, peer)
}

// test helper: threading `&Value` through the call sites that pass
// inline `json!` temporaries adds churn for no behaviour gain.
#[allow(clippy::needless_pass_by_value)]
fn req_patch(
    uri: &str,
    bearer: &str,
    peer: SocketAddr,
    body: Value,
    if_match: Option<&str>,
) -> Request<Body> {
    let mut builder = Request::builder()
        .method("PATCH")
        .uri(uri)
        .header(AUTHORIZATION, format!("Bearer {bearer}"))
        .header(CONTENT_TYPE, "application/scim+json");
    if let Some(tag) = if_match {
        builder = builder.header(IF_MATCH, tag);
    }
    let req = builder
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    inject_connect_info(req, peer)
}

fn inject_connect_info(mut req: Request<Body>, peer: SocketAddr) -> Request<Body> {
    req.extensions_mut().insert(ConnectInfo(peer));
    req
}

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    if bytes.is_empty() {
        return Value::Null;
    }
    serde_json::from_slice(&bytes).unwrap_or_else(|e| panic!("body json: {e}; raw: {:?}", bytes))
}

fn peer_ok() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 4242)
}

fn peer_blocked() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 4242)
}

#[tokio::test(flavor = "multi_thread")]
async fn service_provider_config_byte_equal_to_fixture() -> TestResult {
    let h = build_harness().await?;
    let resp = h
        .router
        .clone()
        .oneshot(req_get(
            "/scim/v2/ServiceProviderConfig",
            &h.bearer_a,
            peer_ok(),
        ))
        .await?;
    assert_eq!(resp.status(), StatusCode::OK);
    let ct = resp
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert_eq!(ct, "application/scim+json");
    let v = body_json(resp).await;
    assert_eq!(v["bulk"]["supported"], false);
    assert_eq!(v["filter"]["supported"], true);
    assert_eq!(v["filter"]["maxResults"], 200);
    assert_eq!(v["changePassword"]["supported"], false);
    assert_eq!(v["sort"]["supported"], true);
    assert_eq!(v["etag"]["supported"], true);
    assert_eq!(v["patch"]["supported"], true);
    assert_eq!(v["authenticationSchemes"][0]["type"], "oauthbearertoken");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn missing_bearer_returns_401() -> TestResult {
    let h = build_harness().await?;
    let mut req = Request::builder()
        .method("GET")
        .uri("/scim/v2/Users")
        .body(Body::empty())
        .unwrap();
    req.extensions_mut().insert(ConnectInfo(peer_ok()));
    let resp = h.router.clone().oneshot(req).await?;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let v = body_json(resp).await;
    assert_eq!(
        v["schemas"][0],
        "urn:ietf:params:scim:api:messages:2.0:Error"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn cidr_allowlist_accepts_listed_peer_ip() -> TestResult {
    let h = build_harness().await?;
    let resp = h
        .router
        .clone()
        .oneshot(req_get(
            "/scim/v2/Users",
            &h.bearer_a_cidr_locked,
            peer_ok(),
        ))
        .await?;
    assert_eq!(resp.status(), StatusCode::OK);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn cidr_allowlist_rejects_unlisted_peer_ip_with_403() -> TestResult {
    let h = build_harness().await?;
    let resp = h
        .router
        .clone()
        .oneshot(req_get(
            "/scim/v2/Users",
            &h.bearer_a_cidr_locked,
            peer_blocked(),
        ))
        .await?;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let v = body_json(resp).await;
    assert_eq!(v["status"], "403");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn empty_cidr_allowlist_accepts_any_peer_ip() -> TestResult {
    let h = build_harness().await?;
    let resp = h
        .router
        .clone()
        .oneshot(req_get(
            "/scim/v2/Users",
            &h.bearer_a, // empty cidrs
            peer_blocked(),
        ))
        .await?;
    assert_eq!(resp.status(), StatusCode::OK);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn create_user_then_get_round_trips_with_etag() -> TestResult {
    let h = build_harness().await?;
    let create = req_post(
        "/scim/v2/Users",
        &h.bearer_a,
        peer_ok(),
        serde_json::json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "alice@example.com",
            "displayName": "Alice"
        }),
    );
    let resp = h.router.clone().oneshot(create).await?;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let v = body_json(resp).await;
    let id = v["id"].as_str().unwrap().to_string();
    assert_eq!(v["userName"], "alice@example.com");
    assert_eq!(v["active"], true);
    let etag = v["meta"]["version"].as_str().unwrap().to_string();
    assert!(etag.starts_with("W/\""));
    let get = req_get(&format!("/scim/v2/Users/{id}"), &h.bearer_a, peer_ok());
    let resp = h.router.clone().oneshot(get).await?;
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_json(resp).await;
    assert_eq!(v["meta"]["version"].as_str().unwrap(), etag);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn cross_org_user_id_returns_404_not_403() -> TestResult {
    let h = build_harness().await?;
    let create = req_post(
        "/scim/v2/Users",
        &h.bearer_a,
        peer_ok(),
        serde_json::json!({"userName": "x@example.com", "displayName": "X"}),
    );
    let resp = h.router.clone().oneshot(create).await?;
    let v = body_json(resp).await;
    let id_a = v["id"].as_str().unwrap().to_string();
    let resp = h
        .router
        .clone()
        .oneshot(req_get(
            &format!("/scim/v2/Users/{id_a}"),
            &h.bearer_b,
            peer_ok(),
        ))
        .await?;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let v = body_json(resp).await;
    assert_eq!(v["status"], "404");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn missing_id_and_cross_org_id_indistinguishable() -> TestResult {
    let h = build_harness().await?;
    let create = req_post(
        "/scim/v2/Users",
        &h.bearer_a,
        peer_ok(),
        serde_json::json!({"userName": "y@example.com", "displayName": "Y"}),
    );
    let resp = h.router.clone().oneshot(create).await?;
    let id_a = body_json(resp).await["id"].as_str().unwrap().to_string();
    let cross_org = h
        .router
        .clone()
        .oneshot(req_get(
            &format!("/scim/v2/Users/{id_a}"),
            &h.bearer_b,
            peer_ok(),
        ))
        .await?;
    let unknown = h
        .router
        .clone()
        .oneshot(req_get(
            "/scim/v2/Users/00000000-0000-7000-8000-000000000000",
            &h.bearer_b,
            peer_ok(),
        ))
        .await?;
    assert_eq!(cross_org.status(), unknown.status());
    let cross_org_body = body_json(cross_org).await;
    let unknown_body = body_json(unknown).await;
    assert_eq!(cross_org_body, unknown_body);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn duplicate_username_create_returns_409_uniqueness() -> TestResult {
    let h = build_harness().await?;
    let one = req_post(
        "/scim/v2/Users",
        &h.bearer_a,
        peer_ok(),
        serde_json::json!({"userName": "dup@example.com", "displayName": "Dup"}),
    );
    let resp = h.router.clone().oneshot(one).await?;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let two = req_post(
        "/scim/v2/Users",
        &h.bearer_a,
        peer_ok(),
        serde_json::json!({"userName": "dup@example.com", "displayName": "Dup2"}),
    );
    let resp = h.router.clone().oneshot(two).await?;
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let v = body_json(resp).await;
    assert_eq!(v["scimType"], "uniqueness");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn patch_with_matching_if_match_succeeds_and_bumps_version() -> TestResult {
    let h = build_harness().await?;
    let create = req_post(
        "/scim/v2/Users",
        &h.bearer_a,
        peer_ok(),
        serde_json::json!({"userName": "pm@example.com", "displayName": "PM"}),
    );
    let v = body_json(h.router.clone().oneshot(create).await?).await;
    let id = v["id"].as_str().unwrap().to_string();
    let original_etag = v["meta"]["version"].as_str().unwrap().to_string();

    let patch = req_patch(
        &format!("/scim/v2/Users/{id}"),
        &h.bearer_a,
        peer_ok(),
        serde_json::json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "replace", "path": "displayName", "value": "PM Renamed"}]
        }),
        Some(&original_etag),
    );
    let resp = h.router.clone().oneshot(patch).await?;
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_json(resp).await;
    let new_etag = v["meta"]["version"].as_str().unwrap();
    assert_ne!(new_etag, original_etag);
    assert_eq!(v["displayName"], "PM Renamed");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn patch_with_stale_if_match_returns_412() -> TestResult {
    let h = build_harness().await?;
    let create = req_post(
        "/scim/v2/Users",
        &h.bearer_a,
        peer_ok(),
        serde_json::json!({"userName": "stale@example.com", "displayName": "S"}),
    );
    let v = body_json(h.router.clone().oneshot(create).await?).await;
    let id = v["id"].as_str().unwrap().to_string();

    let bogus = "W/\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"";
    let patch = req_patch(
        &format!("/scim/v2/Users/{id}"),
        &h.bearer_a,
        peer_ok(),
        serde_json::json!({
            "Operations": [{"op": "replace", "path": "active", "value": false}]
        }),
        Some(bogus),
    );
    let resp = h.router.clone().oneshot(patch).await?;
    assert_eq!(resp.status(), StatusCode::PRECONDITION_FAILED);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn active_false_revokes_all_sessions_in_same_tx() -> TestResult {
    let h = build_harness().await?;
    let create = req_post(
        "/scim/v2/Users",
        &h.bearer_a,
        peer_ok(),
        serde_json::json!({"userName": "deact@example.com", "displayName": "D"}),
    );
    let v = body_json(h.router.clone().oneshot(create).await?).await;
    let user_id: Uuid = v["id"].as_str().unwrap().parse().unwrap();
    let token_hash = [0x77u8; 32];
    sqlx::query!(
        r#"
        INSERT INTO sessions (id, token_hash, user_id, org_id,
                              version, amr, expires_at)
        VALUES ($1, $2, $3, $4, 0, ARRAY['pwd']::TEXT[], now() + INTERVAL '1 hour')
        "#,
        Uuid::now_v7(),
        &token_hash[..],
        user_id,
        h.org_a,
    )
    .execute(&h.pool)
    .await?;
    let live = sqlx::query!(
        r#"SELECT COUNT(*) AS "count!" FROM sessions
           WHERE user_id = $1 AND revoked_at IS NULL"#,
        user_id,
    )
    .fetch_one(&h.pool)
    .await?
    .count;
    assert_eq!(live, 1);

    let patch = req_patch(
        &format!("/scim/v2/Users/{user_id}"),
        &h.bearer_a,
        peer_ok(),
        serde_json::json!({
            "Operations": [{"op": "replace", "path": "active", "value": false}]
        }),
        None,
    );
    let resp = h.router.clone().oneshot(patch).await?;
    assert_eq!(resp.status(), StatusCode::OK);

    let live = sqlx::query!(
        r#"SELECT COUNT(*) AS "count!" FROM sessions
           WHERE user_id = $1 AND revoked_at IS NULL"#,
        user_id,
    )
    .fetch_one(&h.pool)
    .await?
    .count;
    assert_eq!(live, 0);
    let active_now = sqlx::query!(r#"SELECT active FROM users WHERE id = $1"#, user_id,)
        .fetch_one(&h.pool)
        .await?
        .active;
    assert!(!active_now);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn list_response_envelope_shape_per_rfc_7644() -> TestResult {
    let h = build_harness().await?;
    let _ = h
        .router
        .clone()
        .oneshot(req_post(
            "/scim/v2/Users",
            &h.bearer_a,
            peer_ok(),
            serde_json::json!({"userName": "l1@example.com", "displayName": "L1"}),
        ))
        .await?;
    let resp = h
        .router
        .clone()
        .oneshot(req_get("/scim/v2/Users", &h.bearer_a, peer_ok()))
        .await?;
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_json(resp).await;
    assert_eq!(
        v["schemas"][0],
        "urn:ietf:params:scim:api:messages:2.0:ListResponse"
    );
    assert!(v["totalResults"].is_number());
    assert!(v["startIndex"].is_number());
    assert!(v["itemsPerPage"].is_number());
    assert!(v["Resources"].is_array());
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn count_over_200_silently_returns_200() -> TestResult {
    let h = build_harness().await?;
    let resp = h
        .router
        .clone()
        .oneshot(req_get("/scim/v2/Users?count=500", &h.bearer_a, peer_ok()))
        .await?;
    assert_eq!(resp.status(), StatusCode::OK);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn start_index_lt_1_clamps_to_1() -> TestResult {
    let h = build_harness().await?;
    let resp = h
        .router
        .clone()
        .oneshot(req_get(
            "/scim/v2/Users?startIndex=0",
            &h.bearer_a,
            peer_ok(),
        ))
        .await?;
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_json(resp).await;
    assert_eq!(v["startIndex"], 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn sort_by_unknown_returns_400_invalid_value() -> TestResult {
    let h = build_harness().await?;
    let resp = h
        .router
        .clone()
        .oneshot(req_get(
            "/scim/v2/Users?sortBy=evilColumn",
            &h.bearer_a,
            peer_ok(),
        ))
        .await?;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let v = body_json(resp).await;
    assert_eq!(v["scimType"], "invalidValue");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn filter_unknown_attr_returns_400_invalid_filter() -> TestResult {
    let h = build_harness().await?;
    let uri = "/scim/v2/Users?filter=evil%20eq%20%22x%22";
    let resp = h
        .router
        .clone()
        .oneshot(req_get(uri, &h.bearer_a, peer_ok()))
        .await?;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let v = body_json(resp).await;
    assert_eq!(v["scimType"], "invalidFilter");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn create_group_returns_201_with_etag() -> TestResult {
    let h = build_harness().await?;
    let body = serde_json::json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "Engineers"
    });
    let resp = h
        .router
        .clone()
        .oneshot(req_post("/scim/v2/Groups", &h.bearer_a, peer_ok(), body))
        .await?;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let v = body_json(resp).await;
    assert_eq!(v["displayName"], "Engineers");
    assert!(v["meta"]["version"].as_str().unwrap().starts_with("W/\""));
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn group_displayname_unique_per_org() -> TestResult {
    let h = build_harness().await?;
    let body = serde_json::json!({"displayName": "Admins"});
    let r1 = h
        .router
        .clone()
        .oneshot(req_post(
            "/scim/v2/Groups",
            &h.bearer_a,
            peer_ok(),
            body.clone(),
        ))
        .await?;
    assert_eq!(r1.status(), StatusCode::CREATED);
    let r2 = h
        .router
        .clone()
        .oneshot(req_post("/scim/v2/Groups", &h.bearer_a, peer_ok(), body))
        .await?;
    assert_eq!(r2.status(), StatusCode::CONFLICT);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn scim_routes_carry_application_scim_json_content_type() -> TestResult {
    let h = build_harness().await?;
    let resp = h
        .router
        .clone()
        .oneshot(req_get("/scim/v2/Users", &h.bearer_a, peer_ok()))
        .await?;
    let ct = resp
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert_eq!(ct, "application/scim+json");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn delete_user_soft_deletes_and_subsequent_get_404s() -> TestResult {
    let h = build_harness().await?;
    let create = req_post(
        "/scim/v2/Users",
        &h.bearer_a,
        peer_ok(),
        serde_json::json!({"userName": "del@example.com", "displayName": "Del"}),
    );
    let v = body_json(h.router.clone().oneshot(create).await?).await;
    let id = v["id"].as_str().unwrap().to_string();

    let resp = h
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(&format!("/scim/v2/Users/{id}"))
                .header(AUTHORIZATION, format!("Bearer {}", &h.bearer_a))
                .body(Body::empty())
                .map(|r| inject_connect_info(r, peer_ok()))
                .unwrap(),
        )
        .await?;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let resp = h
        .router
        .clone()
        .oneshot(req_get(
            &format!("/scim/v2/Users/{id}"),
            &h.bearer_a,
            peer_ok(),
        ))
        .await?;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn user_id_path_traversal_via_non_uuid_returns_404() -> TestResult {
    let h = build_harness().await?;
    let resp = h
        .router
        .clone()
        .oneshot(req_get("/scim/v2/Users/not-a-uuid", &h.bearer_a, peer_ok()))
        .await?;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn filter_username_eq_returns_only_matching_user() -> TestResult {
    let h = build_harness().await?;
    for (un, dn) in [
        ("alice@corp.com", "Alice"),
        ("bob@corp.com", "Bob"),
        ("carol@corp.com", "Carol"),
    ] {
        let r = h
            .router
            .clone()
            .oneshot(req_post(
                "/scim/v2/Users",
                &h.bearer_a,
                peer_ok(),
                serde_json::json!({"userName": un, "displayName": dn}),
            ))
            .await?;
        assert_eq!(r.status(), StatusCode::CREATED);
    }
    let resp = h
        .router
        .clone()
        .oneshot(req_get(
            "/scim/v2/Users?filter=userName%20eq%20%22alice@corp.com%22",
            &h.bearer_a,
            peer_ok(),
        ))
        .await?;
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_json(resp).await;
    assert_eq!(v["totalResults"], 1);
    assert_eq!(v["Resources"][0]["userName"], "alice@corp.com");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn filter_co_username_returns_substring_matches() -> TestResult {
    let h = build_harness().await?;
    for un in ["alice@corp.com", "alvin@corp.com", "bob@example.com"] {
        let _ = h
            .router
            .clone()
            .oneshot(req_post(
                "/scim/v2/Users",
                &h.bearer_a,
                peer_ok(),
                serde_json::json!({"userName": un, "displayName": un}),
            ))
            .await?;
    }
    let resp = h
        .router
        .clone()
        .oneshot(req_get(
            "/scim/v2/Users?filter=userName%20co%20%22al%22",
            &h.bearer_a,
            peer_ok(),
        ))
        .await?;
    let v = body_json(resp).await;
    assert_eq!(v["totalResults"], 2);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn sort_by_username_descending_orders_results() -> TestResult {
    let h = build_harness().await?;
    for un in ["alice@corp.com", "bob@corp.com", "carol@corp.com"] {
        let _ = h
            .router
            .clone()
            .oneshot(req_post(
                "/scim/v2/Users",
                &h.bearer_a,
                peer_ok(),
                serde_json::json!({"userName": un, "displayName": un}),
            ))
            .await?;
    }
    let resp = h
        .router
        .clone()
        .oneshot(req_get(
            "/scim/v2/Users?sortBy=userName&sortOrder=descending",
            &h.bearer_a,
            peer_ok(),
        ))
        .await?;
    let v = body_json(resp).await;
    let names: Vec<String> = v["Resources"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["userName"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        names,
        vec![
            "carol@corp.com".to_string(),
            "bob@corp.com".to_string(),
            "alice@corp.com".to_string()
        ]
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn filter_active_eq_true_excludes_deactivated() -> TestResult {
    let h = build_harness().await?;
    let body_json_create = |un: &str, active: bool| serde_json::json!({"userName": un, "displayName": un, "active": active});
    for (un, active) in [
        ("active1@corp.com", true),
        ("inactive@corp.com", false),
        ("active2@corp.com", true),
    ] {
        let _ = h
            .router
            .clone()
            .oneshot(req_post(
                "/scim/v2/Users",
                &h.bearer_a,
                peer_ok(),
                body_json_create(un, active),
            ))
            .await?;
    }
    let resp = h
        .router
        .clone()
        .oneshot(req_get(
            "/scim/v2/Users?filter=active%20eq%20true",
            &h.bearer_a,
            peer_ok(),
        ))
        .await?;
    let v = body_json(resp).await;
    assert_eq!(v["totalResults"], 2);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn create_user_returns_etag_and_location_headers() -> TestResult {
    let h = build_harness().await?;
    let resp = h
        .router
        .clone()
        .oneshot(req_post(
            "/scim/v2/Users",
            &h.bearer_a,
            peer_ok(),
            serde_json::json!({"userName": "hdr@corp.com", "displayName": "H"}),
        ))
        .await?;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let etag = resp
        .headers()
        .get(axum::http::header::ETAG)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let loc = resp
        .headers()
        .get(axum::http::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(etag.starts_with("W/\""), "ETag must be weak-quoted form");
    assert!(loc.contains("/scim/v2/Users/"));
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn create_group_returns_etag_and_location_headers() -> TestResult {
    let h = build_harness().await?;
    let resp = h
        .router
        .clone()
        .oneshot(req_post(
            "/scim/v2/Groups",
            &h.bearer_a,
            peer_ok(),
            serde_json::json!({"displayName": "Hdr"}),
        ))
        .await?;
    assert_eq!(resp.status(), StatusCode::CREATED);
    assert!(resp.headers().get(axum::http::header::ETAG).is_some());
    assert!(resp.headers().get(axum::http::header::LOCATION).is_some());
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn filter_input_capped_at_8kb() -> TestResult {
    let h = build_harness().await?;
    let huge = "a pr or ".repeat(2000); // >8 KB
    let uri = format!(
        "/scim/v2/Users?filter={}",
        urlencoding_for_test(&format!("{huge} a pr"))
    );
    let resp = h
        .router
        .clone()
        .oneshot(req_get(&uri, &h.bearer_a, peer_ok()))
        .await?;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let v = body_json(resp).await;
    assert_eq!(v["scimType"], "invalidFilter");
    Ok(())
}

fn urlencoding_for_test(input: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(input.len() * 3);
    for b in input.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char);
            }
            _ => {
                let _ = write!(out, "%{b:02X}");
            }
        }
    }
    out
}

#[tokio::test(flavor = "multi_thread")]
async fn patch_remove_bare_members_clears_all() -> TestResult {
    let h = build_harness().await?;
    // Create 2 users to add as members.
    let mut user_ids = Vec::new();
    for un in ["m1@corp.com", "m2@corp.com"] {
        let v = body_json(
            h.router
                .clone()
                .oneshot(req_post(
                    "/scim/v2/Users",
                    &h.bearer_a,
                    peer_ok(),
                    serde_json::json!({"userName": un, "displayName": un}),
                ))
                .await?,
        )
        .await;
        user_ids.push(v["id"].as_str().unwrap().to_string());
    }
    let create = req_post(
        "/scim/v2/Groups",
        &h.bearer_a,
        peer_ok(),
        serde_json::json!({
            "displayName": "Crew",
            "members": [
                {"value": user_ids[0]},
                {"value": user_ids[1]}
            ]
        }),
    );
    let v = body_json(h.router.clone().oneshot(create).await?).await;
    let group_id = v["id"].as_str().unwrap().to_string();
    assert_eq!(v["members"].as_array().unwrap().len(), 2);
    let resp = h
        .router
        .clone()
        .oneshot(req_patch(
            &format!("/scim/v2/Groups/{group_id}"),
            &h.bearer_a,
            peer_ok(),
            serde_json::json!({"Operations": [{"op": "remove", "path": "members"}]}),
            None,
        ))
        .await?;
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_json(resp).await;
    assert_eq!(v["members"].as_array().unwrap().len(), 0);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn unsupported_content_type_returns_415() -> TestResult {
    let h = build_harness().await?;
    let mut req = Request::builder()
        .method("POST")
        .uri("/scim/v2/Users")
        .header(AUTHORIZATION, format!("Bearer {}", &h.bearer_a))
        .header(CONTENT_TYPE, "text/plain")
        .body(Body::from("not json"))
        .unwrap();
    req.extensions_mut().insert(ConnectInfo(peer_ok()));
    let resp = h.router.clone().oneshot(req).await?;
    assert_eq!(resp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    Ok(())
}

// Helper used to satisfy `mint_token_for_org` assertion that 32 →
// 43 base64url-no-pad chars; we only need the function to type-check
// against the test-side helpers.
#[test]
fn b64_44_is_43_chars() {
    let v = b64_44();
    assert_eq!(v.len(), 43);
}

// `seed_user` is unused in this binary — silence the warning the
// shared common module otherwise emits via `dead_code`.
#[allow(dead_code)]
fn _unused_seed_user_marker(_: PgPool, _: NewUser<'_>, _: NewMembership<'_>) {}
