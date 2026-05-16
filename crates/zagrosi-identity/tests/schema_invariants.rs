// SPDX-License-Identifier: AGPL-3.0-or-later

//! Persistence-layer schema-invariant tests.
//!
//! These confirm DB-level invariants the design notes lean on:
//! UUID v7 sortability, `email_lower` generated column behaviour,
//! `password_hash_version` default, and the `org_id NOT NULL`
//! requirement on every multi-tenant table.

mod common;

use common::{TestResult, migrated_env};
use serial_test::serial;
use sqlx::Row;
use uuid::Uuid;

#[tokio::test]
#[serial]
async fn now_v7_is_b_tree_sorted() -> TestResult {
    let env = migrated_env().await?;

    let mut ids: Vec<Uuid> = Vec::with_capacity(1000);
    for _ in 0..1000_u32 {
        let id = Uuid::now_v7();
        sqlx::query("INSERT INTO orgs (id, slug, display_name) VALUES ($1, $2, $2)")
            .bind(id)
            .bind(id.to_string())
            .execute(&env.pool)
            .await?;
        ids.push(id);
    }

    // Read back the slugs ordered by id; `slug = id.to_string()` lets
    // the test compare the b-tree scan order against the insertion order.
    let rows: Vec<String> = sqlx::query_scalar("SELECT slug FROM orgs ORDER BY id ASC")
        .fetch_all(&env.pool)
        .await?;

    let expected: Vec<String> = {
        let mut sorted = ids.clone();
        sorted.sort();
        sorted.into_iter().map(|i| i.to_string()).collect()
    };

    assert_eq!(rows, expected, "B-tree scan order must equal sorted ids");
    // Spot-check that insertion order matches sorted order for monotonic v7.
    let inserted: Vec<String> = ids.into_iter().map(|i| i.to_string()).collect();
    assert_eq!(rows, inserted, "v7 ids inserted in clock order");
    Ok(())
}

#[tokio::test]
#[serial]
async fn email_lower_generated_column_lowercases_on_insert() -> TestResult {
    let env = migrated_env().await?;
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO users (id, email, display_name) VALUES ($1, $2, $3)")
        .bind(id)
        .bind("MixedCase@Example.COM")
        .bind("Mixed Display")
        .execute(&env.pool)
        .await?;

    let lower: String = sqlx::query_scalar("SELECT email_lower FROM users WHERE id = $1")
        .bind(id)
        .fetch_one(&env.pool)
        .await?;
    assert_eq!(lower, "mixedcase@example.com");
    Ok(())
}

#[tokio::test]
#[serial]
async fn email_lower_updates_when_email_updates() -> TestResult {
    let env = migrated_env().await?;
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO users (id, email, display_name) VALUES ($1, $2, $3)")
        .bind(id)
        .bind("First@Example.com")
        .bind("disp")
        .execute(&env.pool)
        .await?;
    sqlx::query("UPDATE users SET email = $2 WHERE id = $1")
        .bind(id)
        .bind("Second@Example.COM")
        .execute(&env.pool)
        .await?;
    let lower: String = sqlx::query_scalar("SELECT email_lower FROM users WHERE id = $1")
        .bind(id)
        .fetch_one(&env.pool)
        .await?;
    assert_eq!(lower, "second@example.com");
    Ok(())
}

#[tokio::test]
#[serial]
async fn password_hash_version_defaults_to_one() -> TestResult {
    let env = migrated_env().await?;
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO users (id, email, display_name) VALUES ($1, $2, $3)")
        .bind(id)
        .bind("v@example.com")
        .bind("v")
        .execute(&env.pool)
        .await?;
    let v: i16 = sqlx::query_scalar("SELECT password_hash_version FROM users WHERE id = $1")
        .bind(id)
        .fetch_one(&env.pool)
        .await?;
    assert_eq!(v, 1, "password_hash_version default must be 1");
    Ok(())
}

#[tokio::test]
#[serial]
async fn multi_tenant_inserts_require_org_id() -> TestResult {
    let env = migrated_env().await?;

    // For each multi-tenant table the section asserts NOT NULL on
    // org_id (or its analogue: org_idp_id for child tables). We
    // attempt an insert that omits the column and assert a
    // not-null-violation comes back.
    let cases: &[(&str, &str)] = &[
        // (table, "INSERT statement that should fail with NOT NULL")
        (
            "api_tokens",
            r"INSERT INTO api_tokens (id, token_hash, user_id, display_name)
               SELECT $1::uuid, $2::bytea, u.id, 'd'
               FROM users u LIMIT 1",
        ),
        (
            "scim_tokens",
            r"INSERT INTO scim_tokens (id, display_name, token_hash)
               VALUES ($1, 'd', $2)",
        ),
        (
            "org_idps",
            r"INSERT INTO org_idps (id, protocol, display_name, config)
               VALUES ($1, 'oidc', 'd', '{}')",
        ),
    ];

    // Seed a user so api_tokens has a valid FK target.
    let user_id = Uuid::now_v7();
    sqlx::query("INSERT INTO users (id, email, display_name) VALUES ($1, $2, $3)")
        .bind(user_id)
        .bind("e@example.com")
        .bind("e")
        .execute(&env.pool)
        .await?;

    for (table, sql) in cases {
        let id = Uuid::now_v7();
        let res = sqlx::query(sql)
            .bind(id)
            .bind(vec![0_u8; 32])
            .execute(&env.pool)
            .await;
        let Err(err) = res else {
            panic!("expected NOT NULL violation for {table} but insert succeeded");
        };
        // SQLSTATE 23502 = not_null_violation.
        let code = match err {
            sqlx::Error::Database(db_err) => db_err.code().map(std::borrow::Cow::into_owned),
            _ => None,
        };
        assert_eq!(
            code.as_deref(),
            Some("23502"),
            "{table} insert without org_id must raise not_null_violation",
        );
    }
    Ok(())
}

#[tokio::test]
#[serial]
async fn now_v7_collision_resistance() -> TestResult {
    let mut ids = std::collections::HashSet::new();
    for _ in 0..1000_u32 {
        let id = Uuid::now_v7();
        assert!(ids.insert(id));
    }
    Ok(())
}

#[tokio::test]
#[serial]
async fn email_unique_partial_excludes_tombstones() -> TestResult {
    let env = migrated_env().await?;
    // Insert + soft-delete user with a given email, then re-insert
    // the same email. The partial unique on `email_lower WHERE
    // deleted_at IS NULL` should permit the new row.
    let id1 = Uuid::now_v7();
    sqlx::query("INSERT INTO users (id, email, display_name) VALUES ($1, $2, $3)")
        .bind(id1)
        .bind("dup@example.com")
        .bind("d")
        .execute(&env.pool)
        .await?;
    sqlx::query("UPDATE users SET deleted_at = now() WHERE id = $1")
        .bind(id1)
        .execute(&env.pool)
        .await?;

    let id2 = Uuid::now_v7();
    sqlx::query("INSERT INTO users (id, email, display_name) VALUES ($1, $2, $3)")
        .bind(id2)
        .bind("dup@example.com")
        .bind("d")
        .execute(&env.pool)
        .await?;

    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE email_lower = 'dup@example.com'")
            .fetch_one(&env.pool)
            .await?;
    assert_eq!(count, 2);
    // But only one is live.
    let live: i64 =
        sqlx::query("SELECT COUNT(*) FROM users WHERE email_lower = $1 AND deleted_at IS NULL")
            .bind("dup@example.com")
            .fetch_one(&env.pool)
            .await?
            .get(0);
    assert_eq!(live, 1);
    Ok(())
}
