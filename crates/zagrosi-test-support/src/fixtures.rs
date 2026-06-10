// SPDX-License-Identifier: AGPL-3.0-or-later

//! Thin shared fixtures (moved from identity's `tests/common`).
//!
//! Fixtures grow only when a migrated suite already duplicates a helper —
//! keep this module deliberately small (the dev-dep loop doubles
//! identity's test builds; see README).

use sqlx::PgPool;
use uuid::Uuid;

/// Insert a minimal `orgs` row and return its UUID v7.
///
/// # Errors
///
/// Propagates the underlying insert failure.
pub async fn seed_org(pool: &PgPool, slug: &str) -> Result<Uuid, sqlx::Error> {
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO orgs (id, slug, display_name) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(slug)
        .bind(slug)
        .execute(pool)
        .await?;
    Ok(id)
}

/// Insert a minimal `users` row and return its UUID v7.
///
/// # Errors
///
/// Propagates the underlying insert failure.
pub async fn seed_user(pool: &PgPool, email: &str) -> Result<Uuid, sqlx::Error> {
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO users (id, email, display_name) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(email)
        .bind(email)
        .execute(pool)
        .await?;
    Ok(id)
}
