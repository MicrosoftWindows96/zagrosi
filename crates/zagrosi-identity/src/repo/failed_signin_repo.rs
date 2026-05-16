// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! `FailedSigninRepo` — per-window aggregates of failed sign-in attempts.

use chrono::{DateTime, Utc};
use sqlx::types::ipnetwork::IpNetwork;
use std::net::IpAddr;
use uuid::Uuid;

use crate::error::{IdentityError, Result};

/// Repository for `failed_signin_aggregates`.
///
/// Each row aggregates `count` failed sign-ins for a
/// `(user_id, ip, window_start)` triple within a one-minute window.
/// `user_id` is `NULL`-able so the unknown-email path can still
/// aggregate by IP. `org_id` is `NULL`-able for the same reason.
pub struct FailedSigninRepo {
    pool: sqlx::PgPool,
}

/// Outcome the upsert returns so the caller can wire audit emission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FailedSigninUpsert {
    /// Total failed-attempt count in this window after the upsert.
    pub count: i32,
    /// Whether this row was newly created (count was 0 before).
    pub first_in_window: bool,
}

impl FailedSigninRepo {
    /// Wrap a connection pool.
    #[must_use]
    pub const fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }

    /// Increment the aggregate for `(user_id, ip)` in the current
    /// minute window. Creates the row on first failure; bumps `count`
    /// + `last_attempt_at` thereafter.
    ///
    /// Uses `NULLS NOT DISTINCT` semantics so `user_id = NULL` (the
    /// unknown-email path) collapses into a single per-window IP row
    /// rather than spawning one row per unique unknown email.
    pub async fn record_failure(
        &self,
        org_id: Option<Uuid>,
        user_id: Option<Uuid>,
        ip: IpAddr,
        now: DateTime<Utc>,
    ) -> Result<FailedSigninUpsert> {
        let window_start = truncate_to_minute(now);
        let ip_net: IpNetwork = ip.into();
        let row = sqlx::query!(
            r#"
            INSERT INTO failed_signin_aggregates (
                id, org_id, user_id, ip, window_start, count,
                first_attempt_at, last_attempt_at
            )
            VALUES ($1, $2, $3, $4, $5, 1, $6, $6)
            ON CONFLICT (user_id, window_start) DO UPDATE
                SET count = failed_signin_aggregates.count + 1,
                    last_attempt_at = EXCLUDED.last_attempt_at
            RETURNING count, (xmax = 0) AS "first!: bool"
            "#,
            Uuid::now_v7(),
            org_id,
            user_id,
            ip_net,
            window_start,
            now,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(IdentityError::from)?;
        Ok(FailedSigninUpsert {
            count: row.count,
            first_in_window: row.first,
        })
    }
}

fn truncate_to_minute(ts: DateTime<Utc>) -> DateTime<Utc> {
    use chrono::Timelike as _;
    ts.with_second(0)
        .and_then(|t| t.with_nanosecond(0))
        .unwrap_or(ts)
}
