// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::missing_panics_doc,
    clippy::missing_errors_doc,
    clippy::missing_const_for_fn
)]
//! Mailpit message-capture client for the section-16 stack.
//!
//! Mailpit (the SMTP sink in `compose.test.yaml`) exposes a REST API
//! on `:8025`. The password-flow integration suite drives sign-up /
//! reset and then polls here for the resulting `vrf_` / `rst_`
//! verification mails. Every call is a fail-soft reqwest GET so a
//! mis-configured stack surfaces as a skip, not a panic.

use std::time::Duration;

use super::TestResult;

/// Default Mailpit REST base (mapped to `127.0.0.1:8025` by
/// `compose.test.yaml`). Overridable via `ZAGROSI_TEST_MAILPIT_URL`.
#[must_use]
pub fn base_url() -> String {
    std::env::var("ZAGROSI_TEST_MAILPIT_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:8025".to_string())
}

/// `GET /api/v1/info` — liveness probe mirroring the compose
/// healthcheck. `true` only on a 2xx.
pub async fn healthy(http: &reqwest::Client) -> bool {
    http.get(format!("{}/api/v1/info", base_url()))
        .send()
        .await
        .map(|r| r.status().is_success())
        .unwrap_or(false)
}

/// Search captured messages by recipient, newest first
/// (`GET /api/v1/search?query=to:<addr>`). Returns the raw JSON
/// `messages` array.
pub async fn messages_to(
    http: &reqwest::Client,
    address: &str,
) -> TestResult<Vec<serde_json::Value>> {
    let url = format!("{}/api/v1/search", base_url());
    let resp = http
        .get(&url)
        .query(&[("query", format!("to:{address}"))])
        .send()
        .await?
        .error_for_status()?;
    let body: serde_json::Value = resp.json().await?;
    Ok(body
        .get("messages")
        .and_then(|m| m.as_array())
        .cloned()
        .unwrap_or_default())
}

/// Poll [`messages_to`] until at least one message is captured or
/// `timeout` elapses. Returns the newest message body
/// (`GET /api/v1/message/{ID}`) so callers can extract the
/// embedded token.
pub async fn await_latest_to(
    http: &reqwest::Client,
    address: &str,
    timeout: Duration,
) -> TestResult<serde_json::Value> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let msgs = messages_to(http, address).await.unwrap_or_default();
        if let Some(first) = msgs.first()
            && let Some(id) = first.get("ID").and_then(serde_json::Value::as_str)
        {
            let url = format!("{}/api/v1/message/{id}", base_url());
            let body: serde_json::Value = http
                .get(&url)
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            return Ok(body);
        }
        if std::time::Instant::now() >= deadline {
            return Err(format!("no Mailpit message for {address} within {timeout:?}").into());
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}
