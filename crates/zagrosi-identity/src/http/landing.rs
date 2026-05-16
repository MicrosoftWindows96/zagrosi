// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! Shared landing-page renderer.
//!
//! The verify-email and password-reset email links land on a `GET`
//! page that does NOT mutate state. The page renders an auto-POST
//! form pointing at the canonical confirm URL with the token in the
//! form body. This strips the token from browser history + the
//! `Referer` header on subsequent navigation.
//!
//! Required headers:
//! - `Referrer-Policy: no-referrer`
//! - `Content-Security-Policy: default-src 'none'; form-action 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'`
//!
//! The page MUST NOT load any third-party assets (no CDN fonts, no
//! analytics, no external favicon). The auto-POST script is inline.

use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

/// Render an auto-POST landing page for `confirm_url` with the
/// supplied `token` rendered into a hidden form input.
///
/// Returns a fully-built [`Response`] carrying the documented
/// security headers + an HTML body that submits to `confirm_url` on
/// `window.onload`. Users without JavaScript see a "Continue" button
/// (graceful degradation).
#[must_use]
pub fn render_landing(confirm_url: &str, token: &str) -> Response {
    let body = format!(
        concat!(
            "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">",
            "<title>Continuing…</title>",
            "<style>body{{font-family:system-ui,sans-serif;text-align:center;margin-top:4rem}}",
            "form{{display:inline-block}}button{{padding:.6rem 1.2rem;font-size:1rem}}</style>",
            "</head><body>",
            "<form id=\"f\" method=\"POST\" action=\"{confirm_url}\">",
            "<input type=\"hidden\" name=\"token\" value=\"{token}\">",
            "<button type=\"submit\">Continue</button>",
            "</form>",
            "<script>document.getElementById('f').submit()</script>",
            "</body></html>",
        ),
        confirm_url = html_escape(confirm_url),
        token = html_escape(token),
    );

    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; form-action 'self'; \
             style-src 'self' 'unsafe-inline'; \
             script-src 'self' 'unsafe-inline'",
        ),
    );
    (StatusCode::OK, headers, body).into_response()
}

fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            '&' => out.push_str("&amp;"),
            _ => out.push(ch),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_form_with_token() {
        let resp = render_landing("/confirm", "rst_abc");
        let headers = resp.headers().clone();
        assert_eq!(
            headers
                .get(header::REFERRER_POLICY)
                .map(|v| v.to_str().unwrap_or("")),
            Some("no-referrer"),
        );
        let csp = headers
            .get(header::CONTENT_SECURITY_POLICY)
            .map_or("", |v| v.to_str().unwrap_or(""));
        assert!(csp.contains("default-src 'none'"));
        assert!(csp.contains("form-action 'self'"));
    }

    #[test]
    fn html_escape_round_trip() {
        assert_eq!(html_escape("<script>"), "&lt;script&gt;");
        assert_eq!(html_escape("&\"'"), "&amp;&quot;&#39;");
    }
}
