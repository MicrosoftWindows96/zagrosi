// SPDX-License-Identifier: AGPL-3.0-or-later

//! CSRF double-submit middleware for browser auth routes.
//!
//! Browser callers (those that present the
//! [`crate::session::cookie::SESSION_COOKIE_NAME`] cookie) MUST also
//! echo the [`crate::session::cookie::CSRF_COOKIE_NAME`] cookie's
//! value via the [`crate::session::cookie::CSRF_HEADER_NAME`] header
//! on every unsafe request. The middleware compares the two with a
//! constant-time comparison and rejects mismatches with `403`.
//!
//! Skipped for:
//! - Requests that carry no session cookie (bearer-only API / MCP).
//! - Routes mounted by federated-auth callbacks (OIDC / SAML) which
//!   carry their own state-binding mechanism (`state` parameter,
//!   signed `RelayState`).
//!
//! Mount the middleware at the auth-router level only; the gateway
//! mounts the same middleware shape at its router boundary.

use axum::body::Body;
use axum::extract::Request;
use axum::http::{HeaderMap, Method, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use subtle::ConstantTimeEq;
use tracing::warn;

use crate::session::cookie::{CSRF_COOKIE_NAME, CSRF_HEADER_NAME, SESSION_COOKIE_NAME};

/// Routes that opt out of CSRF middleware. Federated-auth callbacks
/// own their own state-binding mechanism and cannot rely on a
/// pre-existing browser cookie because `SameSite=Lax` blocks the
/// cookie on cross-site form POSTs.
const CSRF_EXEMPT_PATH_PREFIXES: &[&str] = &["/v1/auth/oidc/", "/v1/auth/saml/"];

/// CSRF double-submit middleware.
///
/// Pass-through for safe methods (`GET` / `HEAD` / `OPTIONS`),
/// bearer-only requests (no session cookie present), and the
/// federated-auth callback exemption list. Every other request
/// must echo the CSRF cookie value via the header; failure returns
/// `403 Forbidden` with empty body.
pub async fn csrf_middleware(req: Request<Body>, next: Next) -> Response {
    if matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS) {
        return next.run(req).await;
    }
    if CSRF_EXEMPT_PATH_PREFIXES
        .iter()
        .any(|prefix| req.uri().path().starts_with(prefix))
    {
        return next.run(req).await;
    }
    let headers = req.headers();
    let Some(cookie_value) = extract_cookie(headers, SESSION_COOKIE_NAME) else {
        // No browser session cookie → bearer / MCP path. The CSRF
        // double-submit doesn't apply (the bearer credential lives
        // in the `Authorization` header, not in a cookie that a
        // cross-site form could replay).
        return next.run(req).await;
    };
    let path = req.uri().path().to_owned();
    let method = req.method().clone();
    let _ = cookie_value;
    // Sanity: a request that carries the session cookie but no CSRF
    // cookie is structurally inconsistent — reject it.
    let Some(csrf_cookie) = extract_cookie(headers, CSRF_COOKIE_NAME) else {
        warn!(reason = "missing_csrf_cookie", %path, %method, "csrf_validation_failed");
        return forbidden();
    };
    let Some(csrf_header) = headers.get(CSRF_HEADER_NAME).and_then(|v| v.to_str().ok()) else {
        warn!(reason = "missing_csrf_header", %path, %method, "csrf_validation_failed");
        return forbidden();
    };
    if csrf_header.as_bytes().ct_eq(csrf_cookie.as_bytes()).into() {
        next.run(req).await
    } else {
        warn!(reason = "csrf_mismatch", %path, %method, "csrf_validation_failed");
        forbidden()
    }
}

fn extract_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    cookie::Cookie::split_parse(raw)
        .filter_map(Result::ok)
        .find(|c| c.name() == name)
        .map(|c| c.value().to_owned())
}

fn forbidden() -> Response {
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .body(Body::empty())
        .unwrap_or_else(|_| StatusCode::FORBIDDEN.into_response())
}

// `into_response` for StatusCode in scope.
use axum::response::IntoResponse;

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn headers_with(cookies: &str, csrf_header: Option<&str>) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            axum::http::header::COOKIE,
            HeaderValue::from_str(cookies).expect("cookie header"),
        );
        if let Some(value) = csrf_header {
            h.insert(
                CSRF_HEADER_NAME,
                HeaderValue::from_str(value).expect("csrf header"),
            );
        }
        h
    }

    #[test]
    fn extract_cookie_resolves_named_value() {
        let h = headers_with(
            "__Host-zagrosi_sid=sid_abc; __Host-zagrosi_csrf=csrf_xyz",
            None,
        );
        assert_eq!(
            extract_cookie(&h, SESSION_COOKIE_NAME).as_deref(),
            Some("sid_abc")
        );
        assert_eq!(
            extract_cookie(&h, CSRF_COOKIE_NAME).as_deref(),
            Some("csrf_xyz")
        );
    }

    #[test]
    fn extract_cookie_returns_none_for_missing_name() {
        let h = headers_with("__Host-zagrosi_sid=sid_abc", None);
        assert!(extract_cookie(&h, CSRF_COOKIE_NAME).is_none());
    }

    #[test]
    fn exempt_prefix_match_blocks_oidc_callback() {
        assert!(
            CSRF_EXEMPT_PATH_PREFIXES
                .iter()
                .any(|p| "/v1/auth/oidc/google/callback".starts_with(p))
        );
        assert!(
            CSRF_EXEMPT_PATH_PREFIXES
                .iter()
                .any(|p| "/v1/auth/saml/acme/acs".starts_with(p))
        );
        assert!(
            !CSRF_EXEMPT_PATH_PREFIXES
                .iter()
                .any(|p| "/v1/auth/sign-in".starts_with(p))
        );
    }

    #[test]
    fn forbidden_response_carries_403_status() {
        let resp = forbidden();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }
}
