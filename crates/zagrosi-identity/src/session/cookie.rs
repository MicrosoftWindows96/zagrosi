// SPDX-License-Identifier: AGPL-3.0-or-later

//! Browser cookie builders for the session-resolver fast path.
//!
//! Two cookies are emitted on every successful sign-in (any path:
//! password, OIDC callback, SAML ACS):
//!
//! - `__Host-zagrosi_sid` carries the raw `sid_*` token. `HttpOnly`
//!   blocks DOM access; `Secure` is mandated by the `__Host-` prefix
//!   so the cookie cannot land on a plaintext channel; `SameSite=Lax`
//!   blocks the cookie from cross-site form POSTs while permitting
//!   top-level GET navigation. The `__Host-` prefix also forbids
//!   `Domain` and forces `Path=/`, which is what we set explicitly.
//!
//! - `__Host-zagrosi_csrf` carries a 32-byte `OsRng` value the SPA
//!   reads from JavaScript and copies into the `X-Zagrosi-CSRF`
//!   header on every unsafe request. The CSRF cookie deliberately
//!   omits `HttpOnly` — the SPA must read it.
//!
//! API / MCP clients that opt out of cookies (no browser context)
//! receive the `sid_*` token in the response body for bearer use;
//! see [`SessionAttachment`] for the typed seam between the auth
//! handlers and the response shaping.

use cookie::{Cookie, SameSite};

/// Cookie name for the browser session token.
pub const SESSION_COOKIE_NAME: &str = "__Host-zagrosi_sid";

/// Cookie name for the CSRF double-submit value.
pub const CSRF_COOKIE_NAME: &str = "__Host-zagrosi_csrf";

/// HTTP header carrying the CSRF echo value on unsafe browser
/// requests. Validated against [`CSRF_COOKIE_NAME`]'s value by
/// [`crate::http::csrf::csrf_middleware`].
pub const CSRF_HEADER_NAME: &str = "x-zagrosi-csrf";

/// Render a `Set-Cookie` value that clears the browser session cookie.
#[must_use]
pub fn build_clear_session_cookie() -> String {
    format!("{SESSION_COOKIE_NAME}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0")
}

/// Render a `Set-Cookie` value that clears the CSRF cookie.
#[must_use]
pub fn build_clear_csrf_cookie() -> String {
    format!("{CSRF_COOKIE_NAME}=; Path=/; Secure; SameSite=Lax; Max-Age=0")
}

/// Issued cookie pair the auth handler attaches to its response.
///
/// `session` carries the raw `sid_*` token; `csrf` carries the
/// 32-byte CSRF value. The auth handler decides whether to emit
/// these as `Set-Cookie` headers (browser path) or to surface the
/// raw token + CSRF value in the response body (bearer / MCP path).
#[derive(Debug, Clone)]
pub struct SessionAttachment {
    /// Browser session cookie. Carries the raw `sid_*` token.
    pub session: Cookie<'static>,
    /// CSRF double-submit cookie. Carries a fresh 32-byte
    /// `OsRng`-sourced random value, base64url-no-pad encoded.
    pub csrf: Cookie<'static>,
    /// Raw `sid_*` token. Repeats the value embedded in the session
    /// cookie so bearer / MCP responses can lift it without parsing.
    pub raw_session_token: String,
    /// CSRF cookie value as a free-standing string. SPA bootstrap
    /// reads this from the response body to avoid having to parse
    /// the cookie jar before the first XHR.
    pub csrf_value: String,
}

impl SessionAttachment {
    /// Build a cookie pair from a freshly minted session token + CSRF
    /// value. The CSRF value should already be the desired shape
    /// (typically 43 base64url-no-pad chars from 32 random bytes).
    #[must_use]
    pub fn new(raw_session_token: String, csrf_value: String) -> Self {
        let session = Cookie::build((SESSION_COOKIE_NAME, raw_session_token.clone()))
            .path("/")
            .secure(true)
            .http_only(true)
            .same_site(SameSite::Lax)
            .build();
        let csrf = Cookie::build((CSRF_COOKIE_NAME, csrf_value.clone()))
            .path("/")
            .secure(true)
            .http_only(false)
            .same_site(SameSite::Lax)
            .build();
        Self {
            session,
            csrf,
            raw_session_token,
            csrf_value,
        }
    }

    /// Render the session cookie's `Set-Cookie` header value.
    #[must_use]
    pub fn session_set_cookie(&self) -> String {
        self.session.to_string()
    }

    /// Render the CSRF cookie's `Set-Cookie` header value.
    #[must_use]
    pub fn csrf_set_cookie(&self) -> String {
        self.csrf.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_prefix_required_on_session_cookie_name() {
        assert!(SESSION_COOKIE_NAME.starts_with("__Host-"));
    }

    #[test]
    fn host_prefix_required_on_csrf_cookie_name() {
        assert!(CSRF_COOKIE_NAME.starts_with("__Host-"));
    }

    #[test]
    fn session_cookie_carries_secure_httponly_lax_path() {
        let attach = SessionAttachment::new(
            "sid_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            "csrf-token-value".to_string(),
        );
        let rendered = attach.session_set_cookie();
        assert!(rendered.contains("__Host-zagrosi_sid="));
        assert!(rendered.contains("sid_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
        assert!(rendered.contains("Path=/"));
        assert!(rendered.contains("Secure"));
        assert!(rendered.contains("HttpOnly"));
        assert!(rendered.contains("SameSite=Lax"));
    }

    #[test]
    fn csrf_cookie_carries_secure_lax_path_but_not_httponly() {
        let attach = SessionAttachment::new(
            "sid_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            "csrf-value".to_string(),
        );
        let rendered = attach.csrf_set_cookie();
        assert!(rendered.contains("__Host-zagrosi_csrf="));
        assert!(rendered.contains("Path=/"));
        assert!(rendered.contains("Secure"));
        assert!(rendered.contains("SameSite=Lax"));
        assert!(!rendered.contains("HttpOnly"));
    }

    #[test]
    fn raw_session_token_round_trips() {
        let raw = "sid_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx".to_string();
        let attach = SessionAttachment::new(raw.clone(), "c".repeat(43));
        assert_eq!(attach.raw_session_token, raw);
        assert_eq!(attach.csrf_value, "c".repeat(43));
    }

    #[test]
    fn clear_session_cookie_expires_host_cookie() {
        let rendered = build_clear_session_cookie();
        assert!(rendered.contains("__Host-zagrosi_sid="));
        assert!(rendered.contains("Path=/"));
        assert!(rendered.contains("Secure"));
        assert!(rendered.contains("HttpOnly"));
        assert!(rendered.contains("SameSite=Lax"));
        assert!(rendered.contains("Max-Age=0"));
    }

    #[test]
    fn clear_csrf_cookie_expires_host_cookie_without_httponly() {
        let rendered = build_clear_csrf_cookie();
        assert!(rendered.contains("__Host-zagrosi_csrf="));
        assert!(rendered.contains("Path=/"));
        assert!(rendered.contains("Secure"));
        assert!(rendered.contains("SameSite=Lax"));
        assert!(rendered.contains("Max-Age=0"));
        assert!(!rendered.contains("HttpOnly"));
    }
}
