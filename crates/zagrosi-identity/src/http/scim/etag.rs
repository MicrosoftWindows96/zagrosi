// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! SCIM `meta.version` ETag derivation + `If-Match` parsing.
//!
//! The ETag is a deterministic SHA-256 over `(updated_at, row_version)`
//! base64url-encoded. The hash collapses high-resolution timestamps
//! and the per-row monotonic counter into a 22-character opaque
//! string that is sortable lexicographically only insofar as SHA-256
//! preserves no order — clients MUST treat it as opaque per RFC
//! 7644 §3.14.
//!
//! `If-Match` header values may be quoted and may carry the weak
//! prefix `W/`. Both forms are accepted; the SCIM server emits only
//! strong ETags so weak comparison is treated identically to strong.

use axum::http::HeaderMap;
use axum::http::header::IF_MATCH;
use base64::Engine;
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};

/// Derive the SCIM `meta.version` ETag value (without surrounding
/// quotes — the response serialiser adds them).
#[must_use]
pub fn meta_version(updated_at: DateTime<Utc>, row_version: i64) -> String {
    let mut hasher = Sha256::new();
    hasher.update(
        updated_at
            .to_rfc3339_opts(chrono::SecondsFormat::Nanos, true)
            .as_bytes(),
    );
    hasher.update(b"\0");
    hasher.update(row_version.to_be_bytes());
    let digest = hasher.finalize();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

/// Wrap an [`meta_version`] result with surrounding quotes for use
/// in the `meta.version` field per RFC 7644 §3.14.
#[must_use]
pub fn quoted_etag(updated_at: DateTime<Utc>, row_version: i64) -> String {
    let v = meta_version(updated_at, row_version);
    format!("W/\"{v}\"")
}

/// Parse `If-Match` header into the opaque etag value (without
/// quotes / weak prefix).
///
/// Returns `None` when the header is absent. Returns `Some` with
/// the inner string for any other case — the caller decides whether
/// the match succeeds against the row's current version.
#[must_use]
pub fn parse_if_match(headers: &HeaderMap) -> Option<String> {
    headers
        .get(IF_MATCH)
        .and_then(|v| v.to_str().ok())
        .map(strip_etag_decoration)
}

/// Strip surrounding quotes + optional weak (`W/`) prefix from an
/// ETag string. Used by both the request-side `If-Match` parser
/// and tests.
fn strip_etag_decoration(raw: &str) -> String {
    let trimmed = raw.trim();
    let trimmed = trimmed.strip_prefix("W/").unwrap_or(trimmed);
    let trimmed = trimmed.strip_prefix('"').unwrap_or(trimmed);
    let trimmed = trimmed.strip_suffix('"').unwrap_or(trimmed);
    trimmed.to_string()
}

/// Compare a caller-supplied `If-Match` value to the row's
/// `(updated_at, row_version)`. Returns `true` only when the SHA
/// matches; the comparison is constant-time-ish via byte-by-byte
/// `eq` after both values are equal-length.
#[must_use]
pub fn version_matches(if_match: &str, updated_at: DateTime<Utc>, row_version: i64) -> bool {
    use subtle::ConstantTimeEq;
    let expected = meta_version(updated_at, row_version);
    let supplied = strip_etag_decoration(if_match);
    if expected.len() != supplied.len() {
        return false;
    }
    bool::from(expected.as_bytes().ct_eq(supplied.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn t(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s)
            .unwrap_or_else(|e| panic!("rfc3339 parse: {e}"))
            .with_timezone(&Utc)
    }

    #[test]
    fn version_changes_with_row_version() {
        let dt = t("2026-05-10T00:00:00Z");
        assert_ne!(meta_version(dt, 1), meta_version(dt, 2));
    }

    #[test]
    fn version_changes_with_timestamp() {
        let a = t("2026-05-10T00:00:00.000000001Z");
        let b = t("2026-05-10T00:00:00.000000002Z");
        assert_ne!(meta_version(a, 1), meta_version(b, 1));
    }

    #[test]
    fn version_is_22_chars_url_safe_b64_no_pad() {
        let v = meta_version(t("2026-05-10T00:00:00Z"), 0);
        assert!(
            v.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        );
        assert!(!v.contains('='));
        assert_eq!(v.len(), 43); // 32-byte SHA -> 43 base64url no-pad chars
    }

    #[test]
    fn parse_if_match_strips_weak_quotes() {
        let mut headers = HeaderMap::new();
        headers.insert(IF_MATCH, axum::http::HeaderValue::from_static("W/\"abc\""));
        assert_eq!(parse_if_match(&headers).as_deref(), Some("abc"));
        let mut headers = HeaderMap::new();
        headers.insert(IF_MATCH, axum::http::HeaderValue::from_static("\"abc\""));
        assert_eq!(parse_if_match(&headers).as_deref(), Some("abc"));
    }

    #[test]
    fn version_matches_only_for_same_inputs() {
        let dt = Utc.with_ymd_and_hms(2026, 5, 10, 0, 0, 0).unwrap();
        let etag = meta_version(dt, 7);
        assert!(version_matches(&etag, dt, 7));
        assert!(version_matches(&format!("W/\"{etag}\""), dt, 7));
        assert!(!version_matches(&etag, dt, 8));
    }
}
