// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! SCIM 2.0 discovery endpoints (RFC 7643 §5–7).
//!
//! `ServiceProviderConfig`, `Schemas`, `ResourceTypes` are static
//! payloads compiled into the binary via `include_str!`. The same
//! files live under `tests/fixtures/` so integration tests assert
//! response bytes equal the committed fixture (golden-file
//! comparison defends against accidental capability advertisement
//! drift, which is a persistent source of conformance-suite flakes).
//!
//! The static `OnceLock`s parse the JSON once and reuse the parsed
//! `serde_json::Value` for every request; serialisation per request
//! is unavoidable because axum hands ownership to the response
//! builder.

use std::sync::OnceLock;

use axum::http::StatusCode;
use axum::response::Response;
use serde_json::Value;

use super::{SCIM_LIST_RESPONSE_SCHEMA, ScimError, scim_json};

/// Embedded ServiceProviderConfig fixture.
const SERVICE_PROVIDER_CONFIG_RAW: &str =
    include_str!("../../../tests/fixtures/scim_service_provider_config.json");

/// Embedded ResourceTypes fixture (array of `ResourceType` objects).
const RESOURCE_TYPES_RAW: &str = include_str!("../../../tests/fixtures/scim_resource_types.json");

/// Embedded Schemas fixture (array of `Schema` objects).
const SCHEMAS_RAW: &str = include_str!("../../../tests/fixtures/scim_schemas.json");

fn parsed_service_provider_config() -> &'static Value {
    static CELL: OnceLock<Value> = OnceLock::new();
    CELL.get_or_init(|| {
        // infallible: parsing a static literal embedded at compile
        // time via include_str! and pinned by a golden-file test.
        #[allow(clippy::expect_used)]
        serde_json::from_str(SERVICE_PROVIDER_CONFIG_RAW)
            .expect("ServiceProviderConfig fixture must be valid JSON")
    })
}

fn parsed_resource_types() -> &'static Value {
    static CELL: OnceLock<Value> = OnceLock::new();
    CELL.get_or_init(|| {
        // infallible: parsing a static literal embedded at compile
        // time via include_str! and pinned by a golden-file test.
        #[allow(clippy::expect_used)]
        serde_json::from_str(RESOURCE_TYPES_RAW).expect("ResourceTypes fixture must be valid JSON")
    })
}

fn parsed_schemas() -> &'static Value {
    static CELL: OnceLock<Value> = OnceLock::new();
    CELL.get_or_init(|| {
        // infallible: parsing a static literal embedded at compile
        // time via include_str! and pinned by a golden-file test.
        #[allow(clippy::expect_used)]
        serde_json::from_str(SCHEMAS_RAW).expect("Schemas fixture must be valid JSON")
    })
}

/// `GET /scim/v2/ServiceProviderConfig` (RFC 7644 §4).
pub async fn service_provider_config() -> Result<Response, ScimError> {
    Ok(scim_json(StatusCode::OK, parsed_service_provider_config()))
}

/// `GET /scim/v2/ResourceTypes` (RFC 7644 §4).
///
/// Returned shape is the SCIM `ListResponse` envelope so validators
/// that probe `totalResults` against the discovery endpoint receive
/// the canonical surface. The committed fixture is the bare array;
/// the envelope wraps it here so callers see the documented shape.
pub async fn resource_types() -> Result<Response, ScimError> {
    let resources = parsed_resource_types();
    let envelope = serde_json::json!({
        "schemas": [SCIM_LIST_RESPONSE_SCHEMA],
        "totalResults": resources.as_array().map_or(0, Vec::len),
        "Resources": resources,
    });
    Ok(scim_json(StatusCode::OK, &envelope))
}

/// `GET /scim/v2/Schemas` (RFC 7644 §4).
pub async fn schemas() -> Result<Response, ScimError> {
    let resources = parsed_schemas();
    let envelope = serde_json::json!({
        "schemas": [SCIM_LIST_RESPONSE_SCHEMA],
        "totalResults": resources.as_array().map_or(0, Vec::len),
        "Resources": resources,
    });
    Ok(scim_json(StatusCode::OK, &envelope))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixtures_parse() {
        let _ = parsed_service_provider_config();
        let _ = parsed_resource_types();
        let _ = parsed_schemas();
    }

    #[test]
    fn service_provider_config_advertises_v01_contract() {
        let v = parsed_service_provider_config();
        assert_eq!(v["bulk"]["supported"], false);
        assert_eq!(v["filter"]["supported"], true);
        assert_eq!(v["filter"]["maxResults"], 200);
        assert_eq!(v["changePassword"]["supported"], false);
        assert_eq!(v["sort"]["supported"], true);
        assert_eq!(v["etag"]["supported"], true);
        assert_eq!(v["patch"]["supported"], true);
        let auth = &v["authenticationSchemes"][0];
        assert_eq!(auth["type"], "oauthbearertoken");
    }
}
