// SPDX-License-Identifier: AGPL-3.0-or-later

//! Custom Postgres image coordinates.
//!
//! The default image reference is compiled in from
//! `deploy/docker/postgres/IMAGE_TAG` (the single source of truth section
//! 01 established), so a tag bump there propagates here without a second
//! edit. The pinned extension versions mirror
//! `deploy/docker/postgres/VERSIONS` — bump both together (the Dockerfile
//! and that file carry the matching cross-comment).

/// Full default image reference, embedded from
/// `deploy/docker/postgres/IMAGE_TAG` at compile time (trailing newline
/// trimmed by [`pg_image`]).
pub const DEFAULT_PG_IMAGE: &str = include_str!("../../../deploy/docker/postgres/IMAGE_TAG");

/// Mirrors `PG_PARTMAN_VERSION` in `deploy/docker/postgres/VERSIONS`.
pub const PINNED_PG_PARTMAN_VERSION: &str = "5.4.3";

/// Mirrors `PG_PARQUET_VERSION` in `deploy/docker/postgres/VERSIONS`.
pub const PINNED_PG_PARQUET_VERSION: &str = "0.5.1";

/// Env var overriding the image reference (e.g. a locally built tag).
pub const PG_IMAGE_ENV: &str = "ZAGROSI_TEST_PG_IMAGE";

/// Resolve the image reference: `ZAGROSI_TEST_PG_IMAGE` override, else the
/// compiled-in `IMAGE_TAG` value.
#[must_use]
pub fn pg_image() -> String {
    std::env::var(PG_IMAGE_ENV).ok().map_or_else(
        || DEFAULT_PG_IMAGE.trim().to_string(),
        |v| v.trim().to_string(),
    )
}

/// Split a full image reference into `(name, tag)` for `GenericImage`.
///
/// Splits on the last `:` so registry ports (`host:5000/img:tag`) survive.
/// Digest references (`name@sha256:...`) are NOT supported — the harness
/// consumes the tag-form `IMAGE_TAG` contract only.
#[must_use]
pub fn split_image_ref(image_ref: &str) -> (String, String) {
    image_ref.rsplit_once(':').map_or_else(
        || (image_ref.to_string(), "latest".to_string()),
        |(name, tag)| (name.to_string(), tag.to_string()),
    )
}
