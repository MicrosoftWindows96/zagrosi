// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! SCIM attribute → column whitelist.
//!
//! The filter translation layer pushes parameterised SQL into
//! `sqlx::QueryBuilder`. Attribute names are NEVER interpolated as
//! SQL — they round-trip through the maps below to produce static
//! `&'static str` column identifiers. Unknown attributes return
//! [`super::ScimError::InvalidFilter`] so injection attempts fail
//! at the parser, not the database.
//!
//! `users` columns surfaced via SCIM:
//! - `id`            ← `users.id`
//! - `userName`      ← `users.email_lower`
//! - `displayName`   ← `users.display_name`
//! - `active`        ← `users.active`
//! - `externalId`    ← `users.external_id`
//! - `meta.created`  ← `users.created_at`
//! - `meta.lastModified` ← `users.updated_at`
//! - `name.familyName` / `name.givenName` ← virtual (parsed from
//!   `display_name`; not filterable in v0.1).
//! - `emails.value`  ← virtual (the lower-cased primary email
//!   currently equals `email_lower`; multi-emails arrive in a
//!   later split).
//!
//! `groups` columns:
//! - `id`            ← `groups.id`
//! - `displayName`   ← `groups.display_name`
//! - `externalId`    ← `groups.external_id`
//! - `meta.created`  ← `groups.created_at`
//! - `meta.lastModified` ← `groups.updated_at`

use super::ScimError;
use super::filter::{AttrPath, ResourceKind};

/// Column the attribute path resolves to, or `None` when the
/// attribute is virtual / non-filterable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ColumnRef {
    /// The fully-qualified `table.column` literal pushed into the
    /// `QueryBuilder`. Always `&'static str` so attacker-controlled
    /// input can never reach the SQL.
    pub sql: &'static str,
    /// Postgres type kind used by the translator to choose between
    /// `LIKE`, `ILIKE`, integer comparisons, timestamp coercion.
    pub kind: ColumnKind,
}

/// Postgres column-type discriminator used by the filter
/// translator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColumnKind {
    /// `TEXT` (case-insensitive on `eq`/`ne`/`co`/`sw`/`ew`).
    Text,
    /// `BOOLEAN`.
    Bool,
    /// `TIMESTAMPTZ`.
    Timestamp,
    /// `UUID`.
    Uuid,
    /// `BIGINT`.
    BigInt,
}

/// Resolve a SCIM `User` attribute path to its backing column.
///
/// # Errors
///
/// Returns [`ScimError::InvalidFilter`] for attributes outside the
/// SCIM 2.0 core User schema or attributes that are virtual /
/// non-filterable.
pub fn user_column(path: &AttrPath) -> Result<ColumnRef, ScimError> {
    match (path.attr_name.as_str(), path.sub_attr.as_deref()) {
        ("id", None) => Ok(ColumnRef {
            sql: "users.id",
            kind: ColumnKind::Uuid,
        }),
        ("username", None) | ("emails", Some("value")) => Ok(ColumnRef {
            sql: "users.email_lower",
            kind: ColumnKind::Text,
        }),
        ("displayname", None) => Ok(ColumnRef {
            sql: "users.display_name",
            kind: ColumnKind::Text,
        }),
        ("active", None) => Ok(ColumnRef {
            sql: "users.active",
            kind: ColumnKind::Bool,
        }),
        ("externalid", None) => Ok(ColumnRef {
            sql: "users.external_id",
            kind: ColumnKind::Text,
        }),
        ("meta", Some("created")) => Ok(ColumnRef {
            sql: "users.created_at",
            kind: ColumnKind::Timestamp,
        }),
        ("meta", Some("lastmodified")) => Ok(ColumnRef {
            sql: "users.updated_at",
            kind: ColumnKind::Timestamp,
        }),
        _ => Err(ScimError::InvalidFilter {
            detail: format!("unknown User attribute: {path}"),
        }),
    }
}

/// Resolve a SCIM `Group` attribute path to its backing column.
///
/// # Errors
///
/// Returns [`ScimError::InvalidFilter`] for unknown attributes.
pub fn group_column(path: &AttrPath) -> Result<ColumnRef, ScimError> {
    match (path.attr_name.as_str(), path.sub_attr.as_deref()) {
        ("id", None) => Ok(ColumnRef {
            sql: "groups.id",
            kind: ColumnKind::Uuid,
        }),
        ("displayname", None) => Ok(ColumnRef {
            sql: "groups.display_name",
            kind: ColumnKind::Text,
        }),
        ("externalid", None) => Ok(ColumnRef {
            sql: "groups.external_id",
            kind: ColumnKind::Text,
        }),
        ("meta", Some("created")) => Ok(ColumnRef {
            sql: "groups.created_at",
            kind: ColumnKind::Timestamp,
        }),
        ("meta", Some("lastmodified")) => Ok(ColumnRef {
            sql: "groups.updated_at",
            kind: ColumnKind::Timestamp,
        }),
        _ => Err(ScimError::InvalidFilter {
            detail: format!("unknown Group attribute: {path}"),
        }),
    }
}

/// Dispatch by resource kind.
///
/// # Errors
///
/// Returns [`ScimError::InvalidFilter`] for attributes outside the
/// resource's schema.
pub fn column_for(kind: ResourceKind, path: &AttrPath) -> Result<ColumnRef, ScimError> {
    match kind {
        ResourceKind::User => user_column(path),
        ResourceKind::Group => group_column(path),
    }
}

/// Resolve a `sortBy` attribute to its column. The whitelist is
/// stricter than the filter map (no `meta.*`, no virtual paths) and
/// rejects unknown names with [`ScimError::InvalidSortBy`] so the
/// SCIM error envelope can carry a deterministic `scimType` per
/// RFC 7644 §3.4.2.3.
///
/// # Errors
///
/// Returns [`ScimError::InvalidSortBy`] for unknown attributes.
pub fn user_sort_column(name: &str) -> Result<ColumnRef, ScimError> {
    match name {
        "id" => Ok(ColumnRef {
            sql: "users.id",
            kind: ColumnKind::Uuid,
        }),
        "userName" => Ok(ColumnRef {
            sql: "users.email_lower",
            kind: ColumnKind::Text,
        }),
        "displayName" | "name.familyName" | "name.givenName" => Ok(ColumnRef {
            sql: "users.display_name",
            kind: ColumnKind::Text,
        }),
        "meta.created" => Ok(ColumnRef {
            sql: "users.created_at",
            kind: ColumnKind::Timestamp,
        }),
        "meta.lastModified" => Ok(ColumnRef {
            sql: "users.updated_at",
            kind: ColumnKind::Timestamp,
        }),
        _ => Err(ScimError::InvalidSortBy {
            attr: name.to_string(),
        }),
    }
}

/// `sortBy` whitelist for the Group resource.
///
/// # Errors
///
/// Returns [`ScimError::InvalidSortBy`] for unknown attributes.
pub fn group_sort_column(name: &str) -> Result<ColumnRef, ScimError> {
    match name {
        "id" => Ok(ColumnRef {
            sql: "groups.id",
            kind: ColumnKind::Uuid,
        }),
        "displayName" => Ok(ColumnRef {
            sql: "groups.display_name",
            kind: ColumnKind::Text,
        }),
        "meta.created" => Ok(ColumnRef {
            sql: "groups.created_at",
            kind: ColumnKind::Timestamp,
        }),
        "meta.lastModified" => Ok(ColumnRef {
            sql: "groups.updated_at",
            kind: ColumnKind::Timestamp,
        }),
        _ => Err(ScimError::InvalidSortBy {
            attr: name.to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::scim::filter::AttrPath;

    fn p(attr: &str, sub: Option<&str>) -> AttrPath {
        AttrPath {
            schema: None,
            attr_name: attr.to_string(),
            sub_attr: sub.map(str::to_string),
        }
    }

    #[test]
    fn user_known_attributes_resolve() {
        assert!(user_column(&p("username", None)).is_ok());
        assert!(user_column(&p("displayname", None)).is_ok());
        assert!(user_column(&p("active", None)).is_ok());
        assert!(user_column(&p("externalid", None)).is_ok());
        assert!(user_column(&p("emails", Some("value"))).is_ok());
        assert!(user_column(&p("meta", Some("created"))).is_ok());
        assert!(user_column(&p("meta", Some("lastmodified"))).is_ok());
    }

    #[test]
    fn user_unknown_attribute_named_in_error() {
        let err = user_column(&p("nope", None)).unwrap_err();
        let ScimError::InvalidFilter { detail } = err else {
            panic!("expected invalid filter")
        };
        assert!(detail.contains("nope"));
    }

    #[test]
    fn group_known_attributes_resolve() {
        assert!(group_column(&p("displayname", None)).is_ok());
        assert!(group_column(&p("externalid", None)).is_ok());
    }

    #[test]
    fn sort_unknown_uses_invalid_sort_by_variant() {
        let err = user_sort_column("nope").unwrap_err();
        assert!(matches!(err, ScimError::InvalidSortBy { .. }));
    }

    #[test]
    fn sort_known_attrs_each_resolve() {
        for name in [
            "id",
            "userName",
            "displayName",
            "meta.created",
            "meta.lastModified",
            "name.familyName",
            "name.givenName",
        ] {
            user_sort_column(name).unwrap_or_else(|e| panic!("`{name}` should resolve: {e}"));
        }
    }
}
