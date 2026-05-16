// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! SCIM filter AST → `sqlx::QueryBuilder` predicate emitter.
//!
//! Walks the parsed [`Filter`] tree and pushes parameterised SQL
//! into a [`sqlx::QueryBuilder`]. Attribute names are resolved
//! through the `&'static str` whitelist in [`super::attrs`] —
//! never user input. Right-hand-side literals are bound via
//! `push_bind` so untrusted values cannot reach the SQL parser.
//!
//! Type coercion is per [`ColumnKind`]:
//! - `Text` columns use `LOWER()` + `LIKE` for case-insensitive
//!   comparisons (RFC 7644 §3.4.2.2 mandates case-insensitive
//!   string comparison by default).
//! - `Bool`, `Timestamp`, `Uuid`, `BigInt` use natural equality /
//!   ordering operators.
//!
//! Unsupported combinations (e.g. `co` on a `Bool`) return
//! [`ScimError::InvalidValue`] rather than emitting malformed SQL.

use sqlx::Postgres;
use sqlx::QueryBuilder;

use super::ScimError;
use super::attrs::{ColumnKind, ColumnRef, column_for};
use super::filter::{AttrPath, CompareOp, Filter, ResourceKind, Value};

/// Push the `Filter` tree as a parenthesised SQL predicate into
/// `qb`. The caller is responsible for the surrounding `WHERE` /
/// `AND` glue.
///
/// # Errors
///
/// Returns [`ScimError::InvalidFilter`] for unknown attributes,
/// [`ScimError::InvalidValue`] for type mismatches between operator
/// and column kind.
pub fn push_filter(
    qb: &mut QueryBuilder<'_, Postgres>,
    kind: ResourceKind,
    filter: &Filter,
) -> Result<(), ScimError> {
    qb.push("(");
    match filter {
        Filter::And(a, b) => {
            push_filter(qb, kind, a)?;
            qb.push(" AND ");
            push_filter(qb, kind, b)?;
        }
        Filter::Or(a, b) => {
            push_filter(qb, kind, a)?;
            qb.push(" OR ");
            push_filter(qb, kind, b)?;
        }
        Filter::Not(inner) => {
            qb.push("NOT ");
            push_filter(qb, kind, inner)?;
        }
        Filter::Present { attr } => {
            let col = column_for(kind, attr)?;
            qb.push(col.sql);
            qb.push(" IS NOT NULL");
        }
        Filter::Comparison { attr, op, value } => {
            push_comparison(qb, kind, attr, *op, value)?;
        }
        Filter::ValuePath { attr, inner } => {
            // RFC 7644 §3.4.2.2 valuePath. The v0.1 translation
            // supports the restricted shape where the inner
            // expression references a sub-attribute that, when
            // joined with the outer attribute path, resolves to a
            // whitelisted column. `emails[value eq "x"]` becomes
            // `emails.value eq "x"`. Anything else (e.g.
            // `emails[type eq "work"]`) returns InvalidFilter so
            // the caller knows the feature is not yet supported
            // for that sub-attribute.
            return push_value_path(qb, kind, attr, inner);
        }
    }
    qb.push(")");
    Ok(())
}

fn push_value_path(
    qb: &mut QueryBuilder<'_, Postgres>,
    kind: ResourceKind,
    outer: &AttrPath,
    inner: &Filter,
) -> Result<(), ScimError> {
    push_filter(qb, kind, &rewrite_value_path(outer, inner)?)
}

/// Rewrite `outer[inner]` into a flat `Filter` whose attr paths
/// are `outer.attr_name.<inner.attr_name>` so the existing
/// translator handles it without special-casing.
///
/// Restrictions: every leaf comparison's inner attr must be a
/// bare attr (no schema, no further dot-path). Only `and` / `or`
/// / `not` boolean combinators are permitted in the inner
/// expression.
fn rewrite_value_path(outer: &AttrPath, inner: &Filter) -> Result<Filter, ScimError> {
    match inner {
        Filter::Comparison { attr, op, value } => Ok(Filter::Comparison {
            attr: combine_attr_path(outer, attr)?,
            op: *op,
            value: value.clone(),
        }),
        Filter::Present { attr } => Ok(Filter::Present {
            attr: combine_attr_path(outer, attr)?,
        }),
        Filter::And(a, b) => Ok(Filter::And(
            Box::new(rewrite_value_path(outer, a)?),
            Box::new(rewrite_value_path(outer, b)?),
        )),
        Filter::Or(a, b) => Ok(Filter::Or(
            Box::new(rewrite_value_path(outer, a)?),
            Box::new(rewrite_value_path(outer, b)?),
        )),
        Filter::Not(i) => Ok(Filter::Not(Box::new(rewrite_value_path(outer, i)?))),
        Filter::ValuePath { .. } => Err(ScimError::InvalidFilter {
            detail: "nested valuePath filters are not supported".to_string(),
        }),
    }
}

fn combine_attr_path(outer: &AttrPath, inner: &AttrPath) -> Result<AttrPath, ScimError> {
    if inner.schema.is_some() {
        return Err(ScimError::InvalidFilter {
            detail: "schema-qualified attributes inside valuePath are not supported".to_string(),
        });
    }
    if inner.sub_attr.is_some() {
        return Err(ScimError::InvalidFilter {
            detail: format!(
                "valuePath inner attribute '{inner}' has its own sub-attribute; flatten first"
            ),
        });
    }
    Ok(AttrPath {
        schema: outer.schema.clone(),
        attr_name: outer.attr_name.clone(),
        sub_attr: Some(inner.attr_name.clone()),
    })
}

fn push_comparison(
    qb: &mut QueryBuilder<'_, Postgres>,
    kind: ResourceKind,
    attr: &AttrPath,
    op: CompareOp,
    value: &Value,
) -> Result<(), ScimError> {
    let col = column_for(kind, attr)?;
    match col.kind {
        ColumnKind::Text => push_text_compare(qb, col, op, value),
        ColumnKind::Bool => push_bool_compare(qb, col, op, value),
        ColumnKind::Timestamp => push_timestamp_compare(qb, col, op, value),
        ColumnKind::Uuid => push_uuid_compare(qb, col, op, value),
        ColumnKind::BigInt => push_bigint_compare(qb, col, op, value),
    }
}

fn push_text_compare(
    qb: &mut QueryBuilder<'_, Postgres>,
    col: ColumnRef,
    op: CompareOp,
    value: &Value,
) -> Result<(), ScimError> {
    let s = match value {
        Value::Str(s) => s.clone(),
        Value::Null => {
            return push_null_compare(qb, col, op);
        }
        _ => {
            return Err(ScimError::InvalidValue {
                detail: format!("text column {} requires a string literal", col.sql),
            });
        }
    };
    let lower = s.to_lowercase();
    match op {
        CompareOp::Eq => {
            qb.push("LOWER(").push(col.sql).push(") = ");
            qb.push_bind(lower);
        }
        CompareOp::Ne => {
            qb.push("LOWER(").push(col.sql).push(") <> ");
            qb.push_bind(lower);
        }
        CompareOp::Co => {
            qb.push("LOWER(").push(col.sql).push(") LIKE ");
            qb.push_bind(format!("%{}%", escape_like(&lower)));
        }
        CompareOp::Sw => {
            qb.push("LOWER(").push(col.sql).push(") LIKE ");
            qb.push_bind(format!("{}%", escape_like(&lower)));
        }
        CompareOp::Ew => {
            qb.push("LOWER(").push(col.sql).push(") LIKE ");
            qb.push_bind(format!("%{}", escape_like(&lower)));
        }
        CompareOp::Gt | CompareOp::Lt | CompareOp::Ge | CompareOp::Le => {
            qb.push(col.sql).push(sql_inequality(op));
            qb.push_bind(s);
        }
    }
    Ok(())
}

fn push_bool_compare(
    qb: &mut QueryBuilder<'_, Postgres>,
    col: ColumnRef,
    op: CompareOp,
    value: &Value,
) -> Result<(), ScimError> {
    let b = match value {
        Value::Bool(b) => *b,
        Value::Null => {
            return push_null_compare(qb, col, op);
        }
        _ => {
            return Err(ScimError::InvalidValue {
                detail: format!("bool column {} requires a boolean literal", col.sql),
            });
        }
    };
    match op {
        CompareOp::Eq => {
            qb.push(col.sql).push(" = ").push_bind(b);
        }
        CompareOp::Ne => {
            qb.push(col.sql).push(" <> ").push_bind(b);
        }
        _ => {
            return Err(ScimError::InvalidValue {
                detail: format!("bool column {} supports only eq/ne", col.sql),
            });
        }
    }
    Ok(())
}

fn push_timestamp_compare(
    qb: &mut QueryBuilder<'_, Postgres>,
    col: ColumnRef,
    op: CompareOp,
    value: &Value,
) -> Result<(), ScimError> {
    let s = match value {
        Value::Str(s) => s.clone(),
        Value::Null => {
            return push_null_compare(qb, col, op);
        }
        _ => {
            return Err(ScimError::InvalidValue {
                detail: format!(
                    "timestamp column {} requires an RFC3339 string literal",
                    col.sql
                ),
            });
        }
    };
    let parsed =
        chrono::DateTime::parse_from_rfc3339(&s).map_err(|err| ScimError::InvalidValue {
            detail: format!("malformed RFC3339 timestamp: {err}"),
        })?;
    let utc = parsed.with_timezone(&chrono::Utc);
    let cmp = match op {
        CompareOp::Eq => " = ",
        CompareOp::Ne => " <> ",
        CompareOp::Gt => " > ",
        CompareOp::Lt => " < ",
        CompareOp::Ge => " >= ",
        CompareOp::Le => " <= ",
        _ => {
            return Err(ScimError::InvalidValue {
                detail: format!(
                    "timestamp column {} supports only eq/ne/gt/lt/ge/le",
                    col.sql
                ),
            });
        }
    };
    qb.push(col.sql).push(cmp).push_bind(utc);
    Ok(())
}

fn push_uuid_compare(
    qb: &mut QueryBuilder<'_, Postgres>,
    col: ColumnRef,
    op: CompareOp,
    value: &Value,
) -> Result<(), ScimError> {
    let s = match value {
        Value::Str(s) => s.clone(),
        Value::Null => {
            return push_null_compare(qb, col, op);
        }
        _ => {
            return Err(ScimError::InvalidValue {
                detail: format!("uuid column {} requires a UUID string literal", col.sql),
            });
        }
    };
    let parsed = uuid::Uuid::parse_str(&s).map_err(|_| ScimError::InvalidValue {
        detail: format!("malformed UUID literal: {s}"),
    })?;
    let cmp = match op {
        CompareOp::Eq => " = ",
        CompareOp::Ne => " <> ",
        _ => {
            return Err(ScimError::InvalidValue {
                detail: format!("uuid column {} supports only eq/ne", col.sql),
            });
        }
    };
    qb.push(col.sql).push(cmp).push_bind(parsed);
    Ok(())
}

fn push_bigint_compare(
    qb: &mut QueryBuilder<'_, Postgres>,
    col: ColumnRef,
    op: CompareOp,
    value: &Value,
) -> Result<(), ScimError> {
    let n = match value {
        Value::Int(n) => *n,
        Value::Null => {
            return push_null_compare(qb, col, op);
        }
        _ => {
            return Err(ScimError::InvalidValue {
                detail: format!("bigint column {} requires an integer literal", col.sql),
            });
        }
    };
    let cmp = match op {
        CompareOp::Eq => " = ",
        CompareOp::Ne => " <> ",
        CompareOp::Gt => " > ",
        CompareOp::Lt => " < ",
        CompareOp::Ge => " >= ",
        CompareOp::Le => " <= ",
        _ => {
            return Err(ScimError::InvalidValue {
                detail: format!("bigint column {} supports only eq/ne/gt/lt/ge/le", col.sql),
            });
        }
    };
    qb.push(col.sql).push(cmp).push_bind(n);
    Ok(())
}

fn push_null_compare(
    qb: &mut QueryBuilder<'_, Postgres>,
    col: ColumnRef,
    op: CompareOp,
) -> Result<(), ScimError> {
    match op {
        CompareOp::Eq => {
            qb.push(col.sql).push(" IS NULL");
            Ok(())
        }
        CompareOp::Ne => {
            qb.push(col.sql).push(" IS NOT NULL");
            Ok(())
        }
        _ => Err(ScimError::InvalidValue {
            detail: format!("null literal supports only eq/ne on {}", col.sql),
        }),
    }
}

const fn sql_inequality(op: CompareOp) -> &'static str {
    match op {
        CompareOp::Gt => " > ",
        CompareOp::Lt => " < ",
        CompareOp::Ge => " >= ",
        CompareOp::Le => " <= ",
        _ => " = ",
    }
}

fn escape_like(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            '\\' | '%' | '_' => {
                out.push('\\');
                out.push(c);
            }
            other => out.push(other),
        }
    }
    out
}

/// Sort direction parsed from SCIM `sortOrder` query string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortDir {
    /// `ascending` (default per RFC).
    Asc,
    /// `descending`.
    Desc,
}

impl SortDir {
    /// Parse `ascending` / `descending`. Defaults to `Asc` when
    /// the input is `None` or empty.
    #[must_use]
    pub fn parse(value: Option<&str>) -> Self {
        match value
            .unwrap_or("ascending")
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "descending" | "desc" => Self::Desc,
            _ => Self::Asc,
        }
    }

    /// Render as the SQL keyword.
    #[must_use]
    pub const fn as_sql(self) -> &'static str {
        match self {
            Self::Asc => "ASC",
            Self::Desc => "DESC",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::filter::parse;
    use super::*;

    fn render(qb: QueryBuilder<'_, Postgres>) -> String {
        qb.into_sql()
    }

    #[test]
    fn eq_text_emits_lower_case_compare() {
        let mut qb: QueryBuilder<'_, Postgres> = QueryBuilder::new("WHERE ");
        let f = parse("userName eq \"Alice@Corp.com\"").unwrap();
        push_filter(&mut qb, ResourceKind::User, &f).unwrap();
        let sql = render(qb);
        assert!(sql.contains("LOWER(users.email_lower)"));
        assert!(sql.contains('='));
    }

    #[test]
    fn co_text_uses_like_with_percents() {
        let mut qb: QueryBuilder<'_, Postgres> = QueryBuilder::new("WHERE ");
        let f = parse("userName co \"alice\"").unwrap();
        push_filter(&mut qb, ResourceKind::User, &f).unwrap();
        let sql = render(qb);
        assert!(sql.contains("LIKE"));
    }

    #[test]
    fn sw_text_uses_like_with_trailing_percent() {
        let mut qb: QueryBuilder<'_, Postgres> = QueryBuilder::new("WHERE ");
        let f = parse("userName sw \"al\"").unwrap();
        push_filter(&mut qb, ResourceKind::User, &f).unwrap();
        let sql = render(qb);
        assert!(sql.contains("LIKE"));
    }

    #[test]
    fn ew_text_uses_like_with_leading_percent() {
        let mut qb: QueryBuilder<'_, Postgres> = QueryBuilder::new("WHERE ");
        let f = parse("userName ew \"corp.com\"").unwrap();
        push_filter(&mut qb, ResourceKind::User, &f).unwrap();
        let sql = render(qb);
        assert!(sql.contains("LIKE"));
    }

    #[test]
    fn pr_emits_is_not_null() {
        let mut qb: QueryBuilder<'_, Postgres> = QueryBuilder::new("WHERE ");
        let f = parse("externalId pr").unwrap();
        push_filter(&mut qb, ResourceKind::User, &f).unwrap();
        let sql = render(qb);
        assert!(sql.contains("IS NOT NULL"));
    }

    #[test]
    fn and_or_not_combine_correctly() {
        let mut qb: QueryBuilder<'_, Postgres> = QueryBuilder::new("WHERE ");
        let f = parse("active eq true and (userName co \"al\" or not (externalId pr))").unwrap();
        push_filter(&mut qb, ResourceKind::User, &f).unwrap();
        let sql = render(qb);
        assert!(sql.contains("AND"));
        assert!(sql.contains("OR"));
        assert!(sql.contains("NOT"));
    }

    #[test]
    fn unknown_attr_invalid_filter() {
        let mut qb: QueryBuilder<'_, Postgres> = QueryBuilder::new("WHERE ");
        let f = parse("nope eq \"x\"").unwrap();
        let err = push_filter(&mut qb, ResourceKind::User, &f).unwrap_err();
        assert!(matches!(err, ScimError::InvalidFilter { .. }));
    }

    #[test]
    fn type_mismatch_returns_invalid_value() {
        let mut qb: QueryBuilder<'_, Postgres> = QueryBuilder::new("WHERE ");
        let f = parse("active eq \"yes\"").unwrap();
        let err = push_filter(&mut qb, ResourceKind::User, &f).unwrap_err();
        assert!(matches!(err, ScimError::InvalidValue { .. }));
    }

    #[test]
    fn sort_dir_parses() {
        assert_eq!(SortDir::parse(None), SortDir::Asc);
        assert_eq!(SortDir::parse(Some("ascending")), SortDir::Asc);
        assert_eq!(SortDir::parse(Some("DESCENDING")), SortDir::Desc);
        assert_eq!(SortDir::parse(Some("desc")), SortDir::Desc);
    }

    #[test]
    fn escape_like_escapes_percent_underscore_backslash() {
        assert_eq!(escape_like("100%"), "100\\%");
        assert_eq!(escape_like("a_b"), "a\\_b");
        assert_eq!(escape_like("a\\b"), "a\\\\b");
    }
}
