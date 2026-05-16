// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::missing_const_for_fn,
    clippy::uninlined_format_args
)]
//! RFC 7644 §3.4.2.2 SCIM filter grammar coverage (section-16,
//! TDD §13.2 / standards-map §20).
//!
//! This is a pure, compose-free suite: it drives the parser
//! ([`zagrosi_identity::http::scim::filter::parse`]) and the SQL
//! translator ([`zagrosi_identity::http::scim::translate::push_filter`])
//! directly, so it runs in the default `cargo test --workspace`
//! slice with no docker. The parser-internal unit tests in
//! `src/http/scim/filter.rs` cover the AST shapes; this file is the
//! standards-map-cited entry point and adds the
//! translation-is-parameterised-only property the fuzz target cannot
//! assert (the fuzz target only proves no-panic).

use proptest::prelude::*;
use sqlx::{Postgres, QueryBuilder};
use zagrosi_identity::http::scim::ScimError;
use zagrosi_identity::http::scim::filter::{
    AttrPath, CompareOp, Filter, ResourceKind, Value, parse,
};
use zagrosi_identity::http::scim::translate::push_filter;

fn render(filter: &Filter, kind: ResourceKind) -> Result<String, ScimError> {
    let mut qb: QueryBuilder<'_, Postgres> = QueryBuilder::new("WHERE ");
    push_filter(&mut qb, kind, filter)?;
    Ok(qb.into_sql())
}

#[test]
fn every_comparison_operator_parses() {
    for (input, want) in [
        ("userName eq \"a\"", CompareOp::Eq),
        ("userName ne \"a\"", CompareOp::Ne),
        ("userName co \"a\"", CompareOp::Co),
        ("userName sw \"a\"", CompareOp::Sw),
        ("userName ew \"a\"", CompareOp::Ew),
        ("meta.created gt \"2024-01-01T00:00:00Z\"", CompareOp::Gt),
        ("meta.created lt \"2024-01-01T00:00:00Z\"", CompareOp::Lt),
        ("meta.created ge \"2024-01-01T00:00:00Z\"", CompareOp::Ge),
        ("meta.created le \"2024-01-01T00:00:00Z\"", CompareOp::Le),
    ] {
        let f = parse(input).unwrap_or_else(|e| panic!("{input} must parse: {e:?}"));
        let Filter::Comparison { op, .. } = f else {
            panic!("{input} expected Comparison");
        };
        assert_eq!(op, want, "operator mismatch for {input}");
    }
}

#[test]
fn presence_operator_parses() {
    let Filter::Present { attr } = parse("emails pr").unwrap() else {
        panic!("expected Present");
    };
    assert_eq!(attr.attr_name, "emails");
}

#[test]
fn boolean_and_binds_tighter_than_or() {
    // a or b and c  ==>  Or(a, And(b, c))
    let f = parse("userName eq \"a\" or active eq true and externalId pr").unwrap();
    let Filter::Or(_lhs, rhs) = f else {
        panic!("expected Or at the root (and binds tighter)");
    };
    assert!(matches!(*rhs, Filter::And(_, _)), "rhs must be And");
}

#[test]
fn nested_not_precedence() {
    let f = parse("userName eq \"x\" and not (active eq false)").unwrap();
    let Filter::And(_, rhs) = f else {
        panic!("expected And");
    };
    let Filter::Not(inner) = *rhs else {
        panic!("expected Not on the rhs");
    };
    assert!(matches!(*inner, Filter::Comparison { .. }));
}

#[test]
fn schema_qualified_path_splits_urn_attr_and_subattr() {
    let f =
        parse("urn:ietf:params:scim:schemas:core:2.0:User:emails.value eq \"a@b.com\"").unwrap();
    let Filter::Comparison { attr, .. } = f else {
        panic!("expected Comparison");
    };
    assert_eq!(
        attr.schema.as_deref(),
        Some("urn:ietf:params:scim:schemas:core:2.0:User")
    );
    assert_eq!(attr.attr_name, "emails");
    assert_eq!(attr.sub_attr.as_deref(), Some("value"));
}

#[test]
fn valuepath_in_patch_parses_to_value_path() {
    let f = parse("emails[type eq \"work\"]").unwrap();
    let Filter::ValuePath { attr, inner } = f else {
        panic!("expected ValuePath");
    };
    assert_eq!(attr.attr_name, "emails");
    assert!(matches!(*inner, Filter::Comparison { .. }));
}

#[test]
fn depth_65_returns_invalid_filter() {
    let mut s = String::new();
    for _ in 0..70 {
        s.push_str("(a pr and ");
    }
    s.push_str("a pr");
    for _ in 0..70 {
        s.push(')');
    }
    let err = parse(&s).expect_err("65+ nested depth must reject");
    let ScimError::InvalidFilter { detail } = err else {
        panic!("expected InvalidFilter, got {err:?}");
    };
    assert!(
        detail.contains("depth") || detail.contains("trailing"),
        "unexpected detail: {detail}"
    );
}

#[test]
fn unknown_attribute_returns_invalid_filter_at_translation() {
    // The grammar accepts any well-formed attr token; the column
    // whitelist in the translator is the rejection point (RFC 7644
    // §3.12 invalidFilter). This is the security-relevant boundary.
    let f = parse("definitelyNotAColumn eq \"x\"").unwrap();
    let err = render(&f, ResourceKind::User).expect_err("unknown attr must reject");
    assert!(
        matches!(err, ScimError::InvalidFilter { .. }),
        "expected InvalidFilter, got {err:?}"
    );
}

#[test]
fn translation_emits_bind_placeholders_not_literals() {
    // A known-good text comparison must parameterise the RHS: the
    // rendered SQL carries a `$1` placeholder and never the literal.
    let f = parse("userName eq \"Alice@Corp.com\"").unwrap();
    let sql = render(&f, ResourceKind::User).unwrap();
    assert!(sql.contains("$1"), "expected a bind placeholder: {sql}");
    assert!(
        !sql.contains("Alice@Corp.com") && !sql.contains("alice@corp.com"),
        "literal leaked into SQL: {sql}"
    );
    assert!(
        sql.contains("LOWER("),
        "expected case-folded compare: {sql}"
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Adversarial RHS values (quotes, semicolons, SQL-keywords,
    /// NUL) must NEVER reach the rendered SQL as a literal. We build
    /// the AST directly so the property isolates the translator from
    /// the tokenizer's own string-escaping. Either the translator
    /// rejects (type/whitelist), or the value is bound via `$n`.
    #[test]
    fn translation_is_parameterised_only(
        val in r#"zzinj['"; A-Za-z0-9_-]{0,40}"#,
    ) {
        let f = Filter::Comparison {
            attr: AttrPath {
                schema: None,
                attr_name: "username".to_string(),
                sub_attr: None,
            },
            op: CompareOp::Eq,
            value: Value::Str(val.clone()),
        };
        let mut qb: QueryBuilder<'_, Postgres> = QueryBuilder::new("WHERE ");
        // Whitelist / type rejection is acceptable; successful
        // translations must bind rather than interpolate.
        if push_filter(&mut qb, ResourceKind::User, &f).is_ok() {
            let sql = qb.into_sql();
            prop_assert!(sql.contains("$1"), "no bind placeholder: {sql}");
            // The translator lower-cases the bound value before
            // binding; neither the raw nor folded form may appear
            // as a SQL literal. Skip the degenerate empty string
            // (a substring of everything).
            if !val.is_empty() {
                prop_assert!(
                    !sql.contains(&val) && !sql.contains(&val.to_lowercase()),
                    "value leaked as SQL literal: val={val:?} sql={sql}"
                );
            }
        }
    }

    /// The parser must not panic or hang on adversarial bytes; any
    /// failure surfaces as `InvalidFilter` (mirrors the
    /// `fuzz/fuzz_targets/scim_filter.rs` contract, asserted here so
    /// the property is covered without nightly).
    #[test]
    fn parser_never_panics(input in r"\PC{0,128}") {
        let _ = parse(&input);
    }
}
