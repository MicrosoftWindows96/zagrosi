// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! Attribute mapping over a verified SAML assertion.
//!
//! `samael::schema::Assertion` carries `AttributeStatement` →
//! `Attribute` → `AttributeValue`s. The SP layer applies the per-IdP
//! [`crate::saml::config::AttributeMapping`] to produce a typed
//! [`MappedAttributes`] view used by the JIT path + audit emission.
//!
//! The mapper reads ONLY from the verified assertion `samael` returned
//! after signature verification + XSW reduction. No re-parse of raw
//! input; no traversal of unverified siblings.

use samael::schema::Assertion;

use super::config::AttributeMapping;

/// Typed view over the mapped attribute set.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MappedAttributes {
    /// Email value, when the configured mapping resolved.
    pub email: Option<String>,
    /// Given name (first name), when present.
    pub given_name: Option<String>,
    /// Family name (last name / surname), when present.
    pub family_name: Option<String>,
    /// Group memberships, when the optional mapping is configured.
    pub groups: Vec<String>,
}

impl MappedAttributes {
    /// Convenience accessor: `<given_name> <family_name>` falling back
    /// to the email local-part, then the literal "User". The OIDC JIT
    /// path uses an analogous derive_display_name fallback.
    #[must_use]
    pub fn display_name(&self) -> String {
        match (&self.given_name, &self.family_name) {
            (Some(g), Some(f)) if !g.is_empty() && !f.is_empty() => format!("{g} {f}"),
            (Some(g), _) if !g.is_empty() => g.clone(),
            (_, Some(f)) if !f.is_empty() => f.clone(),
            _ => self
                .email
                .as_ref()
                .and_then(|e| e.split('@').next())
                .filter(|s| !s.is_empty())
                .map_or_else(|| "User".to_owned(), str::to_owned),
        }
    }
}

/// Apply the attribute mapping to a verified assertion.
#[must_use]
pub fn map_attributes(assertion: &Assertion, mapping: &AttributeMapping) -> MappedAttributes {
    let mut out = MappedAttributes::default();
    let Some(statements) = &assertion.attribute_statements else {
        return out;
    };
    for statement in statements {
        for attr in &statement.attributes {
            let name_owned = attr.name.clone().unwrap_or_default();
            let friendly_owned = attr.friendly_name.clone().unwrap_or_default();
            let name = name_owned.as_str();
            let friendly = friendly_owned.as_str();
            // Pull the first string value — single-valued attributes
            // are the spec for email + names; only `groups` is multi.
            let first_value = attr
                .values
                .iter()
                .find_map(|v| v.value.clone())
                .unwrap_or_default();

            if matches_mapping(&mapping.email, name, friendly) {
                if !first_value.is_empty() {
                    out.email = Some(first_value.clone());
                }
            } else if matches_mapping(&mapping.given_name, name, friendly) {
                if !first_value.is_empty() {
                    out.given_name = Some(first_value.clone());
                }
            } else if matches_mapping(&mapping.family_name, name, friendly) {
                if !first_value.is_empty() {
                    out.family_name = Some(first_value.clone());
                }
            } else if let Some(groups_attr) = mapping.groups.as_deref()
                && matches_mapping(groups_attr, name, friendly)
            {
                for v in &attr.values {
                    if let Some(s) = &v.value
                        && !s.is_empty()
                    {
                        out.groups.push(s.clone());
                    }
                }
            }
        }
    }
    out
}

/// An attribute matches a mapping selector when the selector equals
/// either the canonical `Name` or the `FriendlyName`. Empty selectors
/// disable the mapping (admin opt-out).
fn matches_mapping(selector: &str, name: &str, friendly: &str) -> bool {
    !selector.is_empty() && (selector == name || selector == friendly)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_mapping() -> AttributeMapping {
        AttributeMapping {
            email: String::new(),
            given_name: String::new(),
            family_name: String::new(),
            groups: None,
        }
    }

    #[test]
    fn display_name_prefers_full_name() {
        let m = MappedAttributes {
            email: Some("alice@example.com".into()),
            given_name: Some("Alice".into()),
            family_name: Some("Example".into()),
            groups: vec![],
        };
        assert_eq!(m.display_name(), "Alice Example");
    }

    #[test]
    fn display_name_falls_back_to_email_local_part() {
        let m = MappedAttributes {
            email: Some("alice@example.com".into()),
            given_name: None,
            family_name: None,
            groups: vec![],
        };
        assert_eq!(m.display_name(), "alice");
    }

    #[test]
    fn display_name_falls_back_to_user_when_nothing() {
        let m = MappedAttributes::default();
        assert_eq!(m.display_name(), "User");
    }

    #[test]
    fn empty_selector_disables_mapping() {
        assert!(!matches_mapping("", "mail", "Email"));
        assert!(matches_mapping("mail", "mail", "Email"));
        assert!(matches_mapping("Email", "mail", "Email"));
        assert!(!matches_mapping("groups", "mail", "Email"));
    }

    #[test]
    fn assertion_with_no_statements_yields_default() {
        let mapping = empty_mapping();
        let assertion = Assertion {
            id: "id-empty".to_owned(),
            issue_instant: chrono::Utc::now(),
            version: "2.0".to_owned(),
            issuer: samael::schema::Issuer {
                value: Some("https://idp.example.com".to_owned()),
                ..samael::schema::Issuer::default()
            },
            signature: None,
            subject: None,
            conditions: None,
            authn_statements: None,
            attribute_statements: None,
        };
        let mapped = map_attributes(&assertion, &mapping);
        assert_eq!(mapped, MappedAttributes::default());
    }
}
