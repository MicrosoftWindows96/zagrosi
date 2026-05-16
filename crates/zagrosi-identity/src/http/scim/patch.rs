// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! SCIM 2.0 PATCH op envelope (RFC 7644 §3.5.2).
//!
//! Three operations are defined: `add`, `remove`, `replace`. The
//! body envelope is:
//!
//! ```json
//! {
//!   "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
//!   "Operations": [
//!     { "op": "replace", "path": "active", "value": false }
//!   ]
//! }
//! ```
//!
//! `path` may be omitted (Entra ID PATCH bodies sometimes drop it
//! and put attribute names directly under `value`); when tolerant
//! mode is enabled the parser tolerates both shapes. Casing on `op` is also tolerated under
//! `tolerant_mode` (Entra ID emits `Replace` with a leading
//! capital).
//!
//! `valuePath` PATCH targets (`emails[type eq "work"].value`) are
//! parsed by [`super::filter::parse`] but **not yet applied** by
//! the Users / Groups handlers in v0.1 — sub-attribute targeting
//! returns [`super::ScimError::InvalidPath`] with a message that
//! identifies the unsupported attribute. The PATCH parser still
//! accepts the syntax so future work only needs to flesh out the
//! per-attribute applier rather than touch the wire format.

use serde::Deserialize;
use serde_json::Value;

use super::ScimError;
use super::groups::GroupDraft;
use super::users::UserDraft;

/// Parsed SCIM PATCH operation. The wire format permits an
/// arbitrary `value`; this enum keeps the original envelope so
/// the per-resource applier can branch by `path`.
#[derive(Debug, Clone)]
pub struct PatchOpInput {
    /// Operation kind.
    pub op: PatchOpKind,
    /// Target path (may be `None` under tolerant mode).
    pub path: Option<String>,
    /// Operation value. `null` for `remove` of scalar attributes.
    pub value: Value,
}

/// PATCH op discriminator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatchOpKind {
    /// `add` — insert / append.
    Add,
    /// `remove` — clear scalar / drop multi-valued entry.
    Remove,
    /// `replace` — overwrite scalar / replace multi-valued entry.
    Replace,
}

#[derive(Debug, Deserialize)]
struct PatchEnvelope {
    #[allow(dead_code)] // wire-format field; unused by the applier
    #[serde(default)]
    schemas: Vec<String>,
    #[serde(default, rename = "Operations")]
    operations: Vec<PatchOpRaw>,
}

#[derive(Debug, Deserialize)]
struct PatchOpRaw {
    #[serde(default)]
    op: Option<String>,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    value: Value,
}

/// Parse a SCIM PATCH body into the typed op list.
///
/// `tolerant_mode` accepts mixed-case `op` values
/// (`Replace` / `REMOVE`) and tolerates Entra ID's path-less
/// shape where the body's `value` is an object whose keys map
/// onto top-level attributes. The strict path is RFC-compliant.
///
/// # Errors
///
/// Returns [`ScimError::InvalidValue`] for malformed JSON or
/// missing `Operations` array, [`ScimError::InvalidPath`] for
/// unrecognised `op` values.
pub fn parse_patch_ops(body: &[u8], tolerant_mode: bool) -> Result<Vec<PatchOpInput>, ScimError> {
    let env: PatchEnvelope =
        serde_json::from_slice(body).map_err(|err| ScimError::InvalidValue {
            detail: format!("malformed json: {err}"),
        })?;
    if env.operations.is_empty() {
        return Err(ScimError::InvalidValue {
            detail: "Operations array missing or empty".to_string(),
        });
    }
    let mut out = Vec::with_capacity(env.operations.len());
    for raw in env.operations {
        let op_raw = raw.op.unwrap_or_else(|| "replace".to_string());
        let op = parse_op(&op_raw, tolerant_mode)?;
        out.push(PatchOpInput {
            op,
            path: raw.path,
            value: raw.value,
        });
    }
    Ok(out)
}

fn parse_op(raw: &str, tolerant: bool) -> Result<PatchOpKind, ScimError> {
    let normalised = if tolerant {
        raw.to_ascii_lowercase()
    } else {
        raw.to_string()
    };
    match normalised.as_str() {
        "add" => Ok(PatchOpKind::Add),
        "remove" => Ok(PatchOpKind::Remove),
        "replace" => Ok(PatchOpKind::Replace),
        other => Err(ScimError::InvalidPath {
            detail: format!("unknown op '{other}'"),
        }),
    }
}

/// Apply a list of PATCH ops to a mutable [`UserDraft`].
///
/// Supported paths in v0.1:
/// - `displayName` (replace / add).
/// - `externalId` (replace / add / remove).
/// - `active` (replace).
///
/// Path-less ops (Entra ID tolerant mode) treat the value as an
/// object whose keys are top-level attributes.
///
/// `valuePath` targets (`emails[...]`) and complex sub-attributes
/// (`name.givenName`) return
/// [`ScimError::InvalidPath`] in v0.1 — the parser already accepts
/// the syntax via [`super::filter::parse`], the applier is the
/// future-extension point.
///
/// # Errors
///
/// Returns [`ScimError::InvalidPath`] for unsupported paths and
/// [`ScimError::InvalidValue`] for type mismatches.
pub fn apply_user_patch_ops(draft: &mut UserDraft, ops: &[PatchOpInput]) -> Result<(), ScimError> {
    for op in ops {
        match op.path.as_deref() {
            None => apply_user_pathless(draft, op)?,
            Some(path) => apply_user_path(draft, op.op, path, &op.value)?,
        }
    }
    Ok(())
}

fn apply_user_pathless(draft: &mut UserDraft, op: &PatchOpInput) -> Result<(), ScimError> {
    if !matches!(op.op, PatchOpKind::Add | PatchOpKind::Replace) {
        return Err(ScimError::InvalidPath {
            detail: "remove without path is not supported".to_string(),
        });
    }
    let Some(map) = op.value.as_object() else {
        return Err(ScimError::InvalidValue {
            detail: "path-less PATCH value must be an object".to_string(),
        });
    };
    for (k, v) in map {
        apply_user_path(draft, op.op, k.as_str(), v)?;
    }
    Ok(())
}

fn apply_user_path(
    draft: &mut UserDraft,
    op: PatchOpKind,
    path: &str,
    value: &Value,
) -> Result<(), ScimError> {
    let normalised = path.trim_start_matches('/');
    match normalised {
        "displayName" | "displayname" => match op {
            PatchOpKind::Add | PatchOpKind::Replace => match value.as_str() {
                Some(s) => {
                    draft.display_name = s.to_string();
                    Ok(())
                }
                None => Err(ScimError::InvalidValue {
                    detail: "displayName must be a string".to_string(),
                }),
            },
            PatchOpKind::Remove => Err(ScimError::InvalidValue {
                detail: "cannot remove required attribute displayName".to_string(),
            }),
        },
        "externalId" | "externalid" => match op {
            PatchOpKind::Add | PatchOpKind::Replace => match value {
                Value::String(s) => {
                    draft.external_id = Some(s.clone());
                    Ok(())
                }
                Value::Null => {
                    draft.external_id = None;
                    Ok(())
                }
                _ => Err(ScimError::InvalidValue {
                    detail: "externalId must be a string".to_string(),
                }),
            },
            PatchOpKind::Remove => {
                draft.external_id = None;
                Ok(())
            }
        },
        "active" => match op {
            PatchOpKind::Add | PatchOpKind::Replace => match value.as_bool() {
                Some(b) => {
                    draft.active = b;
                    Ok(())
                }
                None => Err(ScimError::InvalidValue {
                    detail: "active must be a boolean".to_string(),
                }),
            },
            PatchOpKind::Remove => Err(ScimError::InvalidValue {
                detail: "cannot remove active".to_string(),
            }),
        },
        other => Err(ScimError::InvalidPath {
            detail: format!("unsupported PATCH path: {other}"),
        }),
    }
}

/// Group PATCH op input shape parsed from the request body —
/// distinct from [`PatchOpInput`] only at the type level so the
/// applier can branch on the resource it targets.
pub use PatchOpInput as GroupPatchOp;

/// Apply PATCH ops to a [`GroupDraft`] + accumulated member
/// adds / removes.
///
/// Supported paths:
/// - `displayName` (replace / add).
/// - `externalId` (replace / add / remove).
/// - `members` (add → push, remove → pop, replace → reset).
///
/// `valuePath` targets on `members[value eq "<uuid>"]` are accepted
/// but resolved by the caller after parsing so the applier stays
/// purely structural.
///
/// # Errors
///
/// Returns [`ScimError::InvalidPath`] for unsupported paths and
/// [`ScimError::InvalidValue`] for type mismatches.
pub fn apply_group_patch_ops(
    draft: &mut GroupDraft,
    ops: &[PatchOpInput],
) -> Result<(), ScimError> {
    for op in ops {
        match op.path.as_deref() {
            None => apply_group_pathless(draft, op)?,
            Some(path) => apply_group_path(draft, op.op, path, &op.value)?,
        }
    }
    Ok(())
}

fn apply_group_pathless(draft: &mut GroupDraft, op: &PatchOpInput) -> Result<(), ScimError> {
    if !matches!(op.op, PatchOpKind::Add | PatchOpKind::Replace) {
        return Err(ScimError::InvalidPath {
            detail: "remove without path is not supported".to_string(),
        });
    }
    let Some(map) = op.value.as_object() else {
        return Err(ScimError::InvalidValue {
            detail: "path-less PATCH value must be an object".to_string(),
        });
    };
    for (k, v) in map {
        apply_group_path(draft, op.op, k.as_str(), v)?;
    }
    Ok(())
}

fn apply_group_path(
    draft: &mut GroupDraft,
    op: PatchOpKind,
    path: &str,
    value: &Value,
) -> Result<(), ScimError> {
    let normalised = path.trim_start_matches('/');
    let lower = normalised.to_ascii_lowercase();
    if normalised.starts_with("members") {
        return apply_group_members(draft, op, normalised, value);
    }
    match lower.as_str() {
        "displayname" => match op {
            PatchOpKind::Add | PatchOpKind::Replace => match value.as_str() {
                Some(s) => {
                    draft.display_name = s.to_string();
                    Ok(())
                }
                None => Err(ScimError::InvalidValue {
                    detail: "displayName must be a string".to_string(),
                }),
            },
            PatchOpKind::Remove => Err(ScimError::InvalidValue {
                detail: "cannot remove required attribute displayName".to_string(),
            }),
        },
        "externalid" => match op {
            PatchOpKind::Add | PatchOpKind::Replace => match value {
                Value::String(s) => {
                    draft.external_id = Some(s.clone());
                    Ok(())
                }
                Value::Null => {
                    draft.external_id = None;
                    Ok(())
                }
                _ => Err(ScimError::InvalidValue {
                    detail: "externalId must be a string".to_string(),
                }),
            },
            PatchOpKind::Remove => {
                draft.external_id = None;
                Ok(())
            }
        },
        other => Err(ScimError::InvalidPath {
            detail: format!("unsupported PATCH path: {other}"),
        }),
    }
}

fn apply_group_members(
    draft: &mut GroupDraft,
    op: PatchOpKind,
    path: &str,
    value: &Value,
) -> Result<(), ScimError> {
    let inner = path
        .strip_prefix("members")
        .map_or("", |tail| tail.trim_start_matches('.'));
    if let Some(filter_part) = inner.strip_prefix('[') {
        let close = filter_part
            .find(']')
            .ok_or_else(|| ScimError::InvalidPath {
                detail: "members[...] missing closing bracket".to_string(),
            })?;
        let filter_text = &filter_part[..close];
        let parsed = super::filter::parse(filter_text)?;
        let target_id = extract_member_value(&parsed)?;
        return match op {
            PatchOpKind::Remove => {
                draft.member_removes.push(target_id);
                Ok(())
            }
            // RFC 7644 §3.5.2.3: `replace` on a multi-valued attr
            // via valuePath replaces the targeted element. Modeled
            // here as remove-the-old + add-the-replacement, where
            // the replacement payload is the request `value`.
            PatchOpKind::Replace => {
                draft.member_removes.push(target_id);
                push_member_adds(draft, value)
            }
            PatchOpKind::Add => Err(ScimError::InvalidPath {
                detail: "members[<filter>] does not support `add`".to_string(),
            }),
        };
    }
    match op {
        PatchOpKind::Replace => {
            draft.member_resets = true;
            draft.member_adds.clear();
            draft.member_removes.clear();
            push_member_adds(draft, value)
        }
        PatchOpKind::Add => push_member_adds(draft, value),
        // RFC 7644 §3.5.2.2: `remove` on a multi-valued attribute
        // path with no filter clears every value.
        PatchOpKind::Remove => {
            draft.member_resets = true;
            draft.member_adds.clear();
            draft.member_removes.clear();
            Ok(())
        }
    }
}

fn push_member_adds(draft: &mut GroupDraft, value: &Value) -> Result<(), ScimError> {
    if let Some(arr) = value.as_array() {
        for entry in arr {
            if let Some(uuid) = entry.get("value").and_then(Value::as_str)
                && let Ok(id) = uuid::Uuid::parse_str(uuid)
            {
                draft.member_adds.push(id);
            }
        }
        return Ok(());
    }
    if value.is_object()
        && let Some(uuid) = value.get("value").and_then(Value::as_str)
        && let Ok(id) = uuid::Uuid::parse_str(uuid)
    {
        draft.member_adds.push(id);
        return Ok(());
    }
    Err(ScimError::InvalidValue {
        detail: "members value must be an array or object".to_string(),
    })
}

fn extract_member_value(filter: &super::filter::Filter) -> Result<uuid::Uuid, ScimError> {
    use super::filter::{CompareOp, Filter, Value as FilterValue};
    match filter {
        Filter::Comparison {
            attr,
            op: CompareOp::Eq,
            value: FilterValue::Str(s),
        } if attr.attr_name == "value" => {
            uuid::Uuid::parse_str(s).map_err(|_| ScimError::InvalidValue {
                detail: "member value must be a UUID".to_string(),
            })
        }
        _ => Err(ScimError::InvalidPath {
            detail: "members[...] filter must be `value eq \"<uuid>\"`".to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(s: &str) -> Vec<u8> {
        s.as_bytes().to_vec()
    }

    #[test]
    fn parses_replace_active_false() {
        let raw = body(
            r#"{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                  "Operations":[{"op":"replace","path":"active","value":false}]}"#,
        );
        let ops = parse_patch_ops(&raw, false).unwrap();
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].op, PatchOpKind::Replace);
        assert_eq!(ops[0].path.as_deref(), Some("active"));
        assert_eq!(ops[0].value, Value::Bool(false));
    }

    #[test]
    fn tolerant_mode_accepts_capitalised_op() {
        let raw = body(r#"{"Operations":[{"op":"Replace","path":"active","value":true}]}"#);
        let strict = parse_patch_ops(&raw, false);
        assert!(strict.is_err());
        let tolerant = parse_patch_ops(&raw, true).unwrap();
        assert_eq!(tolerant[0].op, PatchOpKind::Replace);
    }

    #[test]
    fn pathless_replaces_top_level_attrs() {
        let raw =
            body(r#"{"Operations":[{"op":"replace","value":{"active":false,"displayName":"x"}}]}"#);
        let ops = parse_patch_ops(&raw, true).unwrap();
        let user = crate::domain::User {
            id: uuid::Uuid::nil(),
            email: "a".into(),
            email_lower: "a".into(),
            display_name: "y".into(),
            email_verified_at: None,
            password_hash: None,
            password_updated_at: None,
            password_hash_version: 0,
            mfa_enrolled_at: None,
            active: true,
            external_id: None,
            row_version: 0,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            deleted_at: None,
        };
        let mut draft = UserDraft::from(&user);
        apply_user_patch_ops(&mut draft, &ops).unwrap();
        assert!(!draft.active);
        assert_eq!(draft.display_name, "x");
    }

    #[test]
    fn unknown_path_returns_invalid_path() {
        let raw = body(r#"{"Operations":[{"op":"replace","path":"nope","value":"x"}]}"#);
        let ops = parse_patch_ops(&raw, false).unwrap();
        let user = crate::domain::User {
            id: uuid::Uuid::nil(),
            email: "a".into(),
            email_lower: "a".into(),
            display_name: "y".into(),
            email_verified_at: None,
            password_hash: None,
            password_updated_at: None,
            password_hash_version: 0,
            mfa_enrolled_at: None,
            active: true,
            external_id: None,
            row_version: 0,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            deleted_at: None,
        };
        let mut draft = UserDraft::from(&user);
        let err = apply_user_patch_ops(&mut draft, &ops).unwrap_err();
        assert!(matches!(err, ScimError::InvalidPath { .. }));
    }

    #[test]
    fn extract_member_value_rejects_non_value_filter() {
        let f = super::super::filter::parse("type eq \"work\"").unwrap();
        assert!(extract_member_value(&f).is_err());
    }
}
