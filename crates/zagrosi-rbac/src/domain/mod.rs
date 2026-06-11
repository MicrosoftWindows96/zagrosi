// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure rbac value types: scope vocabulary, built-in role names, entry
//! effects, and the row/insert structs the repo layer round-trips.
//!
//! Built-in role *grant sets* are deliberately absent — they are
//! code-versioned and arrive with the resolution engine (section-07);
//! only the six names exist here, matching the `role_assignments`
//! CHECK list. All string mappings are exact mirrors of the SQL CHECK
//! vocabularies; parsing is fail-closed (unknown strings error).

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::error::Error;

/// Scope-tree node kind, widest first.
///
/// The derived order (`Org` lowest) is the validation order: a parent's
/// scope must be strictly lower (wider) than its child's, which is what
/// the SQL parent-validation trigger enforces via
/// `zagrosi_rbac_scope_level`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ScopeType {
    /// Org root — exactly one live root per org, no parent.
    Org,
    /// Workspace under the org root.
    Workspace,
    /// Project under org/workspace.
    Project,
    /// Service under org/workspace/project.
    Service,
    /// Record — the deepest registrable scope.
    Record,
}

impl ScopeType {
    /// Stable lowercase string form, matching the SQL CHECK list.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Org => "org",
            Self::Workspace => "workspace",
            Self::Project => "project",
            Self::Service => "service",
            Self::Record => "record",
        }
    }

    /// Tree level (org = 0 … record = 4), mirroring
    /// `zagrosi_rbac_scope_level` in rbac migration 001.
    #[must_use]
    pub const fn level(self) -> i16 {
        match self {
            Self::Org => 0,
            Self::Workspace => 1,
            Self::Project => 2,
            Self::Service => 3,
            Self::Record => 4,
        }
    }

    /// Parse a stored string; unknown values error (fail-closed).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidStoredValue`] for anything outside the
    /// five-entry vocabulary.
    pub fn parse(s: &str) -> Result<Self, Error> {
        match s {
            "org" => Ok(Self::Org),
            "workspace" => Ok(Self::Workspace),
            "project" => Ok(Self::Project),
            "service" => Ok(Self::Service),
            "record" => Ok(Self::Record),
            other => Err(Error::InvalidStoredValue {
                column: "scope_type",
                value: other.to_owned(),
            }),
        }
    }
}

/// The six built-in role names. Grant sets are code-versioned and land
/// in section-07 — only bindings (names) are stored in the database.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BuiltinRole {
    /// Full org control, including org deletion.
    OrgOwner,
    /// Org administration short of org deletion.
    OrgAdmin,
    /// Workspace-scoped administration.
    WorkspaceAdmin,
    /// Standard member.
    Member,
    /// Restricted guest.
    Guest,
    /// External collaborator.
    External,
}

impl BuiltinRole {
    /// Stable string form, matching the `role_assignments` CHECK list.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OrgOwner => "org_owner",
            Self::OrgAdmin => "org_admin",
            Self::WorkspaceAdmin => "workspace_admin",
            Self::Member => "member",
            Self::Guest => "guest",
            Self::External => "external",
        }
    }

    /// Parse a stored string; unknown values error (fail-closed).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidStoredValue`] for anything outside the
    /// six-name vocabulary.
    pub fn parse(s: &str) -> Result<Self, Error> {
        match s {
            "org_owner" => Ok(Self::OrgOwner),
            "org_admin" => Ok(Self::OrgAdmin),
            "workspace_admin" => Ok(Self::WorkspaceAdmin),
            "member" => Ok(Self::Member),
            "guest" => Ok(Self::Guest),
            "external" => Ok(Self::External),
            other => Err(Error::InvalidStoredValue {
                column: "builtin_role",
                value: other.to_owned(),
            }),
        }
    }
}

/// Custom-role entry effect. Deny outranks grant at resolution time
/// (section-07); here it is just the stored vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Effect {
    /// Grants the capability.
    Grant,
    /// Denies the capability, outranking grants.
    Deny,
}

impl Effect {
    /// Stable string form, matching the `custom_role_entries` CHECK.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Grant => "grant",
            Self::Deny => "deny",
        }
    }

    /// Parse a stored string; unknown values error (fail-closed).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidStoredValue`] for anything other than
    /// `grant` / `deny`.
    pub fn parse(s: &str) -> Result<Self, Error> {
        match s {
            "grant" => Ok(Self::Grant),
            "deny" => Ok(Self::Deny),
            other => Err(Error::InvalidStoredValue {
                column: "effect",
                value: other.to_owned(),
            }),
        }
    }
}

/// The role side of an assignment: exactly one of a built-in name or a
/// custom-role reference (the `role_assignments_role_xor` CHECK, made
/// unrepresentable in Rust).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AssignmentRole {
    /// One of the six code-versioned built-in roles.
    Builtin(BuiltinRole),
    /// A custom role owned by the same org.
    Custom(Uuid),
}

impl AssignmentRole {
    /// Decompose into the `(builtin_role, custom_role_id)` column pair.
    #[must_use]
    pub const fn columns(self) -> (Option<&'static str>, Option<Uuid>) {
        match self {
            Self::Builtin(role) => (Some(role.as_str()), None),
            Self::Custom(id) => (None, Some(id)),
        }
    }

    /// Recompose from the stored column pair; violations of the XOR
    /// CHECK or unknown role names error (fail-closed).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidStoredValue`] when both/neither column is
    /// set or the built-in name is unknown.
    pub fn from_columns(builtin: Option<&str>, custom: Option<Uuid>) -> Result<Self, Error> {
        match (builtin, custom) {
            (Some(name), None) => Ok(Self::Builtin(BuiltinRole::parse(name)?)),
            (None, Some(id)) => Ok(Self::Custom(id)),
            (Some(_), Some(_)) | (None, None) => Err(Error::InvalidStoredValue {
                column: "builtin_role/custom_role_id",
                value: format!("builtin={builtin:?} custom={custom:?}"),
            }),
        }
    }
}

/// One scope-tree node row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceNode {
    /// Application-generated UUID v7 primary key (org roots:
    /// trigger-generated via Postgres `uuidv7()`).
    pub id: Uuid,
    /// Owning org.
    pub org_id: Uuid,
    /// Node kind.
    pub scope_type: ScopeType,
    /// Parent node; `None` iff this is the org root.
    pub parent_id: Option<Uuid>,
    /// The domain row this node mirrors (workspace/project/… id).
    pub external_id: Option<Uuid>,
    /// Row creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Soft-delete tombstone; `None` for live rows.
    pub deleted_at: Option<DateTime<Utc>>,
}

/// Insert payload for a non-org [`ResourceNode`] (org roots come only
/// from the provisioning trigger / backfill).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewResourceNode {
    /// Application-generated UUID v7.
    pub id: Uuid,
    /// Node kind; [`ScopeType::Org`] is rejected by the repo.
    pub scope_type: ScopeType,
    /// Parent node id (required — only org roots are parentless).
    pub parent_id: Uuid,
    /// The domain row this node mirrors.
    pub external_id: Option<Uuid>,
}

/// One custom-role row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustomRole {
    /// Application-generated UUID v7 primary key.
    pub id: Uuid,
    /// Owning org.
    pub org_id: Uuid,
    /// Display name; unique per org among live rows, case-insensitively.
    pub name: String,
    /// Optional description.
    pub description: Option<String>,
    /// Row creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Last-mutation timestamp.
    pub updated_at: DateTime<Utc>,
    /// Soft-delete tombstone; `None` for live rows.
    pub deleted_at: Option<DateTime<Utc>>,
}

/// Insert payload for a [`CustomRole`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewCustomRole {
    /// Application-generated UUID v7.
    pub id: Uuid,
    /// Display name.
    pub name: String,
    /// Optional description.
    pub description: Option<String>,
}

/// One capability entry of a custom role. Entries carry no
/// `deleted_at` — sets are hard-replaced wholesale.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustomRoleEntry {
    /// Application-generated UUID v7 primary key.
    pub id: Uuid,
    /// Parent custom role.
    pub custom_role_id: Uuid,
    /// Owning org (denormalized for RLS; FK-pinned to the parent's org).
    pub org_id: Uuid,
    /// Capability string (catalog-validated by the service layer).
    pub capability: String,
    /// Grant or deny.
    pub effect: Effect,
    /// Row creation timestamp.
    pub created_at: DateTime<Utc>,
}

/// Insert payload for a [`CustomRoleEntry`] (the parent role id is
/// supplied by the `replace_entries` call, not per entry).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewCustomRoleEntry {
    /// Application-generated UUID v7.
    pub id: Uuid,
    /// Capability string.
    pub capability: String,
    /// Grant or deny.
    pub effect: Effect,
}

/// One role-assignment row: a user bound to a role at a scope node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleAssignment {
    /// Application-generated UUID v7 primary key.
    pub id: Uuid,
    /// Owning org.
    pub org_id: Uuid,
    /// Assigned user.
    pub user_id: Uuid,
    /// Built-in name or custom-role reference (XOR).
    pub role: AssignmentRole,
    /// Scope node the binding attaches to.
    pub node_id: Uuid,
    /// Actor who created the binding (backfill: self-attributed).
    pub created_by: Uuid,
    /// Row creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Soft-delete tombstone; `None` for live rows.
    pub deleted_at: Option<DateTime<Utc>>,
}

/// Insert payload for a [`RoleAssignment`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewRoleAssignment {
    /// Application-generated UUID v7.
    pub id: Uuid,
    /// Assigned user.
    pub user_id: Uuid,
    /// Built-in name or custom-role reference.
    pub role: AssignmentRole,
    /// Scope node the binding attaches to.
    pub node_id: Uuid,
    /// Actor creating the binding.
    pub created_by: Uuid,
}

#[cfg(test)]
mod tests {
    use super::*;
    use static_assertions::assert_impl_all;

    assert_impl_all!(ScopeType: Send, Sync, Copy, Clone, std::fmt::Debug, std::hash::Hash);
    assert_impl_all!(BuiltinRole: Send, Sync, Copy, Clone, std::fmt::Debug, std::hash::Hash);
    assert_impl_all!(Effect: Send, Sync, Copy, Clone, std::fmt::Debug, std::hash::Hash);
    assert_impl_all!(AssignmentRole: Send, Sync, Copy, Clone, std::fmt::Debug);
    assert_impl_all!(ResourceNode: Send, Sync, Clone, std::fmt::Debug);
    assert_impl_all!(NewResourceNode: Send, Sync, Clone, std::fmt::Debug);
    assert_impl_all!(CustomRole: Send, Sync, Clone, std::fmt::Debug);
    assert_impl_all!(NewCustomRole: Send, Sync, Clone, std::fmt::Debug);
    assert_impl_all!(CustomRoleEntry: Send, Sync, Clone, std::fmt::Debug);
    assert_impl_all!(NewCustomRoleEntry: Send, Sync, Clone, std::fmt::Debug);
    assert_impl_all!(RoleAssignment: Send, Sync, Clone, std::fmt::Debug);
    assert_impl_all!(NewRoleAssignment: Send, Sync, Clone, std::fmt::Debug);
    const _: fn() = || {
        fn require_static<T: 'static + Send + Sync>() {}
        require_static::<ResourceNode>();
        require_static::<NewResourceNode>();
        require_static::<CustomRole>();
        require_static::<NewCustomRole>();
        require_static::<CustomRoleEntry>();
        require_static::<NewCustomRoleEntry>();
        require_static::<RoleAssignment>();
        require_static::<NewRoleAssignment>();
    };

    #[test]
    fn scope_type_round_trips_and_orders_widest_first() {
        let all = [
            ScopeType::Org,
            ScopeType::Workspace,
            ScopeType::Project,
            ScopeType::Service,
            ScopeType::Record,
        ];
        for (index, scope) in all.into_iter().enumerate() {
            assert_eq!(
                ScopeType::parse(scope.as_str()).unwrap_or_else(|e| panic!("round trip: {e}")),
                scope
            );
            assert_eq!(scope.level(), i16::try_from(index).unwrap_or(i16::MAX));
        }
        assert!(all.windows(2).all(|w| w[0] < w[1]), "Ord mirrors level()");
        assert!(ScopeType::parse("galaxy").is_err());
        assert!(ScopeType::parse("ORG").is_err(), "parse is exact-case");
    }

    #[test]
    fn builtin_role_round_trips_all_six() {
        let all = [
            BuiltinRole::OrgOwner,
            BuiltinRole::OrgAdmin,
            BuiltinRole::WorkspaceAdmin,
            BuiltinRole::Member,
            BuiltinRole::Guest,
            BuiltinRole::External,
        ];
        for role in all {
            assert_eq!(
                BuiltinRole::parse(role.as_str()).unwrap_or_else(|e| panic!("round trip: {e}")),
                role
            );
        }
        assert!(BuiltinRole::parse("superadmin").is_err());
    }

    #[test]
    fn effect_round_trips_and_rejects_unknown() {
        assert_eq!(Effect::parse("grant").ok(), Some(Effect::Grant));
        assert_eq!(Effect::parse("deny").ok(), Some(Effect::Deny));
        assert!(Effect::parse("allow").is_err());
    }

    #[test]
    fn assignment_role_round_trips_columns() {
        let builtin = AssignmentRole::Builtin(BuiltinRole::Member);
        assert_eq!(builtin.columns(), (Some("member"), None));
        let custom_id = Uuid::from_bytes([7; 16]);
        let custom = AssignmentRole::Custom(custom_id);
        assert_eq!(custom.columns(), (None, Some(custom_id)));
        for role in [builtin, custom] {
            let (b, c) = role.columns();
            assert_eq!(
                AssignmentRole::from_columns(b, c).unwrap_or_else(|e| panic!("round trip: {e}")),
                role
            );
        }
        assert!(AssignmentRole::from_columns(None, None).is_err());
        assert!(AssignmentRole::from_columns(Some("member"), Some(custom_id)).is_err());
        assert!(AssignmentRole::from_columns(Some("bogus"), None).is_err());
    }
}
