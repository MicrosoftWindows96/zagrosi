// SPDX-License-Identifier: AGPL-3.0-or-later

//! Authorization port + dependency-free RBAC value types.
//!
//! This module mirrors the [`crate::Auditor`] port pattern: `zagrosi-core`
//! declares the [`PermissionChecker`] trait; the `zagrosi-rbac` crate ships
//! the real implementation (`RbacChecker`); `zagrosi-identity` consumes an
//! `Arc<dyn PermissionChecker>` injected at composition time. A direct
//! `zagrosi-identity → zagrosi-rbac` Rust dependency would invert the
//! workspace's dependency direction and risk cycles, so only this port and
//! its small value types ([`Capability`], [`ScopeRef`], [`ScopePath`],
//! [`Decision`], [`DenyReason`]) live here. SQL-level foreign keys between
//! the crates' tables are fine — only Rust-type coupling is forbidden.
//!
//! Two test implementations ship alongside the port: [`AllowAllChecker`]
//! keeps identity's legacy tests passing before real RBAC wiring exists,
//! and [`DenyAllChecker`] lets negative-path tests force 403s.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth_context::AuthContext;

/// The 12-capability catalog, v1 (locked). Naming: `domain.verb`.
///
/// The dot-form strings returned by [`Capability::as_str`] are the wire and
/// storage representation; `zagrosi-rbac`'s `role_entries` rows store them
/// verbatim and the capabilities endpoint lists them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
#[non_exhaustive]
pub enum Capability {
    /// Org settings/profile mutations; audit retention policy.
    OrgManage,
    /// Org soft-delete (owner-only by default).
    OrgDelete,
    /// Invite/remove members, membership lifecycle.
    MemberManage,
    /// Custom role create/edit/delete.
    RoleManage,
    /// Grant/revoke role bindings.
    RoleAssign,
    /// SSO/OIDC/SAML config, domain verification, SCIM tokens.
    IdpManage,
    /// Revoke other members' sessions (org-scoped surfaces only; the
    /// network-gated admin-port unlock route is not governed by this).
    SessionRevoke,
    /// List/revoke other members' PATs (own-token self-service stays
    /// capability-free).
    ApiTokenManage,
    /// Audit query API.
    AuditRead,
    /// SIEM destination CRUD (org-scoped).
    AuditExport,
    /// Downstream placeholder (units 05+); exercised only by this unit's
    /// test matrix.
    WorkItemRead,
    /// Downstream placeholder (units 05+).
    WorkItemWrite,
}

impl Capability {
    /// Stable string form, e.g. `"org.manage"`. The explicit mapping table.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OrgManage => "org.manage",
            Self::OrgDelete => "org.delete",
            Self::MemberManage => "member.manage",
            Self::RoleManage => "role.manage",
            Self::RoleAssign => "role.assign",
            Self::IdpManage => "idp.manage",
            Self::SessionRevoke => "session.revoke",
            Self::ApiTokenManage => "api_token.manage",
            Self::AuditRead => "audit.read",
            Self::AuditExport => "audit.export",
            Self::WorkItemRead => "work_item.read",
            Self::WorkItemWrite => "work_item.write",
        }
    }

    /// Parse a stable string; unknown strings error (fail-closed), never
    /// panic.
    ///
    /// # Errors
    ///
    /// Returns [`CapabilityParseError::Unknown`] when the input is not one
    /// of the 12 catalog strings.
    pub fn parse(s: &str) -> Result<Self, CapabilityParseError> {
        match s {
            "org.manage" => Ok(Self::OrgManage),
            "org.delete" => Ok(Self::OrgDelete),
            "member.manage" => Ok(Self::MemberManage),
            "role.manage" => Ok(Self::RoleManage),
            "role.assign" => Ok(Self::RoleAssign),
            "idp.manage" => Ok(Self::IdpManage),
            "session.revoke" => Ok(Self::SessionRevoke),
            "api_token.manage" => Ok(Self::ApiTokenManage),
            "audit.read" => Ok(Self::AuditRead),
            "audit.export" => Ok(Self::AuditExport),
            "work_item.read" => Ok(Self::WorkItemRead),
            "work_item.write" => Ok(Self::WorkItemWrite),
            other => Err(CapabilityParseError::Unknown(other.to_owned())),
        }
    }

    /// All catalog entries, for matrix tests + the capabilities endpoint
    /// (section 09).
    #[must_use]
    pub const fn all() -> [Self; 12] {
        [
            Self::OrgManage,
            Self::OrgDelete,
            Self::MemberManage,
            Self::RoleManage,
            Self::RoleAssign,
            Self::IdpManage,
            Self::SessionRevoke,
            Self::ApiTokenManage,
            Self::AuditRead,
            Self::AuditExport,
            Self::WorkItemRead,
            Self::WorkItemWrite,
        ]
    }
}

impl TryFrom<String> for Capability {
    type Error = CapabilityParseError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<Capability> for String {
    fn from(value: Capability) -> Self {
        value.as_str().to_owned()
    }
}

/// Error for unknown capability strings.
///
/// Core only supplies the fallible parse; fail-closed *ignore-with-warn*
/// handling of unknown strings in stored rows is the RBAC resolver's job.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum CapabilityParseError {
    /// Input did not match any catalog entry.
    #[error("unknown capability string: `{0}`")]
    Unknown(String),
}

/// Resource being authorized: the caller's org root, or a registered scope
/// node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScopeRef {
    /// The caller's whole org (root of the scope tree).
    OrgRoot,
    /// A registered scope node (workspace / project / service / record).
    Node(Uuid),
}

/// Maximum number of nodes a [`ScopePath`] may carry
/// (org > workspace > project > service > record).
pub const SCOPE_PATH_MAX_DEPTH: usize = 5;

/// Ordered node-id chain, resource → org-root. Max depth
/// [`SCOPE_PATH_MAX_DEPTH`], min 1, no nil ids.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopePath(Vec<Uuid>);

impl ScopePath {
    /// Build a path from an ordered node-id chain (resource first,
    /// org-root last).
    ///
    /// # Errors
    ///
    /// Returns [`ScopePathError::Empty`] for zero nodes,
    /// [`ScopePathError::TooDeep`] for more than
    /// [`SCOPE_PATH_MAX_DEPTH`] nodes, and [`ScopePathError::NilNode`]
    /// when any node id is the nil UUID.
    pub fn new(nodes: Vec<Uuid>) -> Result<Self, ScopePathError> {
        if nodes.is_empty() {
            return Err(ScopePathError::Empty);
        }
        if nodes.len() > SCOPE_PATH_MAX_DEPTH {
            return Err(ScopePathError::TooDeep {
                depth: nodes.len(),
                max: SCOPE_PATH_MAX_DEPTH,
            });
        }
        if let Some(index) = nodes.iter().position(Uuid::is_nil) {
            return Err(ScopePathError::NilNode { index });
        }
        Ok(Self(nodes))
    }

    /// Ordered node ids, resource → org-root.
    #[must_use]
    pub fn nodes(&self) -> &[Uuid] {
        &self.0
    }
}

/// [`ScopePath`] construction failures.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum ScopePathError {
    /// Zero nodes supplied; a path names at least the resource itself.
    #[error("scope path must contain at least one node")]
    Empty,
    /// More nodes than the scope tree allows.
    #[error("scope path depth {depth} exceeds maximum {max}")]
    TooDeep {
        /// Number of nodes supplied.
        depth: usize,
        /// Configured maximum ([`SCOPE_PATH_MAX_DEPTH`]).
        max: usize,
    },
    /// A node id was the nil UUID.
    #[error("scope path node at index {index} is the nil UUID")]
    NilNode {
        /// Zero-based index of the offending node.
        index: usize,
    },
}

/// Why a check denied. Never serialized into client responses (the
/// `RequireCapability` guard maps every `Deny` to an opaque 403).
///
/// Deliberately NOT `#[non_exhaustive]`: consumers match exhaustively, so
/// adding a reason forces every guard to decide its handling at compile
/// time instead of falling into a wildcard arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyReason {
    /// No role grant covers the capability on the resource.
    NoGrant,
    /// An explicit deny entry outranks any grants.
    ExplicitDeny,
    /// The referenced scope node is not registered.
    UnknownResource,
    /// The resource belongs to a different org than the caller's context.
    OrgMismatch,
}

/// Authorization outcome.
///
/// Deliberately NOT `#[non_exhaustive]`: a binary allow/deny is the whole
/// contract, and exhaustive matching on a security decision is the
/// stronger property — a future variant must fail compilation at every
/// consumer rather than slide into a wildcard arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// The subject may exercise the capability on the resource.
    Allow,
    /// The subject may not; `reason` stays server-side (opaque 403 to
    /// clients).
    Deny {
        /// Why the check denied.
        reason: DenyReason,
    },
}

/// Single platform-wide authorization entry point.
///
/// Mirror of the [`crate::Auditor`] port pattern: `zagrosi-rbac` implements
/// this trait (`RbacChecker`); consumers receive `Arc<dyn PermissionChecker>`
/// at composition time and never link the implementation crate.
#[async_trait]
pub trait PermissionChecker: Send + Sync + 'static {
    /// Check whether `ctx`'s subject may exercise `capability` on
    /// `resource`.
    ///
    /// `Err(_)` means infrastructure failure (DB down, etc.) — callers
    /// treat it as deny (fail-closed); it is distinct from
    /// `Ok(Decision::Deny)`.
    ///
    /// # Errors
    ///
    /// Returns an error only for infrastructure failures, never for an
    /// authorization denial.
    async fn check(
        &self,
        ctx: &AuthContext,
        capability: Capability,
        resource: ScopeRef,
    ) -> crate::Result<Decision>;
}

/// Test/composition impl: always `Allow`. Keeps identity's legacy tests
/// green before real RBAC wiring exists.
#[derive(Debug, Default, Clone, Copy)]
pub struct AllowAllChecker;

#[async_trait]
impl PermissionChecker for AllowAllChecker {
    async fn check(
        &self,
        _ctx: &AuthContext,
        _capability: Capability,
        _resource: ScopeRef,
    ) -> crate::Result<Decision> {
        Ok(Decision::Allow)
    }
}

/// Test impl: always `Deny { reason: NoGrant }`. For negative-path tests
/// that need to force 403s.
#[derive(Debug, Default, Clone, Copy)]
pub struct DenyAllChecker;

#[async_trait]
impl PermissionChecker for DenyAllChecker {
    async fn check(
        &self,
        _ctx: &AuthContext,
        _capability: Capability,
        _resource: ScopeRef,
    ) -> crate::Result<Decision> {
        Ok(Decision::Deny {
            reason: DenyReason::NoGrant,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth_context::{AuthMethod, TokenClass};
    use chrono::{DateTime, Utc};
    use static_assertions::{assert_impl_all, assert_obj_safe};

    assert_obj_safe!(PermissionChecker);
    assert_impl_all!(Capability: Send, Sync, Copy, Clone, std::fmt::Debug);
    assert_impl_all!(Capability: serde::Serialize, serde::de::DeserializeOwned, std::hash::Hash);
    assert_impl_all!(ScopeRef: Send, Sync, Copy, Clone, std::fmt::Debug, std::hash::Hash);
    assert_impl_all!(Decision: Send, Sync, Copy, Clone, std::fmt::Debug);
    assert_impl_all!(DenyReason: Send, Sync, Copy, Clone, std::fmt::Debug);
    assert_impl_all!(ScopePath: Send, Sync, Clone, std::fmt::Debug);
    assert_impl_all!(CapabilityParseError: Send, Sync, std::error::Error);
    assert_impl_all!(ScopePathError: Send, Sync, std::error::Error);
    const _: fn() = || {
        fn require_static<T: 'static + Send + Sync>() {}
        require_static::<AllowAllChecker>();
        require_static::<DenyAllChecker>();
        require_static::<Capability>();
        require_static::<ScopePath>();
    };

    fn ts(secs: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(secs, 0)
            .unwrap_or_else(|| panic!("failed to build DateTime<Utc> from {secs}"))
    }

    fn valid_uuid(byte: u8) -> Uuid {
        Uuid::from_bytes([byte; 16])
    }

    fn valid_auth_context() -> AuthContext {
        AuthContext::new(
            valid_uuid(1),
            valid_uuid(2),
            valid_uuid(3),
            AuthMethod::Password,
            TokenClass::Session,
            vec!["pwd".into()],
            None,
            ts(0),
            ts(3600),
            valid_uuid(4),
        )
        .unwrap_or_else(|e| panic!("valid AuthContext rejected: {e}"))
    }

    #[test]
    fn capability_round_trips_every_variant_via_stable_strings() {
        let all = Capability::all();
        assert_eq!(all.len(), 12, "catalog is locked at 12 entries");
        for capability in all {
            // Drive the exhaustiveness check via match — the explicit
            // string table fails compilation when a variant is added
            // without a mapping here.
            let expected = match capability {
                Capability::OrgManage => "org.manage",
                Capability::OrgDelete => "org.delete",
                Capability::MemberManage => "member.manage",
                Capability::RoleManage => "role.manage",
                Capability::RoleAssign => "role.assign",
                Capability::IdpManage => "idp.manage",
                Capability::SessionRevoke => "session.revoke",
                Capability::ApiTokenManage => "api_token.manage",
                Capability::AuditRead => "audit.read",
                Capability::AuditExport => "audit.export",
                Capability::WorkItemRead => "work_item.read",
                Capability::WorkItemWrite => "work_item.write",
            };
            assert_eq!(capability.as_str(), expected);
            assert_eq!(Capability::parse(expected), Ok(capability));
            let json =
                serde_json::to_string(&capability).unwrap_or_else(|e| panic!("serialise: {e}"));
            assert_eq!(json, format!("\"{expected}\""));
            let parsed: Capability =
                serde_json::from_str(&json).unwrap_or_else(|e| panic!("deserialise: {e}"));
            assert_eq!(parsed, capability);
        }
    }

    #[test]
    fn capability_parse_rejects_unknown_strings() {
        for input in ["org.frobnicate", "", "ORG.MANAGE", "org.manage "] {
            match Capability::parse(input) {
                Err(CapabilityParseError::Unknown(s)) => assert_eq!(s, input),
                other => panic!("`{input}` must fail to parse, got {other:?}"),
            }
        }
    }

    #[test]
    fn capability_serde_rejects_unknown_strings() {
        let bad: Result<Capability, _> = serde_json::from_str("\"org.frobnicate\"");
        assert!(bad.is_err(), "unknown capability must fail at deserialise");
    }

    #[tokio::test]
    async fn allow_all_checker_always_allows() {
        let checker = AllowAllChecker;
        let ctx = valid_auth_context();
        for capability in Capability::all() {
            let decision = checker
                .check(&ctx, capability, ScopeRef::OrgRoot)
                .await
                .unwrap_or_else(|e| panic!("AllowAllChecker must not error: {e}"));
            assert_eq!(decision, Decision::Allow);
        }
        let node = checker
            .check(&ctx, Capability::AuditRead, ScopeRef::Node(valid_uuid(7)))
            .await
            .unwrap_or_else(|e| panic!("AllowAllChecker must not error: {e}"));
        assert_eq!(node, Decision::Allow);
    }

    #[tokio::test]
    async fn deny_all_checker_always_denies_with_no_grant() {
        let checker = DenyAllChecker;
        let ctx = valid_auth_context();
        for capability in Capability::all() {
            let decision = checker
                .check(&ctx, capability, ScopeRef::OrgRoot)
                .await
                .unwrap_or_else(|e| panic!("DenyAllChecker must not error: {e}"));
            assert_eq!(
                decision,
                Decision::Deny {
                    reason: DenyReason::NoGrant
                }
            );
        }
    }

    #[tokio::test]
    async fn checkers_are_usable_as_trait_objects() {
        let checkers: Vec<std::sync::Arc<dyn PermissionChecker>> = vec![
            std::sync::Arc::new(AllowAllChecker),
            std::sync::Arc::new(DenyAllChecker),
        ];
        let ctx = valid_auth_context();
        let mut decisions = Vec::new();
        for checker in checkers {
            decisions.push(
                checker
                    .check(&ctx, Capability::OrgManage, ScopeRef::OrgRoot)
                    .await
                    .unwrap_or_else(|e| panic!("checker must not error: {e}")),
            );
        }
        assert_eq!(
            decisions,
            vec![
                Decision::Allow,
                Decision::Deny {
                    reason: DenyReason::NoGrant
                }
            ]
        );
    }

    #[test]
    fn scope_path_rejects_empty() {
        assert_eq!(ScopePath::new(Vec::new()), Err(ScopePathError::Empty));
    }

    #[test]
    fn scope_path_rejects_too_deep() {
        let nodes: Vec<Uuid> = (1..=6).map(valid_uuid).collect();
        assert_eq!(
            ScopePath::new(nodes),
            Err(ScopePathError::TooDeep { depth: 6, max: 5 })
        );
    }

    #[test]
    fn scope_path_rejects_nil_node() {
        let nodes = vec![valid_uuid(1), Uuid::nil(), valid_uuid(3)];
        assert_eq!(
            ScopePath::new(nodes),
            Err(ScopePathError::NilNode { index: 1 })
        );
    }

    #[test]
    fn scope_path_accepts_one_to_five_nodes_and_preserves_order() {
        for depth in 1..=5u8 {
            let nodes: Vec<Uuid> = (1..=depth).map(valid_uuid).collect();
            let path = ScopePath::new(nodes.clone())
                .unwrap_or_else(|e| panic!("depth {depth} must validate: {e}"));
            assert_eq!(path.nodes(), nodes.as_slice(), "order must be preserved");
        }
    }
}
