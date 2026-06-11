// SPDX-License-Identifier: AGPL-3.0-or-later

//! Persistence layer.
//!
//! Every function takes `&mut TenantTx` — there are deliberately no
//! pool- or raw-connection entry points, so a caller cannot reach an
//! rbac table without the org GUC set (the type-level "you cannot
//! forget the org filter" mechanism from `zagrosi-db`).
//!
//! Reads are live-row reads (`deleted_at IS NULL`); under RLS a foreign
//! org's row and an absent row are indistinguishable, so cross-tenant
//! probes surface as [`crate::Error::NotFound`] / `None`, never as a
//! permission error.

pub mod assignments;
pub mod cascade;
pub mod custom_roles;
pub mod nodes;
pub mod versions;

pub use assignments::{insert_assignment, list_assignments_for_user, soft_delete_assignment};
pub use cascade::{soft_delete_node_cascade, soft_delete_org_cascade};
pub use custom_roles::{
    find_custom_role, insert_custom_role, list_custom_roles, replace_entries,
    soft_delete_custom_role,
};
pub use nodes::{find_node, insert_node, org_root};
pub use versions::{bump_version, current_version};
