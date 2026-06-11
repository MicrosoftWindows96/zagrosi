// SPDX-License-Identifier: AGPL-3.0-or-later

//! Dev-only integration-test harness for the Zagrosi workspace.
//!
//! Boots ephemeral Postgres containers on the custom image
//! (`deploy/docker/postgres`), bootstraps the four runtime roles with the
//! container superuser, applies every registered migration set as
//! `zagrosi_migrate`, and hands out **role-specific pools**. The repo-wide
//! rule this crate enforces: integration tests never connect as superuser —
//! the superuser exists for container bootstrap only.
//!
//! The migration runner ([`migrations::run_all_migrations`]) is the single
//! entry point for tests and future apps; sections register additional
//! migration sets (rbac, audit) in [`migrations::migration_sets`].

#![deny(missing_docs)]

mod bootstrap;
pub mod error;
pub mod fixtures;
pub mod harness;
pub mod image;
pub mod migrations;
pub mod minio;
pub mod rls_catalog;

pub use error::HarnessError;
pub use fixtures::{seed_org, seed_user};
pub use harness::{DbRole, TestDb};
pub use migrations::{
    MigrationSet, migration_sets, run_all_migrations, run_identity_migrations, run_rbac_migrations,
};
pub use minio::MinioHarness;
pub use rls_catalog::{RlsCatalogEntry, RlsPattern, SeedFn, rls_catalog};
