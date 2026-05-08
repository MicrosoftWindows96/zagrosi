// SPDX-License-Identifier: AGPL-3.0-or-later

//! Foundation library for the Zagrosi platform.
//!
//! Provides three primitives that every other Zagrosi crate consumes:
//!
//! - Shared error types (`ZagrosiError`, `Result`); see [`error`].
//! - A layered configuration loader (`CoreConfig`, `LoadOptions`); see [`config`].
//! - An off-by-default observability guard wrapping `tracing`, OpenTelemetry,
//!   and a Prometheus admin server; see [`observability`].
//!
//! See `documentation/governance.md` for the project-wide conventions this
//! crate enforces (DCO, Conventional Commits, lint policy).

#![deny(missing_docs)]

pub mod config;
pub mod error;
pub mod observability;

pub use config::{CoreConfig, LoadOptions, LogFormat};
pub use error::{Result, ZagrosiError};
pub use observability::Observability;
