// SPDX-License-Identifier: AGPL-3.0-or-later

//! Error type for the test harness.

/// Anything the harness can fail on, lifted via `?` from the underlying
/// container, database, and migration layers.
#[derive(Debug, thiserror::Error)]
pub enum HarnessError {
    /// Container runtime failure (docker unavailable, image missing, ...).
    #[error("container error: {0}")]
    Container(#[from] testcontainers_modules::testcontainers::TestcontainersError),
    /// Database connection or query failure.
    #[error("sqlx error: {0}")]
    Sqlx(#[from] sqlx::Error),
    /// Migration application failure.
    #[error("migrate error: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
    /// Harness configuration / invariant violation.
    #[error("harness config error: {0}")]
    Config(String),
}
