// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared error and result types for the Zagrosi workspace.
//!
//! # Boundary policy
//!
//! Per-crate libraries (identity, rbac, work-item, etc.) define their own
//! `thiserror` enums for domain-specific failures. Binaries (`apps/api-gateway`,
//! `apps/worker`, `apps/zagrosi-mcp`) use `anyhow::Error` at the entry point.
//! Conversion through [`ZagrosiError`] happens only when an OS-level failure
//! mode (configuration, I/O) needs to surface across the library boundary, or
//! when a binary-level helper wants a single typed error to match on.
//!
//! Downstream crates should NOT extend [`ZagrosiError`] with domain-specific
//! variants; their own `thiserror` enum is the right home.

/// Errors produced by foundation-level operations in `zagrosi-core`.
///
/// The `Config` variant holds a boxed [`figment::Error`] to keep the enum
/// itself small (under 32 bytes); `figment::Error` is otherwise large enough
/// to bloat every `Result<T, ZagrosiError>` returned across the workspace.
///
/// Boundary policy is documented in the module-level rustdoc on this crate's
/// `error` module: per-crate libraries define their own `thiserror` enums,
/// binaries use `anyhow::Error` at the entry point, and conversion through
/// this enum happens only at OS-level failure surfaces.
#[derive(Debug, thiserror::Error)]
pub enum ZagrosiError {
    /// Configuration loading or parsing failed.
    #[error("configuration error: {0}")]
    Config(#[source] Box<figment::Error>),

    /// Underlying I/O operation failed.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Caller passed an argument that violated a documented precondition.
    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    /// An internal invariant was violated; surfaces the message as-is.
    #[error("internal error: {0}")]
    Internal(String),
}

impl From<figment::Error> for ZagrosiError {
    fn from(err: figment::Error) -> Self {
        Self::Config(Box::new(err))
    }
}

impl ZagrosiError {
    /// Construct an [`ZagrosiError::InvalidArgument`] variant.
    #[must_use]
    pub fn invalid_argument(msg: impl Into<String>) -> Self {
        Self::InvalidArgument(msg.into())
    }

    /// Construct an [`ZagrosiError::Internal`] variant.
    #[must_use]
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::Internal(msg.into())
    }
}

/// Crate-wide result type defaulting to [`ZagrosiError`].
pub type Result<T, E = ZagrosiError> = std::result::Result<T, E>;

#[cfg(test)]
mod tests {
    use super::*;
    use static_assertions::assert_impl_all;

    assert_impl_all!(ZagrosiError: Send, Sync);

    #[test]
    fn invalid_argument_constructor_carries_message() {
        let err = ZagrosiError::invalid_argument("bad input");
        match err {
            ZagrosiError::InvalidArgument(msg) => assert_eq!(msg, "bad input"),
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
    }

    #[test]
    fn internal_constructor_carries_message() {
        let err = ZagrosiError::internal("oops");
        match err {
            ZagrosiError::Internal(msg) => assert_eq!(msg, "oops"),
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn io_error_converts_via_from() {
        let io_err = std::io::Error::other("boom");
        let zerr: ZagrosiError = io_err.into();
        match zerr {
            ZagrosiError::Io(_) => {}
            other => panic!("expected Io, got {other:?}"),
        }
    }

    #[test]
    fn display_renders_variant_specific_message() {
        let err = ZagrosiError::invalid_argument("xyz");
        let rendered = format!("{err}");
        assert!(rendered.contains("xyz"));
        assert!(rendered.starts_with("invalid argument:"));
    }

    #[test]
    fn debug_renders_for_all_variants() {
        let _ = format!("{:?}", ZagrosiError::invalid_argument("a"));
        let _ = format!("{:?}", ZagrosiError::internal("b"));
        let io = ZagrosiError::Io(std::io::Error::other("c"));
        let _ = format!("{io:?}");
    }

    #[test]
    fn result_alias_uses_zagrosi_error_default() {
        fn returns_result() -> Result<u32> {
            Err(ZagrosiError::internal("nope"))
        }
        assert!(returns_result().is_err());
    }
}
