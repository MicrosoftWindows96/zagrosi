// SPDX-License-Identifier: AGPL-3.0-or-later

//! Crate error type.
//!
//! Hand-rolled (no `thiserror`) to keep the crate's `[dependencies]`
//! at sqlx + uuid only.

use std::fmt;

/// Errors produced by the tenancy plumbing.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// Caller passed `Uuid::nil()` as the org id. The nil UUID is the
    /// legacy "no org" sentinel and must never become a tenant scope.
    NilOrgId,
    /// Caller passed `Uuid::nil()` as the user id.
    NilUserId,
    /// Debug-build read-back verification found the GUC missing or
    /// holding the wrong value after `set_config` reported success.
    GucVerificationFailed {
        /// GUC name that failed verification.
        guc: &'static str,
        /// Value `set_config` was asked to store.
        expected: String,
        /// Value `current_setting` actually returned.
        actual: Option<String>,
    },
    /// Underlying database failure.
    Sqlx(sqlx::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NilOrgId => f.write_str("org_id must not be the nil UUID"),
            Self::NilUserId => f.write_str("user_id must not be the nil UUID"),
            Self::GucVerificationFailed {
                guc,
                expected,
                actual,
            } => write!(
                f,
                "GUC `{guc}` read-back returned {actual:?}, expected `{expected}`"
            ),
            Self::Sqlx(err) => write!(f, "database error: {err}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Sqlx(err) => Some(err),
            Self::NilOrgId | Self::NilUserId | Self::GucVerificationFailed { .. } => None,
        }
    }
}

impl From<sqlx::Error> for Error {
    fn from(err: sqlx::Error) -> Self {
        Self::Sqlx(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_renders_each_variant() {
        assert_eq!(
            Error::NilOrgId.to_string(),
            "org_id must not be the nil UUID"
        );
        assert_eq!(
            Error::NilUserId.to_string(),
            "user_id must not be the nil UUID"
        );
        let verification = Error::GucVerificationFailed {
            guc: "app.org_id",
            expected: "abc".to_string(),
            actual: None,
        };
        assert!(verification.to_string().contains("app.org_id"));
        let wrapped = Error::from(sqlx::Error::PoolClosed);
        assert!(wrapped.to_string().starts_with("database error:"));
    }

    #[test]
    fn source_carries_sqlx_chain() {
        use std::error::Error as _;
        assert!(Error::from(sqlx::Error::PoolClosed).source().is_some());
        assert!(Error::NilOrgId.source().is_none());
    }
}
