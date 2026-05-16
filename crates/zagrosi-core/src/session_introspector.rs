// SPDX-License-Identifier: AGPL-3.0-or-later

//! Gateway-facing session-resolution port.
//!
//! Concrete impl in `zagrosi-identity`. Behavioural contract:
//!
//! - MUST validate the token-class prefix (`sid_` / `pat_` / `scim_` /
//!   `svc_`) before any DB or cache touch; malformed prefix →
//!   [`AuthError::MalformedPrefix`].
//! - Cache-hit path MUST return without DB touch (latency budget — primary
//!   acceptance gate, ≥ 10 000 ops/sec on the 32 vCPU reference).

use async_trait::async_trait;

use crate::auth_context::{AuthContext, AuthError};

/// Gateway-facing fast path for resolving a raw bearer / cookie token to
/// an [`AuthContext`].
#[async_trait]
pub trait SessionIntrospector: Send + Sync + 'static {
    /// Resolve a raw bearer or cookie token to an [`AuthContext`], or
    /// surface the appropriate [`AuthError`].
    async fn resolve(&self, raw_token: &str) -> Result<AuthContext, AuthError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use static_assertions::assert_obj_safe;

    assert_obj_safe!(SessionIntrospector);
}
