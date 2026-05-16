// SPDX-License-Identifier: AGPL-3.0-or-later

//! Valkey-backed implementation of [`zagrosi_core::RateLimiter`].
//!
//! Sliding-window per-IP / per-token buckets and per-account
//! exponential lockouts run as atomic Lua scripts (see
//! [`crate::rate_limit::lua`]) so multi-replica clients converge on
//! consistent counters without round-trip races.
//!
//! Construction wires a multiplexed [`fred::clients::Pool`] sized
//! from [`crate::config::RateLimitConfig::valkey_pool_size`]; on
//! init the limiter pre-loads all three Lua scripts via `SCRIPT LOAD`
//! and falls back to an automatic re-load on `NOSCRIPT` errors via
//! [`fred::types::scripts::Script::evalsha_with_reload`].
//!
//! ## Failure semantics
//!
//! Every Valkey-side failure surfaces as
//! [`zagrosi_core::RateLimiterError::Backend`] so the auth service
//! can fail-closed (reject the sign-in with a 503). Dropping silently
//! to "allow" would invert the security posture.

use async_trait::async_trait;
use fred::clients::{Client, Pool};
use fred::interfaces::ClientLike;
use fred::types::Builder;
use fred::types::config::Config as FredConfig;
use fred::types::scripts::Script;
use std::time::Duration;
use uuid::Uuid;
use zagrosi_core::{
    RateLimitDecision, RateLimitKey, RateLimiter as RateLimiterPort, RateLimiterError,
};

use crate::config::{IdentityConfig, RateLimitBudget, RateLimitConfig};
use crate::rate_limit::lua::{LOCKOUT_LUA, SLIDING_WINDOW_LUA, UNLOCK_LUA};

/// Pool plus pre-loaded Lua scripts.
///
/// Cheap to clone — every field wraps a refcount internally.
#[derive(Clone)]
pub struct ValkeyRateLimiter {
    pool: Pool,
    config: RateLimitConfig,
    sliding_window: Script,
    lockout: Script,
    unlock: Script,
}

impl std::fmt::Debug for ValkeyRateLimiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ValkeyRateLimiter")
            .field("pool_size", &self.pool.clients().len())
            .field("config", &self.config)
            .field("sliding_window_sha", &self.sliding_window.sha1())
            .field("lockout_sha", &self.lockout.sha1())
            .field("unlock_sha", &self.unlock.sha1())
            .finish()
    }
}

impl ValkeyRateLimiter {
    /// Construct a limiter from a fully-loaded [`IdentityConfig`].
    ///
    /// Steps:
    ///
    /// 1. Build a `fred` `Pool` sized from
    ///    [`RateLimitConfig::valkey_pool_size`] and bound to
    ///    [`IdentityConfig::valkey_url`].
    /// 2. `init()` the pool (connects every client; returns the
    ///    handles needed to reconnect on partition).
    /// 3. `SCRIPT LOAD` all three Lua scripts so warm calls hit
    ///    `EVALSHA`.
    ///
    /// # Errors
    ///
    /// Returns [`RateLimiterError::Backend`] for any URL parse,
    /// connection, or script-load failure. Sign-in code paths fail
    /// closed on this — a misconfigured Valkey URL must not silently
    /// drop rate limiting.
    pub async fn from_config(cfg: &IdentityConfig) -> Result<Self, RateLimiterError> {
        let fred_cfg = FredConfig::from_url(&cfg.valkey_url)
            .map_err(|e| RateLimiterError::Backend(format!("parse valkey url: {e}")))?;
        let pool = Builder::from_config(fred_cfg)
            .build_pool(cfg.rate_limit.valkey_pool_size)
            .map_err(|e| RateLimiterError::Backend(format!("build valkey pool: {e}")))?;
        pool.init()
            .await
            .map_err(|e| RateLimiterError::Backend(format!("init valkey pool: {e}")))?;

        let sliding_window = Script::from_lua(SLIDING_WINDOW_LUA);
        let lockout = Script::from_lua(LOCKOUT_LUA);
        let unlock = Script::from_lua(UNLOCK_LUA);

        for script in [&sliding_window, &lockout, &unlock] {
            for client in pool.clients() {
                script
                    .load(client)
                    .await
                    .map_err(|e| RateLimiterError::Backend(format!("preload lua script: {e}")))?;
            }
        }

        Ok(Self {
            pool,
            config: cfg.rate_limit.clone(),
            sliding_window,
            lockout,
            unlock,
        })
    }

    /// Borrow the configured rate-limit policy.
    #[must_use]
    pub const fn config(&self) -> &RateLimitConfig {
        &self.config
    }

    fn next_client(&self) -> &Client {
        self.pool.next()
    }

    /// Resolve the per-token sliding-window budget for `scope`.
    ///
    /// Personal access tokens use the dedicated `pat_per_minute`
    /// budget so MCP and API clients do not contend with SCIM
    /// provisioners on the same bucket. Every other per-token scope
    /// (SCIM, service tokens) shares the generic `signin_per_token`
    /// budget until their own sections land an override.
    fn budget_for_token_scope(&self, scope: &str) -> RateLimitBudget {
        const PAT_RESOLVE_SCOPE: &str = "pat_resolve";
        if scope == PAT_RESOLVE_SCOPE {
            self.config.pat_per_minute
        } else {
            self.config.signin_per_token
        }
    }

    async fn run_sliding_window(
        &self,
        storage_key: String,
        budget: RateLimitBudget,
    ) -> Result<RateLimitDecision, RateLimiterError> {
        let window_ms: i64 = i64::from(budget.window_seconds).saturating_mul(1_000);
        let client = self.next_client();
        let response: (i64, i64) = self
            .sliding_window
            .evalsha_with_reload(client, vec![storage_key], vec![window_ms])
            .await
            .map_err(|e| RateLimiterError::Backend(format!("sliding-window eval: {e}")))?;
        let (count, ttl_ms) = response;
        let count = count.max(0);
        let ttl_ms = ttl_ms.max(0);
        let count_u32 = u32::try_from(count).unwrap_or(u32::MAX);
        let reset = Duration::from_millis(u64::try_from(ttl_ms).unwrap_or(0));
        if count_u32 > budget.count {
            return Ok(RateLimitDecision::Deny { retry_after: reset });
        }
        let remaining = budget.count.saturating_sub(count_u32);
        Ok(RateLimitDecision::Allow {
            remaining,
            reset_in: reset,
        })
    }

    async fn run_lockout(
        &self,
        active_key: String,
        history_key: String,
    ) -> Result<RateLimitDecision, RateLimiterError> {
        let threshold: i64 = i64::from(self.config.lockout_threshold);
        let initial_ms: i64 = i64::try_from(self.config.initial_backoff_ms()).unwrap_or(i64::MAX);
        let max_ms: i64 = i64::try_from(self.config.max_backoff_ms()).unwrap_or(i64::MAX);
        let history_ttl_ms: i64 = i64::try_from(self.config.history_ttl_ms()).unwrap_or(i64::MAX);
        let grace_ms: i64 = i64::try_from(self.config.unlock_grace_ms()).unwrap_or(i64::MAX);
        let client = self.next_client();
        let response: (i64, i64, i64, i64) = self
            .lockout
            .evalsha_with_reload(
                client,
                vec![active_key, history_key],
                vec![threshold, initial_ms, max_ms, history_ttl_ms, grace_ms],
            )
            .await
            .map_err(|e| RateLimiterError::Backend(format!("lockout eval: {e}")))?;
        let (state, attempts, remaining_ms, backoff_ms) = response;
        let attempts_u32 = u32::try_from(attempts.max(0)).unwrap_or(u32::MAX);
        if state == 1 {
            let remaining = u64::try_from(remaining_ms.max(0)).unwrap_or(0);
            return Ok(RateLimitDecision::LockedOut {
                retry_after: Duration::from_millis(remaining),
                attempts: attempts_u32,
            });
        }
        // `backoff_ms` is meaningful only on the LockedOut branch;
        // bind it explicitly so the four-tuple shape is documented at
        // the call site.
        let _ = backoff_ms;
        let remaining = self.config.lockout_threshold.saturating_sub(attempts_u32);
        Ok(RateLimitDecision::Allow {
            remaining,
            reset_in: Duration::from_millis(self.config.initial_backoff_ms()),
        })
    }

    async fn run_unlock_lockout(
        &self,
        active_key: String,
        history_key: String,
    ) -> Result<(), RateLimiterError> {
        let grace_ms: i64 = i64::try_from(self.config.unlock_grace_ms()).unwrap_or(i64::MAX);
        let client = self.next_client();
        let _: i64 = self
            .unlock
            .evalsha_with_reload(client, vec![active_key, history_key], vec![grace_ms])
            .await
            .map_err(|e| RateLimiterError::Backend(format!("unlock eval: {e}")))?;
        Ok(())
    }

    async fn run_unlock_sliding(&self, storage_key: String) -> Result<(), RateLimiterError> {
        use fred::interfaces::KeysInterface;
        let client = self.next_client();
        let _: i64 = client
            .del(storage_key)
            .await
            .map_err(|e| RateLimiterError::Backend(format!("unlock del: {e}")))?;
        Ok(())
    }
}

#[async_trait]
impl RateLimiterPort for ValkeyRateLimiter {
    async fn check(&self, key: &RateLimitKey) -> Result<RateLimitDecision, RateLimiterError> {
        match key {
            RateLimitKey::PerIp { ip, scope } => {
                let storage_key = format!("rl:{scope}:ip:{ip}");
                self.run_sliding_window(storage_key, self.config.signin_per_ip)
                    .await
            }
            RateLimitKey::PerToken { token_hash, scope } => {
                let storage_key = format!("rl:{scope}:token:{}", hex::encode(token_hash));
                let budget = self.budget_for_token_scope(scope);
                self.run_sliding_window(storage_key, budget).await
            }
            RateLimitKey::PerAccount { user_id, scope } => {
                let uid = render_uuid(user_id);
                let active_key = format!("lockout:{scope}:account:{uid}:active");
                let history_key = format!("lockout:{scope}:account:{uid}:history");
                self.run_lockout(active_key, history_key).await
            }
            _ => Err(RateLimiterError::Backend(
                "unsupported rate-limit key variant".into(),
            )),
        }
    }

    async fn unlock(&self, key: &RateLimitKey) -> Result<(), RateLimiterError> {
        match key {
            RateLimitKey::PerIp { ip, scope } => {
                self.run_unlock_sliding(format!("rl:{scope}:ip:{ip}")).await
            }
            RateLimitKey::PerToken { token_hash, scope } => {
                self.run_unlock_sliding(format!("rl:{scope}:token:{}", hex::encode(token_hash)))
                    .await
            }
            RateLimitKey::PerAccount { user_id, scope } => {
                let uid = render_uuid(user_id);
                let active_key = format!("lockout:{scope}:account:{uid}:active");
                let history_key = format!("lockout:{scope}:account:{uid}:history");
                self.run_unlock_lockout(active_key, history_key).await
            }
            _ => Err(RateLimiterError::Backend(
                "unsupported rate-limit key variant".into(),
            )),
        }
    }
}

fn render_uuid(id: &Uuid) -> String {
    let mut buf = Uuid::encode_buffer();
    let rendered: &str = id.as_hyphenated().encode_lower(&mut buf);
    rendered.to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use static_assertions::assert_impl_all;
    use std::net::IpAddr;

    assert_impl_all!(ValkeyRateLimiter: Send, Sync, Clone);

    #[test]
    fn render_uuid_lowercases_hyphenated() {
        let id = Uuid::from_bytes([0x42; 16]);
        let rendered = render_uuid(&id);
        assert_eq!(rendered, id.to_string());
        assert!(!rendered.chars().any(|c| c.is_ascii_uppercase()));
    }

    #[test]
    fn ip_address_round_trips_in_key_format() {
        let ip: IpAddr = "10.0.0.7".parse().unwrap_or_else(|e| panic!("parse: {e}"));
        let formatted = format!("rl:signin:ip:{ip}");
        assert_eq!(formatted, "rl:signin:ip:10.0.0.7");
    }

    #[test]
    fn token_hash_renders_64_hex_chars() {
        let hash = [0xAB_u8; 32];
        let hex_repr = hex::encode(hash);
        assert_eq!(hex_repr.len(), 64);
        assert_eq!(
            format!("rl:scim:token:{hex_repr}"),
            "rl:scim:token:".to_string() + &"ab".repeat(32)
        );
    }

    #[test]
    fn lockout_active_and_history_keys_diverge() {
        let id = Uuid::from_bytes([0x42; 16]);
        let uid = render_uuid(&id);
        let active = format!("lockout:signin:account:{uid}:active");
        let history = format!("lockout:signin:account:{uid}:history");
        assert_ne!(active, history);
        assert!(active.ends_with(":active"));
        assert!(history.ends_with(":history"));
    }
}
