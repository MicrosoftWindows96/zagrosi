// SPDX-License-Identifier: AGPL-3.0-or-later

//! Lua scripts that drive the rate-limit + lockout state machines.
//!
//! Both scripts run atomically server-side so multi-replica clients
//! converge on a single counter or lockout state without round-trip
//! races. Scripts use only commands available in the Valkey 8 (and
//! Redis 7) baseline so the integration test environment does not
//! need bespoke module loading.
//!
//! ## Wire contract
//!
//! - [`SLIDING_WINDOW_LUA`] increments a single key, sets `PEXPIRE` on
//!   first hit, and returns `{count, ttl_ms}`. The caller compares
//!   `count` against the budget and computes `retry_after_ms` from
//!   `ttl_ms` when the budget is exhausted.
//!
//! - [`LOCKOUT_LUA`] drives the per-account exponential-lockout state
//!   machine. State is split across two keys so escalation memory
//!   survives the active lockout window:
//!
//!   - `KEYS[1]` (active) is a string-typed key with TTL equal to the
//!     current lockout window. Its presence is the lock signal; its
//!     PTTL is the server-authoritative `Retry-After` source.
//!   - `KEYS[2]` (history) is a hash holding `attempts`, `backoff_ms`,
//!     `last_locked_ms`, and `last_unlock_ms`. TTL is the configured
//!     history retention so escalation persists across lockouts.
//!
//!   The script returns
//!   `{state, attempts, remaining_ms, backoff_ms}` where `state` is
//!   `0` for `Allow` and `1` for `LockedOut`. `remaining_ms` is the
//!   PTTL of the active key (always server-clock-derived, no host
//!   skew).
//!
//! - [`UNLOCK_LUA`] clears the active key, zeroes `attempts` and
//!   `backoff_ms` on history, and stamps `last_unlock_ms` so a brief
//!   grace window after unlock drops in-flight stale failures from
//!   concurrent sign-in attempts that started before the success.

/// Sliding-window per-IP / per-token bucket.
///
/// `KEYS[1]` = bucket key.
/// `ARGV[1]` = window length in milliseconds.
///
/// Returns `{count, ttl_ms}` where `count` is the post-INCR value
/// and `ttl_ms` is the live PEXPIRE TTL on the key (always `>= 0`
/// because we set it on the first hit). The caller is responsible for
/// comparing `count` against the configured budget and rendering a
/// `Retry-After` header from `ttl_ms` when exhausted.
pub const SLIDING_WINDOW_LUA: &str = r"
local count = redis.call('INCR', KEYS[1])
if count == 1 then
  redis.call('PEXPIRE', KEYS[1], ARGV[1])
end
local ttl = redis.call('PTTL', KEYS[1])
if ttl < 0 then
  ttl = tonumber(ARGV[1])
end
return { count, ttl }
";

/// Per-account exponential lockout state machine (two-key design).
///
/// `KEYS[1]` = active lockout key. Presence + PTTL = the lock.
/// `KEYS[2]` = history hash (`attempts`, `backoff_ms`,
///             `last_locked_ms`, `last_unlock_ms`).
/// `ARGV[1]` = lockout threshold (consecutive fails before lock).
/// `ARGV[2]` = initial backoff ms.
/// `ARGV[3]` = max backoff ms.
/// `ARGV[4]` = history retention ms (TTL refresh on every breach).
/// `ARGV[5]` = unlock grace ms (drop in-flight failures inside this
///             window after a successful unlock).
///
/// Returns `{state, attempts, remaining_ms, backoff_ms}` where
/// `state` is `0` for `Allow` and `1` for `LockedOut`. `remaining_ms`
/// is read from PTTL on the active key — server-authoritative, no
/// host clock involved.
pub const LOCKOUT_LUA: &str = r"
local now = redis.call('TIME')
local now_ms = tonumber(now[1]) * 1000 + math.floor(tonumber(now[2]) / 1000)

local active_ttl = redis.call('PTTL', KEYS[1])
if active_ttl > 0 then
  local existing_attempts = tonumber(redis.call('HGET', KEYS[2], 'attempts')) or 0
  local existing_backoff = tonumber(redis.call('HGET', KEYS[2], 'backoff_ms')) or tonumber(ARGV[2])
  return { 1, existing_attempts, active_ttl, existing_backoff }
end

local last_unlock = tonumber(redis.call('HGET', KEYS[2], 'last_unlock_ms')) or 0
if last_unlock > 0 and (now_ms - last_unlock) < tonumber(ARGV[5]) then
  return { 0, 0, 0, 0 }
end

local attempts = tonumber(redis.call('HINCRBY', KEYS[2], 'attempts', 1))
local threshold = tonumber(ARGV[1])
local initial_backoff = tonumber(ARGV[2])
local max_backoff = tonumber(ARGV[3])
local history_ttl = tonumber(ARGV[4])

redis.call('PEXPIRE', KEYS[2], history_ttl)

if attempts >= threshold then
  local prior_backoff = tonumber(redis.call('HGET', KEYS[2], 'backoff_ms')) or 0
  local next_backoff
  if prior_backoff <= 0 then
    next_backoff = initial_backoff
  else
    next_backoff = prior_backoff * 2
    if next_backoff > max_backoff then
      next_backoff = max_backoff
    end
  end
  redis.call('HSET', KEYS[2], 'backoff_ms', next_backoff, 'last_locked_ms', now_ms, 'attempts', 0)
  redis.call('SET', KEYS[1], '1', 'PX', next_backoff)
  return { 1, attempts, next_backoff, next_backoff }
end

return { 0, attempts, 0, 0 }
";

/// Unlock the per-account lockout.
///
/// `KEYS[1]` = active lockout key.
/// `KEYS[2]` = history hash.
/// `ARGV[1]` = unlock grace ms.
///
/// Clears the active key, zeroes `attempts` and `backoff_ms` on the
/// history hash, stamps `last_unlock_ms`, and pins the history hash
/// TTL to twice the grace window (with a 1-second floor) so the
/// in-flight-race guard stays addressable until concurrent stale
/// failures drain. Returns `1`.
pub const UNLOCK_LUA: &str = r"
local now = redis.call('TIME')
local now_ms = tonumber(now[1]) * 1000 + math.floor(tonumber(now[2]) / 1000)
redis.call('DEL', KEYS[1])
redis.call('HSET', KEYS[2], 'attempts', 0, 'backoff_ms', 0, 'last_unlock_ms', now_ms)
local grace_ms = tonumber(ARGV[1])
local ttl_ms = grace_ms * 2
if ttl_ms < 1000 then
  ttl_ms = 1000
end
redis.call('PEXPIRE', KEYS[2], ttl_ms)
return 1
";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sliding_window_lua_uses_keys_and_argv() {
        assert!(SLIDING_WINDOW_LUA.contains("KEYS[1]"));
        assert!(SLIDING_WINDOW_LUA.contains("ARGV[1]"));
        assert!(SLIDING_WINDOW_LUA.contains("INCR"));
        assert!(SLIDING_WINDOW_LUA.contains("PEXPIRE"));
        assert!(SLIDING_WINDOW_LUA.contains("PTTL"));
    }

    #[test]
    fn lockout_lua_carries_two_key_state_machine() {
        for needle in [
            "KEYS[1]",
            "KEYS[2]",
            "ARGV[1]",
            "ARGV[2]",
            "ARGV[3]",
            "ARGV[4]",
            "ARGV[5]",
            "attempts",
            "backoff_ms",
            "last_locked_ms",
            "last_unlock_ms",
            "TIME",
            "HINCRBY",
            "PEXPIRE",
            "PTTL",
            "SET",
        ] {
            assert!(
                LOCKOUT_LUA.contains(needle),
                "LOCKOUT_LUA missing `{needle}`"
            );
        }
    }

    #[test]
    fn unlock_lua_zeroes_state_and_stamps_last_unlock() {
        for needle in [
            "KEYS[1]",
            "KEYS[2]",
            "ARGV[1]",
            "DEL",
            "HSET",
            "attempts",
            "backoff_ms",
            "last_unlock_ms",
            "PEXPIRE",
        ] {
            assert!(UNLOCK_LUA.contains(needle), "UNLOCK_LUA missing `{needle}`");
        }
    }
}
