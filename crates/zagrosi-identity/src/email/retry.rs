// SPDX-License-Identifier: AGPL-3.0-or-later

//! Exponential-backoff schedule for the email-outbox worker.
//!
//! The `email_outbox` row carries an `attempts` counter. Each failed
//! send increments it; [`next_attempt`] maps the **post-increment**
//! count to the delay before the row becomes eligible again. After
//! [`MAX_ATTEMPTS`] failures the row is dead-lettered (the function
//! returns `None`) and no further sends are attempted.
//!
//! The schedule is a fixed table rather than a computed `base * 2^n`
//! so the operator-visible cadence is exact and asserted by tests:
//! 30 s → 2 min → 10 min → 1 h, then dead-letter. There are
//! [`MAX_ATTEMPTS`] (`5`) total send attempts: the initial attempt
//! plus four backed-off retries consuming the four schedule entries.

use std::time::Duration;

/// Total send attempts before a row is moved to `dead`.
///
/// One initial attempt plus four backed-off retries. The producer
/// writes the row with `attempts = 0`; the worker increments on each
/// failed send. When the post-increment count reaches this value the
/// row is dead-lettered.
pub const MAX_ATTEMPTS: i32 = 5;

/// Backoff delays indexed by `attempts - 1` (the just-incremented
/// failure count). Length is `MAX_ATTEMPTS - 1`: the last failure
/// has no following retry, it dead-letters instead.
///
/// 1st failure → wait 30 s, 2nd → 2 min, 3rd → 10 min, 4th → 1 h.
/// The 5th failure dead-letters.
const BACKOFF: [Duration; (MAX_ATTEMPTS - 1) as usize] = [
    Duration::from_secs(30),
    Duration::from_secs(120),
    Duration::from_secs(600),
    Duration::from_secs(3_600),
];

/// Map a post-increment `attempts` count to the delay before the row
/// is eligible for another send.
///
/// `attempts` is the value **after** incrementing on a failed send
/// (so the first failed send calls this with `1`). Returns `None`
/// when the cap is reached — the caller dead-letters the row.
///
/// Values `<= 0` are treated as `1` (defence against a caller passing
/// the pre-increment count); the schedule is clamped, never indexed
/// out of bounds.
#[must_use]
pub fn next_attempt(attempts: i32) -> Option<Duration> {
    if attempts >= MAX_ATTEMPTS {
        return None;
    }
    let idx = attempts.max(1) - 1;
    // `idx >= 0` (because `attempts.max(1) >= 1`), so `try_from`
    // cannot fail; `get` bounds-checks the upper end. No sign-losing
    // `as` cast.
    usize::try_from(idx)
        .ok()
        .and_then(|i| BACKOFF.get(i))
        .copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schedule_is_monotonically_increasing() {
        let mut prev = Duration::ZERO;
        for attempts in 1..MAX_ATTEMPTS {
            let delay = next_attempt(attempts).expect("retry below cap yields a delay");
            assert!(
                delay > prev,
                "delay for attempts={attempts} ({delay:?}) must exceed prior ({prev:?})",
            );
            prev = delay;
        }
    }

    #[test]
    fn schedule_matches_documented_constants() {
        assert_eq!(next_attempt(1), Some(Duration::from_secs(30)));
        assert_eq!(next_attempt(2), Some(Duration::from_secs(120)));
        assert_eq!(next_attempt(3), Some(Duration::from_secs(600)));
        assert_eq!(next_attempt(4), Some(Duration::from_secs(3_600)));
    }

    #[test]
    fn cap_reached_returns_none() {
        assert_eq!(next_attempt(MAX_ATTEMPTS), None);
        assert_eq!(next_attempt(MAX_ATTEMPTS + 1), None);
        assert_eq!(next_attempt(99), None);
    }

    #[test]
    fn non_positive_attempts_clamp_to_first_delay() {
        // Defence against a caller passing the pre-increment count.
        assert_eq!(next_attempt(0), Some(Duration::from_secs(30)));
        assert_eq!(next_attempt(-5), Some(Duration::from_secs(30)));
    }

    #[test]
    fn backoff_table_length_is_max_attempts_minus_one() {
        // The final failed attempt dead-letters instead of scheduling
        // another retry, so the table has MAX_ATTEMPTS-1 entries.
        assert_eq!(BACKOFF.len(), (MAX_ATTEMPTS - 1) as usize);
    }
}
