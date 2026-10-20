//! Rate limits and the wrong-password throttle as small state machines the app owns.
//!
//! Keep them in memory behind a `Mutex` (as latchkey 0.2 did: they reset on restart and are
//! per process) or persist the per-key states, which are plain data. Every decision takes
//! `now`.
//!
//! ```
//! use latchkey::limits::RateLimiter;
//! use time::OffsetDateTime;
//!
//! let mut per_ip = RateLimiter::per_minute(2);
//! let now = OffsetDateTime::UNIX_EPOCH;
//! assert!(per_ip.check("ip:203.0.113.9", now).is_ok());
//! assert!(per_ip.check("ip:203.0.113.9", now).is_ok());
//! let refused = per_ip.check("ip:203.0.113.9", now);
//! assert_eq!(refused.unwrap_err().retry_after_secs(), Some(60));
//! ```

use std::collections::{HashMap, VecDeque};

use time::{Duration, OffsetDateTime};

use crate::Error;
use crate::account::AccountKey;

/// The limits latchkey 0.2 applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RateLimits {
    /// Sign-in requests per client IP per minute (fixed windows). Default 30.
    pub per_ip_per_minute: u32,
    /// Sign-in requests per account (or address) per minute. Default 10.
    pub per_account_per_minute: u32,
    /// Wrong passwords per account within `wrong_password_window` (sliding), counted for
    /// unknown addresses alike and not reset by a successful sign-in; 0 turns it off.
    /// Default 10.
    pub wrong_passwords_per_account: u32,
    /// Default 15 minutes.
    pub wrong_password_window: Duration,
}

impl Default for RateLimits {
    fn default() -> Self {
        Self {
            per_ip_per_minute: 30,
            per_account_per_minute: 10,
            wrong_passwords_per_account: 10,
            wrong_password_window: Duration::minutes(15),
        }
    }
}

/// A fixed-window counter for one key.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct FixedWindow {
    window: i64,
    count: u32,
}

impl FixedWindow {
    /// Counts one hit and refuses it when the window already had `limit` hits. Windows are
    /// aligned to multiples of `window` since the Unix epoch.
    ///
    /// # Errors
    ///
    /// [`Error::TooManyAttempts`] with the seconds until the next window.
    pub fn hit(&mut self, limit: u32, window: Duration, now: OffsetDateTime) -> Result<(), Error> {
        let len = window.whole_seconds().max(1);
        let now = now.unix_timestamp();
        let current = now.div_euclid(len);
        if self.window != current {
            *self = Self {
                window: current,
                count: 0,
            };
        }
        self.count = self.count.saturating_add(1);
        if self.count <= limit {
            return Ok(());
        }
        let next = current.saturating_add(1).saturating_mul(len);
        Err(Error::too_many(
            u64::try_from(next.saturating_sub(now)).unwrap_or(1),
        ))
    }

    fn is_current(&self, window: Duration, now: OffsetDateTime) -> bool {
        self.window
            == now
                .unix_timestamp()
                .div_euclid(window.whole_seconds().max(1))
    }
}

/// Fixed-window limits for many keys, such as `ip:<address>` or `account:<email>`.
///
/// It holds at most `max_keys` keys (100 000 by default); when full, keys from earlier windows
/// are dropped first.
#[derive(Debug, Clone)]
pub struct RateLimiter {
    limit: u32,
    window: Duration,
    max_keys: usize,
    keys: HashMap<String, FixedWindow>,
}

impl RateLimiter {
    /// `limit` hits per `window` per key.
    #[must_use]
    pub fn new(limit: u32, window: Duration) -> Self {
        Self {
            limit,
            window,
            max_keys: 100_000,
            keys: HashMap::new(),
        }
    }

    /// `limit` hits per minute per key.
    #[must_use]
    pub fn per_minute(limit: u32) -> Self {
        Self::new(limit, Duration::MINUTE)
    }

    /// Caps the number of keys held.
    #[must_use]
    pub fn with_max_keys(mut self, max_keys: usize) -> Self {
        self.max_keys = max_keys.max(1);
        self
    }

    /// Counts a hit for `key`.
    ///
    /// # Errors
    ///
    /// [`Error::TooManyAttempts`] once `key` is over the limit in the current window.
    pub fn check(&mut self, key: &str, now: OffsetDateTime) -> Result<(), Error> {
        if self.keys.len() >= self.max_keys && !self.keys.contains_key(key) {
            let window = self.window;
            self.keys
                .retain(|_, counter| counter.is_current(window, now));
            if self.keys.len() >= self.max_keys {
                self.keys.clear();
            }
        }
        self.keys
            .entry(key.to_owned())
            .or_default()
            .hit(self.limit, self.window, now)
    }
}

/// When one key failed recently: a sliding window of failure times.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct FailureWindow {
    failures: VecDeque<i64>,
}

impl FailureWindow {
    /// Seconds to wait when there are already `max` failures within `window` before `now`;
    /// `None` when another attempt is allowed. `max` = 0 never blocks.
    #[must_use]
    pub fn blocked(&self, max: u32, window: Duration, now: OffsetDateTime) -> Option<u64> {
        if max == 0 {
            return None;
        }
        let now = now.unix_timestamp();
        let window = window.whole_seconds().max(1);
        let max = usize::try_from(max).unwrap_or(usize::MAX);
        let recent: Vec<i64> = self
            .failures
            .iter()
            .copied()
            .filter(|at| at.saturating_add(window) > now)
            .collect();
        if recent.len() < max {
            return None;
        }
        let oldest_counted = recent
            .len()
            .checked_sub(max)
            .and_then(|index| recent.get(index))
            .copied()
            .unwrap_or(now);
        u64::try_from(oldest_counted.saturating_add(window).saturating_sub(now))
            .ok()
            .map(|secs| secs.max(1))
    }

    /// Records a failure at `now`, keeping at most `max` entries.
    pub fn record(&mut self, max: u32, window: Duration, now: OffsetDateTime) {
        if max == 0 {
            return;
        }
        let now = now.unix_timestamp();
        let window = window.whole_seconds().max(1);
        while self
            .failures
            .front()
            .is_some_and(|at| at.saturating_add(window) <= now)
        {
            self.failures.pop_front();
        }
        self.failures.push_back(now);
        let keep = usize::try_from(max).unwrap_or(usize::MAX);
        while self.failures.len() > keep {
            self.failures.pop_front();
        }
    }

    /// Whether nothing is recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.failures.is_empty()
    }
}

/// The wrong-password throttle for many accounts, keyed by [`AccountKey`] so unknown
/// addresses are throttled like known ones.
#[derive(Debug, Clone)]
pub struct WrongPasswordThrottle {
    max: u32,
    window: Duration,
    max_keys: usize,
    keys: HashMap<AccountKey, FailureWindow>,
}

impl WrongPasswordThrottle {
    /// Uses [`RateLimits::wrong_passwords_per_account`] and
    /// [`RateLimits::wrong_password_window`].
    #[must_use]
    pub fn new(limits: &RateLimits) -> Self {
        Self {
            max: limits.wrong_passwords_per_account,
            window: limits.wrong_password_window,
            max_keys: 100_000,
            keys: HashMap::new(),
        }
    }

    /// The window for `key`, to pass to a flow event.
    #[must_use]
    pub fn window(&self, key: &AccountKey) -> FailureWindow {
        self.keys.get(key).cloned().unwrap_or_default()
    }

    /// Refuses once `key` has had too many wrong passwords. Check before hashing.
    ///
    /// # Errors
    ///
    /// [`Error::TooManyAttempts`].
    pub fn check(&self, key: &AccountKey, now: OffsetDateTime) -> Result<(), Error> {
        match self
            .keys
            .get(key)
            .and_then(|log| log.blocked(self.max, self.window, now))
        {
            Some(secs) => Err(Error::too_many(secs)),
            None => Ok(()),
        }
    }

    /// Records a wrong password for `key`.
    pub fn record(&mut self, key: &AccountKey, now: OffsetDateTime) {
        if self.max == 0 {
            return;
        }
        if self.keys.len() >= self.max_keys && !self.keys.contains_key(key) {
            let window = self.window;
            self.keys
                .retain(|_, log| log.blocked(1, window, now).is_some());
            if self.keys.len() >= self.max_keys {
                self.keys.clear();
            }
        }
        self.keys
            .entry(key.clone())
            .or_default()
            .record(self.max, self.window, now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(offset: i64) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_800_000_000 + offset)
            .unwrap_or(OffsetDateTime::UNIX_EPOCH)
    }

    #[test]
    fn limits_within_a_window_and_resets_after() {
        let mut limiter = RateLimiter::per_minute(3);
        for _ in 0..3 {
            assert!(limiter.check("ip:1", at(0)).is_ok());
        }
        assert!(limiter.check("ip:1", at(0)).is_err());
        assert!(limiter.check("ip:2", at(0)).is_ok());
        assert!(limiter.check("ip:1", at(61)).is_ok());
    }

    #[test]
    fn a_full_limiter_forgets_old_windows_first() {
        let mut limiter = RateLimiter::per_minute(1).with_max_keys(2);
        assert!(limiter.check("a", at(0)).is_ok());
        assert!(limiter.check("b", at(120)).is_ok());
        assert!(limiter.check("c", at(120)).is_ok());
        assert!(limiter.check("b", at(120)).is_err(), "b is still counted");
    }

    #[test]
    fn failure_window_slides() {
        let mut log = FailureWindow::default();
        let window = Duration::minutes(15);
        for i in 0..3 {
            let now = at(i * 60);
            assert_eq!(log.blocked(3, window, now), None);
            log.record(3, window, now);
        }
        assert_eq!(log.blocked(3, window, at(5 * 60)), Some(10 * 60));
        assert_eq!(
            log.blocked(3, window, at(15 * 60)),
            None,
            "the first failure aged out"
        );
        log.record(3, window, at(15 * 60));
        assert_eq!(log.blocked(3, window, at(15 * 60)), Some(60));
    }

    #[test]
    fn failure_window_off_at_zero() {
        let mut log = FailureWindow::default();
        log.record(0, Duration::minutes(15), at(0));
        assert_eq!(log.blocked(0, Duration::minutes(15), at(0)), None);
        assert!(log.is_empty());
    }

    #[test]
    fn throttle_counts_per_account_key() {
        let mut throttle = WrongPasswordThrottle::new(&RateLimits::default());
        let alice = AccountKey::from_login("Alice@Example.com");
        let bob = AccountKey::from_login("bob@example.com");
        for minute in 0..10 {
            assert!(throttle.check(&alice, at(minute * 60)).is_ok());
            throttle.record(&alice, at(minute * 60));
        }
        let refused = throttle.check(&AccountKey::from_login(" alice@example.COM "), at(600));
        assert_eq!(
            refused,
            Err(Error::TooManyAttempts {
                retry_after_secs: 300
            })
        );
        assert!(throttle.check(&bob, at(600)).is_ok());
        assert!(throttle.check(&alice, at(15 * 60)).is_ok());
    }
}
