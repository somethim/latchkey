use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

use time::{Duration, OffsetDateTime};

const WINDOW_SECS: i64 = 60;
const MAX_KEYS: usize = 100_000;

#[derive(Debug, Default)]
pub(crate) struct RateLimiter {
    windows: Mutex<HashMap<String, (i64, u32)>>,
}

impl RateLimiter {
    /// Counts one hit and returns the seconds to wait when `key` is over `limit`.
    pub(crate) fn hit(&self, key: &str, limit: u32, now: OffsetDateTime) -> Option<u64> {
        let now = now.unix_timestamp();
        let window = now.div_euclid(WINDOW_SECS);
        let mut windows = self
            .windows
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if windows.len() >= MAX_KEYS {
            windows.retain(|_, (start, _)| *start == window);
        }
        let entry = windows.entry(key.to_owned()).or_insert((window, 0));
        if entry.0 != window {
            *entry = (window, 0);
        }
        entry.1 = entry.1.saturating_add(1);
        (entry.1 > limit).then(|| {
            let next = window.saturating_add(1).saturating_mul(WINDOW_SECS);
            u64::try_from(next.saturating_sub(now)).unwrap_or(1).max(1)
        })
    }
}

/// Remembers when each key failed, for limits such as 10 wrong passwords per 15 minutes.
#[derive(Debug, Default)]
pub(crate) struct FailureLog {
    failures: Mutex<HashMap<String, VecDeque<i64>>>,
}

impl FailureLog {
    /// Seconds to wait when `key` already has `max` failures within `window` of `now`.
    pub(crate) fn blocked(
        &self,
        key: &str,
        max: u32,
        window: Duration,
        now: OffsetDateTime,
    ) -> Option<u64> {
        if max == 0 {
            return None;
        }
        let now = now.unix_timestamp();
        let window = window.whole_seconds().max(1);
        let mut failures = self
            .failures
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let log = failures.get_mut(key)?;
        prune(log, now, window);
        if log.len() < usize::try_from(max).unwrap_or(usize::MAX) {
            return None;
        }
        let oldest = log.front().copied().unwrap_or(now);
        u64::try_from(oldest.saturating_add(window).saturating_sub(now))
            .ok()
            .map(|secs| secs.max(1))
    }

    pub(crate) fn record(&self, key: &str, max: u32, window: Duration, now: OffsetDateTime) {
        if max == 0 {
            return;
        }
        let now = now.unix_timestamp();
        let window = window.whole_seconds().max(1);
        let keep = usize::try_from(max).unwrap_or(usize::MAX);
        let mut failures = self
            .failures
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if failures.len() >= MAX_KEYS && !failures.contains_key(key) {
            failures.retain(|_, log| {
                prune(log, now, window);
                !log.is_empty()
            });
            if failures.len() >= MAX_KEYS
                && let Some(stalest) = failures
                    .iter()
                    .min_by_key(|(_, log)| log.back().copied().unwrap_or(i64::MIN))
                    .map(|(key, _)| key.clone())
            {
                failures.remove(&stalest);
            }
        }
        let log = failures.entry(key.to_owned()).or_default();
        prune(log, now, window);
        log.push_back(now);
        while log.len() > keep {
            log.pop_front();
        }
    }
}

fn prune(log: &mut VecDeque<i64>, now: i64, window: i64) {
    while log
        .front()
        .is_some_and(|at| at.saturating_add(window) <= now)
    {
        log.pop_front();
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn limits_within_a_window_and_resets_after() {
        let limiter = RateLimiter::default();
        let start = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
        for _ in 0..3 {
            assert_eq!(limiter.hit("ip:1", 3, start), None);
        }
        assert!(limiter.hit("ip:1", 3, start).is_some());
        assert_eq!(limiter.hit("ip:2", 3, start), None);
        let later = start + time::Duration::seconds(61);
        assert_eq!(limiter.hit("ip:1", 3, later), None);
    }

    #[test]
    fn failure_log_slides_over_the_window() {
        let log = FailureLog::default();
        let window = Duration::minutes(15);
        let start = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
        for i in 0..3 {
            let at = start + Duration::minutes(i);
            assert_eq!(log.blocked("a", 3, window, at), None);
            log.record("a", 3, window, at);
        }
        let at = start + Duration::minutes(5);
        assert_eq!(log.blocked("a", 3, window, at), Some(10 * 60));
        assert_eq!(log.blocked("b", 3, window, at), None);
        let at = start + Duration::minutes(15);
        assert_eq!(
            log.blocked("a", 3, window, at),
            None,
            "the first failure aged out"
        );
        log.record("a", 3, window, at);
        assert_eq!(log.blocked("a", 3, window, at), Some(60));
    }

    #[test]
    fn failure_log_off_at_zero() {
        let log = FailureLog::default();
        let now = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
        log.record("a", 0, Duration::minutes(15), now);
        assert_eq!(log.blocked("a", 0, Duration::minutes(15), now), None);
    }
}
