use std::collections::HashMap;
use std::sync::Mutex;

use time::OffsetDateTime;

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
}
