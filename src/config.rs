use time::Duration;
use url::Url;

use crate::error::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PasswordParams {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Default for PasswordParams {
    fn default() -> Self {
        Self {
            memory_kib: 64 * 1024,
            iterations: 3,
            parallelism: 2,
        }
    }
}

/// Every `threshold`-th consecutive failure locks the account, starting at `base` and doubling
/// up to `max`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockoutPolicy {
    pub threshold: u32,
    pub base: Duration,
    pub max: Duration,
}

impl Default for LockoutPolicy {
    fn default() -> Self {
        Self {
            threshold: 5,
            base: Duration::minutes(5),
            max: Duration::hours(1),
        }
    }
}

impl LockoutPolicy {
    pub fn lock_for(&self, failures: u32) -> Option<Duration> {
        if self.threshold == 0 || failures == 0 || !failures.is_multiple_of(self.threshold) {
            return None;
        }
        let mut lock = self.base;
        for _ in 1..failures / self.threshold {
            if lock >= self.max {
                break;
            }
            lock = lock.saturating_mul(2);
        }
        Some(lock.min(self.max))
    }
}

/// Fixed one-minute windows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimits {
    pub per_ip_per_minute: u32,
    pub per_account_per_minute: u32,
}

impl Default for RateLimits {
    fn default() -> Self {
        Self {
            per_ip_per_minute: 30,
            per_account_per_minute: 10,
        }
    }
}

#[derive(Clone)]
pub struct Config {
    /// The account created on first start; setup links only ever go to this address.
    pub owner_email: String,
    pub owner_name: String,
    /// The single origin the app is served from, e.g. `https://home.example.com`.
    pub origin: Url,
    pub rp_id: String,
    pub rp_name: String,
    /// Must start with `__Host-`.
    pub cookie_name: String,
    /// Front-end pages that receive `?token=` from the emailed links.
    pub setup_url: Url,
    pub sign_in_link_url: Url,
    pub invite_url: Url,
    pub session_ttl: Duration,
    pub pending_ttl: Duration,
    pub setup_ttl: Duration,
    pub link_ttl: Duration,
    pub invite_ttl: Duration,
    pub resend_cooldown: Duration,
    pub step_up_window: Duration,
    pub lockout: LockoutPolicy,
    pub rate_limits: RateLimits,
    pub password: PasswordParams,
    /// Keys the HMAC that pseudonymises IP addresses in sessions and the audit log.
    pub secret_key: [u8; 32],
    /// AES-256-GCM key for TOTP secrets and passkey data at rest; must differ from
    /// `secret_key`. Changing it makes stored factors unreadable.
    pub data_key: [u8; 32],
    /// Take the client IP from the last `X-Forwarded-For` entry instead of the socket.
    pub trust_forwarded_for: bool,
}

impl Config {
    pub fn new(
        owner_email: &str,
        origin: &str,
        secret_key: [u8; 32],
        data_key: [u8; 32],
    ) -> Result<Self, Error> {
        let origin = Url::parse(origin).map_err(|_| Error::Config("origin is not a URL"))?;
        let rp_id = origin
            .host_str()
            .ok_or(Error::Config("origin has no host"))?
            .to_owned();
        let owner_email = normalize_email(owner_email).ok_or(Error::Config("owner email"))?;
        let join = |path: &str| {
            origin
                .join(path)
                .map_err(|_| Error::Config("origin cannot be joined"))
        };
        Ok(Self {
            owner_name: owner_email.clone(),
            owner_email,
            rp_name: rp_id.clone(),
            rp_id,
            cookie_name: "__Host-latchkey".to_owned(),
            setup_url: join("/setup")?,
            sign_in_link_url: join("/sign-in/link")?,
            invite_url: join("/invite")?,
            origin,
            session_ttl: Duration::days(30),
            pending_ttl: Duration::minutes(10),
            setup_ttl: Duration::hours(1),
            link_ttl: Duration::minutes(15),
            invite_ttl: Duration::days(3),
            resend_cooldown: Duration::minutes(1),
            step_up_window: Duration::minutes(5),
            lockout: LockoutPolicy::default(),
            rate_limits: RateLimits::default(),
            password: PasswordParams::default(),
            secret_key,
            data_key,
            trust_forwarded_for: false,
        })
    }

    pub(crate) fn validate(&self) -> Result<(), Error> {
        if !self.cookie_name.starts_with("__Host-") {
            return Err(Error::Config("cookie name must start with __Host-"));
        }
        if self.origin.scheme() != "https" && self.origin.host_str() != Some("localhost") {
            return Err(Error::Config("origin must be https"));
        }
        if self.secret_key == [0u8; 32] {
            return Err(Error::Config("secret key is all zeroes"));
        }
        if self.data_key == [0u8; 32] {
            return Err(Error::Config("data key is all zeroes"));
        }
        if self.data_key == self.secret_key {
            return Err(Error::Config("data key must differ from the secret key"));
        }
        Ok(())
    }

    pub(crate) fn origin_string(&self) -> String {
        self.origin.origin().ascii_serialization()
    }
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("owner_email", &self.owner_email)
            .field("origin", &self.origin.as_str())
            .field("rp_id", &self.rp_id)
            .field("cookie_name", &self.cookie_name)
            .field("secret_key", &"<redacted>")
            .field("data_key", &"<redacted>")
            .finish_non_exhaustive()
    }
}

pub(crate) fn normalize_email(raw: &str) -> Option<String> {
    let email = raw.trim().to_lowercase();
    let (local, domain) = email.split_once('@')?;
    let valid = !local.is_empty()
        && !domain.is_empty()
        && !domain.contains('@')
        && email.len() <= 254
        && !email.chars().any(|c| c.is_whitespace() || c.is_control());
    valid.then_some(email)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn lockout_doubles_on_every_threshold_and_caps() {
        let policy = LockoutPolicy::default();
        assert_eq!(policy.lock_for(4), None);
        assert_eq!(policy.lock_for(5), Some(Duration::minutes(5)));
        assert_eq!(policy.lock_for(6), None);
        assert_eq!(policy.lock_for(10), Some(Duration::minutes(10)));
        assert_eq!(policy.lock_for(15), Some(Duration::minutes(20)));
        assert_eq!(policy.lock_for(20), Some(Duration::minutes(40)));
        assert_eq!(policy.lock_for(25), Some(Duration::hours(1)));
        assert_eq!(policy.lock_for(500), Some(Duration::hours(1)));
    }

    #[test]
    fn emails_are_normalised() {
        assert_eq!(
            normalize_email("  Owner@Example.COM "),
            Some("owner@example.com".into())
        );
        assert_eq!(normalize_email("no-at-sign"), None);
        assert_eq!(normalize_email("a@b@c"), None);
        assert_eq!(normalize_email("a b@c"), None);
    }

    #[test]
    fn config_rejects_bad_cookie_and_plain_http() {
        let mut config = Config::new(
            "o@example.com",
            "https://home.example.com",
            [7; 32],
            [8; 32],
        )
        .unwrap();
        assert!(config.validate().is_ok());
        config.cookie_name = "session".into();
        assert!(config.validate().is_err());
        let config =
            Config::new("o@example.com", "http://home.example.com", [7; 32], [8; 32]).unwrap();
        assert!(config.validate().is_err());
    }

    #[test]
    fn config_needs_a_separate_nonzero_data_key() {
        let new = |data_key| {
            Config::new(
                "o@example.com",
                "https://home.example.com",
                [7; 32],
                data_key,
            )
            .unwrap()
        };
        assert!(new([0; 32]).validate().is_err());
        assert!(new([7; 32]).validate().is_err());
        assert!(new([8; 32]).validate().is_ok());
    }

    #[test]
    fn debug_output_hides_the_keys() {
        let config = Config::new(
            "o@example.com",
            "https://home.example.com",
            [7; 32],
            [8; 32],
        )
        .unwrap();
        let debug = format!("{config:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("7, 7"));
        assert!(!debug.contains("8, 8"));
    }
}
