//! The policy settings the flows apply, built and validated once.
//!
//! ```
//! use latchkey::Config;
//! use time::Duration;
//!
//! let config = Config::builder("owner@example.com", "https://home.example.com")
//!     .session_ttl(Duration::days(14))
//!     .build()?;
//! assert_eq!(config.rp_id(), "home.example.com");
//! assert_eq!(config.origin_string(), "https://home.example.com");
//! assert_eq!(config.setup_url().as_str(), "https://home.example.com/setup");
//! # Ok::<(), latchkey::Error>(())
//! ```

use crate::error::ConfigReason;
use time::Duration;
use url::Url;

use crate::Error;
use crate::account::{Email, LockoutPolicy, PasswordOnly};
use crate::flow::step_up::StepUpFailures;
use crate::http::CookieName;
use crate::limits::RateLimits;
use crate::password::PasswordParams;

/// Validated settings: the origin and relying party, cookie names, mailed link targets,
/// lifetimes, the lockout and step-up failure policies and the rate-limit and password
/// parameters. Build it with
/// [`Config::builder`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    origin: Url,
    rp_id: String,
    rp_name: String,
    owner_email: Email,
    owner_name: String,
    cookie_name: CookieName,
    device_cookie_name: CookieName,
    ceremony_cookie_name: CookieName,
    setup_url: Url,
    sign_in_link_url: Url,
    invite_url: Url,
    sessions_url: Url,
    durations: Durations,
    lockout: LockoutPolicy,
    step_up_failures: StepUpFailures,
    password_only: PasswordOnly,
    rate_limits: RateLimits,
    password: PasswordParams,
    insecure_localhost_cookies: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Durations {
    device_ttl: Duration,
    session_ttl: Duration,
    pending_ttl: Duration,
    setup_ttl: Duration,
    link_ttl: Duration,
    invite_ttl: Duration,
    resend_cooldown: Duration,
    step_up_window: Duration,
}

impl Default for Durations {
    fn default() -> Self {
        Self {
            device_ttl: Duration::days(400),
            session_ttl: Duration::days(30),
            pending_ttl: Duration::minutes(10),
            setup_ttl: Duration::hours(1),
            link_ttl: Duration::minutes(15),
            invite_ttl: Duration::days(3),
            resend_cooldown: Duration::minutes(1),
            step_up_window: Duration::minutes(5),
        }
    }
}

/// Builds a [`Config`]; every setting has the default latchkey 0.2 used.
#[derive(Debug, Clone)]
#[must_use = "call build() to get a Config"]
pub struct ConfigBuilder {
    owner_email: String,
    origin: String,
    rp_id: Option<String>,
    rp_name: Option<String>,
    owner_name: Option<String>,
    cookie_name: String,
    device_cookie_name: String,
    ceremony_cookie_name: String,
    setup_path: String,
    sign_in_link_path: String,
    invite_path: String,
    sessions_path: String,
    durations: Durations,
    lockout: LockoutPolicy,
    step_up_failures: StepUpFailures,
    password_only: PasswordOnly,
    rate_limits: RateLimits,
    password: PasswordParams,
    insecure_localhost_cookies: bool,
}

macro_rules! durations {
    ($($(#[$doc:meta])* $name:ident),* $(,)?) => {
        impl ConfigBuilder {
            $(
                $(#[$doc])*
                pub fn $name(mut self, value: Duration) -> Self {
                    self.durations.$name = value;
                    self
                }
            )*
        }

        impl Config {
            $(
                $(#[$doc])*
                #[must_use]
                pub fn $name(&self) -> Duration {
                    self.durations.$name
                }
            )*
        }
    };
}

durations!(
    /// How long a device stays known after its last sign-in. Default 400 days.
    device_ttl,
    /// Lifetime of a signed-in session. Default 30 days.
    session_ttl,
    /// Lifetime of a session waiting for its second factor. Default 10 minutes.
    pending_ttl,
    /// Lifetime of a setup session. Default 1 hour.
    setup_ttl,
    /// Lifetime of a setup or sign-in link. Default 15 minutes.
    link_ttl,
    /// Lifetime of an invite link. Default 3 days.
    invite_ttl,
    /// Minimum time between two setup or sign-in links to one account. Default 1 minute.
    resend_cooldown,
    /// How long a sign-in or step-up counts as recent. Default 5 minutes.
    step_up_window,
);

impl ConfigBuilder {
    /// The relying party id for passkeys. Default: the origin's host.
    pub fn rp_id(mut self, rp_id: &str) -> Self {
        self.rp_id = Some(rp_id.to_owned());
        self
    }

    /// The name passkey prompts show. Default: the relying party id.
    pub fn rp_name(mut self, rp_name: &str) -> Self {
        self.rp_name = Some(rp_name.to_owned());
        self
    }

    /// The owner's display name. Default: the owner's address.
    pub fn owner_name(mut self, name: &str) -> Self {
        self.owner_name = Some(name.to_owned());
        self
    }

    /// The session cookie's name; must start with `__Host-`. Default `__Host-latchkey`.
    pub fn cookie_name(mut self, name: &str) -> Self {
        name.clone_into(&mut self.cookie_name);
        self
    }

    /// The device cookie's name; must start with `__Host-` and differ from the session
    /// cookie's. Default `__Host-latchkey_device`.
    pub fn device_cookie_name(mut self, name: &str) -> Self {
        name.clone_into(&mut self.device_cookie_name);
        self
    }

    /// The name of the cookie that binds a passkey sign-in to the browser that started it
    /// (the `passkey` module, feature `passkeys`); must start with
    /// `__Host-` and differ from the other two. Default `__Host-latchkey_ceremony`.
    pub fn ceremony_cookie_name(mut self, name: &str) -> Self {
        name.clone_into(&mut self.ceremony_cookie_name);
        self
    }

    /// The page that receives `?token=` from setup links, relative to the origin. Default
    /// `/setup`.
    pub fn setup_path(mut self, path: &str) -> Self {
        path.clone_into(&mut self.setup_path);
        self
    }

    /// The page for sign-in links. Default `/sign-in/link`.
    pub fn sign_in_link_path(mut self, path: &str) -> Self {
        path.clone_into(&mut self.sign_in_link_path);
        self
    }

    /// The page for invite links. Default `/invite`.
    pub fn invite_path(mut self, path: &str) -> Self {
        path.clone_into(&mut self.invite_path);
        self
    }

    /// The sessions page the new-device mail links to. Default `/settings/sessions`.
    pub fn sessions_path(mut self, path: &str) -> Self {
        path.clone_into(&mut self.sessions_path);
        self
    }

    /// The lockout policy. Default: 5 failures lock for 5 minutes, doubling up to an hour.
    pub fn lockout(mut self, lockout: LockoutPolicy) -> Self {
        self.lockout = lockout;
        self
    }

    /// Where wrong step-up guesses count. Default [`StepUpFailures::AccountLockout`], as in
    /// latchkey 0.2.
    pub fn step_up_failures(mut self, policy: StepUpFailures) -> Self {
        self.step_up_failures = policy;
        self
    }

    /// Whether accounts with a password and no second factor may sign in. Default
    /// [`PasswordOnly::Refused`], as in latchkey 0.2.
    pub fn password_only(mut self, policy: PasswordOnly) -> Self {
        self.password_only = policy;
        self
    }

    /// **Development only.** Cookies for a plain-HTTP origin on this machine: the cookie names
    /// lose their `__Host-` prefix (browsers refuse `__Host-` cookies without `Secure`) and
    /// [`SetCookie`](crate::http::SetCookie) leaves out `Secure`, so browsers that do not
    /// treat `http://localhost` as secure (Safari) keep the cookies.
    ///
    /// [`build`](Self::build) refuses this unless the origin is `http://localhost`,
    /// `http://127.0.0.1` or `http://[::1]` (any port), so a production config, which needs
    /// an `https` origin, cannot have it. Never derive the origin from a request.
    ///
    /// ```
    /// use latchkey::Config;
    ///
    /// let dev = Config::builder("owner@example.com", "http://localhost:3000")
    ///     .danger_insecure_localhost_cookies()
    ///     .build()?;
    /// assert_eq!(dev.cookie_name().as_str(), "latchkey");
    /// assert!(!dev.cookie_name().is_secure());
    ///
    /// let prod = Config::builder("owner@example.com", "https://home.example.com")
    ///     .danger_insecure_localhost_cookies()
    ///     .build();
    /// assert!(prod.is_err());
    /// # Ok::<(), latchkey::Error>(())
    /// ```
    pub fn danger_insecure_localhost_cookies(mut self) -> Self {
        self.insecure_localhost_cookies = true;
        self
    }

    /// The rate limits and wrong-password throttle.
    pub fn rate_limits(mut self, rate_limits: RateLimits) -> Self {
        self.rate_limits = rate_limits;
        self
    }

    /// Argon2id parameters. Default 64 MiB, t=3, p=2.
    pub fn password_params(mut self, params: PasswordParams) -> Self {
        self.password = params;
        self
    }

    /// Validates everything.
    ///
    /// # Errors
    ///
    /// [`Error::Config`] when the origin is not an `https` URL (or `http://` on `localhost`,
    /// `127.0.0.1` or `[::1]`), insecure localhost cookies are asked for any other origin, the
    /// owner address or a cookie name is invalid, two cookie names are equal, or a path does
    /// not join onto the origin, or a [`StepUpFailures::PerSession`] limit is 0.
    /// [`Error::InvalidRequest`] with `email` for a bad owner
    /// address.
    pub fn build(self) -> Result<Config, Error> {
        let origin =
            Url::parse(&self.origin).map_err(|_| Error::Config(ConfigReason::OriginNotUrl))?;
        let host = origin
            .host_str()
            .ok_or(Error::Config(ConfigReason::OriginHasNoHost))?
            .to_owned();
        let local = matches!(host.as_str(), "localhost" | "127.0.0.1" | "[::1]");
        let plain_local = origin.scheme() == "http" && local;
        if origin.scheme() != "https" && !plain_local {
            return Err(Error::Config(ConfigReason::OriginNotHttps));
        }
        if self.insecure_localhost_cookies && !plain_local {
            return Err(Error::Config(ConfigReason::InsecureCookiesNotLocalhost));
        }
        let owner_email =
            Email::parse(&self.owner_email).map_err(|_| Error::Config(ConfigReason::OwnerEmail))?;
        let cookie = |name: &str| {
            if self.insecure_localhost_cookies {
                CookieName::insecure_localhost(name)
            } else {
                CookieName::new(name)
            }
        };
        let cookie_name = cookie(&self.cookie_name)?;
        let device_cookie_name = cookie(&self.device_cookie_name)?;
        let ceremony_cookie_name = cookie(&self.ceremony_cookie_name)?;
        if cookie_name == device_cookie_name
            || cookie_name == ceremony_cookie_name
            || device_cookie_name == ceremony_cookie_name
        {
            return Err(Error::Config(ConfigReason::CookieNamesEqual));
        }
        let join = |path: &str| {
            origin
                .join(path)
                .map_err(|_| Error::Config(ConfigReason::PathDoesNotJoin))
        };
        if self.step_up_failures == (StepUpFailures::PerSession { limit: 0 }) {
            return Err(Error::Config(ConfigReason::StepUpLimitZero));
        }
        let rp_id = self.rp_id.unwrap_or(host);
        Ok(Config {
            setup_url: join(&self.setup_path)?,
            sign_in_link_url: join(&self.sign_in_link_path)?,
            invite_url: join(&self.invite_path)?,
            sessions_url: join(&self.sessions_path)?,
            rp_name: self.rp_name.unwrap_or_else(|| rp_id.clone()),
            rp_id,
            owner_name: self
                .owner_name
                .unwrap_or_else(|| owner_email.as_str().to_owned()),
            owner_email,
            cookie_name,
            device_cookie_name,
            ceremony_cookie_name,
            origin,
            durations: self.durations,
            lockout: self.lockout,
            step_up_failures: self.step_up_failures,
            password_only: self.password_only,
            rate_limits: self.rate_limits,
            password: self.password,
            insecure_localhost_cookies: self.insecure_localhost_cookies,
        })
    }
}

impl Config {
    /// Starts a builder for the owner's address and the single origin the app is served
    /// from, such as `https://home.example.com`.
    pub fn builder(owner_email: &str, origin: &str) -> ConfigBuilder {
        ConfigBuilder {
            owner_email: owner_email.to_owned(),
            origin: origin.to_owned(),
            rp_id: None,
            rp_name: None,
            owner_name: None,
            cookie_name: "__Host-latchkey".to_owned(),
            device_cookie_name: "__Host-latchkey_device".to_owned(),
            ceremony_cookie_name: "__Host-latchkey_ceremony".to_owned(),
            setup_path: "/setup".to_owned(),
            sign_in_link_path: "/sign-in/link".to_owned(),
            invite_path: "/invite".to_owned(),
            sessions_path: "/settings/sessions".to_owned(),
            durations: Durations::default(),
            lockout: LockoutPolicy::default(),
            step_up_failures: StepUpFailures::default(),
            password_only: PasswordOnly::default(),
            rate_limits: RateLimits::default(),
            password: PasswordParams::default(),
            insecure_localhost_cookies: false,
        }
    }

    /// The origin.
    #[must_use]
    pub fn origin(&self) -> &Url {
        &self.origin
    }

    /// The origin as browsers send it in `Origin`, e.g. `https://home.example.com`.
    #[must_use]
    pub fn origin_string(&self) -> String {
        self.origin.origin().ascii_serialization()
    }

    /// The passkey relying party id.
    #[must_use]
    pub fn rp_id(&self) -> &str {
        &self.rp_id
    }

    /// The passkey relying party name.
    #[must_use]
    pub fn rp_name(&self) -> &str {
        &self.rp_name
    }

    /// The owner's address: setup links only ever go here.
    #[must_use]
    pub fn owner_email(&self) -> &Email {
        &self.owner_email
    }

    /// The owner's display name.
    #[must_use]
    pub fn owner_name(&self) -> &str {
        &self.owner_name
    }

    /// The session cookie's name.
    #[must_use]
    pub fn cookie_name(&self) -> &CookieName {
        &self.cookie_name
    }

    /// The device cookie's name.
    #[must_use]
    pub fn device_cookie_name(&self) -> &CookieName {
        &self.device_cookie_name
    }

    /// Whether it was built with
    /// [`danger_insecure_localhost_cookies`](ConfigBuilder::danger_insecure_localhost_cookies).
    #[must_use]
    pub fn insecure_localhost_cookies(&self) -> bool {
        self.insecure_localhost_cookies
    }

    /// The passkey sign-in binding cookie's name.
    #[must_use]
    pub fn ceremony_cookie_name(&self) -> &CookieName {
        &self.ceremony_cookie_name
    }

    /// Where setup links point.
    #[must_use]
    pub fn setup_url(&self) -> &Url {
        &self.setup_url
    }

    /// Where sign-in links point.
    #[must_use]
    pub fn sign_in_link_url(&self) -> &Url {
        &self.sign_in_link_url
    }

    /// Where invite links point.
    #[must_use]
    pub fn invite_url(&self) -> &Url {
        &self.invite_url
    }

    /// The sessions page the new-device mail links to.
    #[must_use]
    pub fn sessions_url(&self) -> &Url {
        &self.sessions_url
    }

    /// The lockout policy.
    #[must_use]
    pub fn lockout(&self) -> &LockoutPolicy {
        &self.lockout
    }

    /// Where wrong step-up guesses count.
    #[must_use]
    pub fn step_up_failures(&self) -> StepUpFailures {
        self.step_up_failures
    }

    /// Whether accounts with a password and no second factor may sign in.
    #[must_use]
    pub fn password_only(&self) -> PasswordOnly {
        self.password_only
    }

    /// The rate limits.
    #[must_use]
    pub fn rate_limits(&self) -> &RateLimits {
        &self.rate_limits
    }

    /// The Argon2id parameters.
    #[must_use]
    pub fn password_params(&self) -> PasswordParams {
        self.password
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_latchkey_0_2() -> Result<(), Error> {
        let config = Config::builder("o@example.com", "https://home.example.com").build()?;
        assert_eq!(config.cookie_name().as_str(), "__Host-latchkey");
        assert_eq!(
            config.device_cookie_name().as_str(),
            "__Host-latchkey_device"
        );
        assert_eq!(
            config.ceremony_cookie_name().as_str(),
            "__Host-latchkey_ceremony"
        );
        assert_eq!(config.session_ttl(), Duration::days(30));
        assert_eq!(config.step_up_window(), Duration::minutes(5));
        assert_eq!(config.link_ttl(), Duration::minutes(15));
        assert_eq!(
            config.invite_url().as_str(),
            "https://home.example.com/invite"
        );
        assert_eq!(config.owner_name(), "o@example.com");
        assert_eq!(config.rp_name(), "home.example.com");
        assert_eq!(config.step_up_failures(), StepUpFailures::AccountLockout);
        assert_eq!(config.password_only(), PasswordOnly::Refused);
        Ok(())
    }

    #[test]
    fn rejects_bad_cookie_names_and_plain_http() {
        let builder = || Config::builder("o@example.com", "https://home.example.com");
        assert!(builder().cookie_name("session").build().is_err());
        assert!(
            builder()
                .device_cookie_name("__Host-latchkey")
                .build()
                .is_err()
        );
        assert!(
            builder()
                .ceremony_cookie_name("__Host-latchkey_device")
                .build()
                .is_err()
        );
        assert!(builder().ceremony_cookie_name("ceremony").build().is_err());
        assert!(
            Config::builder("o@example.com", "http://home.example.com")
                .build()
                .is_err()
        );
        assert!(
            Config::builder("o@example.com", "http://localhost:3000")
                .build()
                .is_ok()
        );
        assert!(
            Config::builder("not an email", "https://h.example")
                .build()
                .is_err()
        );
        assert!(
            Config::builder("o@example.com", "not a url")
                .build()
                .is_err()
        );
        assert_eq!(
            builder()
                .step_up_failures(StepUpFailures::PerSession { limit: 0 })
                .build()
                .err(),
            Some(Error::Config(ConfigReason::StepUpLimitZero))
        );
        assert!(
            builder()
                .step_up_failures(StepUpFailures::PerSession { limit: 5 })
                .build()
                .is_ok()
        );
    }
}

#[cfg(test)]
mod insecure_localhost_tests {
    use super::*;

    fn dev(origin: &str) -> Result<Config, Error> {
        Config::builder("o@example.com", origin)
            .danger_insecure_localhost_cookies()
            .build()
    }

    #[test]
    fn insecure_cookies_only_for_plain_http_on_this_machine() -> Result<(), Error> {
        for origin in [
            "http://localhost",
            "http://localhost:3000",
            "http://127.0.0.1:8080",
            "http://[::1]:8080",
        ] {
            let config = dev(origin)?;
            assert!(config.insecure_localhost_cookies(), "{origin}");
            assert_eq!(config.cookie_name().as_str(), "latchkey");
            assert_eq!(config.device_cookie_name().as_str(), "latchkey_device");
            assert_eq!(config.ceremony_cookie_name().as_str(), "latchkey_ceremony");
            assert!(!config.cookie_name().is_secure());
        }
        let refused = Some(Error::Config(ConfigReason::InsecureCookiesNotLocalhost));
        for origin in [
            "https://home.example.com",
            "https://localhost:3000",
            "https://127.0.0.1",
        ] {
            assert_eq!(dev(origin).err(), refused, "{origin}");
        }
        for origin in [
            "http://home.example.com",
            "http://localhost.example.com",
            "http://127.0.0.2",
            "http://10.0.0.1",
        ] {
            assert_eq!(
                dev(origin).err(),
                Some(Error::Config(ConfigReason::OriginNotHttps)),
                "{origin}"
            );
        }
        Ok(())
    }

    #[test]
    fn by_default_cookies_are_host_only_and_secure_even_on_localhost() -> Result<(), Error> {
        let config = Config::builder("o@example.com", "http://127.0.0.1:3000").build()?;
        assert!(!config.insecure_localhost_cookies());
        assert_eq!(config.cookie_name().as_str(), "__Host-latchkey");
        assert!(config.cookie_name().is_secure());
        Ok(())
    }

    #[test]
    fn insecure_names_still_differ_and_stay_valid() {
        let builder = || {
            Config::builder("o@example.com", "http://localhost:3000")
                .danger_insecure_localhost_cookies()
        };
        assert!(builder().device_cookie_name("latchkey").build().is_err());
        assert!(builder().cookie_name("__Host-").build().is_err());
        assert_eq!(
            builder()
                .cookie_name("__Host-app")
                .build()
                .map(|config| config.cookie_name().as_str().to_owned()),
            Ok("app".to_owned())
        );
    }
}
