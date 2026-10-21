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
//! assert_eq!(config.setup_url(), "https://home.example.com/setup");
//! # Ok::<(), latchkey::Error>(())
//! ```

use crate::error::ConfigReason;
use time::Duration;
use url::Url;

use crate::Error;
use crate::account::{Email, LockoutPolicy, PasswordOnly};
use crate::flow::email_link::{DEFAULT_CODE_ATTEMPTS, DEFAULT_CODE_DIGITS};
use crate::flow::invite::DEFAULT_MAX_NAME_LEN;
use crate::flow::step_up::StepUpFailures;
use crate::http::CookieName;
use crate::limits::RateLimits;
use crate::password::{DEFAULT_MAX_LEN, DEFAULT_MIN_LEN, PasswordLength, PasswordParams};
use crate::recovery::DEFAULT_COUNT;
use crate::totp::{DEFAULT_DIGITS, DEFAULT_SKEW, DEFAULT_STEP_SECS, TotpParams};

/// The default [`Config::passkey_ceremony_ttl`], also what
/// `passkey::RelyingParty::from_parts` uses.
pub(crate) const DEFAULT_PASSKEY_CEREMONY_TTL: Duration = Duration::minutes(5);

/// The digits an email sign-in code may have.
const EMAIL_CODE_DIGITS: std::ops::RangeInclusive<u8> = 6..=10;
/// The guesses an email sign-in code may allow.
const EMAIL_CODE_ATTEMPTS: std::ops::RangeInclusive<u32> = 1..=20;
/// How many recovery codes a set may have.
const RECOVERY_CODE_COUNT: std::ops::RangeInclusive<usize> = 4..=32;
/// The bounds of the display-name limit.
const DISPLAY_NAME_MAX_LEN: std::ops::RangeInclusive<usize> = 1..=1000;

/// Validated settings: the origin and relying party, cookie names, mailed link targets,
/// lifetimes, the lockout and step-up failure policies, the rate-limit and password
/// parameters, and the sizes of codes and names (email codes, TOTP, recovery codes,
/// password and display-name lengths). Build it with [`Config::builder`].
///
/// Every number latchkey applies is a setting here with a default; the constants left in
/// the modules are formats and security floors (see the README's "Configuration").
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
    email_cookie_name: CookieName,
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
    password_length: PasswordLength,
    totp: TotpParams,
    email_code_digits: u8,
    email_code_attempts: u32,
    recovery_code_count: usize,
    display_name_max_len: usize,
    insecure_localhost_cookies: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Durations {
    device_ttl: Duration,
    session_ttl: Duration,
    pending_ttl: Duration,
    setup_ttl: Duration,
    link_ttl: Duration,
    setup_link_ttl: Duration,
    invite_ttl: Duration,
    resend_cooldown: Duration,
    step_up_window: Duration,
    passkey_ceremony_ttl: Duration,
}

impl Default for Durations {
    fn default() -> Self {
        Self {
            device_ttl: Duration::days(400),
            session_ttl: Duration::days(30),
            pending_ttl: Duration::minutes(10),
            setup_ttl: Duration::hours(1),
            link_ttl: Duration::minutes(5),
            setup_link_ttl: Duration::hours(1),
            invite_ttl: Duration::hours(24),
            resend_cooldown: Duration::minutes(1),
            step_up_window: Duration::minutes(5),
            passkey_ceremony_ttl: DEFAULT_PASSKEY_CEREMONY_TTL,
        }
    }
}

/// Builds a [`Config`]; every setting has a default (latchkey 0.2's, except the shorter link
/// and invite lifetimes), and [`build`](Self::build) refuses values outside a setting's
/// bounds.
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
    email_cookie_name: String,
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
    password_min_len: usize,
    password_max_len: usize,
    totp_digits: u8,
    totp_step: u64,
    totp_skew: u8,
    email_code_digits: u8,
    email_code_attempts: u32,
    recovery_code_count: usize,
    display_name_max_len: usize,
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
    /// Lifetime of an email sign-in link and the code mailed with it. Default 5 minutes (15
    /// before 0.4). Keep it short: a 6-digit code is safe only because it lives minutes
    /// (see [`flow::email_link`](crate::flow::email_link)). The mail states the expiry time
    /// this gives.
    link_ttl,
    /// Lifetime of the owner's first-open setup link. Default 1 hour (before 0.4 it shared
    /// `link_ttl`, 15 minutes): a fresh server's owner may take a while to get to it.
    setup_link_ttl,
    /// Lifetime of an invite link, and of the setup link a sign-in reset mails. Default 24
    /// hours (3 days before 0.4).
    invite_ttl,
    /// Minimum time between two setup or sign-in links to one account. Default 1 minute.
    resend_cooldown,
    /// How long a sign-in or step-up counts as recent. Default 5 minutes.
    step_up_window,
    /// Lifetime of a passkey ceremony (feature `passkeys`), and of the cookie that binds a
    /// passkey sign-in to its browser: `passkey::RelyingParty::new` takes it from here.
    /// Default 5 minutes (before 0.4 the constant `passkey::CEREMONY_TTL`).
    passkey_ceremony_ttl,
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

    /// The name of the cookie that binds an email sign-in code to the device that asked for
    /// it ([`flow::email_link`](crate::flow::email_link)); must start with `__Host-` and differ
    /// from the other cookies. Default `__Host-latchkey_email`.
    pub fn email_cookie_name(mut self, name: &str) -> Self {
        name.clone_into(&mut self.email_cookie_name);
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

    /// The shortest new password, in characters. Default 12; allowed 8 to 128, and at most
    /// [`password_max_len`](Self::password_max_len). Applies to
    /// [`check_policy`](crate::password::check_policy) and
    /// [`hash_new_password`](crate::password::PasswordHasher::hash_new_password) through
    /// [`Config::password_length`]; existing passwords keep working whatever it is.
    pub fn password_min_len(mut self, chars: usize) -> Self {
        self.password_min_len = chars;
        self
    }

    /// The longest new password, in characters. Default 1024; allowed 64 to 1024 (verifying
    /// never hashes more than 4096 bytes, whatever this is).
    pub fn password_max_len(mut self, chars: usize) -> Self {
        self.password_max_len = chars;
        self
    }

    /// Digits in a TOTP code. Default 6; allowed 6 or 8.
    ///
    /// **Changing it breaks existing authenticator setups**: an app enrolled under one value
    /// shows codes of that length, and latchkey stores nothing per enrolment to remember it.
    /// Enrolments keep working only while the setting stays the same; after a change, every
    /// account must enrol TOTP again. The `otpauth://` URL (and QR code) carries the digits
    /// whenever they are not 6, so new enrolments pick them up.
    pub fn totp_digits(mut self, digits: u8) -> Self {
        self.totp_digits = digits;
        self
    }

    /// Seconds per TOTP step. Default 30; allowed 15 to 120.
    ///
    /// **Changing it breaks existing authenticator setups** (as for
    /// [`totp_digits`](Self::totp_digits)), and also the stored last-used steps, which count
    /// steps of the old length: after a change, every account must enrol TOTP again and its
    /// stored step be cleared. The `otpauth://` URL carries the period whenever it is not 30.
    pub fn totp_step(mut self, seconds: u64) -> Self {
        self.totp_step = seconds;
        self
    }

    /// TOTP steps accepted on either side of the current one, for clock drift. Default 1;
    /// allowed 0 to 3. Safe to change at any time: authenticators do not know it.
    pub fn totp_skew(mut self, steps: u8) -> Self {
        self.totp_skew = steps;
        self
    }

    /// Digits in an email sign-in code. Default 6; allowed 6 to 10. Changing it affects only
    /// codes mailed afterwards (a pending code of the old length simply stops matching).
    pub fn email_code_digits(mut self, digits: u8) -> Self {
        self.email_code_digits = digits;
        self
    }

    /// Guesses one email sign-in code allows; the guess that reaches it, if wrong, ends the
    /// request and its link. Default 5; allowed 1 to 20.
    pub fn email_code_attempts(mut self, attempts: u32) -> Self {
        self.email_code_attempts = attempts;
        self
    }

    /// Recovery codes per set (at setup and when regenerated). Default 10; allowed 4 to 32.
    /// Sets issued earlier keep their size until regenerated.
    pub fn recovery_code_count(mut self, count: usize) -> Self {
        self.recovery_code_count = count;
        self
    }

    /// The longest display name an invite may carry, in characters. Default 100; allowed 1
    /// to 1000.
    pub fn display_name_max_len(mut self, chars: usize) -> Self {
        self.display_name_max_len = chars;
        self
    }

    /// Validates everything.
    ///
    /// # Errors
    ///
    /// [`Error::Config`] when the origin is not an `https` URL (or `http://` on `localhost`,
    /// `127.0.0.1` or `[::1]`), insecure localhost cookies are asked for any other origin, the
    /// owner address or a cookie name is invalid, two cookie names are equal, or a path does
    /// not join onto the origin, a [`StepUpFailures::PerSession`] limit is 0, or a number is
    /// outside its setting's bounds ([`ConfigReason::PasswordLength`],
    /// [`TotpDigits`](ConfigReason::TotpDigits), [`TotpStep`](ConfigReason::TotpStep),
    /// [`TotpSkew`](ConfigReason::TotpSkew),
    /// [`EmailCodeDigits`](ConfigReason::EmailCodeDigits),
    /// [`EmailCodeAttempts`](ConfigReason::EmailCodeAttempts),
    /// [`RecoveryCodeCount`](ConfigReason::RecoveryCodeCount),
    /// [`DisplayNameLength`](ConfigReason::DisplayNameLength)).
    ///
    /// ```
    /// use latchkey::Config;
    /// use latchkey::error::ConfigReason;
    ///
    /// let builder = || Config::builder("owner@example.com", "https://home.example.com");
    /// let config = builder().email_code_digits(8).totp_digits(8).totp_step(60).build()?;
    /// assert_eq!(config.email_code_digits(), 8);
    /// assert_eq!(config.totp_params().step_secs(), 60);
    /// assert_eq!(
    ///     builder().email_code_digits(4).build().err(),
    ///     Some(latchkey::Error::Config(ConfigReason::EmailCodeDigits))
    /// );
    /// # Ok::<(), latchkey::Error>(())
    /// ```
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
        let email_cookie_name = cookie(&self.email_cookie_name)?;
        let names = [
            &cookie_name,
            &device_cookie_name,
            &ceremony_cookie_name,
            &email_cookie_name,
        ];
        let distinct = names
            .iter()
            .enumerate()
            .all(|(i, a)| names.iter().skip(i + 1).all(|b| a != b));
        if !distinct {
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
        let (password_length, totp) = self.check_numbers()?;
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
            email_cookie_name,
            origin,
            durations: self.durations,
            lockout: self.lockout,
            step_up_failures: self.step_up_failures,
            password_only: self.password_only,
            rate_limits: self.rate_limits,
            password: self.password,
            password_length,
            totp,
            email_code_digits: self.email_code_digits,
            email_code_attempts: self.email_code_attempts,
            recovery_code_count: self.recovery_code_count,
            display_name_max_len: self.display_name_max_len,
            insecure_localhost_cookies: self.insecure_localhost_cookies,
        })
    }
}

impl ConfigBuilder {
    /// Checks the numeric settings against their bounds.
    fn check_numbers(&self) -> Result<(PasswordLength, TotpParams), Error> {
        let password_length = PasswordLength::new(self.password_min_len, self.password_max_len)?;
        let totp = TotpParams::new(self.totp_digits, self.totp_step, self.totp_skew)?;
        let checks = [
            (
                EMAIL_CODE_DIGITS.contains(&self.email_code_digits),
                ConfigReason::EmailCodeDigits,
            ),
            (
                EMAIL_CODE_ATTEMPTS.contains(&self.email_code_attempts),
                ConfigReason::EmailCodeAttempts,
            ),
            (
                RECOVERY_CODE_COUNT.contains(&self.recovery_code_count),
                ConfigReason::RecoveryCodeCount,
            ),
            (
                DISPLAY_NAME_MAX_LEN.contains(&self.display_name_max_len),
                ConfigReason::DisplayNameLength,
            ),
        ];
        match checks.into_iter().find(|(ok, _)| !ok) {
            Some((_, reason)) => Err(Error::Config(reason)),
            None => Ok((password_length, totp)),
        }
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
            email_cookie_name: "__Host-latchkey_email".to_owned(),
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
            password_min_len: DEFAULT_MIN_LEN,
            password_max_len: DEFAULT_MAX_LEN,
            totp_digits: DEFAULT_DIGITS,
            totp_step: DEFAULT_STEP_SECS,
            totp_skew: DEFAULT_SKEW,
            email_code_digits: DEFAULT_CODE_DIGITS,
            email_code_attempts: DEFAULT_CODE_ATTEMPTS,
            recovery_code_count: DEFAULT_COUNT,
            display_name_max_len: DEFAULT_MAX_NAME_LEN,
            insecure_localhost_cookies: false,
        }
    }

    /// The origin.
    #[must_use]
    pub fn origin(&self) -> &str {
        self.origin.as_str()
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

    /// The email sign-in binding cookie's name.
    #[must_use]
    pub fn email_cookie_name(&self) -> &CookieName {
        &self.email_cookie_name
    }

    /// Where setup links point.
    #[must_use]
    pub fn setup_url(&self) -> &str {
        self.setup_url.as_str()
    }

    pub(crate) fn setup_target(&self) -> &Url {
        &self.setup_url
    }

    /// Where sign-in links point.
    #[must_use]
    pub fn sign_in_link_url(&self) -> &str {
        self.sign_in_link_url.as_str()
    }

    pub(crate) fn sign_in_link_target(&self) -> &Url {
        &self.sign_in_link_url
    }

    /// Where invite links point.
    #[must_use]
    pub fn invite_url(&self) -> &str {
        self.invite_url.as_str()
    }

    pub(crate) fn invite_target(&self) -> &Url {
        &self.invite_url
    }

    /// The sessions page the new-device mail links to.
    #[must_use]
    pub fn sessions_url(&self) -> &str {
        self.sessions_url.as_str()
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

    /// The length policy for new passwords, for
    /// [`check_policy`](crate::password::check_policy) and
    /// [`hash_new_password`](crate::password::PasswordHasher::hash_new_password).
    #[must_use]
    pub fn password_length(&self) -> PasswordLength {
        self.password_length
    }

    /// The TOTP digits, step and skew, for the [`totp`](crate::totp) functions.
    #[must_use]
    pub fn totp_params(&self) -> TotpParams {
        self.totp
    }

    /// Digits in an email sign-in code.
    #[must_use]
    pub fn email_code_digits(&self) -> u8 {
        self.email_code_digits
    }

    /// Guesses one email sign-in code allows.
    #[must_use]
    pub fn email_code_attempts(&self) -> u32 {
        self.email_code_attempts
    }

    /// Recovery codes per set.
    #[must_use]
    pub fn recovery_code_count(&self) -> usize {
        self.recovery_code_count
    }

    /// The longest display name an invite may carry, in characters.
    #[must_use]
    pub fn display_name_max_len(&self) -> usize {
        self.display_name_max_len
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults() -> Result<(), Error> {
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
        assert_eq!(config.email_cookie_name().as_str(), "__Host-latchkey_email");
        assert_eq!(config.link_ttl(), Duration::minutes(5));
        assert_eq!(config.invite_ttl(), Duration::hours(24));
        assert_eq!(config.setup_link_ttl(), Duration::hours(1));
        assert_eq!(config.invite_url(), "https://home.example.com/invite");
        assert_eq!(config.owner_name(), "o@example.com");
        assert_eq!(config.rp_name(), "home.example.com");
        assert_eq!(config.step_up_failures(), StepUpFailures::AccountLockout);
        assert_eq!(config.password_only(), PasswordOnly::Refused);
        assert_eq!(config.passkey_ceremony_ttl(), Duration::minutes(5));
        assert_eq!(config.email_code_digits(), 6);
        assert_eq!(config.email_code_attempts(), 5);
        assert_eq!(config.recovery_code_count(), 10);
        assert_eq!(config.display_name_max_len(), 100);
        assert_eq!(config.totp_params(), TotpParams::default());
        assert_eq!(
            (
                config.totp_params().digits(),
                config.totp_params().step_secs(),
                config.totp_params().skew()
            ),
            (6, 30, 1)
        );
        assert_eq!(config.password_length(), PasswordLength::default());
        assert_eq!(
            (
                config.password_length().min(),
                config.password_length().max()
            ),
            (12, 1024)
        );
        Ok(())
    }

    #[test]
    fn non_default_numbers_are_kept() -> Result<(), Error> {
        let config = Config::builder("o@example.com", "https://home.example.com")
            .email_code_digits(8)
            .email_code_attempts(3)
            .recovery_code_count(16)
            .display_name_max_len(40)
            .totp_digits(8)
            .totp_step(60)
            .totp_skew(0)
            .password_min_len(16)
            .password_max_len(128)
            .passkey_ceremony_ttl(Duration::minutes(2))
            .build()?;
        assert_eq!(config.email_code_digits(), 8);
        assert_eq!(config.email_code_attempts(), 3);
        assert_eq!(config.recovery_code_count(), 16);
        assert_eq!(config.display_name_max_len(), 40);
        assert_eq!(config.totp_params(), TotpParams::new(8, 60, 0)?);
        assert_eq!(config.password_length(), PasswordLength::new(16, 128)?);
        assert_eq!(config.passkey_ceremony_ttl(), Duration::minutes(2));
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
            builder()
                .email_cookie_name("__Host-latchkey_ceremony")
                .build()
                .is_err()
        );
        assert!(
            builder()
                .email_cookie_name("__Host-latchkey")
                .build()
                .is_err()
        );
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
            assert_eq!(config.email_cookie_name().as_str(), "latchkey_email");
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
