//! What the flows need to know about an account, and the lockout rule.
//!
//! The app stores accounts however it likes and builds an [`Account`] snapshot from its row
//! before each flow step.
//!
//! Failures are counted with an atomic increment in the app's storage
//! ([`Effect::RecordFailure`](crate::flow::Effect::RecordFailure)); the lock follows from the
//! count *after* the increment:
//!
//! ```
//! use latchkey::{Lockout, LockoutPolicy};
//! use time::OffsetDateTime;
//!
//! let policy = LockoutPolicy::default();
//! let now = OffsetDateTime::UNIX_EPOCH;
//! // UPDATE users SET failures = failures + 1 WHERE id = ? RETURNING failures  -> 5
//! let locked_until = policy.locked_until(5, now);
//! assert_eq!(locked_until, Some(now + time::Duration::minutes(5)));
//! let lockout = Lockout { failures: 5, locked_until };
//! assert!(lockout.check(now).is_err());
//! ```

use crate::error::{ConflictReason, InvalidRequestReason};
use time::{Duration, OffsetDateTime};

use crate::Error;
use crate::ids::UserId;

/// A normalised email address: trimmed, lowercase, one `@` with text on both sides, at most
/// 254 bytes, no whitespace or control characters.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "String", into = "String"))]
pub struct Email(String);

impl Email {
    /// Normalises and checks `raw`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidRequest`] with `email`.
    ///
    /// ```
    /// use latchkey::Email;
    /// assert_eq!(Email::parse("  Owner@Example.COM ")?.as_str(), "owner@example.com");
    /// assert!(Email::parse("a@b@c").is_err());
    /// # Ok::<(), latchkey::Error>(())
    /// ```
    pub fn parse(raw: &str) -> Result<Self, Error> {
        let email = raw.trim().to_lowercase();
        let valid = email.split_once('@').is_some_and(|(local, domain)| {
            !local.is_empty() && !domain.is_empty() && !domain.contains('@')
        }) && email.len() <= 254
            && !email.chars().any(|c| c.is_whitespace() || c.is_control());
        if valid {
            Ok(Self(email))
        } else {
            Err(Error::InvalidRequest(InvalidRequestReason::Email))
        }
    }

    /// The address.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Email {
    type Error = Error;

    fn try_from(raw: String) -> Result<Self, Error> {
        Self::parse(&raw)
    }
}

impl From<Email> for String {
    fn from(email: Email) -> String {
        email.0
    }
}

impl std::fmt::Display for Email {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The key the per-account limits and the wrong-password throttle count under: the
/// normalised address, or for something that is not an address, its trimmed lowercase form.
/// Unknown addresses get a key like known ones, so the limits do not reveal which exist.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct AccountKey(String);

impl AccountKey {
    /// The key for what was typed into the sign-in form.
    #[must_use]
    pub fn from_login(raw: &str) -> Self {
        Self(Email::parse(raw).map_or_else(|_| raw.trim().to_lowercase(), String::from))
    }

    /// The key text, for a [`RateLimiter`](crate::limits::RateLimiter).
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&Email> for AccountKey {
    fn from(email: &Email) -> Self {
        Self(email.0.clone())
    }
}

/// An account's role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum Role {
    /// The single account created from the configured address; may invite members.
    Owner,
    /// Invited by the owner.
    Member,
}

impl Role {
    /// `owner` or `member`, the values latchkey 0.2 stored.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Role::Owner => "owner",
            Role::Member => "member",
        }
    }
}

impl std::str::FromStr for Role {
    type Err = Error;

    fn from_str(raw: &str) -> Result<Self, Error> {
        match raw {
            "owner" => Ok(Role::Owner),
            "member" => Ok(Role::Member),
            _ => Err(Error::InvalidRequest(InvalidRequestReason::Role)),
        }
    }
}

/// Which factors an account has enrolled.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Factors {
    /// A password is set.
    pub password: bool,
    /// A confirmed TOTP secret is enrolled.
    pub totp: bool,
    /// Number of passkeys.
    pub passkeys: usize,
}

impl Factors {
    /// A password and at least one of TOTP or a passkey: what setup requires before it
    /// completes and what [`issue_session`](crate::flow::issue_session) requires, under the
    /// default [`PasswordOnly::Refused`].
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.password && self.has_second_factor()
    }

    /// TOTP or at least one passkey is enrolled.
    #[must_use]
    pub const fn has_second_factor(&self) -> bool {
        self.totp || self.passkeys > 0
    }

    /// Whether these factors are enough to finish setup, sign in and be issued a session
    /// under `policy`: [`is_complete`](Self::is_complete), or with
    /// [`PasswordOnly::AllowedUntilEnrolled`] a password alone while no second factor is
    /// enrolled.
    ///
    /// ```
    /// use latchkey::{Factors, PasswordOnly};
    ///
    /// let password_only = Factors { password: true, totp: false, passkeys: 0 };
    /// assert!(!password_only.are_sufficient(PasswordOnly::Refused));
    /// assert!(password_only.are_sufficient(PasswordOnly::AllowedUntilEnrolled));
    /// assert!(!Factors::default().are_sufficient(PasswordOnly::AllowedUntilEnrolled));
    /// ```
    #[must_use]
    pub const fn are_sufficient(&self, policy: PasswordOnly) -> bool {
        match policy {
            PasswordOnly::Refused => self.is_complete(),
            PasswordOnly::AllowedUntilEnrolled => self.password,
        }
    }

    /// Whether a password alone completes a sign-in or step-up under `policy`: a password
    /// and no second factor, with [`PasswordOnly::AllowedUntilEnrolled`]. Once a second
    /// factor is enrolled it is always required.
    #[must_use]
    pub const fn password_suffices(&self, policy: PasswordOnly) -> bool {
        matches!(policy, PasswordOnly::AllowedUntilEnrolled)
            && self.password
            && !self.has_second_factor()
    }

    /// Refuses to remove TOTP when it is not enrolled or is the only second factor.
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`], or [`Error::Conflict`] with `last_factor`.
    pub const fn may_remove_totp(&self) -> Result<(), Error> {
        if !self.totp {
            return Err(Error::NotFound);
        }
        if self.passkeys == 0 {
            return Err(Error::Conflict(ConflictReason::LastFactor));
        }
        Ok(())
    }

    /// Refuses to remove the last passkey when there is no TOTP.
    ///
    /// # Errors
    ///
    /// [`Error::Conflict`] with `last_factor`.
    pub const fn may_remove_passkey(&self) -> Result<(), Error> {
        if !self.totp && self.passkeys <= 1 {
            return Err(Error::Conflict(ConflictReason::LastFactor));
        }
        Ok(())
    }
}

/// Whether an account with a password and no second factor may sign in; set with
/// [`ConfigBuilder::password_only`](crate::ConfigBuilder::password_only).
///
/// latchkey asks for a second factor after every password. That leaves accounts imported
/// from another system with only a password, or apps that let users enrol TOTP or a passkey
/// later, unable to sign in. [`AllowedUntilEnrolled`](PasswordOnly::AllowedUntilEnrolled)
/// lets such an account finish sign-in (method
/// [`SignInMethod::PasswordOnly`](crate::session::SignInMethod::PasswordOnly)), step-up,
/// setup and [`issue_session`](crate::flow::issue_session) with its password alone, until it
/// enrols a second factor; from then on the second factor is required as usual.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum PasswordOnly {
    /// Every account needs a password and a second factor. latchkey 0.2's behaviour.
    #[default]
    Refused,
    /// An account with a password and no second factor signs in with the password alone.
    AllowedUntilEnrolled,
}

/// Every `threshold`-th consecutive failure locks the account, starting at `base` and
/// doubling up to `max`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct LockoutPolicy {
    /// Failures per lock; 0 turns the lockout off. Default 5.
    pub threshold: u32,
    /// The first lock. Default 5 minutes.
    pub base: Duration,
    /// The longest lock. Default 1 hour.
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
    /// How long `failures` consecutive failures lock the account for, if at all.
    ///
    /// ```
    /// use latchkey::LockoutPolicy;
    /// use time::Duration;
    ///
    /// let policy = LockoutPolicy::default();
    /// assert_eq!(policy.lock_for(4), None);
    /// assert_eq!(policy.lock_for(5), Some(Duration::minutes(5)));
    /// assert_eq!(policy.lock_for(10), Some(Duration::minutes(10)));
    /// assert_eq!(policy.lock_for(500), Some(Duration::hours(1)));
    /// ```
    #[must_use]
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

    /// The lock an account gets once its failure count has been incremented to
    /// `failures_after_increment` at `now`, if any. Store it as `locked_until` after applying
    /// [`Effect::RecordFailure`](crate::flow::Effect::RecordFailure).
    #[must_use]
    pub fn locked_until(
        &self,
        failures_after_increment: u32,
        now: OffsetDateTime,
    ) -> Option<OffsetDateTime> {
        self.lock_for(failures_after_increment)
            .map(|lock| now.saturating_add(lock))
    }

    /// The [`AuditKind::Lockout`](crate::audit::AuditKind::Lockout) event to append when
    /// `failures_after_increment` starts a lock, with the lock length (`300s`) as detail.
    #[must_use]
    pub fn lockout_event(
        &self,
        user_id: UserId,
        failures_after_increment: u32,
        now: OffsetDateTime,
        ip_tag: Option<crate::http::IpTag>,
    ) -> Option<crate::audit::AuditEvent> {
        self.lock_for(failures_after_increment).map(|lock| {
            crate::audit::AuditEvent::new(
                crate::audit::AuditKind::Lockout,
                Some(user_id),
                now,
                ip_tag,
            )
            .with_detail(format!("{}s", lock.whole_seconds()))
        })
    }
}

/// An account's consecutive failures and lock: the app stores both.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Lockout {
    /// Consecutive failed attempts since the last completed sign-in.
    pub failures: u32,
    /// Locked until then.
    pub locked_until: Option<OffsetDateTime>,
}

impl Lockout {
    /// Refuses while the account is locked.
    ///
    /// # Errors
    ///
    /// [`Error::TooManyAttempts`] with the seconds left.
    pub fn check(&self, now: OffsetDateTime) -> Result<(), Error> {
        match self.locked_until {
            Some(until) if until > now => Err(Error::too_many(
                u64::try_from((until - now).whole_seconds()).unwrap_or(1),
            )),
            _ => Ok(()),
        }
    }

    /// The state after one more failure, and the lock it starts, if any: the model the tests
    /// check [`LockoutPolicy`] against. Apps apply
    /// [`Effect::RecordFailure`](crate::flow::Effect::RecordFailure) as an atomic increment.
    #[cfg(test)]
    pub(crate) fn after_failure(
        self,
        policy: &LockoutPolicy,
        now: OffsetDateTime,
    ) -> (Self, Option<Duration>) {
        let failures = self.failures.saturating_add(1);
        let lock = policy.lock_for(failures);
        let locked_until = policy.locked_until(failures, now).or(self.locked_until);
        (
            Self {
                failures,
                locked_until,
            },
            lock,
        )
    }
}

/// The account as the flows see it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Account {
    /// Its id.
    pub id: UserId,
    /// Where its mail goes.
    pub email: Email,
    /// Shown in passkey prompts.
    pub display_name: String,
    /// Owner or member.
    pub role: Role,
    /// False until setup completes; inactive accounts cannot sign in.
    pub active: bool,
    /// Its enrolled factors.
    pub factors: Factors,
    /// Its failures and lock.
    pub lockout: Lockout,
}

/// An account to create, from [`Invite`](crate::flow::invite::Invite) or for the owner.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NewAccount {
    /// Its id.
    pub id: UserId,
    /// Its address.
    pub email: Email,
    /// Its display name.
    pub display_name: String,
    /// Its role.
    pub role: Role,
    /// When it was created.
    pub created_at: OffsetDateTime,
}

impl NewAccount {
    /// The inactive owner account an app creates on first start, from
    /// [`Config::owner_email`](crate::Config::owner_email). The app must make sure only one
    /// owner exists (for example with a unique index on the role).
    pub fn owner<R: rand_core::CryptoRng + ?Sized>(
        config: &crate::Config,
        now: OffsetDateTime,
        rng: &mut R,
    ) -> Self {
        Self {
            id: UserId::random(rng),
            email: config.owner_email().clone(),
            display_name: config.owner_name().to_owned(),
            role: Role::Owner,
            created_at: now,
        }
    }

    /// The account as the flows see it right after creation: inactive, no factors.
    #[must_use]
    pub fn to_account(&self) -> Account {
        Account {
            id: self.id,
            email: self.email.clone(),
            display_name: self.display_name.clone(),
            role: self.role,
            active: false,
            factors: Factors::default(),
            lockout: Lockout::default(),
        }
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
        let off = LockoutPolicy {
            threshold: 0,
            ..policy
        };
        assert_eq!(off.lock_for(5), None);
    }

    #[test]
    fn five_failures_lock_and_the_lock_lifts() {
        let policy = LockoutPolicy::default();
        let mut state = Lockout::default();
        for i in 0..4 {
            let (next, lock) = state.after_failure(&policy, at(i));
            assert_eq!(lock, None);
            state = next;
        }
        let (state, lock) = state.after_failure(&policy, at(10));
        assert_eq!(lock, Some(Duration::minutes(5)));
        assert_eq!(
            state.check(at(10)),
            Err(Error::TooManyAttempts {
                retry_after_secs: 300
            })
        );
        assert!(state.check(at(10 + 300)).is_ok());
        let mut state = state;
        for i in 0..5 {
            state = state.after_failure(&policy, at(400 + i)).0;
        }
        assert_eq!(state.locked_until, Some(at(404) + Duration::minutes(10)));
    }

    #[test]
    fn emails_are_normalised() {
        assert_eq!(
            Email::parse("  Owner@Example.COM ").map(String::from),
            Ok("owner@example.com".to_owned())
        );
        assert!(Email::parse("no-at-sign").is_err());
        assert!(Email::parse("a@b@c").is_err());
        assert!(Email::parse("a b@c").is_err());
        assert!(Email::parse("@c").is_err());
        assert_eq!(
            AccountKey::from_login(" Not An Email "),
            AccountKey("not an email".into())
        );
    }

    #[test]
    fn the_last_factor_cannot_be_removed() {
        let totp_only = Factors {
            password: true,
            totp: true,
            passkeys: 0,
        };
        assert_eq!(
            totp_only.may_remove_totp(),
            Err(Error::Conflict(ConflictReason::LastFactor))
        );
        let one_passkey = Factors {
            password: true,
            totp: false,
            passkeys: 1,
        };
        assert_eq!(
            one_passkey.may_remove_passkey(),
            Err(Error::Conflict(ConflictReason::LastFactor))
        );
        assert_eq!(one_passkey.may_remove_totp(), Err(Error::NotFound));
        let both = Factors {
            password: true,
            totp: true,
            passkeys: 1,
        };
        assert!(both.may_remove_totp().is_ok());
        assert!(both.may_remove_passkey().is_ok());
        assert!(both.is_complete());
        assert!(!Factors::default().is_complete());
    }
}
