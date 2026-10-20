//! Sessions as plain records, and the rules for what a session may do.
//!
//! A session moves through stages, and every change of stage gets a new token (the flows
//! emit a replacing [`StoreSession`](crate::flow::Effect::StoreSession)):
//! [`Stage::Setup`] (redeemed a setup or invite link), [`Stage::SecondFactor`] (password
//! accepted) and [`Stage::Full`] (signed in). The app stores sessions by
//! [`token_hash`](Session::token_hash) and checks each request with
//! [`Session::authorize`].
//!
//! ```
//! use latchkey::session::{Access, Session};
//! # use latchkey::session::Stage;
//! # use time::{Duration, OffsetDateTime};
//! # fn check(session: &Session, active: bool, now: OffsetDateTime) -> Result<(), latchkey::Error> {
//! // Changing the password needs a sign-in or step-up within the last 5 minutes.
//! session.authorize(active, Access::Recent, Duration::minutes(5), now)?;
//! # Ok(())
//! # }
//! ```

use crate::error::InvalidRequestReason;
use time::{Duration, OffsetDateTime};

use crate::Error;
use crate::http::IpTag;
use crate::ids::{SessionId, UserId};
use crate::token::{SecretToken, TokenHash};

/// Where a session is in the sign-in process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum Stage {
    /// Setting up an account after redeeming a setup or invite link.
    Setup,
    /// Password accepted; a second factor is due.
    SecondFactor,
    /// Signed in.
    Full,
}

impl Stage {
    /// `setup`, `second_factor` or `full`, the values latchkey 0.2 stored.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Stage::Setup => "setup",
            Stage::SecondFactor => "second_factor",
            Stage::Full => "full",
        }
    }
}

impl std::str::FromStr for Stage {
    type Err = Error;

    fn from_str(raw: &str) -> Result<Self, Error> {
        match raw {
            "setup" => Ok(Stage::Setup),
            "second_factor" => Ok(Stage::SecondFactor),
            "full" => Ok(Stage::Full),
            _ => Err(Error::InvalidRequest(InvalidRequestReason::Stage)),
        }
    }
}

const RESERVED_METHODS: &[&str] = &[
    "setup",
    "password",
    "password_only",
    "passkey",
    "email_link",
    "totp",
    "recovery_code",
    "step_up",
];

/// A sign-in method the app names for sessions it completes itself (see
/// [`issue_session`](crate::flow::issue_session)): 1 to 32 characters from `a-z`, `0-9` and
/// `_`, and none of latchkey's own (`setup`, `password`, `password_only`, `passkey`,
/// `email_link`, `totp`, `recovery_code`, `step_up`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AppMethod(String);

impl AppMethod {
    /// Checks the rules above.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidRequest`] with `method`.
    ///
    /// ```
    /// use latchkey::session::AppMethod;
    /// assert!(AppMethod::new("desktop_bridge").is_ok());
    /// assert!(AppMethod::new("passkey").is_err());
    /// ```
    pub fn new(method: &str) -> Result<Self, Error> {
        let ok = (1..=32).contains(&method.len())
            && method
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
            && !RESERVED_METHODS.contains(&method);
        if ok {
            Ok(Self(method.to_owned()))
        } else {
            Err(Error::InvalidRequest(InvalidRequestReason::Method))
        }
    }

    /// The method name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// How a session was signed in, recorded on the session and in audit events.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "String", into = "String"))]
#[non_exhaustive]
pub enum SignInMethod {
    /// Completed setup (`setup`).
    Setup,
    /// Password accepted, second factor pending (`password`).
    Password,
    /// `password+totp`.
    PasswordTotp,
    /// `password+recovery_code`.
    PasswordRecoveryCode,
    /// `password+passkey`.
    PasswordPasskey,
    /// A password alone, for an account without a second factor under
    /// [`PasswordOnly::AllowedUntilEnrolled`](crate::PasswordOnly::AllowedUntilEnrolled)
    /// (`password_only`).
    PasswordOnly,
    /// A passkey on its own, discoverable or from an allow-list (`passkey`).
    Passkey,
    /// An emailed sign-in link (`email_link`).
    EmailLink,
    /// A step-up re-authentication (`step_up`).
    StepUp,
    /// A sign-in the app completed itself.
    App(AppMethod),
}

impl SignInMethod {
    /// The stored name, as latchkey 0.2 wrote it.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            SignInMethod::Setup => "setup",
            SignInMethod::Password => "password",
            SignInMethod::PasswordTotp => "password+totp",
            SignInMethod::PasswordRecoveryCode => "password+recovery_code",
            SignInMethod::PasswordPasskey => "password+passkey",
            SignInMethod::PasswordOnly => "password_only",
            SignInMethod::Passkey => "passkey",
            SignInMethod::EmailLink => "email_link",
            SignInMethod::StepUp => "step_up",
            SignInMethod::App(method) => method.as_str(),
        }
    }
}

impl std::str::FromStr for SignInMethod {
    type Err = Error;

    fn from_str(raw: &str) -> Result<Self, Error> {
        Ok(match raw {
            "setup" => SignInMethod::Setup,
            "password" => SignInMethod::Password,
            "password+totp" => SignInMethod::PasswordTotp,
            "password+recovery_code" => SignInMethod::PasswordRecoveryCode,
            "password+passkey" => SignInMethod::PasswordPasskey,
            "password_only" => SignInMethod::PasswordOnly,
            "passkey" => SignInMethod::Passkey,
            "email_link" => SignInMethod::EmailLink,
            "step_up" => SignInMethod::StepUp,
            other => SignInMethod::App(AppMethod::new(other)?),
        })
    }
}

impl TryFrom<String> for SignInMethod {
    type Error = Error;

    fn try_from(raw: String) -> Result<Self, Error> {
        raw.parse()
    }
}

impl From<SignInMethod> for String {
    fn from(method: SignInMethod) -> String {
        method.as_str().to_owned()
    }
}

impl std::fmt::Display for SignInMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A session as the app stores it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Session {
    /// For listing and revoking; not a secret.
    pub id: SessionId,
    /// The SHA-256 of the cookie value; look sessions up by it.
    pub token_hash: TokenHash,
    /// Whose session it is.
    pub user_id: UserId,
    /// Its stage.
    pub stage: Stage,
    /// The CSRF token unsafe requests must carry in [`CSRF_HEADER`](crate::http::CSRF_HEADER).
    /// The client gets it in the response that starts the session (and may ask for it again).
    pub csrf_token: SecretToken,
    /// How it was signed in; `None` for setup sessions.
    pub method: Option<SignInMethod>,
    /// When it started.
    pub created_at: OffsetDateTime,
    /// When it stops working.
    pub expires_at: OffsetDateTime,
    /// The last sign-in or step-up, from which the step-up window runs. Set only on full
    /// sessions.
    pub authenticated_at: Option<OffsetDateTime>,
    /// The client's IP address as an HMAC.
    pub ip_tag: Option<IpTag>,
    /// The client's user agent, shortened.
    pub user_agent: Option<String>,
    /// Wrong step-up guesses made from this session, counted only under
    /// [`StepUpFailures::PerSession`](crate::flow::step_up::StepUpFailures::PerSession)
    /// ([`Effect::RecordStepUpFailure`](crate::flow::Effect::RecordStepUpFailure)); 0
    /// otherwise.
    #[cfg_attr(feature = "serde", serde(default))]
    pub step_up_failures: u32,
}

/// What a request needs from its session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Access {
    /// Any unexpired session (such as for "who am I" or signing out).
    Any,
    /// A session at exactly this stage.
    Stage(Stage),
    /// A full session.
    SignedIn,
    /// A full session within the step-up window, for sensitive changes.
    Recent,
    /// Enrolling a factor: a setup session, or a full session within the step-up window.
    Enrolling,
}

/// Whether `authenticated_at` lies within `window` before `now`.
#[must_use]
pub fn is_recent(
    authenticated_at: Option<OffsetDateTime>,
    window: Duration,
    now: OffsetDateTime,
) -> bool {
    authenticated_at.is_some_and(|at| at.saturating_add(window) > now)
}

impl Session {
    /// Whether it has expired at `now`. The app may delete expired sessions when it sees them.
    #[must_use]
    pub fn is_expired(&self, now: OffsetDateTime) -> bool {
        self.expires_at <= now
    }

    /// When the step-up window ends, if it is still open.
    #[must_use]
    pub fn step_up_until(&self, window: Duration, now: OffsetDateTime) -> Option<OffsetDateTime> {
        self.authenticated_at
            .map(|at| at.saturating_add(window))
            .filter(|until| *until > now)
    }

    /// Whether the session may make a request needing `access`. `account_active` is the
    /// account's current state: only setup sessions work for inactive accounts.
    ///
    /// # Errors
    ///
    /// [`Error::Unauthorized`] for expired sessions, inactive accounts and wrong stages;
    /// [`Error::StepUpRequired`] for full sessions outside the step-up window where
    /// [`Access::Recent`] or [`Access::Enrolling`] is needed.
    pub fn authorize(
        &self,
        account_active: bool,
        access: Access,
        step_up_window: Duration,
        now: OffsetDateTime,
    ) -> Result<(), Error> {
        if self.is_expired(now) || (self.stage != Stage::Setup && !account_active) {
            return Err(Error::Unauthorized);
        }
        let recent = is_recent(self.authenticated_at, step_up_window, now);
        match (access, self.stage) {
            (Access::Any, _)
            | (Access::SignedIn, Stage::Full)
            | (Access::Enrolling, Stage::Setup) => Ok(()),
            (Access::Stage(wanted), stage) if wanted == stage => Ok(()),
            (Access::Recent | Access::Enrolling, Stage::Full) if recent => Ok(()),
            (Access::Recent | Access::Enrolling, Stage::Full) => Err(Error::StepUpRequired),
            _ => Err(Error::Unauthorized),
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

    fn session(stage: Stage) -> Session {
        let mut rng = crate::test_rng();
        let issued = crate::token::issue(&mut rng);
        Session {
            id: SessionId::random(&mut rng),
            token_hash: issued.hash,
            user_id: UserId::random(&mut rng),
            stage,
            csrf_token: crate::token::issue(&mut rng).token,
            method: None,
            created_at: at(0),
            expires_at: at(3600),
            authenticated_at: (stage == Stage::Full).then(|| at(0)),
            ip_tag: None,
            user_agent: None,
            step_up_failures: 0,
        }
    }

    const WINDOW: Duration = Duration::minutes(5);

    #[test]
    fn the_step_up_window_is_five_minutes_from_authentication() {
        let full = session(Stage::Full);
        assert!(
            full.authorize(true, Access::Recent, WINDOW, at(299))
                .is_ok()
        );
        assert_eq!(
            full.authorize(true, Access::Recent, WINDOW, at(300)),
            Err(Error::StepUpRequired)
        );
        assert!(
            full.authorize(true, Access::SignedIn, WINDOW, at(300))
                .is_ok()
        );
        assert_eq!(full.step_up_until(WINDOW, at(10)), Some(at(300)));
        assert_eq!(full.step_up_until(WINDOW, at(300)), None);
        assert!(is_recent(Some(at(0)), WINDOW, at(1)));
        assert!(!is_recent(None, WINDOW, at(1)));
    }

    #[test]
    fn expired_sessions_and_inactive_accounts_are_refused() {
        let full = session(Stage::Full);
        assert_eq!(
            full.authorize(true, Access::Any, WINDOW, at(3600)),
            Err(Error::Unauthorized)
        );
        assert_eq!(
            full.authorize(false, Access::SignedIn, WINDOW, at(1)),
            Err(Error::Unauthorized)
        );
        let setup = session(Stage::Setup);
        assert!(
            setup
                .authorize(false, Access::Stage(Stage::Setup), WINDOW, at(1))
                .is_ok()
        );
    }

    #[test]
    fn half_finished_sessions_reach_nothing_signed_in() {
        let pending = session(Stage::SecondFactor);
        for access in [Access::SignedIn, Access::Recent, Access::Enrolling] {
            assert_eq!(
                pending.authorize(true, access, WINDOW, at(1)),
                Err(Error::Unauthorized)
            );
        }
        let setup = session(Stage::Setup);
        assert_eq!(
            setup.authorize(false, Access::SignedIn, WINDOW, at(1)),
            Err(Error::Unauthorized)
        );
        assert!(pending.authorize(true, Access::Any, WINDOW, at(1)).is_ok());
    }

    #[test]
    fn enrolling_needs_setup_or_a_recent_sign_in() {
        assert!(
            session(Stage::Setup)
                .authorize(false, Access::Enrolling, WINDOW, at(1))
                .is_ok()
        );
        let full = session(Stage::Full);
        assert!(
            full.authorize(true, Access::Enrolling, WINDOW, at(1))
                .is_ok()
        );
        assert_eq!(
            full.authorize(true, Access::Enrolling, WINDOW, at(600)),
            Err(Error::StepUpRequired)
        );
    }

    #[test]
    fn methods_are_short_lowercase_and_not_latchkeys_own() {
        assert!(AppMethod::new("desktop_bridge").is_ok());
        assert!(AppMethod::new("app2").is_ok());
        for bad in [
            "",
            "Desktop",
            "desktop-bridge",
            "password+totp",
            "setup",
            "password_only",
            "passkey",
            "email_link",
            "step_up",
            "a\nb",
            &"x".repeat(33),
        ] {
            assert!(AppMethod::new(bad).is_err(), "{bad:?} accepted");
        }
    }

    #[cfg(feature = "serde")]
    #[test]
    fn sessions_round_trip_through_serde_with_stored_names() {
        let mut full = session(Stage::Full);
        full.method = Some(SignInMethod::PasswordTotp);
        let json = serde_json::to_value(&full).unwrap();
        assert_eq!(json["stage"], "full");
        assert_eq!(json["method"], "password+totp");
        let mut json = json;
        assert_eq!(json["step_up_failures"], 0);
        let back: Session = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(back, full);
        json.as_object_mut().unwrap().remove("step_up_failures");
        let stored_before_the_count: Session = serde_json::from_value(json).unwrap();
        assert_eq!(stored_before_the_count, full);
    }

    #[test]
    fn methods_round_trip_through_their_stored_names() -> Result<(), Error> {
        for name in [
            "setup",
            "password",
            "password+totp",
            "password+recovery_code",
            "password+passkey",
            "password_only",
            "passkey",
            "email_link",
            "step_up",
            "desktop_bridge",
        ] {
            assert_eq!(name.parse::<SignInMethod>()?.as_str(), name);
        }
        assert!("Bad Method".parse::<SignInMethod>().is_err());
        Ok(())
    }
}
