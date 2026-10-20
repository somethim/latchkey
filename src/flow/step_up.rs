//! Step-up: a signed-in user proves themselves again to reopen the step-up window for
//! sensitive changes.
//!
//! ```text
//! new(account, session) --Password--> VerifyPassword --PasswordChecked--> Done
//!                       \--Passkey-----------------------------------------> Done
//! ```
//!
//! [`Config::step_up_failures`] decides where wrong guesses count:
//!
//! | | [`AccountLockout`](StepUpFailures::AccountLockout) (default) | [`PerSession`](StepUpFailures::PerSession) |
//! |---|---|---|
//! | A wrong password or code | counts towards the account lockout ([`Effect::RecordFailure`]) and, for a password, the wrong-password throttle | counts against the session ([`Effect::RecordStepUpFailure`]) |
//! | A locked account or a throttled address | refuses the step-up | does not refuse it |
//! | At the limit | the account locks | the session ends ([`Effect::DeleteSession`], [`Error::SessionEnded`]) |
//! | A step-up that succeeds | clears the account's failures | clears the account's and the session's failures |
//!
//! Per session, a stolen session cookie cannot lock the owner out, and wrong sign-in guesses
//! from anyone cannot stop a signed-in owner from stepping up; a session gets `limit` guesses
//! and a new one takes a full sign-in. A passkey that fails to verify is not a guess and is
//! not counted in either mode.
//!
//! ```
//! use latchkey::{Config, StepUpFailures};
//!
//! let config = Config::builder("owner@example.com", "https://home.example.com")
//!     .step_up_failures(StepUpFailures::PerSession { limit: 5 })
//!     .build()?;
//! assert!(config.step_up_failures().ends_session(5));
//! # Ok::<(), latchkey::Error>(())
//! ```

use time::OffsetDateTime;

use super::{
    Client, CodeMaterial, Effect, Refusal, Transition, UNEXPECTED, audit, check_code, failure,
    use_code,
};
use crate::Error;
use crate::account::{Account, AccountKey};
use crate::audit::AuditKind;
use crate::config::Config;
use crate::http::SetCookie;
use crate::limits::FailureWindow;
use crate::session::{Access, Session, SignInMethod};

/// Where wrong step-up guesses count; set with
/// [`ConfigBuilder::step_up_failures`](crate::ConfigBuilder::step_up_failures). See the
/// [module docs](self) for what each mode does.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum StepUpFailures {
    /// Like sign-in failures: towards the account lockout and the wrong-password throttle,
    /// and a locked account cannot step up. latchkey 0.2's behaviour.
    #[default]
    AccountLockout,
    /// Against the session ([`Session::step_up_failures`]); the guess that makes `limit`
    /// ends the session. The account lockout and throttle neither count nor block step-up.
    PerSession {
        /// Wrong guesses a session may make; at least 1.
        limit: u32,
    },
}

impl StepUpFailures {
    /// Whether a session with `failures` wrong step-up guesses (such as the count
    /// [`Effect::RecordStepUpFailure`] returned) must end. Always `false` for
    /// [`StepUpFailures::AccountLockout`].
    #[must_use]
    pub const fn ends_session(&self, failures: u32) -> bool {
        match *self {
            StepUpFailures::AccountLockout => false,
            StepUpFailures::PerSession { limit } => failures >= limit,
        }
    }
}

/// Where a step-up is.
// States are moved once per request; boxing the large variants would only complicate
// matching on them.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum StepUp {
    /// A signed-in session asks to step up.
    Start {
        /// Whose.
        account: Account,
        /// The full session.
        session: Session,
    },
    /// Allowed to check the password; verify it and send
    /// [`StepUpEvent::PasswordChecked`].
    VerifyPassword {
        /// Whose.
        account: Account,
        /// The full session.
        session: Session,
    },
    /// Stepped up.
    Done {
        /// The session with `authenticated_at` = now.
        session: Session,
    },
}

/// What happened.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum StepUpEvent {
    /// A password and code arrived. From [`StepUp::Start`].
    Password {
        /// The throttle window for the account's address. Not consulted under
        /// [`StepUpFailures::PerSession`] (pass the default).
        wrong_passwords: FailureWindow,
    },
    /// The password was checked. From [`StepUp::VerifyPassword`].
    PasswordChecked {
        /// Whether it matched.
        matched: bool,
        /// The TOTP or recovery code that came with it. Ignored for an account without a
        /// second factor under
        /// [`PasswordOnly::AllowedUntilEnrolled`](crate::PasswordOnly::AllowedUntilEnrolled),
        /// whose password alone steps up.
        code: String,
        /// What to check the code against.
        material: CodeMaterial,
        /// The client.
        client: Client,
    },
    /// A passkey assertion verified (or not) against a ceremony bound to this session. From
    /// [`StepUp::Start`].
    Passkey {
        /// Whether it verified.
        verified: bool,
        /// The client.
        client: Client,
    },
}

impl StepUp {
    /// Starts a step-up for a full session.
    #[must_use]
    pub fn new(account: Account, session: Session) -> Self {
        StepUp::Start { account, session }
    }

    /// Applies `event`.
    ///
    /// # Errors
    ///
    /// A [`Refusal`]: [`Error::Unauthorized`] unless the session is signed in;
    /// [`Error::TooManyAttempts`] for a lock or the throttle (only under
    /// [`StepUpFailures::AccountLockout`]); [`Error::SignInFailed`] for a wrong password, code
    /// or passkey; [`Error::SessionEnded`], with the effects that end it, when a wrong guess
    /// reaches the [`StepUpFailures::PerSession`] limit or the session had already reached it.
    pub fn advance(
        self,
        config: &Config,
        event: StepUpEvent,
        now: OffsetDateTime,
    ) -> Result<Transition<StepUp>, Refusal> {
        match (self, event) {
            (StepUp::Start { account, session }, StepUpEvent::Password { wrong_passwords }) => {
                signed_in(config, &account, &session, now)?;
                match config.step_up_failures() {
                    StepUpFailures::AccountLockout => {
                        account.lockout.check(now)?;
                        let limits = config.rate_limits();
                        if let Some(secs) = wrong_passwords.blocked(
                            limits.wrong_passwords_per_account,
                            limits.wrong_password_window,
                            now,
                        ) {
                            return Err(Error::too_many(secs).into());
                        }
                    }
                    // No client arrives with this event; the audit event goes without an IP.
                    StepUpFailures::PerSession { .. } => {
                        spent(config, &session, &Client::default(), now)?;
                    }
                }
                Ok(Transition {
                    state: StepUp::VerifyPassword { account, session },
                    effects: Vec::new(),
                })
            }
            (
                StepUp::VerifyPassword { account, session },
                StepUpEvent::PasswordChecked {
                    matched,
                    code,
                    material,
                    client,
                },
            ) => {
                signed_in(config, &account, &session, now)?;
                if !matched {
                    return Err(wrong_guess(
                        config,
                        &account,
                        &session,
                        Guess::Password,
                        &client,
                        now,
                    ));
                }
                if account.factors.password_suffices(config.password_only()) {
                    let effects = vec![Effect::ClearFailures {
                        user_id: account.id,
                    }];
                    return Ok(stepped_up(config, &account, session, &client, now, effects));
                }
                let Some(matched) = check_code(&code, &material, now) else {
                    return Err(wrong_guess(
                        config,
                        &account,
                        &session,
                        Guess::Code,
                        &client,
                        now,
                    ));
                };
                let mut effects = use_code(&account, matched, &client, now);
                effects.push(Effect::ClearFailures {
                    user_id: account.id,
                });
                Ok(stepped_up(config, &account, session, &client, now, effects))
            }
            (StepUp::Start { account, session }, StepUpEvent::Passkey { verified, client }) => {
                signed_in(config, &account, &session, now)?;
                spent(config, &session, &client, now)?;
                if !verified {
                    return Err(Error::SignInFailed.into());
                }
                Ok(stepped_up(
                    config,
                    &account,
                    session,
                    &client,
                    now,
                    Vec::new(),
                ))
            }
            _ => Err(UNEXPECTED.into()),
        }
    }
}

fn signed_in(
    config: &Config,
    account: &Account,
    session: &Session,
    now: OffsetDateTime,
) -> Result<(), Error> {
    if session.user_id != account.id {
        return Err(Error::Unauthorized);
    }
    session.authorize(
        account.active,
        Access::SignedIn,
        config.step_up_window(),
        now,
    )
}

/// Refuses, and ends, a session that already made its [`StepUpFailures::PerSession`] limit of
/// wrong guesses (such as one whose guesses raced).
fn spent(
    config: &Config,
    session: &Session,
    client: &Client,
    now: OffsetDateTime,
) -> Result<(), Refusal> {
    if config
        .step_up_failures()
        .ends_session(session.step_up_failures)
    {
        return Err(Refusal::new(
            Error::SessionEnded,
            end_session(config, session, client, now),
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Guess {
    Password,
    Code,
}

/// The effects of a wrong password or code, counted where the policy says.
fn wrong_guess(
    config: &Config,
    account: &Account,
    session: &Session,
    guess: Guess,
    client: &Client,
    now: OffsetDateTime,
) -> Refusal {
    let detail = match guess {
        Guess::Password => "step_up_password",
        Guess::Code => "step_up_code",
    };
    match config.step_up_failures() {
        StepUpFailures::AccountLockout => {
            let mut effects = Vec::new();
            if guess == Guess::Password {
                effects.push(Effect::RecordWrongPassword {
                    key: AccountKey::from(&account.email),
                });
            }
            effects.extend(failure(account, detail, client, now));
            Refusal::new(Error::SignInFailed, effects)
        }
        policy @ StepUpFailures::PerSession { .. } => {
            let mut effects = vec![
                Effect::Audit(
                    audit(AuditKind::SignInFailed, Some(account.id), client, now)
                        .with_detail(detail),
                ),
                Effect::RecordStepUpFailure {
                    token_hash: session.token_hash,
                },
            ];
            if policy.ends_session(session.step_up_failures.saturating_add(1)) {
                effects.extend(end_session(config, session, client, now));
                return Refusal::new(Error::SessionEnded, effects);
            }
            Refusal::new(Error::SignInFailed, effects)
        }
    }
}

fn end_session(
    config: &Config,
    session: &Session,
    client: &Client,
    now: OffsetDateTime,
) -> Vec<Effect> {
    vec![
        Effect::DeleteSession {
            token_hash: session.token_hash,
        },
        Effect::SetCookie(SetCookie::removal(config.cookie_name().clone())),
        Effect::Audit(
            audit(
                AuditKind::SessionRevoked,
                Some(session.user_id),
                client,
                now,
            )
            .with_detail("step_up_failures"),
        ),
    ]
}

fn stepped_up(
    config: &Config,
    account: &Account,
    mut session: Session,
    client: &Client,
    now: OffsetDateTime,
    mut effects: Vec<Effect>,
) -> Transition<StepUp> {
    session.authenticated_at = Some(now);
    session.method = Some(SignInMethod::StepUp);
    if let StepUpFailures::PerSession { .. } = config.step_up_failures() {
        session.step_up_failures = 0;
        effects.push(Effect::ClearStepUpFailures {
            token_hash: session.token_hash,
        });
    }
    effects.push(Effect::MarkStepUp {
        token_hash: session.token_hash,
        at: now,
        method: SignInMethod::StepUp,
    });
    effects.push(Effect::Audit(audit(
        AuditKind::StepUp,
        Some(account.id),
        client,
        now,
    )));
    Transition {
        state: StepUp::Done { session },
        effects,
    }
}
