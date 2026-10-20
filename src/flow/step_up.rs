//! Step-up: a signed-in user proves themselves again to reopen the step-up window for
//! sensitive changes.
//!
//! ```text
//! new(account, session) --Password--> VerifyPassword --PasswordChecked--> Done
//!                       \--Passkey-----------------------------------------> Done
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
use crate::limits::FailureWindow;
use crate::session::{Access, Session, SignInMethod};

/// Where a step-up is.
// States are moved once per request; boxing the large variants would only complicate
// matching on them.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
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
        /// The throttle window for the account's address.
        wrong_passwords: FailureWindow,
    },
    /// The password was checked. From [`StepUp::VerifyPassword`].
    PasswordChecked {
        /// Whether it matched.
        matched: bool,
        /// The TOTP or recovery code that came with it.
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
    /// [`Error::TooManyAttempts`] for a lock or the throttle; [`Error::SignInFailed`] for a
    /// wrong password, code or passkey.
    pub fn advance(
        self,
        config: &Config,
        event: StepUpEvent,
        now: OffsetDateTime,
    ) -> Result<Transition<StepUp>, Refusal> {
        match (self, event) {
            (StepUp::Start { account, session }, StepUpEvent::Password { wrong_passwords }) => {
                signed_in(config, &account, &session, now)?;
                account.lockout.check(now)?;
                let limits = config.rate_limits();
                if let Some(secs) = wrong_passwords.blocked(
                    limits.wrong_passwords_per_account,
                    limits.wrong_password_window,
                    now,
                ) {
                    return Err(Error::too_many(secs).into());
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
                    let mut effects = vec![Effect::RecordWrongPassword {
                        key: AccountKey::from(&account.email),
                    }];
                    effects.extend(failure(&account, "step_up_password", &client, now));
                    return Err(Refusal::with(Error::SignInFailed, effects));
                }
                let Some(matched) = check_code(&code, &material, now) else {
                    let effects = failure(&account, "step_up_code", &client, now);
                    return Err(Refusal::with(Error::SignInFailed, effects));
                };
                let mut effects = use_code(&account, matched, &client, now);
                effects.push(Effect::ClearFailures {
                    user_id: account.id,
                });
                Ok(stepped_up(&account, session, &client, now, effects))
            }
            (StepUp::Start { account, session }, StepUpEvent::Passkey { verified, client }) => {
                signed_in(config, &account, &session, now)?;
                if !verified {
                    return Err(Error::SignInFailed.into());
                }
                Ok(stepped_up(&account, session, &client, now, Vec::new()))
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

fn stepped_up(
    account: &Account,
    mut session: Session,
    client: &Client,
    now: OffsetDateTime,
    mut effects: Vec<Effect>,
) -> Transition<StepUp> {
    session.authenticated_at = Some(now);
    session.method = Some(SignInMethod::StepUp);
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
