//! Password sign-in with a second factor, and passkey sign-in.
//!
//! ```text
//! Start --Password--> VerifyPassword --PasswordChecked--> SecondFactor --Code----> SignedIn
//!   |                                                                  \--Passkey-/
//!   \--DiscoverablePasskey------------------------------------------------------> SignedIn
//! ```
//!
//! The password is checked in two steps so that the throttle and the lockout refuse
//! *before* the expensive hash: `Password` decides whether to hash at all, the app then runs
//! [`PasswordHasher::verify`](crate::password::PasswordHasher::verify) (with `None` for an
//! unknown account, which still costs a full hash) and reports `PasswordChecked`.
//!
//! The `SecondFactor` state lives in the session the password step started: rebuild it with
//! [`SignIn::second_factor`] from the stored session and the account on the next request.

use rand_core::CryptoRng;
use time::OffsetDateTime;

use super::{
    Client, CodeMaterial, Effect, Refusal, Transition, UNEXPECTED, check_code, complete_sign_in,
    failure, start_session, use_code,
};
use crate::Error;
use crate::account::{Account, AccountKey};
use crate::config::Config;
use crate::limits::FailureWindow;
use crate::session::{Access, Session, SignInMethod, Stage};

/// Where a sign-in is.
// States are moved once per request; boxing the large variants would only complicate
// matching on them.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub enum SignIn {
    /// Nothing yet.
    Start,
    /// Allowed to check the password. Verify it against this account's hash (or `None`) and
    /// send [`SignInEvent::PasswordChecked`].
    VerifyPassword {
        /// The active account the address names, if any.
        account: Option<Account>,
        /// The throttle key for the typed address.
        key: AccountKey,
    },
    /// Password accepted; a second-factor session was started.
    SecondFactor {
        /// Whose.
        account: Account,
        /// The second-factor session (the client got its cookie and CSRF token).
        session: Session,
    },
    /// Signed in.
    SignedIn {
        /// Whose.
        account: Account,
        /// The full session.
        session: Session,
    },
}

/// What happened.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum SignInEvent {
    /// The sign-in form arrived. From [`SignIn::Start`].
    Password {
        /// The address as typed.
        login: String,
        /// The account with that address, if any (inactive accounts are treated as unknown).
        account: Option<Account>,
        /// The throttle window for [`AccountKey::from_login`] of `login`.
        wrong_passwords: FailureWindow,
    },
    /// The password was checked. From [`SignIn::VerifyPassword`].
    PasswordChecked {
        /// Whether it matched.
        matched: bool,
        /// The client.
        client: Client,
    },
    /// A TOTP or recovery code arrived. From [`SignIn::SecondFactor`].
    Code {
        /// As typed.
        code: String,
        /// What to check it against.
        material: CodeMaterial,
        /// The client.
        client: Client,
    },
    /// A passkey assertion was verified (or not) against a ceremony bound to this session,
    /// and matched one of the account's passkeys. From [`SignIn::SecondFactor`].
    Passkey {
        /// Whether it verified.
        verified: bool,
        /// The client.
        client: Client,
    },
    /// A discoverable passkey assertion; the account is the one its user handle names. From
    /// [`SignIn::Start`].
    DiscoverablePasskey {
        /// The account, if the handle names one.
        account: Option<Account>,
        /// Whether the assertion verified against that account's passkeys.
        verified: bool,
        /// The client.
        client: Client,
    },
}

impl SignIn {
    /// Rebuilds the second-factor state from the stored session and its account.
    #[must_use]
    pub fn second_factor(session: Session, account: Account) -> Self {
        SignIn::SecondFactor { account, session }
    }

    /// Applies `event`.
    ///
    /// # Errors
    ///
    /// A [`Refusal`]: [`Error::SignInFailed`] for a wrong or unknown password, code, or
    /// passkey; [`Error::TooManyAttempts`] for the throttle or a lock; [`Error::Unauthorized`]
    /// for an expired second-factor session; [`Error::InvalidRequest`] for an event the state
    /// does not take.
    #[allow(clippy::too_many_lines)] // one arm per (state, event) pair
    pub fn advance<R: CryptoRng + ?Sized>(
        self,
        config: &Config,
        event: SignInEvent,
        now: OffsetDateTime,
        rng: &mut R,
    ) -> Result<Transition<SignIn>, Refusal> {
        match (self, event) {
            (
                SignIn::Start,
                SignInEvent::Password {
                    login,
                    account,
                    wrong_passwords,
                },
            ) => {
                let limits = config.rate_limits();
                if let Some(secs) = wrong_passwords.blocked(
                    limits.wrong_passwords_per_account,
                    limits.wrong_password_window,
                    now,
                ) {
                    return Err(Error::too_many(secs).into());
                }
                let account = account.filter(|account| account.active);
                if let Some(account) = &account {
                    account.lockout.check(now)?;
                }
                Ok(Transition {
                    state: SignIn::VerifyPassword {
                        account,
                        key: AccountKey::from_login(&login),
                    },
                    effects: Vec::new(),
                })
            }
            (
                SignIn::VerifyPassword { account, key },
                SignInEvent::PasswordChecked { matched, client },
            ) => {
                let mut effects = Vec::new();
                if !matched {
                    effects.push(Effect::RecordWrongPassword { key });
                }
                let Some(account) = account else {
                    return Err(Refusal::with(Error::SignInFailed, effects));
                };
                if !matched {
                    effects.extend(failure(config, &account, "password", &client, now));
                    return Err(Refusal::with(Error::SignInFailed, effects));
                }
                let (session, started) = start_session(
                    config,
                    account.id,
                    Stage::SecondFactor,
                    Some(SignInMethod::Password),
                    &client,
                    None,
                    now,
                    rng,
                );
                effects.extend(started);
                Ok(Transition {
                    state: SignIn::SecondFactor { account, session },
                    effects,
                })
            }
            (
                SignIn::SecondFactor { account, session },
                SignInEvent::Code {
                    code,
                    material,
                    client,
                },
            ) => {
                second_factor_allowed(config, &account, &session, now)?;
                let Some(matched) = check_code(&code, &material, now) else {
                    let effects = failure(config, &account, "code", &client, now);
                    return Err(Refusal::with(Error::SignInFailed, effects));
                };
                let method = match matched {
                    super::CodeMatch::Totp(_) => SignInMethod::PasswordTotp,
                    super::CodeMatch::RecoveryCode(_) => SignInMethod::PasswordRecoveryCode,
                };
                let mut effects = use_code(&account, matched, &client, now);
                let (session, done) = complete_sign_in(
                    config,
                    &account,
                    &method,
                    &client,
                    Some(session.token_hash),
                    now,
                    rng,
                );
                effects.extend(done);
                Ok(Transition {
                    state: SignIn::SignedIn { account, session },
                    effects,
                })
            }
            (
                SignIn::SecondFactor { account, session },
                SignInEvent::Passkey { verified, client },
            ) => {
                second_factor_allowed(config, &account, &session, now)?;
                if !verified {
                    return Err(Error::SignInFailed.into());
                }
                let (session, effects) = complete_sign_in(
                    config,
                    &account,
                    &SignInMethod::PasswordPasskey,
                    &client,
                    Some(session.token_hash),
                    now,
                    rng,
                );
                Ok(Transition {
                    state: SignIn::SignedIn { account, session },
                    effects,
                })
            }
            (
                SignIn::Start,
                SignInEvent::DiscoverablePasskey {
                    account,
                    verified,
                    client,
                },
            ) => {
                let Some(account) = account.filter(|account| account.active && verified) else {
                    return Err(Error::SignInFailed.into());
                };
                let (session, effects) = complete_sign_in(
                    config,
                    &account,
                    &SignInMethod::Passkey,
                    &client,
                    None,
                    now,
                    rng,
                );
                Ok(Transition {
                    state: SignIn::SignedIn { account, session },
                    effects,
                })
            }
            _ => Err(UNEXPECTED.into()),
        }
    }
}

fn second_factor_allowed(
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
        Access::Stage(Stage::SecondFactor),
        config.step_up_window(),
        now,
    )?;
    account.lockout.check(now)
}
