//! First-open owner setup, and setting up an invited member's account.
//!
//! ```text
//! Start --RequestLink--> LinkRequested     (owner only, while inactive; answer 202 either way)
//! Start --Redeem-------> InSetup --PasswordSet--> InSetup --Finish--> Complete
//! ```
//!
//! Between `PasswordSet` and `Finish` the account enrols TOTP or a passkey (optional under
//! [`PasswordOnly::AllowedUntilEnrolled`](crate::PasswordOnly::AllowedUntilEnrolled)) with the
//! primitives ([`crate::totp`], and `passkey` with the `passkeys` feature), allowed by
//! [`crate::session::Access::Enrolling`]. Rebuild `InSetup` on each
//! request with [`Setup::resume`] from the stored setup session and the account as it is now.

use crate::error::InvalidRequestReason;
use rand_core::CryptoRng;
use time::OffsetDateTime;

use super::{
    Client, Effect, LinkKind, LinkToken, Refusal, Transition, UNEXPECTED, audit, complete_sign_in,
    send_link, start_session,
};
use crate::Error;
use crate::account::{Account, Role};
use crate::audit::AuditKind;
use crate::config::Config;
use crate::password::PasswordHash;
use crate::recovery::{self, RecoveryCode};
use crate::session::{Access, Session, SignInMethod, Stage};

/// Where a setup is.
// States are moved once per request; boxing the large variants would only complicate
// matching on them.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Setup {
    /// Nothing yet.
    Start,
    /// The request was handled; answer the same way whether or not a link was mailed.
    LinkRequested,
    /// A setup session is open.
    InSetup {
        /// The account being set up.
        account: Account,
        /// The setup session.
        session: Session,
    },
    /// Setup finished: the account is active and signed in.
    Complete {
        /// The account.
        account: Account,
        /// The full session that replaced the setup session.
        session: Session,
        /// Show these once.
        recovery_codes: Vec<RecoveryCode>,
    },
}

/// What happened.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum SetupEvent {
    /// Someone asked for the owner's setup link. From [`Setup::Start`].
    RequestLink {
        /// The owner account, if created.
        owner: Option<Account>,
        /// When the latest setup link was issued, for the resend cooldown.
        last_sent_at: Option<OffsetDateTime>,
        /// The client.
        client: Client,
    },
    /// A setup or invite link was posted back. From [`Setup::Start`].
    Redeem {
        /// [`LinkKind::Setup`] or [`LinkKind::Invite`], by the endpoint it came to.
        kind: LinkKind,
        /// The link record the app deleted by the token's hash, if there was one.
        link: Option<LinkToken>,
        /// The account it belongs to.
        account: Option<Account>,
        /// The client.
        client: Client,
    },
    /// The account chose a password, hashed with
    /// [`hash_new_password`](crate::password::PasswordHasher::hash_new_password).
    PasswordSet {
        /// The hash.
        hash: PasswordHash,
        /// The client.
        client: Client,
    },
    /// The account asks to finish setup.
    Finish {
        /// The client.
        client: Client,
    },
}

impl Setup {
    /// Rebuilds the in-setup state from the stored session and the account as it is now.
    #[must_use]
    pub fn resume(session: Session, account: Account) -> Self {
        Setup::InSetup { account, session }
    }

    /// Applies `event`.
    ///
    /// # Errors
    ///
    /// A [`Refusal`]: [`Error::SignInFailed`] for a bad link or an account already set up;
    /// [`Error::Unauthorized`] for an expired setup session; [`Error::InvalidRequest`] with
    /// `password_required` or `second_factor_required` when finishing too early (a second
    /// factor is not required under
    /// [`PasswordOnly::AllowedUntilEnrolled`](crate::PasswordOnly::AllowedUntilEnrolled)), or
    /// for an event the state does not take.
    #[allow(clippy::too_many_lines)] // one arm per (state, event) pair
    pub fn advance<R: CryptoRng + ?Sized>(
        self,
        config: &Config,
        event: SetupEvent,
        now: OffsetDateTime,
        rng: &mut R,
    ) -> Result<Transition<Setup>, Refusal> {
        match (self, event) {
            (
                Setup::Start,
                SetupEvent::RequestLink {
                    owner,
                    last_sent_at,
                    client,
                },
            ) => {
                let effects = owner
                    .filter(|owner| owner.role == Role::Owner && !owner.active)
                    .map(|owner| {
                        send_link(
                            config,
                            &owner,
                            LinkKind::Setup,
                            last_sent_at,
                            &client,
                            now,
                            rng,
                        )
                    })
                    .unwrap_or_default();
                Ok(Transition {
                    state: Setup::LinkRequested,
                    effects,
                })
            }
            (
                Setup::Start,
                SetupEvent::Redeem {
                    kind,
                    link,
                    account,
                    client,
                },
            ) => {
                if kind == LinkKind::SignIn {
                    return Err(UNEXPECTED.into());
                }
                let valid = |account: &Account| {
                    !account.active
                        && link.is_some_and(|link| {
                            link.is_redeemable(kind, now) && link.user_id == account.id
                        })
                };
                let Some(account) = account.filter(valid) else {
                    return Err(Error::SignInFailed.into());
                };
                let (session, effects) = start_session(
                    config,
                    account.id,
                    Stage::Setup,
                    None,
                    &client,
                    None,
                    now,
                    rng,
                );
                Ok(Transition {
                    state: Setup::InSetup { account, session },
                    effects,
                })
            }
            (
                Setup::InSetup {
                    mut account,
                    session,
                },
                SetupEvent::PasswordSet { hash, client },
            ) => {
                in_setup(config, &account, &session, now)?;
                account.factors.password = true;
                let effects = super::password_changed(account.id, hash, &client, now);
                Ok(Transition {
                    state: Setup::InSetup { account, session },
                    effects,
                })
            }
            (
                Setup::InSetup {
                    mut account,
                    session,
                },
                SetupEvent::Finish { client },
            ) => {
                in_setup(config, &account, &session, now)?;
                if !account.factors.password {
                    return Err(
                        Error::InvalidRequest(InvalidRequestReason::PasswordRequired).into(),
                    );
                }
                if !account.factors.are_sufficient(config.password_only()) {
                    return Err(
                        Error::InvalidRequest(InvalidRequestReason::SecondFactorRequired).into(),
                    );
                }
                let issued = recovery::generate(config.recovery_code_count(), rng);
                let mut effects = vec![
                    Effect::ActivateAccount {
                        user_id: account.id,
                    },
                    Effect::StoreRecoveryCodes {
                        user_id: account.id,
                        hashes: issued.hashes,
                    },
                    Effect::Audit(audit(
                        AuditKind::RecoveryCodesIssued,
                        Some(account.id),
                        &client,
                        now,
                    )),
                    Effect::Audit(audit(
                        AuditKind::SetupCompleted,
                        Some(account.id),
                        &client,
                        now,
                    )),
                ];
                account.active = true;
                let (session, done) = complete_sign_in(
                    config,
                    &account,
                    &SignInMethod::Setup,
                    &client,
                    Some(session.token_hash),
                    now,
                    rng,
                );
                effects.extend(done);
                Ok(Transition {
                    state: Setup::Complete {
                        account,
                        session,
                        recovery_codes: issued.codes,
                    },
                    effects,
                })
            }
            _ => Err(UNEXPECTED.into()),
        }
    }
}

fn in_setup(
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
        Access::Stage(Stage::Setup),
        config.step_up_window(),
        now,
    )
}
