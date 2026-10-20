//! Sign-in by an emailed single-use link (15 minutes by default), which signs in directly.
//!
//! ```text
//! Start --Request--> Requested        (answer 202 whether or not a mail went out)
//! Start --Redeem---> SignedIn
//! ```

use rand_core::CryptoRng;
use time::OffsetDateTime;

use super::{
    Client, LinkKind, LinkToken, Refusal, Transition, UNEXPECTED, complete_sign_in, send_link,
};
use crate::Error;
use crate::account::Account;
use crate::config::Config;
use crate::session::{Session, SignInMethod};

/// Where an email-link sign-in is.
// States are moved once per request; boxing the large variants would only complicate
// matching on them.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub enum EmailLink {
    /// Nothing yet.
    Start,
    /// The request was handled; answer the same way whether or not a link was mailed.
    Requested,
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
pub enum EmailLinkEvent {
    /// Someone asked for a link to an address.
    Request {
        /// The account with that address, if any.
        account: Option<Account>,
        /// When the latest unexpired sign-in link to it was issued, for the resend cooldown.
        last_sent_at: Option<OffsetDateTime>,
        /// The client.
        client: Client,
    },
    /// A link was opened and its token posted back.
    Redeem {
        /// The link record the app deleted by the token's hash, if there was one.
        link: Option<LinkToken>,
        /// The account it belongs to.
        account: Option<Account>,
        /// The client.
        client: Client,
    },
}

impl EmailLink {
    /// Applies `event`.
    ///
    /// # Errors
    ///
    /// A [`Refusal`] with [`Error::SignInFailed`] for an unknown, used, expired or
    /// wrong-kind link or an inactive account; [`Error::InvalidRequest`] for an event the
    /// state does not take.
    #[allow(clippy::too_many_lines)] // one arm per (state, event) pair
    pub fn advance<R: CryptoRng + ?Sized>(
        self,
        config: &Config,
        event: EmailLinkEvent,
        now: OffsetDateTime,
        rng: &mut R,
    ) -> Result<Transition<EmailLink>, Refusal> {
        match (self, event) {
            (
                EmailLink::Start,
                EmailLinkEvent::Request {
                    account,
                    last_sent_at,
                    client,
                },
            ) => {
                let effects = account
                    .filter(|account| account.active)
                    .map(|account| {
                        send_link(
                            config,
                            &account,
                            LinkKind::SignIn,
                            last_sent_at,
                            &client,
                            now,
                            rng,
                        )
                    })
                    .unwrap_or_default();
                Ok(Transition {
                    state: EmailLink::Requested,
                    effects,
                })
            }
            (
                EmailLink::Start,
                EmailLinkEvent::Redeem {
                    link,
                    account,
                    client,
                },
            ) => {
                let valid = |account: &Account| {
                    account.active
                        && link.is_some_and(|link| {
                            link.is_redeemable(LinkKind::SignIn, now) && link.user_id == account.id
                        })
                };
                let Some(account) = account.filter(valid) else {
                    return Err(Error::SignInFailed.into());
                };
                let (session, effects) = complete_sign_in(
                    config,
                    &account,
                    &SignInMethod::EmailLink,
                    &client,
                    None,
                    now,
                    rng,
                );
                Ok(Transition {
                    state: EmailLink::SignedIn { account, session },
                    effects,
                })
            }
            _ => Err(UNEXPECTED.into()),
        }
    }
}
