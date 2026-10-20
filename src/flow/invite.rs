//! The owner invites a member by email; the member then goes through [`setup`](super::setup)
//! with [`super::LinkKind::Invite`].
//!
//! ```text
//! Start --Send--> Sent
//! ```

use crate::error::{ConflictReason, InvalidRequestReason};
use rand_core::CryptoRng;
use time::OffsetDateTime;

use super::{Client, Effect, LinkKind, Refusal, Transition, UNEXPECTED, send_link};
use crate::Error;
use crate::account::{Account, Email, NewAccount, Role};
use crate::config::Config;
use crate::ids::UserId;
use crate::session::{Access, Session};

/// Longest display name, in characters.
pub const MAX_NAME_LEN: usize = 100;

/// Where an invite is.
// States are moved once per request; boxing the large variants would only complicate
// matching on them.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub enum Invite {
    /// Nothing yet.
    Start,
    /// The account is to be created and the invite mailed.
    Sent {
        /// The new, inactive member.
        account: NewAccount,
    },
}

/// What happened.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum InviteEvent {
    /// The owner asked to invite someone.
    Send {
        /// Who is inviting.
        inviter: Account,
        /// The inviter's session; it must be within the step-up window.
        session: Session,
        /// The invitee's address.
        email: Email,
        /// The invitee's display name; blank means the address.
        display_name: Option<String>,
        /// Whether an account with `email` exists already.
        email_taken: bool,
        /// The client.
        client: Client,
    },
}

impl Invite {
    /// Applies `event`.
    ///
    /// # Errors
    ///
    /// A [`Refusal`]: [`Error::StepUpRequired`] outside the step-up window;
    /// [`Error::Forbidden`] for a member; [`Error::InvalidRequest`] with `name_too_long`;
    /// [`Error::Conflict`] with `email_taken`.
    pub fn advance<R: CryptoRng + ?Sized>(
        self,
        config: &Config,
        event: InviteEvent,
        now: OffsetDateTime,
        rng: &mut R,
    ) -> Result<Transition<Invite>, Refusal> {
        let (
            Invite::Start,
            InviteEvent::Send {
                inviter,
                session,
                email,
                display_name,
                email_taken,
                client,
            },
        ) = (self, event)
        else {
            return Err(UNEXPECTED.into());
        };
        if session.user_id != inviter.id {
            return Err(Error::Unauthorized.into());
        }
        session.authorize(inviter.active, Access::Recent, config.step_up_window(), now)?;
        if inviter.role != Role::Owner {
            return Err(Error::Forbidden.into());
        }
        let display_name = optional_name(display_name)?.unwrap_or_else(|| email.to_string());
        if email_taken {
            return Err(Error::Conflict(ConflictReason::EmailTaken).into());
        }
        let account = NewAccount {
            id: UserId::random(rng),
            email,
            display_name,
            role: Role::Member,
            created_at: now,
        };
        let mut effects = vec![Effect::CreateAccount(account.clone())];
        effects.extend(send_link(
            config,
            &account.to_account(),
            LinkKind::Invite,
            None,
            &client,
            now,
            rng,
        ));
        Ok(Transition {
            state: Invite::Sent { account },
            effects,
        })
    }
}

/// Trims a display name; blank is `None`.
///
/// # Errors
///
/// [`Error::InvalidRequest`] with `name_too_long` beyond [`MAX_NAME_LEN`] characters.
pub fn optional_name(raw: Option<String>) -> Result<Option<String>, Error> {
    match raw.map(|name| name.trim().to_owned()) {
        Some(name) if name.chars().count() > MAX_NAME_LEN => {
            Err(Error::InvalidRequest(InvalidRequestReason::NameTooLong))
        }
        Some(name) if name.is_empty() => Ok(None),
        other => Ok(other),
    }
}
