//! The owner resets a member's sign-in, for a member who lost their second factor.
//!
//! ```text
//! Start --Reset--> Done        then the member: setup with LinkKind::Invite
//! ```
//!
//! One step, from the owner's session within the step-up window. Its effects, in order:
//!
//! 1. [`Effect::RevokeSessions`]: the member is signed out everywhere.
//! 2. [`Effect::RemoveFactors`]: TOTP, passkeys and recovery codes are removed, and the
//!    password too when the owner asks for it.
//! 3. [`Effect::DeactivateAccount`] and [`Effect::ClearFailures`]: the account signs in again
//!    only after setup, and starts with no failures.
//! 4. [`Effect::DeletePendingLinks`]: older links and email codes stop working.
//! 5. A one-time setup link for [`Config::invite_ttl`] (24 hours by default), stored with
//!    [`Effect::StoreLinkToken`] as a [`LinkKind::Invite`] link and mailed as
//!    [`MailKind::SignInReset`].
//! 6. An [`AuditKind::SignInReset`] event for the member, with detail `by:<owner id>`.
//!
//! The member opens the link and goes through [`setup`](super::setup) exactly like an
//! invitee (`SetupEvent::Redeem { kind: LinkKind::Invite, .. }`): a new password if theirs
//! was removed (or optionally anyway, with `PasswordSet`), a new TOTP or passkey, and
//! `Finish`, which issues new recovery codes and signs them in. Serve the reset link on the
//! invite page; [`Config::invite_url`] is where it points.
//!
//! ```
//! use latchkey::flow::reset::{Reset, ResetEvent};
//! # use latchkey::{Account, Config, CryptoRng};
//! # use latchkey::flow::{Client, Effect, Refusal};
//! # use latchkey::session::Session;
//! # use time::OffsetDateTime;
//!
//! /// POST /members/{id}/reset-sign-in, from the owner's recent session.
//! fn reset_sign_in(
//!     config: &Config,
//!     owner: Account,
//!     session: Session,
//!     member: Account,
//!     client: Client,
//!     now: OffsetDateTime,
//!     rng: &mut impl CryptoRng,
//! ) -> Result<Vec<Effect>, Refusal> {
//!     let event = ResetEvent::Reset { admin: owner, session, member, remove_password: false, client };
//!     Ok(Reset::Start.advance(config, event, now, rng)?.effects)
//! }
//! ```

use rand_core::CryptoRng;
use time::OffsetDateTime;

use super::{Client, Effect, LinkKind, Refusal, Transition, UNEXPECTED, audit, issue_link};
use crate::Error;
use crate::account::{Account, Factors, Lockout, Role};
use crate::audit::AuditKind;
use crate::config::Config;
use crate::mail::MailKind;
use crate::session::{Access, Session};

/// Where a sign-in reset is.
// States are moved once per request; boxing the large variants would only complicate
// matching on them.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Reset {
    /// Nothing yet.
    Start,
    /// The member's sign-in is reset and the setup link mailed.
    Done {
        /// The member as it is after the reset: inactive, without second factors.
        account: Account,
    },
}

/// What happened.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ResetEvent {
    /// The owner asked to reset a member's sign-in.
    Reset {
        /// Who is resetting: the owner.
        admin: Account,
        /// The owner's session; it must be within the step-up window.
        session: Session,
        /// Whose sign-in to reset.
        member: Account,
        /// Whether to remove the member's password too. Either way the member may choose a
        /// new one during setup.
        remove_password: bool,
        /// The owner's client.
        client: Client,
    },
}

impl Reset {
    /// Applies `event`.
    ///
    /// # Errors
    ///
    /// A [`Refusal`]: [`Error::Unauthorized`] for a session that is not the admin's;
    /// [`Error::StepUpRequired`] outside the step-up window; [`Error::Forbidden`] when the
    /// admin is not the owner, or the member is the owner (reset the owner to first-open
    /// setup instead, with [`AuditKind::OwnerReset`]); [`Error::InvalidRequest`] for an event
    /// the state does not take.
    pub fn advance<R: CryptoRng + ?Sized>(
        self,
        config: &Config,
        event: ResetEvent,
        now: OffsetDateTime,
        rng: &mut R,
    ) -> Result<Transition<Reset>, Refusal> {
        let (
            Reset::Start,
            ResetEvent::Reset {
                admin,
                session,
                mut member,
                remove_password,
                client,
            },
        ) = (self, event)
        else {
            return Err(UNEXPECTED.into());
        };
        if session.user_id != admin.id {
            return Err(Error::Unauthorized.into());
        }
        session.authorize(admin.active, Access::Recent, config.step_up_window(), now)?;
        if admin.role != Role::Owner || member.role == Role::Owner || member.id == admin.id {
            return Err(Error::Forbidden.into());
        }
        let user_id = member.id;
        let keep_password = member.factors.password && !remove_password;
        member.active = false;
        member.factors = Factors::new(keep_password, false, 0);
        member.lockout = Lockout::default();
        let issued = issue_link(config, &member, LinkKind::Invite, now, rng);
        let mut effects = vec![
            Effect::RevokeSessions { user_id },
            Effect::RemoveFactors {
                user_id,
                password: remove_password,
            },
            Effect::DeactivateAccount { user_id },
            Effect::ClearFailures { user_id },
            Effect::DeletePendingLinks { user_id },
        ];
        let reset = audit(AuditKind::SignInReset, Some(user_id), &client, now)
            .with_detail(format!("by:{}", admin.id));
        effects.extend(super::mail_link(
            &member,
            issued,
            MailKind::SignInReset,
            reset,
        ));
        Ok(Transition {
            state: Reset::Done { account: member },
            effects,
        })
    }
}
