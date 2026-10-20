//! The sign-in flows as state machines over plain data.
//!
//! Each flow is an `enum` of states with an `advance` method that consumes the state, takes
//! one event (carrying the facts the app loaded: the account, its factor material, the
//! presented device cookie, a verification result) and `now`, and returns either a
//! [`Transition`] (the next state and the [`Effect`]s to carry out) or a [`Refusal`] (the
//! error to answer with and the effects that must still happen, such as counting a failure).
//!
//! The flows never touch storage, the network or the clock. The app:
//!
//! 1. loads what the event needs (and checks its own rate limits),
//! 2. calls `advance`,
//! 3. carries out **every** effect, in order, also on refusal: storage effects ideally in one
//!    transaction, then mails,
//! 4. answers the client from the new state or the refusal's [`Error`].
//!
//! | Flow | Module | Starts | Ends |
//! |---|---|---|---|
//! | Password, then TOTP, recovery code or passkey; or a passkey alone | [`sign_in`] | [`SignIn::Start`](sign_in::SignIn::Start) | [`SignIn::SignedIn`](sign_in::SignIn::SignedIn) |
//! | Emailed sign-in link | [`email_link`] | [`EmailLink::Start`](email_link::EmailLink::Start) | [`EmailLink::SignedIn`](email_link::EmailLink::SignedIn) |
//! | First-open owner setup, and an invitee's setup | [`setup`] | [`Setup::Start`](setup::Setup::Start) | [`Setup::Complete`](setup::Setup::Complete) |
//! | The owner invites a member | [`invite`] | [`Invite::Start`](invite::Invite::Start) | [`Invite::Sent`](invite::Invite::Sent) |
//! | Step-up re-authentication | [`step_up`] | [`StepUp::new`](step_up::StepUp::new) | [`StepUp::Done`](step_up::StepUp::Done) |
//!
//! Single-step actions are plain functions: [`issue_session`], [`sign_out`],
//! [`password_changed`] and [`regenerate_recovery_codes`].

pub mod email_link;
pub mod invite;
pub mod setup;
pub mod sign_in;
pub mod step_up;

use rand_core::CryptoRng;
use time::OffsetDateTime;

use crate::Error;
use crate::account::{Account, AccountKey, Lockout, NewAccount};
use crate::audit::{AuditEvent, AuditKind};
use crate::config::Config;
use crate::http::{IpTag, SetCookie};
use crate::ids::{SessionId, UserId};
use crate::mail::{Mail, MailKind, SignInDetails};
use crate::password::PasswordHash;
use crate::recovery::{self, RecoveryCode, RecoveryCodeHash};
use crate::session::{AppMethod, Session, SignInMethod, Stage};
use crate::token::{self, SecretToken, TokenHash};
use crate::totp::{self, TotpSecret, TotpStep};

/// What a one-time link is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum LinkKind {
    /// Owner setup.
    Setup,
    /// A member's invite.
    Invite,
    /// Sign-in.
    SignIn,
}

impl LinkKind {
    /// `setup`, `invite` or `sign_in`, the values latchkey 0.2 stored.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            LinkKind::Setup => "setup",
            LinkKind::Invite => "invite",
            LinkKind::SignIn => "sign_in",
        }
    }
}

/// A one-time link as the app stores it, under its token's hash.
///
/// Redeeming must be single use: delete the row by hash and read it in one step (for
/// example `DELETE ... RETURNING`), then pass what was deleted (or `None`) to the flow,
/// which checks the kind and expiry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct LinkToken {
    /// What it is for.
    pub kind: LinkKind,
    /// Whose it is.
    pub user_id: UserId,
    /// When it was issued; the resend cooldown runs from the latest one.
    pub created_at: OffsetDateTime,
    /// When it stops working.
    pub expires_at: OffsetDateTime,
}

impl LinkToken {
    /// Whether it can be redeemed as `kind` at `now`.
    #[must_use]
    pub fn is_redeemable(&self, kind: LinkKind, now: OffsetDateTime) -> bool {
        self.kind == kind && self.expires_at > now
    }
}

/// What the app knows about the client making the request.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Client {
    /// The client IP as an [`IpTag`].
    pub ip_tag: Option<IpTag>,
    /// The `User-Agent`, shortened with
    /// [`truncate_user_agent`](crate::http::truncate_user_agent).
    pub user_agent: Option<String>,
    /// The device cookie the client presented, unchecked.
    pub device_cookie: Option<SecretToken>,
    /// Whether that cookie's hash is already remembered for the account this request signs
    /// in. Look it up with [`TokenHash::of`] before calling the flow; `false` when there is no
    /// cookie.
    pub device_known: bool,
}

/// The TOTP material for checking a code.
#[derive(Debug, Clone)]
pub struct TotpMaterial {
    /// The confirmed secret (opened with [`DataKey::open_totp`](crate::seal::DataKey::open_totp)).
    pub secret: TotpSecret,
    /// The last step accepted for this account.
    pub last_used_step: Option<TotpStep>,
}

/// What a TOTP or recovery code is checked against.
#[derive(Debug, Clone, Default)]
pub struct CodeMaterial {
    /// The account's TOTP, if enrolled.
    pub totp: Option<TotpMaterial>,
    /// The hashes of the account's unused recovery codes.
    pub recovery_codes: Vec<RecoveryCodeHash>,
}

/// Which code matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeMatch {
    /// A TOTP code for this step.
    Totp(TotpStep),
    /// This recovery code.
    RecoveryCode(RecoveryCodeHash),
}

/// Checks a code typed into a single "code" field: six digits are a TOTP code (accepted only
/// for a step newer than the last used one), anything else a recovery code.
#[must_use]
pub fn check_code(code: &str, material: &CodeMaterial, now: OffsetDateTime) -> Option<CodeMatch> {
    if totp::looks_like_code(code) {
        let totp = material.totp.as_ref()?;
        return totp::verify(&totp.secret, code, totp.last_used_step, now)
            .ok()
            .map(CodeMatch::Totp);
    }
    recovery::verify(code, &material.recovery_codes).map(CodeMatch::RecoveryCode)
}

/// Something the app must do. Carry out every effect of a [`Transition`] or [`Refusal`], in
/// order.
#[derive(Debug, Clone)]
#[must_use = "effects must be carried out"]
#[non_exhaustive]
pub enum Effect {
    /// Insert the session. With `replaces`, delete the session with that token hash in the
    /// same transaction (a stage change issues a new token).
    StoreSession {
        /// The session to insert.
        session: Session,
        /// The session it replaces.
        replaces: Option<TokenHash>,
    },
    /// Delete the session with this token hash.
    DeleteSession {
        /// Its token hash.
        token_hash: TokenHash,
    },
    /// Send this `Set-Cookie` header.
    SetCookie(SetCookie),
    /// Store the account's failure count and lock.
    SaveLockout {
        /// Whose.
        user_id: UserId,
        /// The new state.
        lockout: Lockout,
    },
    /// Record a wrong password for the throttle
    /// ([`WrongPasswordThrottle::record`](crate::limits::WrongPasswordThrottle::record)).
    RecordWrongPassword {
        /// The address it counts under.
        key: AccountKey,
    },
    /// Store `step` as the account's last used TOTP step, only if it is newer than the
    /// stored one (compare-and-set); if it is not, the code was raced and the sign-in must
    /// be refused.
    UseTotpStep {
        /// Whose.
        user_id: UserId,
        /// The matched step.
        step: TotpStep,
    },
    /// Mark this recovery code used, only if it is still unused (compare-and-set), as above.
    UseRecoveryCode {
        /// Whose.
        user_id: UserId,
        /// Which.
        hash: RecoveryCodeHash,
    },
    /// Replace the account's recovery codes with these.
    StoreRecoveryCodes {
        /// Whose.
        user_id: UserId,
        /// The new hashes.
        hashes: Vec<RecoveryCodeHash>,
    },
    /// Store a one-time link under its token hash.
    StoreLinkToken {
        /// Look-up key.
        token_hash: TokenHash,
        /// The record.
        link: LinkToken,
    },
    /// Send this mail.
    SendMail(Mail),
    /// Append this audit event.
    Audit(AuditEvent),
    /// Remember (or refresh `last_seen_at` of) the device with this cookie hash for the
    /// account. Forget devices unused for [`Config::device_ttl`].
    RememberDevice {
        /// Whose.
        user_id: UserId,
        /// The device cookie's hash.
        device_hash: TokenHash,
        /// Now.
        seen_at: OffsetDateTime,
    },
    /// Create this inactive account; refuse duplicates by email.
    CreateAccount(NewAccount),
    /// Store the account's new password hash.
    StorePassword {
        /// Whose.
        user_id: UserId,
        /// The hash.
        hash: PasswordHash,
    },
    /// Mark the account active.
    ActivateAccount {
        /// Whose.
        user_id: UserId,
    },
    /// Set the session's `authenticated_at` and `method`: the step-up window starts again.
    MarkStepUp {
        /// Which session.
        token_hash: TokenHash,
        /// Now.
        at: OffsetDateTime,
        /// [`SignInMethod::StepUp`].
        method: SignInMethod,
    },
}

/// A flow moved on: the new state and what to do.
#[derive(Debug)]
#[must_use = "the effects of a transition must be carried out"]
pub struct Transition<S> {
    /// The new state.
    pub state: S,
    /// What to do, in order.
    pub effects: Vec<Effect>,
}

/// A flow refused an event: the error to answer with, and what must still be done (such as
/// counting the failure).
#[derive(Debug, thiserror::Error)]
#[error("{error}")]
#[must_use = "the effects of a refusal must still be carried out"]
pub struct Refusal {
    /// The answer for the client.
    #[source]
    pub error: Error,
    /// What to do anyway, in order.
    pub effects: Vec<Effect>,
}

impl From<Error> for Refusal {
    fn from(error: Error) -> Self {
        Self {
            error,
            effects: Vec::new(),
        }
    }
}

impl Refusal {
    fn with(error: Error, effects: Vec<Effect>) -> Self {
        Self { error, effects }
    }
}

const UNEXPECTED: Error = Error::InvalidRequest("unexpected_flow_event");

fn audit(
    kind: AuditKind,
    user_id: Option<UserId>,
    client: &Client,
    now: OffsetDateTime,
) -> AuditEvent {
    AuditEvent::new(kind, user_id, now, client.ip_tag.clone())
}

#[allow(clippy::too_many_arguments)]
fn start_session<R: CryptoRng + ?Sized>(
    config: &Config,
    user_id: UserId,
    stage: Stage,
    method: Option<SignInMethod>,
    client: &Client,
    replaces: Option<TokenHash>,
    now: OffsetDateTime,
    rng: &mut R,
) -> (Session, Vec<Effect>) {
    let ttl = match stage {
        Stage::Full => config.session_ttl(),
        Stage::SecondFactor => config.pending_ttl(),
        Stage::Setup => config.setup_ttl(),
    };
    let issued = token::issue(rng);
    let session = Session {
        id: SessionId::random(rng),
        token_hash: issued.hash,
        user_id,
        stage,
        csrf_token: token::issue(rng).token,
        method,
        created_at: now,
        expires_at: now.saturating_add(ttl),
        authenticated_at: (stage == Stage::Full).then_some(now),
        ip_tag: client.ip_tag.clone(),
        user_agent: client.user_agent.clone(),
    };
    let effects = vec![
        Effect::StoreSession {
            session: session.clone(),
            replaces,
        },
        Effect::SetCookie(SetCookie::new(
            config.cookie_name().clone(),
            &issued.token,
            ttl,
        )),
    ];
    (session, effects)
}

/// Clears failures, starts a full session, audits the sign-in and recognises the device.
fn complete_sign_in<R: CryptoRng + ?Sized>(
    config: &Config,
    account: &Account,
    method: &SignInMethod,
    client: &Client,
    replaces: Option<TokenHash>,
    now: OffsetDateTime,
    rng: &mut R,
) -> (Session, Vec<Effect>) {
    let mut effects = vec![Effect::SaveLockout {
        user_id: account.id,
        lockout: Lockout::default(),
    }];
    let (session, started) = start_session(
        config,
        account.id,
        Stage::Full,
        Some(method.clone()),
        client,
        replaces,
        now,
        rng,
    );
    effects.extend(started);
    effects.push(Effect::Audit(
        audit(AuditKind::SignIn, Some(account.id), client, now).with_detail(method.as_str()),
    ));
    effects.extend(recognise_device(config, account, method, client, now, rng));
    (session, effects)
}

/// The device cookie is (re)set on every completed sign-in. A device the account has not
/// used before is audited and mailed, except when completing setup, which only records it.
fn recognise_device<R: CryptoRng + ?Sized>(
    config: &Config,
    account: &Account,
    method: &SignInMethod,
    client: &Client,
    now: OffsetDateTime,
    rng: &mut R,
) -> Vec<Effect> {
    let presented = client
        .device_cookie
        .as_ref()
        .and_then(|cookie| cookie.hash().map(|hash| (cookie.clone(), hash)));
    let (cookie, hash, known) = if let Some((cookie, hash)) = presented {
        (cookie, hash, client.device_known)
    } else {
        let issued = token::issue(rng);
        (issued.token, issued.hash, false)
    };
    let mut effects = vec![Effect::RememberDevice {
        user_id: account.id,
        device_hash: hash,
        seen_at: now,
    }];
    if !known && *method != SignInMethod::Setup {
        effects.push(Effect::Audit(
            audit(AuditKind::NewDevice, Some(account.id), client, now).with_detail(method.as_str()),
        ));
        effects.push(Effect::SendMail(Mail {
            kind: MailKind::NewDevice,
            to: account.email.clone(),
            link: config.sessions_url().clone(),
            expires_at: None,
            sign_in: Some(SignInDetails {
                at: now,
                method: method.clone(),
                user_agent: client.user_agent.clone(),
            }),
        }));
    }
    effects.push(Effect::SetCookie(SetCookie::new(
        config.device_cookie_name().clone(),
        &cookie,
        config.device_ttl(),
    )));
    effects
}

/// Audits the failure and counts it towards the lockout.
fn failure(
    config: &Config,
    account: &Account,
    detail: &str,
    client: &Client,
    now: OffsetDateTime,
) -> Vec<Effect> {
    let mut effects = vec![Effect::Audit(
        audit(AuditKind::SignInFailed, Some(account.id), client, now).with_detail(detail),
    )];
    let (lockout, lock) = account.lockout.after_failure(config.lockout(), now);
    effects.push(Effect::SaveLockout {
        user_id: account.id,
        lockout,
    });
    if let Some(lock) = lock {
        effects.push(Effect::Audit(
            audit(AuditKind::Lockout, Some(account.id), client, now)
                .with_detail(format!("{}s", lock.whole_seconds())),
        ));
    }
    effects
}

/// Issues a link and mails it, unless the resend cooldown is running (not for invites).
fn send_link<R: CryptoRng + ?Sized>(
    config: &Config,
    account: &Account,
    kind: LinkKind,
    last_sent_at: Option<OffsetDateTime>,
    client: &Client,
    now: OffsetDateTime,
    rng: &mut R,
) -> Vec<Effect> {
    if kind != LinkKind::Invite
        && last_sent_at.is_some_and(|last| last.saturating_add(config.resend_cooldown()) > now)
    {
        return Vec::new();
    }
    let (ttl, mut link, mail_kind, audit_kind) = match kind {
        LinkKind::Setup => (
            config.link_ttl(),
            config.setup_url().clone(),
            MailKind::Setup,
            AuditKind::SetupLinkSent,
        ),
        LinkKind::SignIn => (
            config.link_ttl(),
            config.sign_in_link_url().clone(),
            MailKind::SignInLink,
            AuditKind::SignInLinkSent,
        ),
        LinkKind::Invite => (
            config.invite_ttl(),
            config.invite_url().clone(),
            MailKind::Invite,
            AuditKind::InviteSent,
        ),
    };
    let issued = token::issue(rng);
    let expires_at = now.saturating_add(ttl);
    link.query_pairs_mut()
        .append_pair("token", issued.token.expose_secret());
    vec![
        Effect::StoreLinkToken {
            token_hash: issued.hash,
            link: LinkToken {
                kind,
                user_id: account.id,
                created_at: now,
                expires_at,
            },
        },
        Effect::SendMail(Mail {
            kind: mail_kind,
            to: account.email.clone(),
            link,
            expires_at: Some(expires_at),
            sign_in: None,
        }),
        Effect::Audit(audit(audit_kind, Some(account.id), client, now)),
    ]
}

/// The effects of a code that matched: consume it, and audit a recovery code.
fn use_code(
    account: &Account,
    matched: CodeMatch,
    client: &Client,
    now: OffsetDateTime,
) -> Vec<Effect> {
    match matched {
        CodeMatch::Totp(step) => vec![Effect::UseTotpStep {
            user_id: account.id,
            step,
        }],
        CodeMatch::RecoveryCode(hash) => vec![
            Effect::UseRecoveryCode {
                user_id: account.id,
                hash,
            },
            Effect::Audit(audit(
                AuditKind::RecoveryCodeUsed,
                Some(account.id),
                client,
                now,
            )),
        ],
    }
}

/// Starts a full session for a sign-in the app completed itself, such as a desktop app
/// handed off from a signed-in browser.
///
/// **This checks no factor.** Only call it for an account the app has just verified through
/// latchkey (for example the user of a full session that started the hand-off), never with a
/// user id a client chose. Everything else is as after a normal sign-in: failures cleared, a
/// fresh token, `session_ttl`, `authenticated_at` = `now`, a `sign_in` audit event with
/// `method`, and the new-device check and mail.
///
/// # Errors
///
/// [`Error::Forbidden`] for an inactive account or one without a password and a second
/// factor; [`Error::TooManyAttempts`] while it is locked.
pub fn issue_session<R: CryptoRng + ?Sized>(
    config: &Config,
    account: &Account,
    method: AppMethod,
    client: &Client,
    now: OffsetDateTime,
    rng: &mut R,
) -> Result<Transition<Session>, Error> {
    if !account.active || !account.factors.is_complete() {
        return Err(Error::Forbidden);
    }
    account.lockout.check(now)?;
    let (session, effects) = complete_sign_in(
        config,
        account,
        &SignInMethod::App(method),
        client,
        None,
        now,
        rng,
    );
    Ok(Transition {
        state: session,
        effects,
    })
}

/// Ends the session: delete it, clear its cookie, audit. The device cookie stays.
#[must_use = "effects must be carried out"]
pub fn sign_out(
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
        Effect::Audit(audit(
            AuditKind::SignOut,
            Some(session.user_id),
            client,
            now,
        )),
    ]
}

/// A password set from a session that may do so ([`Access::Recent`](crate::session::Access)),
/// hashed with
/// [`PasswordHasher::hash_new_password`](crate::password::PasswordHasher::hash_new_password).
#[must_use = "effects must be carried out"]
pub fn password_changed(
    user_id: UserId,
    hash: PasswordHash,
    client: &Client,
    now: OffsetDateTime,
) -> Vec<Effect> {
    vec![
        Effect::StorePassword { user_id, hash },
        Effect::Audit(audit(AuditKind::PasswordSet, Some(user_id), client, now)),
    ]
}

/// New recovery codes replacing the old ones (needs [`Access::Recent`](crate::session::Access)):
/// show the codes once, carry out the effects.
pub fn regenerate_recovery_codes<R: CryptoRng + ?Sized>(
    user_id: UserId,
    client: &Client,
    now: OffsetDateTime,
    rng: &mut R,
) -> Transition<Vec<RecoveryCode>> {
    let issued = recovery::generate(rng);
    Transition {
        state: issued.codes,
        effects: vec![
            Effect::StoreRecoveryCodes {
                user_id,
                hashes: issued.hashes,
            },
            Effect::Audit(audit(
                AuditKind::RecoveryCodesIssued,
                Some(user_id),
                client,
                now,
            )),
        ],
    }
}
