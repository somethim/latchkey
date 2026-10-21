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
//! | Emailed sign-in link or code, then a second factor | [`email_link`], then [`sign_in`] | [`EmailLink::Start`](email_link::EmailLink::Start) | [`SignIn::SignedIn`](sign_in::SignIn::SignedIn) |
//! | First-open owner setup, and an invitee's setup | [`setup`] | [`Setup::Start`](setup::Setup::Start) | [`Setup::Complete`](setup::Setup::Complete) |
//! | The owner invites a member | [`invite`] | [`Invite::Start`](invite::Invite::Start) | [`Invite::Sent`](invite::Invite::Sent) |
//! | The owner resets a member's sign-in (lost second factor) | [`reset`], then [`setup`] | [`Reset::Start`](reset::Reset::Start) | [`Reset::Done`](reset::Reset::Done) |
//! | Step-up re-authentication | [`step_up`] | [`StepUp::new`](step_up::StepUp::new) | [`StepUp::Done`](step_up::StepUp::Done) |
//!
//! Single-step actions are plain functions: [`issue_session`], [`sign_out`],
//! [`password_changed`] and [`regenerate_recovery_codes`].

pub mod email_link;
pub mod invite;
pub mod reset;
pub mod setup;
pub mod sign_in;
pub mod step_up;

use crate::error::InvalidRequestReason;
use rand_core::CryptoRng;
use time::OffsetDateTime;

use crate::Error;
use crate::account::{Account, AccountKey, NewAccount};
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
use email_link::EmailCodeRequest;

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
#[non_exhaustive]
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
    /// A link record read back from storage.
    #[must_use]
    pub const fn new(
        kind: LinkKind,
        user_id: UserId,
        created_at: OffsetDateTime,
        expires_at: OffsetDateTime,
    ) -> Self {
        Self {
            kind,
            user_id,
            created_at,
            expires_at,
        }
    }
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
#[non_exhaustive]
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

impl Client {
    /// A client with this IP tag and user agent, and no device cookie.
    #[must_use]
    pub fn new(ip_tag: Option<IpTag>, user_agent: Option<String>) -> Self {
        Self {
            ip_tag,
            user_agent,
            device_cookie: None,
            device_known: false,
        }
    }

    /// The device cookie the client presented, and whether its hash is remembered for the
    /// account this request signs in.
    #[must_use]
    pub fn with_device_cookie(mut self, cookie: Option<SecretToken>, known: bool) -> Self {
        self.device_known = known && cookie.is_some();
        self.device_cookie = cookie;
        self
    }
}

/// The TOTP material for checking a code.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct TotpMaterial {
    /// The confirmed secret (opened with [`DataKey::open_totp`](crate::seal::DataKey::open_totp)).
    pub secret: TotpSecret,
    /// The last step accepted for this account.
    pub last_used_step: Option<TotpStep>,
}

impl TotpMaterial {
    /// The confirmed secret and the last step accepted.
    #[must_use]
    pub fn new(secret: TotpSecret, last_used_step: Option<TotpStep>) -> Self {
        Self {
            secret,
            last_used_step,
        }
    }
}

/// What a TOTP or recovery code is checked against.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct CodeMaterial {
    /// The account's TOTP, if enrolled.
    pub totp: Option<TotpMaterial>,
    /// The hashes of the account's unused recovery codes.
    pub recovery_codes: Vec<RecoveryCodeHash>,
}

impl CodeMaterial {
    /// The account's TOTP, if enrolled, and the hashes of its unused recovery codes.
    #[must_use]
    pub fn new(totp: Option<TotpMaterial>, recovery_codes: Vec<RecoveryCodeHash>) -> Self {
        Self {
            totp,
            recovery_codes,
        }
    }
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
    /// Count one failure, **atomically**: `UPDATE ... SET failures = failures + 1 ...
    /// RETURNING failures` (never read-modify-write from the [`Account`] snapshot, or
    /// concurrent failures are lost). Then, with the returned count `n`, store
    /// [`LockoutPolicy::locked_until`](crate::LockoutPolicy::locked_until)`(n, at)` as
    /// `locked_until` when it is `Some`, and append
    /// [`LockoutPolicy::lockout_event`](crate::LockoutPolicy::lockout_event)`(user_id, n, at,
    /// ip_tag)` when it is `Some`.
    RecordFailure {
        /// Whose.
        user_id: UserId,
        /// Now.
        at: OffsetDateTime,
        /// The client, for the lockout audit event.
        ip_tag: Option<IpTag>,
    },
    /// Reset the account's failure count to 0 and clear `locked_until`.
    ClearFailures {
        /// Whose.
        user_id: UserId,
    },
    /// Count one wrong step-up guess against this session, **atomically**: `UPDATE sessions
    /// SET step_up_failures = step_up_failures + 1 WHERE token_hash = ? RETURNING
    /// step_up_failures`. Only under
    /// [`StepUpFailures::PerSession`](step_up::StepUpFailures::PerSession). When the guess
    /// reaches the limit the flow also ends the session (with
    /// [`DeleteSession`](Effect::DeleteSession)); an app may end it as soon as the returned
    /// count satisfies
    /// [`StepUpFailures::ends_session`](step_up::StepUpFailures::ends_session), which also
    /// covers guesses that raced, and otherwise the next step-up from it is refused and ends
    /// it.
    RecordStepUpFailure {
        /// The session's token hash.
        token_hash: TokenHash,
    },
    /// Reset this session's step-up failure count to 0, after a step-up succeeded. Only under
    /// [`StepUpFailures::PerSession`](step_up::StepUpFailures::PerSession).
    ClearStepUpFailures {
        /// The session's token hash.
        token_hash: TokenHash,
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
    /// Store a pending email sign-in code under the hash of the requesting device's binding
    /// cookie, replacing any request already stored under it. See
    /// [`email_link`](email_link#what-the-app-stores).
    StoreEmailCode {
        /// Look-up key: the hash of the binding cookie.
        binding_hash: TokenHash,
        /// The record.
        request: EmailCodeRequest,
    },
    /// A sign-in link was redeemed: delete the pending code mailed with it (the request whose
    /// `link_hash` is this), if any.
    DeleteEmailCode {
        /// The redeemed link's hash.
        link_hash: TokenHash,
    },
    /// An email code was accepted: delete the pending request under `binding_hash` **and**
    /// the link under `link_hash` in one transaction, compare-and-set. If either was already
    /// gone, the link or another guess won a race: refuse the sign-in.
    ConsumeEmailCode {
        /// The binding cookie's hash.
        binding_hash: TokenHash,
        /// The link mailed with the code.
        link_hash: TokenHash,
    },
    /// An email sign-in request ended unused (its attempt budget is spent, it expired, or its
    /// account is gone): delete the pending request and its link.
    DeleteEmailSignIn {
        /// The binding cookie's hash.
        binding_hash: TokenHash,
        /// The link mailed with the code.
        link_hash: TokenHash,
    },
    /// Delete every session of the account.
    RevokeSessions {
        /// Whose.
        user_id: UserId,
    },
    /// Remove the account's second factors: its TOTP secret (confirmed and pending), every
    /// passkey and every recovery code, and with `password` its password too. Reset its
    /// last used TOTP step.
    RemoveFactors {
        /// Whose.
        user_id: UserId,
        /// Whether to remove the password as well.
        password: bool,
    },
    /// Mark the account inactive (it signs in again only after setup).
    DeactivateAccount {
        /// Whose.
        user_id: UserId,
    },
    /// Delete every one-time link and pending email code of the account.
    DeletePendingLinks {
        /// Whose.
        user_id: UserId,
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
#[non_exhaustive]
pub struct Transition<S> {
    /// The new state.
    pub state: S,
    /// What to do, in order.
    pub effects: Vec<Effect>,
}

impl<S> Transition<S> {
    /// A new state and its effects, for an app's own flow steps and tests.
    pub fn new(state: S, effects: Vec<Effect>) -> Self {
        Self { state, effects }
    }
}

/// A flow refused an event: the error to answer with, and what must still be done (such as
/// counting the failure).
#[derive(Debug, thiserror::Error)]
#[error("{error}")]
#[must_use = "the effects of a refusal must still be carried out"]
#[non_exhaustive]
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
    /// An error and the effects that must still happen, for an app's own flow steps and
    /// tests.
    pub fn new(error: Error, effects: Vec<Effect>) -> Self {
        Self { error, effects }
    }
}

const UNEXPECTED: Error = Error::InvalidRequest(InvalidRequestReason::UnexpectedFlowEvent);

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
        step_up_failures: 0,
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
    let mut effects = vec![Effect::ClearFailures {
        user_id: account.id,
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
        effects.push(Effect::SendMail(Mail::new(
            MailKind::NewDevice,
            account.email.clone(),
            config.sessions_url(),
            None,
            Some(SignInDetails {
                at: now,
                method: method.clone(),
                user_agent: client.user_agent.clone(),
            }),
        )));
    }
    effects.push(Effect::SetCookie(SetCookie::new(
        config.device_cookie_name().clone(),
        &cookie,
        config.device_ttl(),
    )));
    effects
}

/// Audits the failure and counts it towards the lockout.
fn failure(account: &Account, detail: &str, client: &Client, now: OffsetDateTime) -> Vec<Effect> {
    vec![
        Effect::Audit(
            audit(AuditKind::SignInFailed, Some(account.id), client, now).with_detail(detail),
        ),
        Effect::RecordFailure {
            user_id: account.id,
            at: now,
            ip_tag: client.ip_tag.clone(),
        },
    ]
}

/// A freshly issued one-time link: the record and hash to store and the URL to mail.
pub(crate) struct IssuedLink {
    pub(crate) token_hash: TokenHash,
    pub(crate) link: LinkToken,
    pub(crate) url: String,
}

/// Issues a link of `kind` for `account`: `setup_link_ttl` for owner setup, `link_ttl` for
/// sign-in, `invite_ttl` for invites (and sign-in resets).
pub(crate) fn issue_link<R: CryptoRng + ?Sized>(
    config: &Config,
    account: &Account,
    kind: LinkKind,
    now: OffsetDateTime,
    rng: &mut R,
) -> IssuedLink {
    let (ttl, mut url) = match kind {
        LinkKind::Setup => (config.setup_link_ttl(), config.setup_target().clone()),
        LinkKind::SignIn => (config.link_ttl(), config.sign_in_link_target().clone()),
        LinkKind::Invite => (config.invite_ttl(), config.invite_target().clone()),
    };
    let issued = token::issue(rng);
    url.query_pairs_mut()
        .append_pair("token", issued.token.expose_secret());
    IssuedLink {
        token_hash: issued.hash,
        link: LinkToken {
            kind,
            user_id: account.id,
            created_at: now,
            expires_at: now.saturating_add(ttl),
        },
        url: url.into(),
    }
}

/// Issues a setup or invite link and mails it, unless the resend cooldown is running (not
/// for invites). Sign-in links, which carry a code too, are mailed by
/// [`email_link`].
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
    let (mail_kind, audit_kind) = match kind {
        LinkKind::Setup => (MailKind::Setup, AuditKind::SetupLinkSent),
        LinkKind::SignIn => (MailKind::SignInLink, AuditKind::SignInLinkSent),
        LinkKind::Invite => (MailKind::Invite, AuditKind::InviteSent),
    };
    mail_link(
        account,
        issue_link(config, account, kind, now, rng),
        mail_kind,
        audit(audit_kind, Some(account.id), client, now),
    )
}

/// Stores `issued`, mails it as `mail_kind` and appends `event`.
fn mail_link(
    account: &Account,
    issued: IssuedLink,
    mail_kind: MailKind,
    event: AuditEvent,
) -> Vec<Effect> {
    let expires_at = issued.link.expires_at;
    vec![
        Effect::StoreLinkToken {
            token_hash: issued.token_hash,
            link: issued.link,
        },
        Effect::SendMail(Mail::new(
            mail_kind,
            account.email.clone(),
            issued.url,
            Some(expires_at),
            None,
        )),
        Effect::Audit(event),
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
/// [`Error::Forbidden`] for an inactive account or one whose factors are not
/// [sufficient](crate::Factors::are_sufficient) under [`Config::password_only`] (by default
/// a password and a second factor); [`Error::TooManyAttempts`] while it is locked.
pub fn issue_session<R: CryptoRng + ?Sized>(
    config: &Config,
    account: &Account,
    method: AppMethod,
    client: &Client,
    now: OffsetDateTime,
    rng: &mut R,
) -> Result<Transition<Session>, Error> {
    if !account.active || !account.factors.are_sufficient(config.password_only()) {
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
