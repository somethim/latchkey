//! latchkey 0.2's behavioural tests, ported to the pure flows driven by an in-memory app.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use common::{App, Browser, OWNER, PASSWORD, code_of};
use latchkey::account::Email;
use latchkey::audit::AuditKind;
use latchkey::error::{ConflictReason, InvalidRequestReason};
use latchkey::flow::email_link::EmailLink;
use latchkey::flow::invite::{Invite, InviteEvent};
use latchkey::flow::reset::{Reset, ResetEvent};
use latchkey::flow::setup::Setup;
use latchkey::flow::sign_in::{SignIn, SignInEvent};
use latchkey::flow::step_up::StepUp;
use latchkey::flow::{self, LinkKind};
use latchkey::limits::RateLimits;
use latchkey::mail::MailKind;
use latchkey::session::{Access, AppMethod, SignInMethod, Stage};
use latchkey::token::TokenHash;
use latchkey::{Error, Lockout, LockoutPolicy, PasswordOnly, StepUpFailures};
use time::Duration;

fn signed_in_method(state: &SignIn) -> Option<SignInMethod> {
    match state {
        SignIn::SignedIn { session, .. } => session.method.clone(),
        _ => None,
    }
}

// ---- setup ----

#[test]
fn first_open_requires_setup_and_completes_it() {
    let mut app = App::new();
    let mut browser = Browser::default();
    let owner = app.owner_id();
    assert!(!app.account(owner).unwrap().active);
    let (_, codes) = app.setup_owner(&mut browser);
    assert_eq!(codes.len(), 10);
    let account = app.account(owner).unwrap();
    assert!(account.active);
    let session = app.session_of(&browser).unwrap();
    assert_eq!(session.stage, Stage::Full);
    assert_eq!(session.method, Some(SignInMethod::Setup));
    assert_eq!(app.audit_count(AuditKind::SetupCompleted), 1);
    assert_eq!(app.audit_count(AuditKind::RecoveryCodesIssued), 1);
}

#[test]
fn setup_link_goes_only_to_the_owner_and_is_single_use() {
    let mut app = App::new();
    let mut browser = Browser::default();
    app.request_setup(&mut browser);
    let mail = app.mail.last().unwrap().clone();
    assert_eq!(mail.kind, MailKind::Setup);
    assert_eq!(mail.to.as_str(), OWNER);
    assert!(
        mail.link
            .as_str()
            .starts_with("https://home.example.com/setup?token=")
    );
    let token = mail.link_token().unwrap();
    assert!(
        app.redeem_setup(&mut browser, LinkKind::Setup, &token)
            .is_ok()
    );
    let mut other = Browser::default();
    assert_eq!(
        app.redeem_setup(&mut other, LinkKind::Setup, &token).err(),
        Some(Error::SignInFailed)
    );
}

#[test]
fn setup_link_cannot_be_redeemed_as_another_kind() {
    let mut app = App::new();
    let mut browser = Browser::default();
    app.request_setup(&mut browser);
    let token = app.mail.last().unwrap().link_token().unwrap();
    assert_eq!(
        app.redeem_setup(&mut browser, LinkKind::Invite, &token)
            .err(),
        Some(Error::SignInFailed)
    );
}

#[test]
fn setup_link_lasts_an_hour() {
    let mut app = App::new();
    let mut browser = Browser::default();
    app.request_setup(&mut browser);
    let mail = app.mail.last().unwrap().clone();
    assert_eq!(mail.expires_at, Some(app.now + Duration::hours(1)));
    let token = mail.link_token().unwrap();
    app.advance(Duration::hours(1));
    assert_eq!(
        app.redeem_setup(&mut browser, LinkKind::Setup, &token)
            .err(),
        Some(Error::SignInFailed)
    );

    let mut app = App::new();
    app.request_setup(&mut browser);
    let token = app.mail.last().unwrap().link_token().unwrap();
    app.advance(Duration::minutes(59));
    assert!(matches!(
        app.redeem_setup(&mut browser, LinkKind::Setup, &token),
        Ok(Setup::InSetup { .. })
    ));
}

#[test]
fn setup_link_resend_has_a_cooldown() {
    let mut app = App::new();
    let mut browser = Browser::default();
    app.request_setup(&mut browser);
    app.request_setup(&mut browser);
    assert_eq!(
        app.mail.len(),
        1,
        "second request within a minute sends nothing"
    );
    app.advance(Duration::seconds(61));
    app.request_setup(&mut browser);
    assert_eq!(app.mail.len(), 2);
    assert_eq!(app.audit_count(AuditKind::SetupLinkSent), 2);
}

#[test]
fn setup_cannot_complete_without_password_and_a_second_factor() {
    let mut app = App::new();
    let mut browser = Browser::default();
    app.request_setup(&mut browser);
    let token = app.mail.last().unwrap().link_token().unwrap();
    app.redeem_setup(&mut browser, LinkKind::Setup, &token)
        .unwrap();
    assert_eq!(
        app.finish_setup(&mut browser).err(),
        Some(Error::InvalidRequest(
            InvalidRequestReason::PasswordRequired
        ))
    );
    assert_eq!(
        app.setup_password(&mut browser, "short").err(),
        Some(Error::InvalidRequest(
            InvalidRequestReason::PasswordTooShort
        ))
    );
    app.setup_password(&mut browser, PASSWORD).unwrap();
    assert_eq!(
        app.finish_setup(&mut browser).err(),
        Some(Error::InvalidRequest(
            InvalidRequestReason::SecondFactorRequired
        ))
    );
}

#[test]
fn setup_start_sends_nothing_once_the_owner_is_active() {
    let mut app = App::new();
    let mut browser = Browser::default();
    app.setup_owner(&mut browser);
    let sent = app.mail.len();
    app.advance(Duration::minutes(5));
    app.request_setup(&mut browser);
    assert_eq!(app.mail.len(), sent);
}

#[test]
fn setup_session_cannot_reach_signed_in_routes_and_expires() {
    let mut app = App::new();
    let mut browser = Browser::default();
    app.request_setup(&mut browser);
    let token = app.mail.last().unwrap().link_token().unwrap();
    app.redeem_setup(&mut browser, LinkKind::Setup, &token)
        .unwrap();
    let session = app.session_of(&browser).unwrap();
    let window = app.config.step_up_window();
    assert_eq!(
        session.authorize(false, Access::SignedIn, window, app.now),
        Err(Error::Unauthorized)
    );
    assert!(
        session
            .authorize(false, Access::Enrolling, window, app.now)
            .is_ok()
    );
    app.advance(Duration::hours(1));
    assert_eq!(
        app.setup_password(&mut browser, PASSWORD).err(),
        Some(Error::Unauthorized)
    );
}

#[test]
fn the_setup_device_is_remembered_without_a_mail() {
    let mut app = App::new();
    let mut browser = Browser::default();
    app.setup_owner(&mut browser);
    assert!(browser.device_cookie().is_some());
    assert_eq!(app.devices.len(), 1);
    assert_eq!(app.audit_count(AuditKind::NewDevice), 0);
    assert!(!app.mail.iter().any(|mail| mail.kind == MailKind::NewDevice));
}

// ---- password sign-in ----

#[test]
fn password_then_totp_signs_in_and_rotates_the_token() {
    let mut app = App::new();
    let mut browser = Browser::default();
    let (secret, _) = app.setup_owner(&mut browser);
    let mut laptop = Browser::default();
    let first = app.password_step(&mut laptop, OWNER, PASSWORD).unwrap();
    assert!(matches!(first, SignIn::SecondFactor { .. }));
    let pending = app.session_of(&laptop).unwrap();
    assert_eq!(pending.stage, Stage::SecondFactor);
    let window = app.config.step_up_window();
    assert_eq!(
        pending.authorize(true, Access::SignedIn, window, app.now),
        Err(Error::Unauthorized)
    );
    app.advance(Duration::seconds(30));
    let code = secret.code_at(app.now, app.config.totp_params()).unwrap();
    let done = app.code_step(&mut laptop, &code).unwrap();
    assert_eq!(signed_in_method(&done), Some(SignInMethod::PasswordTotp));
    let full = app.session_of(&laptop).unwrap();
    assert_ne!(full.token_hash, pending.token_hash);
    assert!(!app.sessions.contains_key(&pending.token_hash));
    assert!(
        full.authorize(true, Access::Recent, window, app.now)
            .is_ok()
    );
}

#[test]
fn totp_step_cannot_be_replayed() {
    let mut app = App::new();
    let mut browser = Browser::default();
    let (secret, _) = app.setup_owner(&mut browser);
    app.advance(Duration::seconds(30));
    let code = secret.code_at(app.now, app.config.totp_params()).unwrap();
    let mut a = Browser::default();
    app.password_step(&mut a, OWNER, PASSWORD).unwrap();
    app.code_step(&mut a, &code).unwrap();
    let mut b = Browser::default();
    app.password_step(&mut b, OWNER, PASSWORD).unwrap();
    assert_eq!(
        app.code_step(&mut b, &code).err(),
        Some(Error::SignInFailed)
    );
    assert_eq!(app.account(app.owner_id()).unwrap().lockout.failures, 1);
}

#[test]
fn setup_totp_code_cannot_be_reused_for_sign_in() {
    let mut app = App::new();
    let mut browser = Browser::default();
    app.request_setup(&mut browser);
    let token = app.mail.last().unwrap().link_token().unwrap();
    app.redeem_setup(&mut browser, LinkKind::Setup, &token)
        .unwrap();
    app.setup_password(&mut browser, PASSWORD).unwrap();
    let secret = app.enrol_totp(app.owner_id());
    let enrolment_code = secret.code_at(app.now, app.config.totp_params()).unwrap();
    app.finish_setup(&mut browser).unwrap();
    let mut other = Browser::default();
    app.password_step(&mut other, OWNER, PASSWORD).unwrap();
    assert_eq!(
        app.code_step(&mut other, &enrolment_code).err(),
        Some(Error::SignInFailed)
    );
}

#[test]
fn recovery_codes_work_once() {
    let mut app = App::new();
    let mut browser = Browser::default();
    let (_, codes) = app.setup_owner(&mut browser);
    let code = code_of(&codes, 0).to_uppercase();
    let mut a = Browser::default();
    app.password_step(&mut a, OWNER, PASSWORD).unwrap();
    let done = app.code_step(&mut a, &code).unwrap();
    assert_eq!(
        signed_in_method(&done),
        Some(SignInMethod::PasswordRecoveryCode)
    );
    assert_eq!(app.audit_count(AuditKind::RecoveryCodeUsed), 1);
    let mut b = Browser::default();
    app.password_step(&mut b, OWNER, PASSWORD).unwrap();
    assert_eq!(
        app.code_step(&mut b, &code).err(),
        Some(Error::SignInFailed)
    );
}

#[test]
fn wrong_password_and_unknown_email_look_the_same() {
    let mut app = App::new();
    let mut browser = Browser::default();
    app.setup_owner(&mut browser);
    let wrong = app.password_step(&mut Browser::default(), OWNER, "wrong password!!");
    let unknown = app.password_step(&mut Browser::default(), "nobody@example.com", PASSWORD);
    assert_eq!(wrong.err(), Some(Error::SignInFailed));
    assert_eq!(unknown.err(), Some(Error::SignInFailed));
}

#[test]
fn unfinished_account_cannot_sign_in_with_a_password() {
    let mut app = App::new();
    let mut browser = Browser::default();
    app.request_setup(&mut browser);
    let token = app.mail.last().unwrap().link_token().unwrap();
    app.redeem_setup(&mut browser, LinkKind::Setup, &token)
        .unwrap();
    app.setup_password(&mut browser, PASSWORD).unwrap();
    assert_eq!(
        app.password_step(&mut Browser::default(), OWNER, PASSWORD)
            .err(),
        Some(Error::SignInFailed)
    );
}

#[test]
fn lockout_after_five_failures_doubles_and_lifts() {
    let mut app = App::new();
    let mut browser = Browser::default();
    let (secret, _) = app.setup_owner(&mut browser);
    for _ in 0..5 {
        let refused = app.password_step(&mut Browser::default(), OWNER, "wrong password!!");
        assert_eq!(refused.err(), Some(Error::SignInFailed));
    }
    assert_eq!(app.audit_count(AuditKind::Lockout), 1);
    let locked = app.password_step(&mut Browser::default(), OWNER, PASSWORD);
    assert_eq!(
        locked.err(),
        Some(Error::TooManyAttempts {
            retry_after_secs: 300
        })
    );
    app.advance(Duration::minutes(5));
    for _ in 0..5 {
        let _ = app.password_step(&mut Browser::default(), OWNER, "wrong password!!");
    }
    let locked = app.password_step(&mut Browser::default(), OWNER, PASSWORD);
    assert_eq!(locked.err().and_then(|e| e.retry_after_secs()), Some(600));
    app.advance(Duration::minutes(10));
    app.advance(Duration::seconds(30));
    let done = app.sign_in(&mut Browser::default(), OWNER, PASSWORD, &secret);
    assert!(done.is_ok(), "{done:?}");
    assert_eq!(app.account(app.owner_id()).unwrap().lockout.failures, 0);
}

#[test]
fn concurrent_failures_from_one_snapshot_both_count() {
    let mut app = App::new();
    let mut browser = Browser::default();
    app.setup_owner(&mut browser);
    let owner = app.owner_id();
    app.rows.get_mut(&owner).unwrap().lockout.failures = 3;
    // Two requests load the same account (3 failures) before either stores anything.
    let mut refusals = Vec::new();
    for _ in 0..2 {
        let mut laptop = Browser::default();
        let SignIn::SecondFactor { account, session } =
            app.password_step(&mut laptop, OWNER, PASSWORD).unwrap()
        else {
            panic!("no second factor");
        };
        refusals.push((account, session));
    }
    let mut refused = Vec::new();
    for (account, session) in refusals {
        assert_eq!(account.lockout.failures, 3);
        let step = SignIn::second_factor(session, account).advance(
            &app.config,
            SignInEvent::Code {
                code: "000000".into(),
                material: app.material(owner),
                client: latchkey::flow::Client::default(),
            },
            app.now,
            &mut app.rng,
        );
        refused.push(step.err().unwrap());
    }
    for refusal in refused {
        assert_eq!(refusal.error, Error::SignInFailed);
        assert!(
            refusal
                .effects
                .iter()
                .any(|effect| matches!(effect, flow::Effect::RecordFailure { .. })),
            "a failure is an increment, not a stored count"
        );
        app.apply(refusal.effects, &mut Browser::default()).unwrap();
    }
    let lockout = app.account(owner).unwrap().lockout;
    assert_eq!(lockout.failures, 5, "both failures counted");
    assert_eq!(lockout.locked_until, Some(app.now + Duration::minutes(5)));
    assert_eq!(app.audit_count(AuditKind::Lockout), 1);
}

#[test]
fn wrong_second_factor_codes_count_towards_lockout() {
    let mut app = App::new();
    let mut browser = Browser::default();
    app.setup_owner(&mut browser);
    let mut laptop = Browser::default();
    app.password_step(&mut laptop, OWNER, PASSWORD).unwrap();
    for _ in 0..5 {
        assert_eq!(
            app.code_step(&mut laptop, "000000").err(),
            Some(Error::SignInFailed)
        );
    }
    assert!(matches!(
        app.code_step(&mut laptop, "000000").err(),
        Some(Error::TooManyAttempts { .. })
    ));
}

#[test]
fn second_factor_stage_expires() {
    let mut app = App::new();
    let mut browser = Browser::default();
    let (secret, _) = app.setup_owner(&mut browser);
    let mut laptop = Browser::default();
    app.password_step(&mut laptop, OWNER, PASSWORD).unwrap();
    app.advance(Duration::minutes(10));
    let code = secret.code_at(app.now, app.config.totp_params()).unwrap();
    assert_eq!(
        app.code_step(&mut laptop, &code).err(),
        Some(Error::Unauthorized)
    );
}

#[test]
fn signed_in_sessions_expire() {
    let mut app = App::new();
    let mut browser = Browser::default();
    app.setup_owner(&mut browser);
    let session = app.session_of(&browser).unwrap();
    let window = app.config.step_up_window();
    assert!(
        session
            .authorize(true, Access::SignedIn, window, app.now)
            .is_ok()
    );
    app.advance(Duration::days(30));
    assert_eq!(
        session.authorize(true, Access::SignedIn, window, app.now),
        Err(Error::Unauthorized)
    );
}

#[test]
fn passkey_second_factor_needs_a_verified_assertion() {
    let mut app = App::new();
    let mut browser = Browser::default();
    app.setup_owner(&mut browser);
    let mut laptop = Browser::default();
    let SignIn::SecondFactor { account, session } =
        app.password_step(&mut laptop, OWNER, PASSWORD).unwrap()
    else {
        panic!("not at the second factor");
    };
    let client = app.client(&laptop, Some(account.id));
    let refused = SignIn::second_factor(session.clone(), account.clone()).advance(
        &app.config,
        SignInEvent::Passkey {
            verified: false,
            client: client.clone(),
        },
        app.now,
        &mut app.rng,
    );
    assert_eq!(refused.err().map(|r| r.error), Some(Error::SignInFailed));
    let done = SignIn::second_factor(session, account)
        .advance(
            &app.config,
            SignInEvent::Passkey {
                verified: true,
                client,
            },
            app.now,
            &mut app.rng,
        )
        .unwrap();
    assert_eq!(
        signed_in_method(&done.state),
        Some(SignInMethod::PasswordPasskey)
    );
}

#[test]
fn events_out_of_order_are_refused() {
    let mut app = App::new();
    let refused = SignIn::Start.advance(
        &app.config,
        SignInEvent::PasswordChecked {
            matched: true,
            client: latchkey::flow::Client::default(),
        },
        app.now,
        &mut app.rng,
    );
    assert_eq!(
        refused.err().map(|r| r.error),
        Some(Error::InvalidRequest(
            InvalidRequestReason::UnexpectedFlowEvent
        ))
    );
}

// ---- throttle ----

#[test]
fn ten_wrong_passwords_in_fifteen_minutes_throttle_the_account() {
    let mut app = App::with_config(
        latchkey::Config::builder(OWNER, common::ORIGIN)
            .password_params(common::cheap())
            .lockout(LockoutPolicy::new(
                0,
                Duration::minutes(5),
                Duration::hours(1),
            )),
    );
    let mut browser = Browser::default();
    let (secret, _) = app.setup_owner(&mut browser);
    for _ in 0..10 {
        app.advance(Duration::seconds(30));
        assert_eq!(
            app.password_step(&mut Browser::default(), OWNER, "wrong password!!")
                .err(),
            Some(Error::SignInFailed)
        );
    }
    assert!(matches!(
        app.password_step(&mut Browser::default(), OWNER, PASSWORD)
            .err(),
        Some(Error::TooManyAttempts { .. })
    ));
    app.advance(Duration::minutes(15));
    assert!(
        app.sign_in(&mut Browser::default(), OWNER, PASSWORD, &secret)
            .is_ok()
    );
}

#[test]
fn unknown_addresses_are_throttled_the_same_way() {
    let mut app = App::new();
    for _ in 0..10 {
        let _ = app.password_step(&mut Browser::default(), "ghost@example.com", "whatever");
    }
    assert!(matches!(
        app.password_step(&mut Browser::default(), " GHOST@example.com", "whatever")
            .err(),
        Some(Error::TooManyAttempts { .. })
    ));
}

#[test]
fn a_successful_sign_in_does_not_reset_the_throttle() {
    let mut app = App::with_config(
        latchkey::Config::builder(OWNER, common::ORIGIN)
            .password_params(common::cheap())
            .rate_limits(RateLimits::new(30, 10, 3, Duration::minutes(15))),
    );
    let mut browser = Browser::default();
    let (secret, _) = app.setup_owner(&mut browser);
    for _ in 0..2 {
        let _ = app.password_step(&mut Browser::default(), OWNER, "wrong password!!");
    }
    app.advance(Duration::seconds(30));
    app.sign_in(&mut Browser::default(), OWNER, PASSWORD, &secret)
        .unwrap();
    let _ = app.password_step(&mut Browser::default(), OWNER, "wrong password!!");
    assert!(matches!(
        app.password_step(&mut Browser::default(), OWNER, PASSWORD)
            .err(),
        Some(Error::TooManyAttempts { .. })
    ));
}

// ---- email link ----

fn sign_in_code(app: &App) -> String {
    let mail = app.mail.last().unwrap();
    assert_eq!(mail.kind, MailKind::SignInLink);
    mail.code.as_ref().unwrap().expose_secret().to_owned()
}

fn second_factor_session(state: &EmailLink) -> latchkey::session::Session {
    match state {
        EmailLink::SecondFactor { session, .. } => session.clone(),
        other => panic!("expected a second factor, got {other:?}"),
    }
}

/// The second factor after an emailed link or code.
fn totp_after_email(
    app: &mut App,
    browser: &mut Browser,
    secret: &latchkey::totp::TotpSecret,
) -> Result<SignIn, Error> {
    app.advance(Duration::seconds(30));
    let code = secret.code_at(app.now, app.config.totp_params()).unwrap();
    app.code_step(browser, &code)
}

#[test]
fn email_link_needs_the_second_factor_and_works_once() {
    let mut app = App::new();
    let mut browser = Browser::default();
    let (secret, _) = app.setup_owner(&mut browser);
    app.advance(Duration::minutes(2));
    let mut phone = Browser::default();
    app.request_email_link(&mut phone, OWNER);
    let token = app.mail.last().unwrap().link_token().unwrap();
    let state = app.redeem_email_link(&mut phone, &token).unwrap();
    let pending = second_factor_session(&state);
    assert_eq!(pending.stage, Stage::SecondFactor);
    assert_eq!(pending.method, Some(SignInMethod::EmailLink));
    assert_eq!(
        pending.authorize(true, Access::SignedIn, app.config.step_up_window(), app.now),
        Err(Error::Unauthorized),
        "a link alone does not sign in"
    );
    assert_eq!(app.audit_count(AuditKind::SignIn), 1, "only setup so far");
    let done = totp_after_email(&mut app, &mut phone, &secret).unwrap();
    assert_eq!(signed_in_method(&done), Some(SignInMethod::EmailTotp));
    assert_eq!(app.session_of(&phone).unwrap().stage, Stage::Full);
    assert_eq!(
        app.redeem_email_link(&mut Browser::default(), &token).err(),
        Some(Error::SignInFailed)
    );
}

#[test]
fn email_link_then_a_recovery_code_or_a_passkey() {
    let mut app = App::new();
    let mut browser = Browser::default();
    let (_, codes) = app.setup_owner(&mut browser);
    app.advance(Duration::minutes(2));
    let mut phone = Browser::default();
    app.request_email_link(&mut phone, OWNER);
    let token = app.mail.last().unwrap().link_token().unwrap();
    app.redeem_email_link(&mut phone, &token).unwrap();
    let done = app.code_step(&mut phone, &code_of(&codes, 0)).unwrap();
    assert_eq!(
        signed_in_method(&done),
        Some(SignInMethod::EmailRecoveryCode)
    );

    app.advance(Duration::minutes(2));
    let mut laptop = Browser::default();
    app.request_email_link(&mut laptop, OWNER);
    let code = sign_in_code(&app);
    let state = app.redeem_email_code(&mut laptop, &code).unwrap();
    let session = second_factor_session(&state);
    let account = app.account(session.user_id).unwrap();
    let client = app.client(&laptop, Some(account.id));
    let step = SignIn::second_factor(session, account)
        .advance(
            &app.config,
            SignInEvent::Passkey {
                verified: true,
                client,
            },
            app.now,
            &mut app.rng,
        )
        .unwrap();
    assert_eq!(
        signed_in_method(&step.state),
        Some(SignInMethod::EmailPasskey)
    );
    app.apply(step.effects, &mut laptop).unwrap();
}

#[test]
fn email_code_needs_the_second_factor_and_works_once() {
    let mut app = App::new();
    let mut browser = Browser::default();
    let (secret, _) = app.setup_owner(&mut browser);
    app.advance(Duration::minutes(2));
    let mut tv = Browser::default();
    app.request_email_link(&mut tv, OWNER);
    assert!(
        tv.email_cookie().is_some(),
        "the requesting device is bound"
    );
    let code = sign_in_code(&app);
    assert_eq!(code.len(), 6);
    assert_eq!(app.email_codes.len(), 1);
    assert!(app.email_codes.values().all(
        |request| request.attempts == 0 && request.expires_at == app.now + Duration::minutes(5)
    ));
    let state = app.redeem_email_code(&mut tv, &code).unwrap();
    let pending = second_factor_session(&state);
    assert_eq!(pending.method, Some(SignInMethod::EmailCode));
    assert_eq!(pending.stage, Stage::SecondFactor);
    assert!(tv.email_cookie().is_none(), "the binding cookie is cleared");
    assert!(app.email_codes.is_empty());
    let done = totp_after_email(&mut app, &mut tv, &secret).unwrap();
    assert_eq!(signed_in_method(&done), Some(SignInMethod::EmailTotp));
    // The cookie is gone, and with it the request: the code cannot be used again, even with
    // the old cookie put back.
    assert_eq!(
        app.redeem_email_code(&mut tv, &code).err(),
        Some(Error::SignInFailed)
    );
}

#[test]
fn a_code_works_only_on_the_request_that_sent_it() {
    let mut app = App::new();
    let mut browser = Browser::default();
    app.setup_owner(&mut browser);
    app.advance(Duration::minutes(2));
    let mut tv = Browser::default();
    app.request_email_link(&mut tv, OWNER);
    let tv_code = sign_in_code(&app);
    app.advance(Duration::minutes(2));
    let mut attacker = Browser::default();
    app.request_email_link(&mut attacker, OWNER);
    let attacker_code = sign_in_code(&app);
    assert_ne!(tv.email_cookie(), attacker.email_cookie());
    // The victim's code typed on another request's screen fails (unless the two codes
    // happen to be equal, one chance in a million, which this seed avoids).
    assert_ne!(tv_code, attacker_code);
    assert_eq!(
        app.redeem_email_code(&mut attacker, &tv_code).err(),
        Some(Error::SignInFailed)
    );
    assert_eq!(
        app.redeem_email_code(&mut Browser::default(), &tv_code)
            .err(),
        Some(Error::SignInFailed),
        "no cookie, no code"
    );
    let mut forged = Browser::default();
    forged
        .cookies
        .insert("__Host-latchkey_email".into(), "A".repeat(43));
    assert_eq!(
        app.redeem_email_code(&mut forged, &tv_code).err(),
        Some(Error::SignInFailed)
    );
    assert!(matches!(
        app.redeem_email_code(&mut tv, &tv_code),
        Ok(EmailLink::SecondFactor { .. })
    ));
}

#[test]
fn an_expired_code_fails_and_ends_its_request() {
    let mut app = App::new();
    let mut browser = Browser::default();
    app.setup_owner(&mut browser);
    app.advance(Duration::minutes(2));
    let mut tv = Browser::default();
    app.request_email_link(&mut tv, OWNER);
    let code = sign_in_code(&app);
    app.advance(Duration::minutes(5));
    assert_eq!(
        app.redeem_email_code(&mut tv, &code).err(),
        Some(Error::SignInFailed)
    );
    assert!(app.email_codes.is_empty());
    assert!(tv.email_cookie().is_none());
}

#[test]
fn the_attempt_budget_ends_the_request_and_its_link() {
    let mut app = App::new();
    let mut browser = Browser::default();
    app.setup_owner(&mut browser);
    app.advance(Duration::minutes(2));
    let mut tv = Browser::default();
    app.request_email_link(&mut tv, OWNER);
    let mail = app.mail.last().unwrap().clone();
    let code = mail.code.as_ref().unwrap().expose_secret().to_owned();
    let wrong = if code == "000000" { "000001" } else { "000000" };
    let budget = app.config.email_code_attempts();
    assert_eq!(budget, 5);
    for attempt in 1..=budget {
        assert_eq!(
            app.redeem_email_code(&mut tv, wrong).err(),
            Some(Error::SignInFailed)
        );
        assert_eq!(
            app.email_codes.len(),
            usize::from(attempt < budget),
            "attempt {attempt}"
        );
    }
    assert_eq!(
        app.audit
            .iter()
            .filter(|event| event.detail.as_deref() == Some("email_code"))
            .count(),
        5,
        "wrong codes are audited and counted like wrong passwords"
    );
    assert_eq!(
        app.redeem_email_code(&mut tv, &code).err(),
        Some(Error::SignInFailed),
        "the request is dead"
    );
    assert_eq!(
        app.redeem_email_link(&mut Browser::default(), &mail.link_token().unwrap())
            .err(),
        Some(Error::SignInFailed),
        "and so is its link"
    );
}

#[test]
fn guesses_that_raced_past_the_budget_are_refused_even_when_right() {
    let mut app = App::new();
    let mut browser = Browser::default();
    app.setup_owner(&mut browser);
    app.advance(Duration::minutes(2));
    let mut tv = Browser::default();
    app.request_email_link(&mut tv, OWNER);
    let code = sign_in_code(&app);
    // Five guesses were counted by concurrent requests before this one was checked.
    let budget = app.config.email_code_attempts();
    for request in app.email_codes.values_mut() {
        request.attempts = budget;
    }
    assert_eq!(
        app.redeem_email_code(&mut tv, &code).err(),
        Some(Error::SignInFailed)
    );
    assert!(app.email_codes.is_empty());
}

#[test]
fn the_link_kills_the_code() {
    let mut app = App::new();
    let mut browser = Browser::default();
    app.setup_owner(&mut browser);
    app.advance(Duration::minutes(2));
    let mut tv = Browser::default();
    app.request_email_link(&mut tv, OWNER);
    let code = sign_in_code(&app);
    let token = app.mail.last().unwrap().link_token().unwrap();
    let mut phone = Browser::default();
    app.redeem_email_link(&mut phone, &token).unwrap();
    assert!(app.email_codes.is_empty());
    assert_eq!(
        app.redeem_email_code(&mut tv, &code).err(),
        Some(Error::SignInFailed)
    );
}

#[test]
fn the_code_kills_the_link() {
    let mut app = App::new();
    let mut browser = Browser::default();
    app.setup_owner(&mut browser);
    app.advance(Duration::minutes(2));
    let mut tv = Browser::default();
    app.request_email_link(&mut tv, OWNER);
    let code = sign_in_code(&app);
    let token = app.mail.last().unwrap().link_token().unwrap();
    app.redeem_email_code(&mut tv, &code).unwrap();
    assert_eq!(
        app.redeem_email_link(&mut Browser::default(), &token).err(),
        Some(Error::SignInFailed)
    );
}

#[test]
fn a_code_that_lost_the_race_to_its_link_is_refused() {
    let mut app = App::new();
    let mut browser = Browser::default();
    app.setup_owner(&mut browser);
    app.advance(Duration::minutes(2));
    let mut tv = Browser::default();
    app.request_email_link(&mut tv, OWNER);
    let code = sign_in_code(&app);
    let token = app.mail.last().unwrap().link_token().unwrap();
    // The link request deleted the link but had not yet deleted the code.
    app.links.remove(&TokenHash::of(&token).unwrap());
    assert_eq!(
        app.redeem_email_code(&mut tv, &code).err(),
        Some(Error::SignInFailed),
        "ConsumeEmailCode finds no link"
    );
}

#[test]
fn a_request_keeps_the_devices_binding_and_unknown_addresses_get_one_too() {
    let mut app = App::new();
    let mut browser = Browser::default();
    app.setup_owner(&mut browser);
    let mut stranger = Browser::default();
    app.request_email_link(&mut stranger, "nobody@example.com");
    assert!(stranger.email_cookie().is_some(), "no oracle in the cookie");
    app.advance(Duration::minutes(2));
    let mut tv = Browser::default();
    app.request_email_link(&mut tv, OWNER);
    let first = tv.email_cookie().unwrap().to_owned();
    let code = sign_in_code(&app);
    // Asking again within the cooldown mails nothing and keeps the binding, so the first
    // code still works.
    let mails = app.mail.len();
    app.request_email_link(&mut tv, OWNER);
    assert_eq!(app.mail.len(), mails);
    assert_eq!(tv.email_cookie(), Some(first.as_str()));
    assert!(matches!(
        app.redeem_email_code(&mut tv, &code),
        Ok(EmailLink::SecondFactor { .. })
    ));
}

#[test]
fn email_sign_in_links_and_codes_last_five_minutes() {
    let mut app = App::new();
    let mut browser = Browser::default();
    app.setup_owner(&mut browser);
    app.advance(Duration::minutes(2));
    let mut tv = Browser::default();
    app.request_email_link(&mut tv, OWNER);
    let mail = app.mail.last().unwrap().clone();
    let five = Some(app.now + Duration::minutes(5));
    assert_eq!(mail.expires_at, five);
    assert!(
        app.email_codes
            .values()
            .all(|request| Some(request.expires_at) == five)
    );
    assert!(app.links.values().any(|link| Some(link.expires_at) == five));
    // Just inside the five minutes, the code still works.
    app.advance(Duration::minutes(5) - Duration::seconds(1));
    let code = mail.code.as_ref().unwrap().expose_secret().to_owned();
    assert!(matches!(
        app.redeem_email_code(&mut tv, &code),
        Ok(EmailLink::SecondFactor { .. })
    ));
}

#[test]
fn email_link_expires() {
    let mut app = App::new();
    let mut browser = Browser::default();
    app.setup_owner(&mut browser);
    app.request_email_link(&mut browser, OWNER);
    let token = app.mail.last().unwrap().link_token().unwrap();
    app.advance(Duration::minutes(5));
    assert_eq!(
        app.redeem_email_link(&mut browser, &token).err(),
        Some(Error::SignInFailed)
    );
}

#[test]
fn a_password_only_account_signs_in_with_an_email_link_when_allowed() {
    let mut app = password_only();
    let mut browser = Browser::default();
    setup_with_password_only(&mut app, &mut browser).unwrap();
    app.advance(Duration::minutes(2));
    let mut phone = Browser::default();
    app.request_email_link(&mut phone, OWNER);
    let code = sign_in_code(&app);
    let state = app.redeem_email_code(&mut phone, &code).unwrap();
    assert!(matches!(state, EmailLink::SignedIn { .. }));
    assert_eq!(
        app.session_of(&phone).unwrap().method,
        Some(SignInMethod::EmailCode)
    );
}

#[test]
fn email_link_for_unknown_or_inactive_email_is_silent() {
    let mut app = App::new();
    let mut browser = Browser::default();
    app.request_email_link(&mut browser, "nobody@example.com");
    app.request_email_link(&mut browser, OWNER);
    assert_eq!(app.mail.len(), 0);
}

#[test]
fn email_link_resend_cooldown() {
    let mut app = App::new();
    let mut browser = Browser::default();
    app.setup_owner(&mut browser);
    let before = app.mail.len();
    app.request_email_link(&mut browser, OWNER);
    app.request_email_link(&mut browser, OWNER);
    assert_eq!(app.mail.len(), before + 1);
}

#[test]
fn garbage_tokens_are_rejected_generically() {
    let mut app = App::new();
    let mut browser = Browser::default();
    for token in ["", "short", "!!!!", &"A".repeat(43)] {
        assert_eq!(
            app.redeem_email_link(&mut browser, token).err(),
            Some(Error::SignInFailed)
        );
        assert_eq!(
            app.redeem_setup(&mut browser, LinkKind::Setup, token).err(),
            Some(Error::SignInFailed)
        );
    }
}

#[test]
fn a_setup_link_does_not_sign_in_as_an_email_link() {
    let mut app = App::new();
    let mut browser = Browser::default();
    app.request_setup(&mut browser);
    let token = app.mail.last().unwrap().link_token().unwrap();
    assert_eq!(
        app.redeem_email_link(&mut browser, &token).err(),
        Some(Error::SignInFailed)
    );
}

// ---- devices ----

#[test]
fn known_device_signs_in_quietly_and_keeps_its_cookie() {
    let mut app = App::new();
    let mut browser = Browser::default();
    let (secret, _) = app.setup_owner(&mut browser);
    let device = browser.device_cookie().unwrap().to_owned();
    app.advance(Duration::seconds(30));
    app.sign_in(&mut browser, OWNER, PASSWORD, &secret).unwrap();
    assert_eq!(browser.device_cookie(), Some(device.as_str()));
    assert_eq!(app.audit_count(AuditKind::NewDevice), 0);
}

#[test]
fn unknown_device_mails_the_account_once() {
    let mut app = App::new();
    let mut browser = Browser::default();
    let (secret, _) = app.setup_owner(&mut browser);
    let mut laptop = Browser {
        user_agent: Some("Firefox\r\nBcc: x@y".into()),
        ..Browser::default()
    };
    app.advance(Duration::seconds(30));
    app.sign_in(&mut laptop, OWNER, PASSWORD, &secret).unwrap();
    let mail = app.mail.last().unwrap().clone();
    assert_eq!(mail.kind, MailKind::NewDevice);
    assert_eq!(mail.to.as_str(), OWNER);
    assert_eq!(
        mail.link.as_str(),
        "https://home.example.com/settings/sessions"
    );
    assert!(mail.text().contains("Method: password+totp"));
    assert!(mail.text().contains("Browser: FirefoxBcc: x@y\n"));
    assert_eq!(app.audit_count(AuditKind::NewDevice), 1);
    app.advance(Duration::seconds(30));
    app.sign_in(&mut laptop, OWNER, PASSWORD, &secret).unwrap();
    assert_eq!(app.audit_count(AuditKind::NewDevice), 1);
}

#[test]
fn a_forged_device_cookie_counts_as_unknown_and_is_replaced() {
    let mut app = App::new();
    let mut browser = Browser::default();
    let (secret, _) = app.setup_owner(&mut browser);
    let mut forged = Browser::default();
    forged
        .cookies
        .insert("__Host-latchkey_device".into(), "not-a-token".into());
    app.advance(Duration::seconds(30));
    app.sign_in(&mut forged, OWNER, PASSWORD, &secret).unwrap();
    assert_ne!(forged.device_cookie(), Some("not-a-token"));
    assert_eq!(app.audit_count(AuditKind::NewDevice), 1);
}

#[test]
fn email_link_sign_in_on_an_unknown_device_is_mailed() {
    let mut app = App::new();
    let mut browser = Browser::default();
    let (secret, _) = app.setup_owner(&mut browser);
    let mut phone = Browser::default();
    app.request_email_link(&mut phone, OWNER);
    let token = app.mail.last().unwrap().link_token().unwrap();
    app.redeem_email_link(&mut phone, &token).unwrap();
    assert_eq!(app.mail.last().unwrap().kind, MailKind::SignInLink);
    totp_after_email(&mut app, &mut phone, &secret).unwrap();
    let mail = app.mail.last().unwrap();
    assert_eq!(mail.kind, MailKind::NewDevice);
    assert!(mail.text().contains("Method: email+totp"));
}

// ---- step-up ----

#[test]
fn sensitive_changes_need_a_step_up_within_five_minutes() {
    let mut app = App::new();
    let mut browser = Browser::default();
    let (secret, _) = app.setup_owner(&mut browser);
    app.advance(Duration::minutes(6));
    let window = app.config.step_up_window();
    let session = app.session_of(&browser).unwrap();
    assert_eq!(
        session.authorize(true, Access::Recent, window, app.now),
        Err(Error::StepUpRequired)
    );
    let code = secret.code_at(app.now, app.config.totp_params()).unwrap();
    let done = app.step_up_password(&mut browser, PASSWORD, &code).unwrap();
    assert!(matches!(done, StepUp::Done { .. }));
    let session = app.session_of(&browser).unwrap();
    assert!(
        session
            .authorize(true, Access::Recent, window, app.now)
            .is_ok()
    );
    assert_eq!(session.method, Some(SignInMethod::StepUp));
    assert_eq!(app.audit_count(AuditKind::StepUp), 1);
}

#[test]
fn step_up_with_a_recovery_code() {
    let mut app = App::new();
    let mut browser = Browser::default();
    let (_, codes) = app.setup_owner(&mut browser);
    app.advance(Duration::minutes(6));
    assert!(
        app.step_up_password(&mut browser, PASSWORD, &code_of(&codes, 4))
            .is_ok()
    );
    assert_eq!(app.audit_count(AuditKind::RecoveryCodeUsed), 1);
}

#[test]
fn wrong_step_up_passwords_count_towards_throttle_and_lockout() {
    let mut app = App::new();
    let mut browser = Browser::default();
    let (secret, _) = app.setup_owner(&mut browser);
    let code = secret.code_at(app.now, app.config.totp_params()).unwrap();
    assert_eq!(
        app.step_up_password(&mut browser, "wrong password!!", &code)
            .err(),
        Some(Error::SignInFailed)
    );
    assert_eq!(app.account(app.owner_id()).unwrap().lockout.failures, 1);
    let key = latchkey::account::AccountKey::from_login(OWNER);
    assert!(!app.throttle.window(&key).is_empty());
    assert_eq!(
        app.step_up_password(&mut browser, PASSWORD, "000000").err(),
        Some(Error::SignInFailed)
    );
    assert_eq!(app.account(app.owner_id()).unwrap().lockout.failures, 2);
}

#[test]
fn by_default_a_locked_account_cannot_step_up() {
    let mut app = App::new();
    let mut browser = Browser::default();
    let (secret, _) = app.setup_owner(&mut browser);
    for _ in 0..5 {
        let _ = app.password_step(&mut Browser::default(), OWNER, "wrong password!!");
    }
    let code = secret.code_at(app.now, app.config.totp_params()).unwrap();
    assert_eq!(
        app.step_up_password(&mut browser, PASSWORD, &code)
            .err()
            .and_then(|error| error.retry_after_secs()),
        Some(300)
    );
}

// ---- step-up failures per session ----

fn per_session(limit: u32) -> App {
    App::with_config(
        latchkey::Config::builder(OWNER, common::ORIGIN)
            .password_params(common::cheap())
            .step_up_failures(StepUpFailures::PerSession { limit }),
    )
}

#[test]
fn per_session_wrong_step_ups_end_that_session_and_leave_the_account_alone() {
    let mut app = per_session(5);
    let mut browser = Browser::default();
    let (secret, _) = app.setup_owner(&mut browser);
    let code = secret.code_at(app.now, app.config.totp_params()).unwrap();
    for guess in 1..5 {
        let wrong = if guess % 2 == 0 {
            app.step_up_password(&mut browser, PASSWORD, "000000")
        } else {
            app.step_up_password(&mut browser, "wrong password!!", &code)
        };
        assert_eq!(wrong.err(), Some(Error::SignInFailed));
        assert_eq!(app.session_of(&browser).unwrap().step_up_failures, guess);
    }
    let owner = app.owner_id();
    assert_eq!(app.account(owner).unwrap().lockout.failures, 0);
    let key = latchkey::account::AccountKey::from_login(OWNER);
    assert!(app.throttle.window(&key).is_empty());

    let fifth = app.step_up_password(&mut browser, "wrong password!!", &code);
    assert_eq!(fifth.err(), Some(Error::SessionEnded));
    assert_eq!(Error::SessionEnded.code(), "session_ended");
    assert!(browser.session_cookie().is_none(), "the cookie is cleared");
    assert!(app.sessions.is_empty(), "the session is gone");
    assert_eq!(app.audit_count(AuditKind::SessionRevoked), 1);
    assert_eq!(app.audit_count(AuditKind::SignInFailed), 5);
    assert_eq!(app.account(owner).unwrap().lockout, Lockout::default());

    app.advance(Duration::seconds(30));
    assert!(
        app.sign_in(&mut browser, OWNER, PASSWORD, &secret).is_ok(),
        "signing in again is not blocked"
    );
}

#[test]
fn per_session_counts_are_kept_apart() {
    let mut app = per_session(2);
    let mut laptop = Browser::default();
    let (secret, _) = app.setup_owner(&mut laptop);
    let mut phone = Browser::default();
    app.advance(Duration::seconds(30));
    app.sign_in(&mut phone, OWNER, PASSWORD, &secret).unwrap();
    assert_eq!(
        app.step_up_password(&mut laptop, "wrong password!!", "000000")
            .err(),
        Some(Error::SignInFailed)
    );
    assert_eq!(
        app.step_up_password(&mut laptop, "wrong password!!", "000000")
            .err(),
        Some(Error::SessionEnded)
    );
    assert!(app.session_of(&laptop).is_none());
    let phone_session = app.session_of(&phone).unwrap();
    assert_eq!(phone_session.step_up_failures, 0);
    app.advance(Duration::seconds(30));
    let code = secret.code_at(app.now, app.config.totp_params()).unwrap();
    assert!(app.step_up_password(&mut phone, PASSWORD, &code).is_ok());
}

#[test]
fn per_session_a_locked_account_can_still_step_up_and_success_clears_both_counts() {
    let mut app = per_session(5);
    let mut browser = Browser::default();
    let (secret, _) = app.setup_owner(&mut browser);
    assert_eq!(
        app.step_up_password(&mut browser, PASSWORD, "000000").err(),
        Some(Error::SignInFailed)
    );
    for _ in 0..5 {
        let _ = app.password_step(&mut Browser::default(), OWNER, "wrong password!!");
    }
    let owner = app.owner_id();
    assert!(app.account(owner).unwrap().lockout.check(app.now).is_err());
    let key = latchkey::account::AccountKey::from_login(OWNER);
    for _ in 0..10 {
        let now = app.now;
        app.throttle.record(&key, now);
    }
    assert!(app.throttle.check(&key, app.now).is_err());

    let code = secret.code_at(app.now, app.config.totp_params()).unwrap();
    let done = app.step_up_password(&mut browser, PASSWORD, &code);
    assert!(matches!(done, Ok(StepUp::Done { .. })), "{done:?}");
    assert_eq!(app.session_of(&browser).unwrap().step_up_failures, 0);
    assert_eq!(app.account(owner).unwrap().lockout, Lockout::default());
}

#[test]
fn per_session_a_session_already_at_the_limit_is_ended() {
    let mut app = per_session(3);
    let mut browser = Browser::default();
    let (secret, _) = app.setup_owner(&mut browser);
    // Guesses that raced can leave the stored count at the limit with the session alive.
    let hash = app.session_of(&browser).unwrap().token_hash;
    app.sessions.get_mut(&hash).unwrap().step_up_failures = 3;
    let code = secret.code_at(app.now, app.config.totp_params()).unwrap();
    assert_eq!(
        app.step_up_password(&mut browser, PASSWORD, &code).err(),
        Some(Error::SessionEnded)
    );
    assert!(app.sessions.is_empty());
}

#[test]
fn per_session_passkeys_are_not_guesses_but_respect_an_ended_session() {
    let mut app = per_session(1);
    let mut browser = Browser::default();
    app.setup_owner(&mut browser);
    for _ in 0..3 {
        assert_eq!(
            app.step_up_passkey(&mut browser, false).err(),
            Some(Error::SignInFailed)
        );
    }
    assert_eq!(app.session_of(&browser).unwrap().step_up_failures, 0);
    assert!(app.step_up_passkey(&mut browser, true).is_ok());
    let hash = app.session_of(&browser).unwrap().token_hash;
    app.sessions.get_mut(&hash).unwrap().step_up_failures = 1;
    assert_eq!(
        app.step_up_passkey(&mut browser, true).err(),
        Some(Error::SessionEnded)
    );
    assert!(app.sessions.is_empty());
}

proptest::proptest! {
    #![proptest_config(proptest::prelude::ProptestConfig::with_cases(24))]

    #[test]
    fn per_session_the_limit_th_wrong_guess_ends_the_session(
        limit in 1u32..7,
        guesses in 0u32..10,
    ) {
        let mut app = per_session(limit);
        let mut browser = Browser::default();
        app.setup_owner(&mut browser);
        for guess in 1..=guesses {
            let refused = app.step_up_password(&mut browser, "wrong password!!", "000000");
            let expected = match guess.cmp(&limit) {
                std::cmp::Ordering::Less => Error::SignInFailed,
                std::cmp::Ordering::Equal => Error::SessionEnded,
                std::cmp::Ordering::Greater => Error::Unauthorized,
            };
            proptest::prop_assert_eq!(refused.err(), Some(expected));
        }
        proptest::prop_assert_eq!(app.session_of(&browser).is_some(), guesses < limit);
        let owner = app.owner_id();
        proptest::prop_assert_eq!(app.account(owner).unwrap().lockout, Lockout::default());
    }
}

// ---- invites ----

fn invite(
    app: &mut App,
    inviter: &Browser,
    email: &str,
) -> Result<latchkey::account::NewAccount, Error> {
    let session = app.session_of(inviter).unwrap();
    let account = app.account(session.user_id).unwrap();
    let email = Email::parse(email)?;
    let email_taken = app.id_of(email.as_str()).is_some();
    let client = app.client(inviter, None);
    match Invite::Start.advance(
        &app.config,
        InviteEvent::Send {
            inviter: account,
            session,
            email,
            display_name: Some("  Kid  ".into()),
            email_taken,
            client,
        },
        app.now,
        &mut app.rng,
    ) {
        Ok(step) => {
            app.apply(step.effects, &mut Browser::default())?;
            match step.state {
                Invite::Sent { account } => Ok(account),
                _ => unreachable!(),
            }
        }
        Err(refusal) => Err(app.refused(refusal, &mut Browser::default())),
    }
}

#[test]
fn owner_invites_a_family_member_who_sets_up() {
    let mut app = App::new();
    let mut owner = Browser::default();
    app.setup_owner(&mut owner);
    let member = invite(&mut app, &owner, "Kid@Example.com").unwrap();
    assert_eq!(member.display_name, "Kid");
    let mail = app.mail.last().unwrap().clone();
    assert_eq!(mail.kind, MailKind::Invite);
    assert_eq!(mail.to.as_str(), "kid@example.com");
    assert_eq!(
        mail.expires_at,
        Some(app.now + Duration::hours(24)),
        "invites last a day"
    );
    let mut kid = Browser::default();
    let token = mail.link_token().unwrap();
    assert!(matches!(
        app.redeem_setup(&mut kid, LinkKind::Invite, &token),
        Ok(Setup::InSetup { .. })
    ));
    app.setup_password(&mut kid, PASSWORD).unwrap();
    app.enrol_totp(member.id);
    app.finish_setup(&mut kid).unwrap();
    assert!(app.account(member.id).unwrap().active);
    assert_eq!(
        invite(&mut app, &owner, "kid@example.com").err(),
        Some(Error::Conflict(ConflictReason::EmailTaken))
    );
    assert_eq!(
        invite(&mut app, &kid, "other@example.com").err(),
        Some(Error::Forbidden),
        "members cannot invite"
    );
}

#[test]
fn invite_needs_a_recent_sign_in() {
    let mut app = App::new();
    let mut owner = Browser::default();
    app.setup_owner(&mut owner);
    app.advance(Duration::minutes(6));
    assert_eq!(
        invite(&mut app, &owner, "kid@example.com").err(),
        Some(Error::StepUpRequired)
    );
}

// ---- sign-in reset ----

fn reset(
    app: &mut App,
    admin: &Browser,
    member: latchkey::UserId,
    remove_password: bool,
) -> Result<latchkey::Account, Error> {
    let session = app.session_of(admin).unwrap();
    let admin_account = app.account(session.user_id).unwrap();
    let member = app.account(member).unwrap();
    let client = app.client(admin, None);
    match Reset::Start.advance(
        &app.config,
        ResetEvent::Reset {
            admin: admin_account,
            session,
            member,
            remove_password,
            client,
        },
        app.now,
        &mut app.rng,
    ) {
        Ok(step) => {
            app.apply(step.effects, &mut Browser::default())?;
            match step.state {
                Reset::Done { account } => Ok(account),
                _ => unreachable!(),
            }
        }
        Err(refusal) => Err(app.refused(refusal, &mut Browser::default())),
    }
}

/// The owner and a member who finished setup with a password and TOTP, signed in on `kid`.
fn owner_and_member(app: &mut App, owner: &mut Browser, kid: &mut Browser) -> latchkey::UserId {
    app.setup_owner(owner);
    let member = invite(app, owner, "kid@example.com").unwrap();
    let token = app.mail.last().unwrap().link_token().unwrap();
    app.redeem_setup(kid, LinkKind::Invite, &token).unwrap();
    app.setup_password(kid, PASSWORD).unwrap();
    app.enrol_totp(member.id);
    app.finish_setup(kid).unwrap();
    member.id
}

#[test]
fn the_owner_resets_a_member_who_lost_their_second_factor() {
    let mut app = App::new();
    let mut owner = Browser::default();
    let mut kid = Browser::default();
    let member = owner_and_member(&mut app, &mut owner, &mut kid);
    let mut tablet = Browser::default();
    app.request_email_link(&mut tablet, "kid@example.com");
    let old_link = app.mail.last().unwrap().link_token().unwrap();
    assert!(app.session_of(&kid).is_some());

    let account = reset(&mut app, &owner, member, false).unwrap();
    assert!(!account.active);
    assert_eq!(account.factors, latchkey::Factors::new(true, false, 0));
    assert_eq!(app.account(member).unwrap().factors, account.factors);
    assert!(app.session_of(&kid).is_none(), "signed out everywhere");
    assert_eq!(app.rows[&member].recovery.len(), 0);
    assert!(
        app.email_codes.is_empty() && app.links.values().all(|link| link.kind == LinkKind::Invite),
        "older links and codes are gone"
    );
    assert_eq!(
        app.redeem_email_link(&mut tablet, &old_link).err(),
        Some(Error::SignInFailed)
    );
    let mail = app.mail.last().unwrap().clone();
    assert_eq!(mail.kind, MailKind::SignInReset);
    assert_eq!(mail.to.as_str(), "kid@example.com");
    assert_eq!(mail.expires_at, Some(app.now + Duration::hours(24)));
    assert!(
        mail.link
            .starts_with("https://home.example.com/invite?token=")
    );
    let event = app
        .audit
        .iter()
        .find(|event| event.kind == AuditKind::SignInReset)
        .unwrap();
    assert_eq!(event.user_id, Some(member));
    assert_eq!(event.detail, Some(format!("by:{}", app.owner_id())));
    assert_eq!(
        app.password_step(&mut kid, "kid@example.com", PASSWORD)
            .err(),
        Some(Error::SignInFailed),
        "no sign-in until setup is done again"
    );

    // The member sets up again through the link: the old password stays unless changed.
    let token = mail.link_token().unwrap();
    app.redeem_setup(&mut kid, LinkKind::Invite, &token)
        .unwrap();
    assert_eq!(
        app.finish_setup(&mut kid).err(),
        Some(Error::InvalidRequest(
            InvalidRequestReason::SecondFactorRequired
        ))
    );
    let secret = app.enrol_totp(member);
    app.advance(Duration::seconds(30));
    app.finish_setup(&mut kid).unwrap();
    assert!(app.account(member).unwrap().active);
    app.advance(Duration::seconds(30));
    let mut laptop = Browser::default();
    let done = app
        .sign_in(&mut laptop, "kid@example.com", PASSWORD, &secret)
        .unwrap();
    assert_eq!(signed_in_method(&done), Some(SignInMethod::PasswordTotp));
    assert_eq!(
        app.redeem_setup(&mut kid, LinkKind::Invite, &token).err(),
        Some(Error::SignInFailed),
        "the reset link works once"
    );
}

#[test]
fn a_reset_can_remove_the_password_too() {
    let mut app = App::new();
    let mut owner = Browser::default();
    let mut kid = Browser::default();
    let member = owner_and_member(&mut app, &mut owner, &mut kid);
    let account = reset(&mut app, &owner, member, true).unwrap();
    assert_eq!(account.factors, latchkey::Factors::default());
    let token = app.mail.last().unwrap().link_token().unwrap();
    app.redeem_setup(&mut kid, LinkKind::Invite, &token)
        .unwrap();
    app.enrol_totp(member);
    assert_eq!(
        app.finish_setup(&mut kid).err(),
        Some(Error::InvalidRequest(
            InvalidRequestReason::PasswordRequired
        ))
    );
    app.setup_password(&mut kid, "a brand new passphrase")
        .unwrap();
    app.finish_setup(&mut kid).unwrap();
}

#[test]
fn invite_and_reset_links_last_a_day() {
    let mut app = App::new();
    let mut owner = Browser::default();
    let mut kid = Browser::default();
    let member = owner_and_member(&mut app, &mut owner, &mut kid);
    invite(&mut app, &owner, "other@example.com").unwrap();
    let invite_mail = app.mail.last().unwrap().clone();
    assert_eq!(invite_mail.kind, MailKind::Invite);
    assert_eq!(invite_mail.expires_at, Some(app.now + Duration::hours(24)));
    reset(&mut app, &owner, member, false).unwrap();
    let mail = app.mail.last().unwrap().clone();
    assert_eq!(mail.expires_at, Some(app.now + Duration::hours(24)));
    let token = mail.link_token().unwrap();
    app.advance(Duration::hours(24) - Duration::seconds(1));
    assert!(matches!(
        app.redeem_setup(&mut kid, LinkKind::Invite, &token),
        Ok(Setup::InSetup { .. })
    ));
}

#[test]
fn the_reset_link_expires_after_a_day() {
    let mut app = App::new();
    let mut owner = Browser::default();
    let mut kid = Browser::default();
    let member = owner_and_member(&mut app, &mut owner, &mut kid);
    reset(&mut app, &owner, member, false).unwrap();
    let token = app.mail.last().unwrap().link_token().unwrap();
    app.advance(Duration::hours(24));
    assert_eq!(
        app.redeem_setup(&mut kid, LinkKind::Invite, &token).err(),
        Some(Error::SignInFailed)
    );
}

#[test]
fn only_the_owner_resets_only_members_and_only_recently() {
    let mut app = App::new();
    let mut owner = Browser::default();
    let mut kid = Browser::default();
    let member = owner_and_member(&mut app, &mut owner, &mut kid);
    let owner_id = app.owner_id();
    assert_eq!(
        reset(&mut app, &kid, owner_id, false).err(),
        Some(Error::Forbidden),
        "members cannot reset"
    );
    assert_eq!(
        reset(&mut app, &owner, owner_id, false).err(),
        Some(Error::Forbidden),
        "the owner is reset to first-open setup instead"
    );
    app.advance(Duration::minutes(6));
    assert_eq!(
        reset(&mut app, &owner, member, false).err(),
        Some(Error::StepUpRequired)
    );
    assert!(app.account(member).unwrap().active, "nothing happened");
}

// ---- sessions started by the app, sign-out ----

#[test]
fn issue_session_signs_in_like_a_normal_sign_in() {
    let mut app = App::new();
    let mut browser = Browser::default();
    app.setup_owner(&mut browser);
    let owner = app.account(app.owner_id()).unwrap();
    let mut desktop = Browser::default();
    let client = app.client(&desktop, Some(owner.id));
    let method = AppMethod::new("desktop_bridge").unwrap();
    let issued =
        flow::issue_session(&app.config, &owner, method, &client, app.now, &mut app.rng).unwrap();
    assert_eq!(issued.state.stage, Stage::Full);
    assert_eq!(issued.state.authenticated_at, Some(app.now));
    assert_eq!(issued.state.expires_at, app.now + app.config.session_ttl());
    app.apply(issued.effects, &mut desktop).unwrap();
    assert!(desktop.session_cookie().is_some());
    assert!(desktop.device_cookie().is_some());
    let sign_in = app
        .audit
        .iter()
        .rev()
        .find(|event| event.kind == AuditKind::SignIn)
        .unwrap();
    assert_eq!(sign_in.detail.as_deref(), Some("desktop_bridge"));
    assert_eq!(app.audit_count(AuditKind::NewDevice), 1);
}

#[test]
fn issue_session_refuses_locked_and_unfinished_accounts() {
    let mut app = App::new();
    let owner = app.account(app.owner_id()).unwrap();
    let client = latchkey::flow::Client::default();
    let method = || AppMethod::new("desktop_bridge").unwrap();
    assert_eq!(
        flow::issue_session(
            &app.config,
            &owner,
            method(),
            &client,
            app.now,
            &mut app.rng
        )
        .err(),
        Some(Error::Forbidden)
    );
    let mut browser = Browser::default();
    app.setup_owner(&mut browser);
    let mut owner = app.account(app.owner_id()).unwrap();
    owner.lockout.locked_until = Some(app.now + Duration::minutes(5));
    assert!(matches!(
        flow::issue_session(
            &app.config,
            &owner,
            method(),
            &client,
            app.now,
            &mut app.rng
        )
        .err(),
        Some(Error::TooManyAttempts { .. })
    ));
}

#[test]
fn sign_out_ends_the_session_and_keeps_the_device() {
    let mut app = App::new();
    let mut browser = Browser::default();
    app.setup_owner(&mut browser);
    let session = app.session_of(&browser).unwrap();
    let client = app.client(&browser, None);
    let effects = flow::sign_out(&app.config, &session, &client, app.now);
    app.apply(effects, &mut browser).unwrap();
    assert!(app.session_of(&browser).is_none());
    assert!(browser.session_cookie().is_none());
    assert!(browser.device_cookie().is_some());
    assert_eq!(app.audit_count(AuditKind::SignOut), 1);
}

#[test]
fn recovery_codes_can_be_regenerated() {
    let mut app = App::new();
    let mut browser = Browser::default();
    let (_, old) = app.setup_owner(&mut browser);
    let client = app.client(&browser, None);
    let step = flow::regenerate_recovery_codes(
        &app.config,
        app.owner_id(),
        &client,
        app.now,
        &mut app.rng,
    );
    let new = step.state;
    app.apply(step.effects, &mut browser).unwrap();
    let mut laptop = Browser::default();
    app.password_step(&mut laptop, OWNER, PASSWORD).unwrap();
    assert_eq!(
        app.code_step(&mut laptop, &code_of(&old, 0)).err(),
        Some(Error::SignInFailed)
    );
    assert!(app.code_step(&mut laptop, &code_of(&new, 0)).is_ok());
}

// ---- password-only accounts ----

fn password_only() -> App {
    App::with_config(
        latchkey::Config::builder(OWNER, common::ORIGIN)
            .password_params(common::cheap())
            .password_only(PasswordOnly::AllowedUntilEnrolled),
    )
}

/// Setup with a password and nothing else; `Ok` when setup finished.
fn setup_with_password_only(app: &mut App, browser: &mut Browser) -> Result<(), Error> {
    app.request_setup(browser);
    let token = app.mail.last().unwrap().link_token().unwrap();
    app.redeem_setup(browser, LinkKind::Setup, &token).unwrap();
    app.setup_password(browser, PASSWORD).unwrap();
    app.finish_setup(browser).map(|_| ())
}

#[test]
fn by_default_a_password_only_account_gets_no_session() {
    let mut app = App::new();
    let mut browser = Browser::default();
    assert_eq!(
        setup_with_password_only(&mut app, &mut browser).err(),
        Some(Error::InvalidRequest(
            InvalidRequestReason::SecondFactorRequired
        ))
    );
    let mut owner = app.account(app.owner_id()).unwrap();
    owner.active = true;
    assert!(owner.factors.password && !owner.factors.has_second_factor());
    assert_eq!(
        flow::issue_session(
            &app.config,
            &owner,
            AppMethod::new("desktop_bridge").unwrap(),
            &latchkey::flow::Client::default(),
            app.now,
            &mut app.rng
        )
        .err(),
        Some(Error::Forbidden)
    );
}

#[test]
fn a_password_only_account_signs_in_with_its_password_when_allowed() {
    let mut app = password_only();
    let mut browser = Browser::default();
    setup_with_password_only(&mut app, &mut browser).unwrap();
    assert!(app.account(app.owner_id()).unwrap().active);

    let mut laptop = Browser::default();
    let state = app.password_step(&mut laptop, OWNER, PASSWORD).unwrap();
    assert_eq!(signed_in_method(&state), Some(SignInMethod::PasswordOnly));
    let session = app.session_of(&laptop).unwrap();
    assert_eq!(session.stage, Stage::Full);
    let sign_in = app
        .audit
        .iter()
        .rev()
        .find(|event| event.kind == AuditKind::SignIn)
        .unwrap();
    assert_eq!(sign_in.detail.as_deref(), Some("password_only"));

    assert_eq!(
        app.password_step(&mut Browser::default(), OWNER, "wrong password!!")
            .err(),
        Some(Error::SignInFailed)
    );
    assert_eq!(app.account(app.owner_id()).unwrap().lockout.failures, 1);

    let owner = app.account(app.owner_id()).unwrap();
    let issued = flow::issue_session(
        &app.config,
        &owner,
        AppMethod::new("desktop_bridge").unwrap(),
        &latchkey::flow::Client::default(),
        app.now,
        &mut app.rng,
    );
    assert!(issued.is_ok());
}

#[test]
fn a_password_only_account_steps_up_with_its_password() {
    let mut app = password_only();
    let mut browser = Browser::default();
    setup_with_password_only(&mut app, &mut browser).unwrap();
    app.advance(Duration::minutes(6));
    assert_eq!(
        app.step_up_password(&mut browser, "wrong password!!", "")
            .err(),
        Some(Error::SignInFailed)
    );
    let done = app.step_up_password(&mut browser, PASSWORD, "").unwrap();
    assert!(matches!(done, StepUp::Done { .. }));
    let session = app.session_of(&browser).unwrap();
    assert!(
        session
            .authorize(true, Access::Recent, app.config.step_up_window(), app.now)
            .is_ok()
    );
}

#[test]
fn once_a_second_factor_is_enrolled_it_is_required_again() {
    let mut app = password_only();
    let mut browser = Browser::default();
    setup_with_password_only(&mut app, &mut browser).unwrap();
    let secret = app.enrol_totp(app.owner_id());
    app.advance(Duration::seconds(30));

    let mut laptop = Browser::default();
    let state = app.password_step(&mut laptop, OWNER, PASSWORD).unwrap();
    assert!(matches!(state, SignIn::SecondFactor { .. }));
    assert_eq!(app.session_of(&laptop).unwrap().stage, Stage::SecondFactor);
    let code = secret.code_at(app.now, app.config.totp_params()).unwrap();
    let state = app.code_step(&mut laptop, &code).unwrap();
    assert_eq!(signed_in_method(&state), Some(SignInMethod::PasswordTotp));

    app.advance(Duration::minutes(6));
    assert_eq!(
        app.step_up_password(&mut browser, PASSWORD, "").err(),
        Some(Error::SignInFailed)
    );
}

// ---- plain-HTTP development cookies ----

#[test]
fn development_on_localhost_sets_cookies_without_secure() {
    let mut app = App::with_config(
        latchkey::Config::builder(OWNER, "http://localhost:3000")
            .password_params(common::cheap())
            .danger_insecure_localhost_cookies(),
    );
    let mut owner = app.account(app.owner_id()).unwrap();
    owner.active = true;
    owner.factors.password = true;
    owner.factors.totp = true;
    let issued = flow::issue_session(
        &app.config,
        &owner,
        AppMethod::new("desktop_bridge").unwrap(),
        &latchkey::flow::Client::default(),
        app.now,
        &mut app.rng,
    )
    .unwrap();
    let headers: Vec<String> = issued
        .effects
        .iter()
        .filter_map(|effect| match effect {
            flow::Effect::SetCookie(cookie) => Some(cookie.header_value()),
            _ => None,
        })
        .collect();
    assert_eq!(headers.len(), 2, "session and device cookies");
    assert!(headers[0].starts_with("latchkey="));
    assert!(headers[1].starts_with("latchkey_device="));
    for header in &headers {
        assert!(!header.contains("Secure"), "{header}");
        assert!(!header.contains("__Host-"), "{header}");
        assert!(header.ends_with("; HttpOnly; SameSite=Lax"), "{header}");
    }
}
