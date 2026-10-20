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
use latchkey::flow::invite::{Invite, InviteEvent};
use latchkey::flow::setup::Setup;
use latchkey::flow::sign_in::{SignIn, SignInEvent};
use latchkey::flow::step_up::StepUp;
use latchkey::flow::{self, LinkKind};
use latchkey::limits::RateLimits;
use latchkey::mail::MailKind;
use latchkey::session::{Access, AppMethod, SignInMethod, Stage};
use latchkey::{Error, LockoutPolicy};
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
fn setup_link_expires_after_fifteen_minutes() {
    let mut app = App::new();
    let mut browser = Browser::default();
    app.request_setup(&mut browser);
    let token = app.mail.last().unwrap().link_token().unwrap();
    app.advance(Duration::minutes(15));
    assert_eq!(
        app.redeem_setup(&mut browser, LinkKind::Setup, &token)
            .err(),
        Some(Error::SignInFailed)
    );
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
        Some(Error::InvalidRequest("password_required"))
    );
    assert_eq!(
        app.setup_password(&mut browser, "short").err(),
        Some(Error::InvalidRequest("password_too_short"))
    );
    app.setup_password(&mut browser, PASSWORD).unwrap();
    assert_eq!(
        app.finish_setup(&mut browser).err(),
        Some(Error::InvalidRequest("second_factor_required"))
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
    let code = secret.code_at(app.now).unwrap();
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
    let code = secret.code_at(app.now).unwrap();
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
    let enrolment_code = secret.code_at(app.now).unwrap();
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
    let code = secret.code_at(app.now).unwrap();
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
        Some(Error::InvalidRequest("unexpected_flow_event"))
    );
}

// ---- throttle ----

#[test]
fn ten_wrong_passwords_in_fifteen_minutes_throttle_the_account() {
    let mut app = App::with_config(
        latchkey::Config::builder(OWNER, common::ORIGIN)
            .password(common::cheap())
            .lockout(LockoutPolicy {
                threshold: 0,
                ..LockoutPolicy::default()
            }),
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
            .password(common::cheap())
            .rate_limits(RateLimits {
                wrong_passwords_per_account: 3,
                ..RateLimits::default()
            }),
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

#[test]
fn email_link_signs_in_directly_once() {
    let mut app = App::new();
    let mut browser = Browser::default();
    app.setup_owner(&mut browser);
    app.advance(Duration::minutes(2));
    let mut phone = Browser::default();
    app.request_email_link(&mut phone, OWNER);
    let mail = app.mail.last().unwrap().clone();
    assert_eq!(mail.kind, MailKind::SignInLink);
    let token = mail.link_token().unwrap();
    let done = app.redeem_email_link(&mut phone, &token).unwrap();
    assert!(matches!(
        done,
        latchkey::flow::email_link::EmailLink::SignedIn { .. }
    ));
    assert_eq!(
        app.session_of(&phone).unwrap().method,
        Some(SignInMethod::EmailLink)
    );
    assert_eq!(
        app.redeem_email_link(&mut Browser::default(), &token).err(),
        Some(Error::SignInFailed)
    );
}

#[test]
fn email_link_expires() {
    let mut app = App::new();
    let mut browser = Browser::default();
    app.setup_owner(&mut browser);
    app.request_email_link(&mut browser, OWNER);
    let token = app.mail.last().unwrap().link_token().unwrap();
    app.advance(Duration::minutes(15));
    assert_eq!(
        app.redeem_email_link(&mut browser, &token).err(),
        Some(Error::SignInFailed)
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
    app.setup_owner(&mut browser);
    let mut phone = Browser::default();
    app.request_email_link(&mut phone, OWNER);
    let token = app.mail.last().unwrap().link_token().unwrap();
    app.redeem_email_link(&mut phone, &token).unwrap();
    let mail = app.mail.last().unwrap();
    assert_eq!(mail.kind, MailKind::NewDevice);
    assert!(mail.text().contains("Method: email_link"));
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
    let code = secret.code_at(app.now).unwrap();
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
    let code = secret.code_at(app.now).unwrap();
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
                Invite::Start => unreachable!(),
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
        Some(app.now + Duration::days(3)),
        "invites last three days"
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
        Some(Error::Conflict("email_taken"))
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
    let step = flow::regenerate_recovery_codes(app.owner_id(), &client, app.now, &mut app.rng);
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
