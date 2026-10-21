//! The app's settings take effect: non-default code sizes, attempt budgets, lifetimes and
//! TOTP parameters, driven through the flows by the in-memory app.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use common::{App, Browser, ORIGIN, OWNER, PASSWORD, cheap, code_of};
use latchkey::error::InvalidRequestReason;
use latchkey::flow::email_link::EmailLink;
use latchkey::flow::sign_in::SignIn;
use latchkey::flow::{self, LinkKind};
use latchkey::totp;
use latchkey::{Config, ConfigBuilder, Error};
use time::Duration;

fn builder() -> ConfigBuilder {
    Config::builder(OWNER, ORIGIN).password_params(cheap())
}

#[test]
fn an_eight_digit_email_code_with_three_attempts_and_a_two_minute_link() {
    let mut app = App::with_config(
        builder()
            .email_code_digits(8)
            .email_code_attempts(3)
            .link_ttl(Duration::minutes(2)),
    );
    let mut browser = Browser::default();
    app.setup_owner(&mut browser);
    app.advance(Duration::minutes(2));
    let mut tv = Browser::default();
    app.request_email_link(&mut tv, OWNER);
    let mail = app.mail.last().unwrap().clone();
    let code = mail.code.as_ref().unwrap().expose_secret().to_owned();
    assert_eq!(code.len(), 8);
    assert!(code.bytes().all(|b| b.is_ascii_digit()));
    assert!(mail.text().contains(&code));
    let two = Some(app.now + Duration::minutes(2));
    assert_eq!(mail.expires_at, two);
    assert!(
        app.email_codes
            .values()
            .all(|request| Some(request.expires_at) == two)
    );

    // Three wrong guesses (one of them only 6 digits long) end the request and its link.
    let wrong = if code == "00000000" {
        "00000001"
    } else {
        "00000000"
    };
    for (attempt, guess) in [&code[..6], wrong, wrong].into_iter().enumerate() {
        assert_eq!(
            app.redeem_email_code(&mut tv, guess).err(),
            Some(Error::SignInFailed)
        );
        assert_eq!(app.email_codes.len(), usize::from(attempt < 2), "{attempt}");
    }
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
fn a_two_minute_link_and_its_code_expire_after_two_minutes() {
    let mut app = App::with_config(builder().link_ttl(Duration::minutes(2)));
    let mut browser = Browser::default();
    app.setup_owner(&mut browser);
    app.advance(Duration::minutes(2));

    let mut tv = Browser::default();
    app.request_email_link(&mut tv, OWNER);
    let code = app.mail.last().unwrap().code.clone().unwrap();
    app.advance(Duration::minutes(2) - Duration::seconds(1));
    assert!(matches!(
        app.redeem_email_code(&mut tv, code.expose_secret()),
        Ok(EmailLink::SecondFactor { .. })
    ));

    app.advance(Duration::minutes(2));
    let mut phone = Browser::default();
    app.request_email_link(&mut phone, OWNER);
    let mail = app.mail.last().unwrap().clone();
    app.advance(Duration::minutes(2));
    assert_eq!(
        app.redeem_email_code(&mut phone, mail.code.as_ref().unwrap().expose_secret())
            .err(),
        Some(Error::SignInFailed)
    );
    assert_eq!(
        app.redeem_email_link(&mut phone, &mail.link_token().unwrap())
            .err(),
        Some(Error::SignInFailed)
    );
}

#[test]
fn eight_digit_totp_with_a_sixty_second_step() {
    let mut app = App::with_config(builder().totp_digits(8).totp_step(60));
    let params = app.config.totp_params();
    assert_eq!((params.digits(), params.step_secs()), (8, 60));
    let mut browser = Browser::default();
    let (secret, _) = app.setup_owner(&mut browser);

    let enrolment = totp::enrolment(&secret, "Home", OWNER, params).unwrap();
    assert!(enrolment.otpauth_url.contains("digits=8"));
    assert!(enrolment.otpauth_url.contains("period=60"));

    app.advance(Duration::seconds(60));
    let mut laptop = Browser::default();
    app.password_step(&mut laptop, OWNER, PASSWORD).unwrap();
    // A 6-digit code from an authenticator still on the defaults is not a TOTP code here.
    let six = secret
        .code_at(app.now, totp::TotpParams::default())
        .unwrap();
    assert_eq!(
        app.code_step(&mut laptop, &six).err(),
        Some(Error::SignInFailed)
    );
    let eight = secret.code_at(app.now, params).unwrap();
    assert_eq!(eight.len(), 8);
    assert!(matches!(
        app.code_step(&mut laptop, &eight),
        Ok(SignIn::SignedIn { .. })
    ));
    let step = app.rows[&app.owner_id()].last_step.unwrap();
    let unix = u64::try_from(app.now.unix_timestamp()).unwrap();
    assert_eq!(step.get(), unix / 60, "steps count 60-second periods");
}

#[test]
fn sixteen_recovery_codes_at_setup_and_when_regenerated() {
    let mut app = App::with_config(builder().recovery_code_count(16));
    let mut browser = Browser::default();
    let (_, codes) = app.setup_owner(&mut browser);
    assert_eq!(codes.len(), 16);
    assert_eq!(app.rows[&app.owner_id()].recovery.len(), 16);

    let client = app.client(&browser, None);
    let step = flow::regenerate_recovery_codes(
        &app.config,
        app.owner_id(),
        &client,
        app.now,
        &mut app.rng,
    );
    assert_eq!(step.state.len(), 16);
    let new = step.state;
    app.apply(step.effects, &mut browser).unwrap();
    let mut laptop = Browser::default();
    app.password_step(&mut laptop, OWNER, PASSWORD).unwrap();
    assert!(app.code_step(&mut laptop, &code_of(&new, 15)).is_ok());
}

#[test]
fn a_longer_minimum_password_is_enforced() {
    // PASSWORD has 28 characters.
    let mut app = App::with_config(builder().password_min_len(30));
    let mut browser = Browser::default();
    app.request_setup(&mut browser);
    let token = app.mail.last().unwrap().link_token().unwrap();
    app.redeem_setup(&mut browser, LinkKind::Setup, &token)
        .unwrap();
    assert_eq!(
        app.setup_password(&mut browser, PASSWORD).err(),
        Some(Error::InvalidRequest(
            InvalidRequestReason::PasswordTooShort
        ))
    );
    assert!(
        app.setup_password(&mut browser, "correct horse battery staple again")
            .is_ok()
    );
}

#[test]
fn out_of_range_settings_are_refused() {
    use latchkey::error::ConfigReason;
    let refused = |builder: ConfigBuilder, reason| {
        assert_eq!(builder.build().err(), Some(Error::Config(reason)));
    };
    refused(
        builder().email_code_digits(5),
        ConfigReason::EmailCodeDigits,
    );
    refused(
        builder().email_code_digits(11),
        ConfigReason::EmailCodeDigits,
    );
    refused(
        builder().email_code_attempts(0),
        ConfigReason::EmailCodeAttempts,
    );
    refused(
        builder().email_code_attempts(21),
        ConfigReason::EmailCodeAttempts,
    );
    refused(
        builder().recovery_code_count(3),
        ConfigReason::RecoveryCodeCount,
    );
    refused(
        builder().recovery_code_count(33),
        ConfigReason::RecoveryCodeCount,
    );
    refused(builder().totp_digits(7), ConfigReason::TotpDigits);
    refused(builder().totp_step(10), ConfigReason::TotpStep);
    refused(builder().totp_step(121), ConfigReason::TotpStep);
    refused(builder().totp_skew(4), ConfigReason::TotpSkew);
    refused(builder().password_min_len(7), ConfigReason::PasswordLength);
    refused(
        builder().password_max_len(2000),
        ConfigReason::PasswordLength,
    );
    refused(
        builder().password_min_len(100).password_max_len(64),
        ConfigReason::PasswordLength,
    );
    refused(
        builder().display_name_max_len(0),
        ConfigReason::DisplayNameLength,
    );
    refused(
        builder().display_name_max_len(1001),
        ConfigReason::DisplayNameLength,
    );
    // The edges are allowed.
    for ok in [
        builder().email_code_digits(10).email_code_attempts(20),
        builder().email_code_digits(6).email_code_attempts(1),
        builder().recovery_code_count(4),
        builder().recovery_code_count(32),
        builder().totp_digits(8).totp_step(15).totp_skew(0),
        builder().totp_step(120).totp_skew(3),
        builder().password_min_len(8).password_max_len(64),
        builder().display_name_max_len(1),
    ] {
        assert!(ok.build().is_ok());
    }
}
