#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use axum::http::StatusCode;
use common::{App, OWNER, PASSWORD, password_step, setup_owner};
use latchkey::{MailKind, RateLimits, TestMailer};
use serde_json::json;

#[tokio::test]
async fn password_then_totp_signs_in() {
    let app = App::new().await;
    let owner = setup_owner(&app).await;
    app.advance(30);
    let mut client = app.client();
    let first = password_step(&mut client, OWNER, PASSWORD).await;
    assert_eq!(first.status, StatusCode::OK, "{:?}", first.body);
    assert_eq!(first.body["stage"], "second_factor");
    assert_eq!(first.body["second_factor"]["totp"], true);
    let pending_cookie = client.cookie.clone();

    assert_eq!(
        client.get("/app/private").await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(client.get("/auth/me").await.body["stage"], "second_factor");

    let code = app.totp_code(&owner.totp_secret);
    let second = client
        .post("/auth/sign-in/code", json!({ "code": code }))
        .await;
    assert_eq!(second.status, StatusCode::OK, "{:?}", second.body);
    assert_eq!(second.body["stage"], "full");
    assert_ne!(
        client.cookie, pending_cookie,
        "session must rotate on stage change"
    );
    assert_eq!(client.get("/app/private").await.body, OWNER);

    let mut stale = app.client();
    stale.cookie = pending_cookie;
    assert_eq!(stale.get("/auth/me").await.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn totp_step_cannot_be_replayed() {
    let app = App::new().await;
    let owner = setup_owner(&app).await;
    app.advance(30);
    let code = app.totp_code(&owner.totp_secret);

    let mut first = app.client();
    password_step(&mut first, OWNER, PASSWORD).await;
    let ok = first
        .post("/auth/sign-in/code", json!({ "code": code }))
        .await;
    assert_eq!(ok.status, StatusCode::OK);

    let mut second = app.client();
    password_step(&mut second, OWNER, PASSWORD).await;
    let replay = second
        .post("/auth/sign-in/code", json!({ "code": code }))
        .await;
    assert_eq!(replay.status, StatusCode::UNAUTHORIZED);
    assert_eq!(replay.error(), "sign_in_failed");

    app.advance(30);
    let fresh = app.totp_code(&owner.totp_secret);
    let ok = second
        .post("/auth/sign-in/code", json!({ "code": fresh }))
        .await;
    assert_eq!(ok.status, StatusCode::OK);
}

#[tokio::test]
async fn setup_totp_code_cannot_be_reused_for_sign_in() {
    let app = App::new().await;
    let owner = setup_owner(&app).await;
    let mut client = app.client();
    password_step(&mut client, OWNER, PASSWORD).await;
    let code = app.totp_code(&owner.totp_secret);
    let replay = client
        .post("/auth/sign-in/code", json!({ "code": code }))
        .await;
    assert_eq!(replay.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn recovery_codes_work_once() {
    let app = App::new().await;
    let owner = setup_owner(&app).await;
    let code = owner.recovery_codes[3].clone();

    let mut client = app.client();
    password_step(&mut client, OWNER, PASSWORD).await;
    let used = client
        .post("/auth/sign-in/code", json!({ "code": code.to_uppercase() }))
        .await;
    assert_eq!(used.status, StatusCode::OK, "{:?}", used.body);
    assert_eq!(used.body["recovery_codes_left"], 9);

    let mut again = app.client();
    password_step(&mut again, OWNER, PASSWORD).await;
    let reused = again
        .post("/auth/sign-in/code", json!({ "code": code }))
        .await;
    assert_eq!(reused.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn wrong_password_and_unknown_email_look_the_same() {
    let app = App::new().await;
    setup_owner(&app).await;
    let mut client = app.client();
    let wrong = password_step(&mut client, OWNER, "not the right password").await;
    let unknown = password_step(&mut client, "nobody@example.test", PASSWORD).await;
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED);
    assert_eq!(wrong.status, unknown.status);
    assert_eq!(wrong.body, unknown.body);
    assert!(wrong.set_cookie.is_none() && unknown.set_cookie.is_none());
}

#[tokio::test]
async fn unfinished_account_cannot_sign_in_with_a_password() {
    let app = App::new().await;
    let mut client = app.client();
    client.post("/auth/setup/start", json!({})).await;
    let token = TestMailer::token_of(&app.mail(1).await).unwrap();
    client
        .post("/auth/setup/redeem", json!({ "token": token }))
        .await;
    client
        .post("/auth/setup/password", json!({ "password": PASSWORD }))
        .await;
    let mut other = app.client();
    let attempt = password_step(&mut other, OWNER, PASSWORD).await;
    assert_eq!(attempt.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn lockout_after_five_failures_doubles_and_lifts() {
    let app = App::new().await;
    setup_owner(&app).await;
    let mut client = app.client();
    for _ in 0..5 {
        let attempt = password_step(&mut client, OWNER, "wrong password guess").await;
        assert_eq!(attempt.status, StatusCode::UNAUTHORIZED);
    }
    let locked = password_step(&mut client, OWNER, PASSWORD).await;
    assert_eq!(locked.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(locked.error(), "too_many_attempts");

    app.advance(5 * 60 + 1);
    for _ in 0..5 {
        password_step(&mut client, OWNER, "wrong password guess").await;
    }
    app.advance(5 * 60 + 1);
    let still_locked = password_step(&mut client, OWNER, PASSWORD).await;
    assert_eq!(
        still_locked.status,
        StatusCode::TOO_MANY_REQUESTS,
        "second lock is 10 minutes"
    );

    app.advance(5 * 60);
    let open = password_step(&mut client, OWNER, PASSWORD).await;
    assert_eq!(open.status, StatusCode::OK);

    let audit = app.latchkey.store().audit(None, 100).await.unwrap();
    assert_eq!(audit.iter().filter(|e| e.kind == "lockout").count(), 2);
}

#[tokio::test]
async fn wrong_second_factor_codes_count_towards_lockout() {
    let app = App::new().await;
    setup_owner(&app).await;
    let mut client = app.client();
    password_step(&mut client, OWNER, PASSWORD).await;
    for _ in 0..5 {
        let wrong = client
            .post("/auth/sign-in/code", json!({ "code": "000000" }))
            .await;
        assert_eq!(wrong.status, StatusCode::UNAUTHORIZED);
    }
    let locked = client
        .post("/auth/sign-in/code", json!({ "code": "000000" }))
        .await;
    assert_eq!(locked.status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn per_ip_rate_limit() {
    let mut config = common::config();
    config.rate_limits = RateLimits {
        per_ip_per_minute: 3,
        per_account_per_minute: 100,
        ..RateLimits::default()
    };
    let app = App::with_config(config).await;
    let mut client = app.client();
    for _ in 0..3 {
        let attempt = password_step(&mut client, "x@example.test", PASSWORD).await;
        assert_eq!(attempt.status, StatusCode::UNAUTHORIZED);
    }
    let limited = password_step(&mut client, "y@example.test", PASSWORD).await;
    assert_eq!(limited.status, StatusCode::TOO_MANY_REQUESTS);
    app.advance(60);
    let again = password_step(&mut client, "y@example.test", PASSWORD).await;
    assert_eq!(again.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn per_account_rate_limit() {
    let mut config = common::config();
    config.rate_limits = RateLimits {
        per_ip_per_minute: 100,
        per_account_per_minute: 2,
        ..RateLimits::default()
    };
    let app = App::with_config(config).await;
    let mut client = app.client();
    password_step(&mut client, "x@example.test", PASSWORD).await;
    password_step(&mut client, "X@example.test ", PASSWORD).await;
    let limited = password_step(&mut client, "x@example.test", PASSWORD).await;
    assert_eq!(limited.status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn email_link_signs_in_directly_once() {
    let app = App::new().await;
    setup_owner(&app).await;
    let mut client = app.client();
    let requested = client
        .post("/auth/sign-in/email", json!({ "email": OWNER }))
        .await;
    assert_eq!(requested.status, StatusCode::ACCEPTED);
    let mail = app.mail(2).await;
    assert_eq!(mail.kind, MailKind::SignInLink);
    assert!(
        mail.link
            .as_str()
            .starts_with("https://home.example.test/sign-in/link?token=")
    );
    let token = TestMailer::token_of(&mail).unwrap();

    let redeemed = client
        .post("/auth/sign-in/email/redeem", json!({ "token": token }))
        .await;
    assert_eq!(redeemed.status, StatusCode::OK);
    assert_eq!(redeemed.body["stage"], "full");
    assert_eq!(client.get("/app/private").await.status, StatusCode::OK);

    let mut other = app.client();
    let reused = other
        .post("/auth/sign-in/email/redeem", json!({ "token": token }))
        .await;
    assert_eq!(reused.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn email_link_expires() {
    let app = App::new().await;
    setup_owner(&app).await;
    let mut client = app.client();
    client
        .post("/auth/sign-in/email", json!({ "email": OWNER }))
        .await;
    let token = TestMailer::token_of(&app.mail(2).await).unwrap();
    app.advance(15 * 60);
    let late = client
        .post("/auth/sign-in/email/redeem", json!({ "token": token }))
        .await;
    assert_eq!(late.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn email_link_for_unknown_email_is_silent() {
    let app = App::new().await;
    setup_owner(&app).await;
    let mut client = app.client();
    let known = client
        .post("/auth/sign-in/email", json!({ "email": OWNER }))
        .await;
    let unknown = client
        .post(
            "/auth/sign-in/email",
            json!({ "email": "stranger@example.test" }),
        )
        .await;
    assert_eq!(known.status, unknown.status);
    assert_eq!(known.body, unknown.body);
    app.mail(2).await;
    app.no_mail(3).await;
    assert!(app.mailer.sent().iter().all(|mail| mail.to == OWNER));
}

#[tokio::test]
async fn email_link_resend_cooldown() {
    let app = App::new().await;
    setup_owner(&app).await;
    let mut client = app.client();
    client
        .post("/auth/sign-in/email", json!({ "email": OWNER }))
        .await;
    app.mail(2).await;
    client
        .post("/auth/sign-in/email", json!({ "email": OWNER }))
        .await;
    app.no_mail(3).await;
    app.advance(60);
    client
        .post("/auth/sign-in/email", json!({ "email": OWNER }))
        .await;
    app.mail(3).await;
}

#[tokio::test]
async fn garbage_tokens_are_rejected_generically() {
    let app = App::new().await;
    let mut client = app.client();
    for token in ["", "abc", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"] {
        let response = client
            .post("/auth/sign-in/email/redeem", json!({ "token": token }))
            .await;
        assert_eq!(response.status, StatusCode::UNAUTHORIZED);
        assert_eq!(response.error(), "sign_in_failed");
    }
    let malformed = client
        .post("/auth/sign-in/email/redeem", json!({ "nope": 1 }))
        .await;
    assert_eq!(malformed.status, StatusCode::BAD_REQUEST);
    assert_eq!(malformed.error(), "invalid_request");
}

#[tokio::test]
async fn sign_out_ends_the_session() {
    let app = App::new().await;
    let mut owner = setup_owner(&app).await;
    let cookie = owner.client.cookie.clone();
    let out = owner.client.post("/auth/sign-out", json!({})).await;
    assert_eq!(out.status, StatusCode::NO_CONTENT);
    assert!(out.set_cookie.unwrap().contains("Max-Age=0"));
    let mut stale = app.client();
    stale.cookie = cookie;
    assert_eq!(
        stale.get("/app/private").await.status,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn sessions_expire() {
    let app = App::new().await;
    let mut owner = setup_owner(&app).await;
    app.advance(30 * 24 * 60 * 60);
    assert_eq!(
        owner.client.get("/app/private").await.status,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn second_factor_stage_expires() {
    let app = App::new().await;
    let owner = setup_owner(&app).await;
    let mut client = app.client();
    password_step(&mut client, OWNER, PASSWORD).await;
    app.advance(11 * 60);
    let code = app.totp_code(&owner.totp_secret);
    let late = client
        .post("/auth/sign-in/code", json!({ "code": code }))
        .await;
    assert_eq!(late.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn forgotten_password_is_replaced_after_an_email_link() {
    let app = App::new().await;
    setup_owner(&app).await;
    let mut client = app.client();
    client
        .post("/auth/sign-in/email", json!({ "email": OWNER }))
        .await;
    let token = TestMailer::token_of(&app.mail(2).await).unwrap();
    client
        .post("/auth/sign-in/email/redeem", json!({ "token": token }))
        .await;
    let changed = client
        .post(
            "/auth/password",
            json!({ "password": "a brand new long password" }),
        )
        .await;
    assert_eq!(changed.status, StatusCode::NO_CONTENT);
    let mut other = app.client();
    let old = password_step(&mut other, OWNER, PASSWORD).await;
    assert_eq!(old.status, StatusCode::UNAUTHORIZED);
    let new = password_step(&mut other, OWNER, "a brand new long password").await;
    assert_eq!(new.status, StatusCode::OK);

    app.advance(5 * 60 + 1);
    let stale = client
        .post(
            "/auth/password",
            json!({ "password": "yet another long password" }),
        )
        .await;
    assert_eq!(stale.error(), "step_up_required");
}
