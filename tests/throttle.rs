#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use axum::http::StatusCode;
use common::{App, OWNER, PASSWORD, config, password_step, setup_owner};
use latchkey::LockoutPolicy;
use serde_json::json;

/// Only the wrong-password throttle is in play: no lockout, generous per-minute limits.
async fn app() -> App {
    let mut config = config();
    config.lockout = LockoutPolicy {
        threshold: 0,
        ..LockoutPolicy::default()
    };
    config.rate_limits.per_ip_per_minute = 1000;
    config.rate_limits.per_account_per_minute = 1000;
    App::with_config(config).await
}

#[tokio::test]
async fn ten_wrong_passwords_in_fifteen_minutes_throttle_the_account() {
    let app = app().await;
    setup_owner(&app).await;
    let mut client = app.client();
    for _ in 0..10 {
        let wrong = password_step(&mut client, OWNER, "wrong password!").await;
        assert_eq!(wrong.error(), "sign_in_failed");
        app.advance(60);
    }
    let throttled = password_step(&mut client, OWNER, PASSWORD).await;
    assert_eq!(throttled.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(throttled.error(), "too_many_attempts");

    app.advance(4 * 60);
    assert_eq!(
        password_step(&mut client, OWNER, PASSWORD).await.status,
        StatusCode::TOO_MANY_REQUESTS,
        "14 minutes after the first failure it still counts"
    );
    app.advance(60);
    let allowed = password_step(&mut client, OWNER, PASSWORD).await;
    assert_eq!(allowed.status, StatusCode::OK, "{:?}", allowed.body);
    assert_eq!(allowed.body["stage"], "second_factor");
}

#[tokio::test]
async fn unknown_addresses_are_throttled_the_same_way() {
    let app = app().await;
    setup_owner(&app).await;
    let mut client = app.client();
    for spelling in ["nobody@example.test", " Nobody@Example.TEST "]
        .iter()
        .cycle()
        .take(10)
    {
        let wrong = password_step(&mut client, spelling, "wrong password!").await;
        assert_eq!(wrong.error(), "sign_in_failed");
    }
    let throttled = password_step(&mut client, "nobody@example.test", "anything at all").await;
    assert_eq!(throttled.error(), "too_many_attempts");
    let owner = password_step(&mut client, OWNER, PASSWORD).await;
    assert_eq!(
        owner.status,
        StatusCode::OK,
        "other accounts are unaffected"
    );
}

#[tokio::test]
async fn a_successful_sign_in_does_not_reset_the_count() {
    let app = app().await;
    let owner = setup_owner(&app).await;
    let mut client = app.client();
    for _ in 0..9 {
        password_step(&mut client, OWNER, "wrong password!").await;
    }
    password_step(&mut client, OWNER, PASSWORD).await;
    app.advance(30);
    let code = app.totp_code(&owner.totp_secret);
    let signed_in = client
        .post("/auth/sign-in/code", json!({ "code": code }))
        .await;
    assert_eq!(signed_in.status, StatusCode::OK, "{:?}", signed_in.body);

    let mut other = app.client();
    password_step(&mut other, OWNER, "wrong password!").await;
    assert_eq!(
        password_step(&mut other, OWNER, PASSWORD).await.error(),
        "too_many_attempts"
    );
}

#[tokio::test]
async fn wrong_step_up_passwords_count_too() {
    let app = app().await;
    let mut owner = setup_owner(&app).await;
    for _ in 0..10 {
        let wrong = owner
            .client
            .post(
                "/auth/step-up/password",
                json!({ "password": "wrong password!", "code": "000000" }),
            )
            .await;
        assert_eq!(wrong.error(), "sign_in_failed");
    }
    app.advance(30);
    let code = app.totp_code(&owner.totp_secret);
    let throttled = owner
        .client
        .post(
            "/auth/step-up/password",
            json!({ "password": PASSWORD, "code": code }),
        )
        .await;
    assert_eq!(throttled.error(), "too_many_attempts");
    let mut client = app.client();
    assert_eq!(
        password_step(&mut client, OWNER, PASSWORD).await.error(),
        "too_many_attempts"
    );
}

#[tokio::test]
async fn the_default_lockout_still_applies_first() {
    let app = App::new().await;
    setup_owner(&app).await;
    let mut client = app.client();
    for _ in 0..5 {
        password_step(&mut client, OWNER, "wrong password!").await;
    }
    assert_eq!(
        password_step(&mut client, OWNER, PASSWORD).await.error(),
        "too_many_attempts"
    );
}
