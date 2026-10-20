#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use axum::http::StatusCode;
use common::{App, OWNER, PASSWORD, enrol_totp, setup_owner};
use latchkey::TestMailer;
use serde_json::json;

#[tokio::test]
async fn first_open_requires_setup_and_completes_it() {
    let app = App::new().await;
    let mut anonymous = app.client();
    let status = anonymous.get("/auth/setup/status").await;
    assert_eq!(status.body["setup_required"], true);

    let mut owner = setup_owner(&app).await;
    let status = anonymous.get("/auth/setup/status").await;
    assert_eq!(status.body["setup_required"], false);

    let me = owner.client.get("/auth/me").await;
    assert_eq!(me.status, StatusCode::OK);
    assert_eq!(me.body["account"]["email"], OWNER);
    assert_eq!(me.body["account"]["role"], "owner");
    assert_eq!(me.body["factors"]["totp"], true);
    assert_eq!(me.body["factors"]["recovery_codes_left"], 10);
    let private = owner.client.get("/app/private").await;
    assert_eq!(private.status, StatusCode::OK);
}

#[tokio::test]
async fn setup_cookie_is_host_prefixed_and_locked_down() {
    let app = App::new().await;
    let mut client = app.client();
    client.post("/auth/setup/start", json!({})).await;
    let token = TestMailer::token_of(&app.mail(1).await).unwrap();
    let redeemed = client
        .post("/auth/setup/redeem", json!({ "token": token }))
        .await;
    let cookie = redeemed.set_cookie.unwrap();
    assert!(cookie.starts_with("__Host-latchkey="));
    for attribute in ["Path=/", "HttpOnly", "Secure", "SameSite=Lax"] {
        assert!(cookie.contains(attribute), "{cookie} lacks {attribute}");
    }
    assert!(!cookie.contains("Domain"));
}

#[tokio::test]
async fn setup_link_is_single_use() {
    let app = App::new().await;
    let mut client = app.client();
    client.post("/auth/setup/start", json!({})).await;
    let token = TestMailer::token_of(&app.mail(1).await).unwrap();
    let first = client
        .post("/auth/setup/redeem", json!({ "token": token }))
        .await;
    assert_eq!(first.status, StatusCode::OK);
    let mut other = app.client();
    let again = other
        .post("/auth/setup/redeem", json!({ "token": token }))
        .await;
    assert_eq!(again.status, StatusCode::UNAUTHORIZED);
    assert_eq!(again.error(), "sign_in_failed");
}

#[tokio::test]
async fn setup_link_expires_after_fifteen_minutes() {
    let app = App::new().await;
    let mut client = app.client();
    client.post("/auth/setup/start", json!({})).await;
    let token = TestMailer::token_of(&app.mail(1).await).unwrap();
    app.advance(15 * 60 + 1);
    let late = client
        .post("/auth/setup/redeem", json!({ "token": token }))
        .await;
    assert_eq!(late.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn setup_link_resend_has_a_cooldown_and_replaces_the_old_link() {
    let app = App::new().await;
    let mut client = app.client();
    client.post("/auth/setup/start", json!({})).await;
    let first = TestMailer::token_of(&app.mail(1).await).unwrap();
    client.post("/auth/setup/start", json!({})).await;
    app.no_mail(2).await;
    app.advance(61);
    client.post("/auth/setup/start", json!({})).await;
    let second = TestMailer::token_of(&app.mail(2).await).unwrap();
    let old = client
        .post("/auth/setup/redeem", json!({ "token": first }))
        .await;
    assert_eq!(old.status, StatusCode::UNAUTHORIZED);
    let new = client
        .post("/auth/setup/redeem", json!({ "token": second }))
        .await;
    assert_eq!(new.status, StatusCode::OK);
}

#[tokio::test]
async fn setup_cannot_complete_without_password_and_a_second_factor() {
    let app = App::new().await;
    let mut client = app.client();
    client.post("/auth/setup/start", json!({})).await;
    let token = TestMailer::token_of(&app.mail(1).await).unwrap();
    client
        .post("/auth/setup/redeem", json!({ "token": token }))
        .await;

    let early = client.post("/auth/setup/complete", json!({})).await;
    assert_eq!(early.status, StatusCode::BAD_REQUEST);
    assert_eq!(early.body["detail"], "password_required");

    let short = client
        .post("/auth/setup/password", json!({ "password": "short" }))
        .await;
    assert_eq!(short.status, StatusCode::BAD_REQUEST);
    client
        .post("/auth/setup/password", json!({ "password": PASSWORD }))
        .await;
    let no_factor = client.post("/auth/setup/complete", json!({})).await;
    assert_eq!(no_factor.body["detail"], "second_factor_required");

    let private = client.get("/app/private").await;
    assert_eq!(private.status, StatusCode::UNAUTHORIZED);

    enrol_totp(&app, &mut client).await;
    let done = client.post("/auth/setup/complete", json!({})).await;
    assert_eq!(done.status, StatusCode::OK);
}

#[tokio::test]
async fn setup_start_sends_nothing_once_the_owner_is_active() {
    let app = App::new().await;
    setup_owner(&app).await;
    let mut client = app.client();
    let started = client.post("/auth/setup/start", json!({})).await;
    assert_eq!(started.status, StatusCode::ACCEPTED);
    app.no_mail(2).await;
}

#[tokio::test]
async fn setup_session_cannot_reach_full_routes() {
    let app = App::new().await;
    let mut client = app.client();
    client.post("/auth/setup/start", json!({})).await;
    let token = TestMailer::token_of(&app.mail(1).await).unwrap();
    client
        .post("/auth/setup/redeem", json!({ "token": token }))
        .await;
    assert_eq!(
        client.get("/auth/sessions").await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        client.get("/auth/audit").await.status,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn reset_owner_rearms_setup() {
    let app = App::new().await;
    let mut owner = setup_owner(&app).await;
    app.latchkey.reset_owner().await.unwrap();
    assert_eq!(
        owner.client.get("/auth/me").await.status,
        StatusCode::UNAUTHORIZED
    );
    let status = app.client().get("/auth/setup/status").await;
    assert_eq!(status.body["setup_required"], true);
    let stored = app.latchkey.store().owner().await.unwrap().unwrap();
    assert!(stored.password_hash.is_none());
    assert!(!stored.active);
}

#[tokio::test]
async fn owner_is_created_once() {
    let app = App::new().await;
    let store = app.latchkey.store().clone();
    let again = latchkey::Latchkey::new(common::config(), store.clone(), app.mailer.clone())
        .await
        .unwrap();
    let owner = again.store().owner().await.unwrap().unwrap();
    assert_eq!(owner.email, OWNER);
    assert!(store.user_by_email(OWNER).await.unwrap().is_some());
}
