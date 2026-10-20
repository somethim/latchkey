#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use axum::http::StatusCode;
use common::{App, Client, OWNER, PASSWORD, Response, password_step, setup_owner};
use latchkey::store::{Role, User};
use latchkey::{MailKind, TestMailer};
use serde_json::json;
use uuid::Uuid;

async fn sign_in(app: &App, client: &mut Client, totp_secret: &str) -> Response {
    let first = password_step(client, OWNER, PASSWORD).await;
    assert_eq!(first.status, StatusCode::OK, "{:?}", first.body);
    app.advance(30);
    let code = app.totp_code(totp_secret);
    let done = client
        .post("/auth/sign-in/code", json!({ "code": code }))
        .await;
    assert_eq!(done.status, StatusCode::OK, "{:?}", done.body);
    done
}

async fn new_device_events(app: &App) -> usize {
    app.latchkey
        .store()
        .audit(None, 100)
        .await
        .unwrap()
        .iter()
        .filter(|event| event.kind == "new_device")
        .count()
}

#[tokio::test]
async fn setup_remembers_the_device_without_a_mail() {
    let app = App::new().await;
    let owner = setup_owner(&app).await;
    assert!(owner.client.device.is_some());
    app.no_mail(2).await;
    assert_eq!(new_device_events(&app).await, 0);
}

#[tokio::test]
async fn device_cookie_is_long_lived_and_host_only() {
    let app = App::new().await;
    let mut owner = setup_owner(&app).await;
    let done = sign_in(&app, &mut owner.client, &owner.totp_secret).await;
    let cookie = done.set_device_cookie.unwrap();
    for attribute in [
        "Path=/",
        "Max-Age=34560000",
        "HttpOnly",
        "Secure",
        "SameSite=Lax",
    ] {
        assert!(cookie.contains(attribute), "{cookie} lacks {attribute}");
    }
    assert!(cookie.starts_with("__Host-latchkey_device="));
}

#[tokio::test]
async fn known_device_signs_in_quietly_and_keeps_its_cookie() {
    let app = App::new().await;
    let mut owner = setup_owner(&app).await;
    let device = owner.client.device.clone();
    owner.client.post("/auth/sign-out", json!({})).await;
    assert_eq!(owner.client.device, device, "sign-out keeps the device");
    sign_in(&app, &mut owner.client, &owner.totp_secret).await;
    assert_eq!(owner.client.device, device);
    app.no_mail(2).await;
}

#[tokio::test]
async fn unknown_device_mails_the_account_once() {
    let app = App::new().await;
    let owner = setup_owner(&app).await;
    let mut client = app.client();
    client.user_agent = Some("TestBrowser/1.0".into());
    sign_in(&app, &mut client, &owner.totp_secret).await;

    let mail = app.mail(2).await;
    assert_eq!(mail.kind, MailKind::NewDevice);
    assert_eq!(mail.to, OWNER);
    assert_eq!(mail.link, app.latchkey.config().sessions_url);
    assert_eq!(mail.expires_at, None);
    let details = mail.sign_in.clone().unwrap();
    assert_eq!(details.method, "password+totp");
    assert_eq!(details.user_agent.as_deref(), Some("TestBrowser/1.0"));
    assert!(mail.text().contains("TestBrowser/1.0"));
    assert!(mail.text().contains(mail.link.as_str()));
    assert_eq!(new_device_events(&app).await, 1);

    client.post("/auth/sign-out", json!({})).await;
    sign_in(&app, &mut client, &owner.totp_secret).await;
    app.no_mail(3).await;
    assert_eq!(new_device_events(&app).await, 1);
}

#[tokio::test]
async fn email_link_sign_in_on_an_unknown_device_is_mailed() {
    let app = App::new().await;
    setup_owner(&app).await;
    let mut client = app.client();
    client
        .post("/auth/sign-in/email", json!({ "email": OWNER }))
        .await;
    let token = TestMailer::token_of(&app.mail(2).await).unwrap();
    let redeemed = client
        .post("/auth/sign-in/email/redeem", json!({ "token": token }))
        .await;
    assert_eq!(redeemed.status, StatusCode::OK, "{:?}", redeemed.body);
    let mail = app.mail(3).await;
    assert_eq!(mail.kind, MailKind::NewDevice);
    assert_eq!(mail.sign_in.unwrap().method, "email_link");
}

#[tokio::test]
async fn a_forged_device_cookie_counts_as_unknown_and_is_replaced() {
    let app = App::new().await;
    let owner = setup_owner(&app).await;
    let mut client = app.client();
    client.device = Some("not-a-device-token".into());
    sign_in(&app, &mut client, &owner.totp_secret).await;
    assert_eq!(app.mail(2).await.kind, MailKind::NewDevice);
    assert_ne!(client.device.as_deref(), Some("not-a-device-token"));
}

#[tokio::test]
async fn a_device_is_known_per_account() {
    let app = App::new().await;
    let store = app.latchkey.store();
    let owner = store.owner().await.unwrap().unwrap();
    let member = User {
        id: Uuid::new_v4(),
        email: "member@example.test".into(),
        display_name: "Member".into(),
        role: Role::Member,
        ..owner.clone()
    };
    store.create_user(&member).await.unwrap();
    let hash = [5u8; 32];
    assert!(
        store
            .remember_device(owner.id, &hash, app.now())
            .await
            .unwrap()
    );
    assert!(
        !store
            .remember_device(owner.id, &hash, app.now())
            .await
            .unwrap()
    );
    assert!(
        store
            .remember_device(member.id, &hash, app.now())
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn devices_unused_for_the_ttl_are_forgotten() {
    let app = App::new().await;
    let mut owner = setup_owner(&app).await;
    app.advance(401 * 24 * 60 * 60);
    app.latchkey.purge_expired().await.unwrap();
    sign_in(&app, &mut owner.client, &owner.totp_secret).await;
    assert_eq!(app.mail(2).await.kind, MailKind::NewDevice);
}
