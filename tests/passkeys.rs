#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use axum::http::StatusCode;
use common::{App, Authenticator, OWNER, PASSWORD, password_step, setup_owner};
use latchkey::TestMailer;
use serde_json::json;

#[tokio::test]
async fn setup_with_a_passkey_only_and_sign_in_with_it() {
    let app = App::new().await;
    let mut client = app.client();
    client.post("/auth/setup/start", json!({})).await;
    let token = TestMailer::token_of(&app.mail(1).await).unwrap();
    let redeemed = client
        .post("/auth/setup/redeem", json!({ "token": token }))
        .await;
    let user_id = redeemed.body["account"]["id"].as_str().unwrap().to_owned();
    client
        .post("/auth/setup/password", json!({ "password": PASSWORD }))
        .await;
    let mut key = Authenticator::new();
    let registered = key.register(&mut client, "Laptop").await;
    assert_eq!(
        registered.status,
        StatusCode::CREATED,
        "{:?}",
        registered.body
    );
    assert_eq!(registered.body["name"], "Laptop");
    let done = client.post("/auth/setup/complete", json!({})).await;
    assert_eq!(done.status, StatusCode::OK, "{:?}", done.body);

    let mut fresh = app.client();
    let start = fresh.post("/auth/sign-in/passkey/start", json!({})).await;
    assert_eq!(start.status, StatusCode::OK);
    let credential = key.assert_discoverable(&start.body["options"], &user_id);
    let finish = fresh
        .post(
            "/auth/sign-in/passkey/finish",
            json!({ "ceremony": start.body["ceremony"], "credential": credential }),
        )
        .await;
    assert_eq!(finish.status, StatusCode::OK, "{:?}", finish.body);
    assert_eq!(finish.body["stage"], "full");
    assert_eq!(fresh.get("/app/private").await.body, OWNER);

    let replay = fresh
        .post(
            "/auth/sign-in/passkey/finish",
            json!({ "ceremony": start.body["ceremony"], "credential": credential }),
        )
        .await;
    assert_eq!(
        replay.status,
        StatusCode::UNAUTHORIZED,
        "ceremonies are single use"
    );

    let passkeys = fresh.get("/auth/passkeys").await;
    assert!(passkeys.body["passkeys"][0]["last_used_at"].is_string());
}

#[tokio::test]
async fn passkey_for_another_user_handle_is_rejected() {
    let app = App::new().await;
    let mut owner = setup_owner(&app).await;
    let mut key = Authenticator::new();
    key.register(&mut owner.client, "Phone").await;
    let mut fresh = app.client();
    let start = fresh.post("/auth/sign-in/passkey/start", json!({})).await;
    let credential =
        key.assert_discoverable(&start.body["options"], &uuid::Uuid::new_v4().to_string());
    let finish = fresh
        .post(
            "/auth/sign-in/passkey/finish",
            json!({ "ceremony": start.body["ceremony"], "credential": credential }),
        )
        .await;
    assert_eq!(finish.status, StatusCode::UNAUTHORIZED);
    assert_eq!(finish.error(), "sign_in_failed");
}

#[tokio::test]
async fn passkey_as_second_factor_after_password() {
    let app = App::new().await;
    let mut owner = setup_owner(&app).await;
    let mut key = Authenticator::new();
    let added = key.register(&mut owner.client, "Phone").await;
    assert_eq!(added.status, StatusCode::CREATED, "{:?}", added.body);

    let mut client = app.client();
    let first = password_step(&mut client, OWNER, PASSWORD).await;
    assert_eq!(first.body["second_factor"]["passkey"], true);
    let start = client
        .post("/auth/sign-in/second-factor/passkey/start", json!({}))
        .await;
    assert_eq!(start.status, StatusCode::OK, "{:?}", start.body);
    let credential = key.assert(&start.body["options"]);
    let finish = client
        .post(
            "/auth/sign-in/second-factor/passkey/finish",
            json!({ "ceremony": start.body["ceremony"], "credential": credential }),
        )
        .await;
    assert_eq!(finish.status, StatusCode::OK, "{:?}", finish.body);
    assert_eq!(finish.body["stage"], "full");
}

#[tokio::test]
async fn second_factor_ceremony_is_bound_to_its_session() {
    let app = App::new().await;
    let mut owner = setup_owner(&app).await;
    let mut key = Authenticator::new();
    key.register(&mut owner.client, "Phone").await;

    let mut victim = app.client();
    password_step(&mut victim, OWNER, PASSWORD).await;
    let start = victim
        .post("/auth/sign-in/second-factor/passkey/start", json!({}))
        .await;
    let credential = key.assert(&start.body["options"]);

    let mut attacker = app.client();
    password_step(&mut attacker, OWNER, PASSWORD).await;
    let stolen = attacker
        .post(
            "/auth/sign-in/second-factor/passkey/finish",
            json!({ "ceremony": start.body["ceremony"], "credential": credential }),
        )
        .await;
    assert_eq!(stolen.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn registering_a_passkey_later_needs_a_recent_sign_in() {
    let app = App::new().await;
    let mut owner = setup_owner(&app).await;
    app.advance(5 * 60 + 1);
    let start = owner
        .client
        .post("/auth/passkeys/register/start", json!({}))
        .await;
    assert_eq!(start.status, StatusCode::UNAUTHORIZED);
    assert_eq!(start.error(), "step_up_required");
}

#[tokio::test]
async fn step_up_with_a_passkey() {
    let app = App::new().await;
    let mut owner = setup_owner(&app).await;
    let mut key = Authenticator::new();
    key.register(&mut owner.client, "Phone").await;
    app.advance(5 * 60 + 1);
    assert_eq!(
        owner.client.get("/app/sensitive").await.status,
        StatusCode::UNAUTHORIZED
    );
    let start = owner
        .client
        .post("/auth/step-up/passkey/start", json!({}))
        .await;
    let credential = key.assert(&start.body["options"]);
    let finish = owner
        .client
        .post(
            "/auth/step-up/passkey/finish",
            json!({ "ceremony": start.body["ceremony"], "credential": credential }),
        )
        .await;
    assert_eq!(finish.status, StatusCode::OK, "{:?}", finish.body);
    assert_eq!(
        owner.client.get("/app/sensitive").await.status,
        StatusCode::OK
    );
}

#[tokio::test]
async fn the_last_factor_cannot_be_removed() {
    let app = App::new().await;
    let mut owner = setup_owner(&app).await;
    let mut key = Authenticator::new();
    let added = key.register(&mut owner.client, "Phone").await;
    let id = added.body["id"].as_str().unwrap().to_owned();

    let removed = owner.client.delete("/auth/totp").await;
    assert_eq!(removed.status, StatusCode::NO_CONTENT);
    let last = owner.client.delete(&format!("/auth/passkeys/{id}")).await;
    assert_eq!(last.status, StatusCode::CONFLICT);
    assert_eq!(last.body["detail"], "last_factor");
}

#[tokio::test]
async fn the_same_passkey_cannot_be_registered_twice() {
    let app = App::new().await;
    let mut owner = setup_owner(&app).await;
    let mut key = Authenticator::new();
    key.register(&mut owner.client, "Phone").await;
    let start = owner
        .client
        .post("/auth/passkeys/register/start", json!({ "name": "Again" }))
        .await;
    let excluded = &start.body["options"]["publicKey"]["excludeCredentials"];
    assert_eq!(excluded.as_array().map(Vec::len), Some(1));
}
