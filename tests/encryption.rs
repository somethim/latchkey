#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::Arc;

use axum::http::StatusCode;
use common::{App, Authenticator, OWNER, PASSWORD, config, password_step, setup_owner};
use latchkey::store::PasskeyRecord;
use latchkey::{Error, Latchkey, SqliteStore, Store, TestMailer};
use serde_json::json;
use sqlx::Row;
use uuid::Uuid;

fn raw_secret(base32: &str) -> Vec<u8> {
    totp_rs::Secret::try_from_base32(base32)
        .unwrap()
        .as_bytes()
        .to_vec()
}

async fn start(store: &SqliteStore, config: latchkey::Config) -> Result<Latchkey, Error> {
    Latchkey::new(config, Arc::new(store.clone()), Arc::new(TestMailer::new())).await
}

#[tokio::test]
async fn totp_secrets_and_passkeys_are_encrypted_at_rest() {
    let store = SqliteStore::in_memory().await.unwrap();
    let app = App::with_store(config(), store.clone()).await;
    let mut owner = setup_owner(&app).await;
    let mut authenticator = Authenticator::new();
    let registered = authenticator.register(&mut owner.client, "Laptop").await;
    assert_eq!(
        registered.status,
        StatusCode::CREATED,
        "{:?}",
        registered.body
    );

    let row = sqlx::query("SELECT secret FROM latchkey_totp")
        .fetch_one(store.pool())
        .await
        .unwrap();
    let stored: Vec<u8> = row.get("secret");
    let secret = raw_secret(&owner.totp_secret);
    assert!(stored.starts_with(b"lk1\0"));
    assert!(!stored.windows(secret.len()).any(|w| w == secret));

    let row = sqlx::query("SELECT data FROM latchkey_passkeys")
        .fetch_one(store.pool())
        .await
        .unwrap();
    let data: String = row.get("data");
    assert!(data.starts_with("lk1:"));
    assert!(!data.contains("cred"));

    let mut client = app.client();
    password_step(&mut client, OWNER, PASSWORD).await;
    app.advance(30);
    let code = app.totp_code(&owner.totp_secret);
    let signed_in = client
        .post("/auth/sign-in/code", json!({ "code": code }))
        .await;
    assert_eq!(signed_in.status, StatusCode::OK, "{:?}", signed_in.body);

    let mut client = app.client();
    let start = client.post("/auth/sign-in/passkey/start", json!({})).await;
    let user_id = registered_owner_id(&store).await;
    let credential = authenticator.assert_discoverable(&start.body["options"], &user_id);
    let finish = client
        .post(
            "/auth/sign-in/passkey/finish",
            json!({ "ceremony": start.body["ceremony"], "credential": credential }),
        )
        .await;
    assert_eq!(finish.status, StatusCode::OK, "{:?}", finish.body);
    let after_use: String = sqlx::query("SELECT data FROM latchkey_passkeys")
        .fetch_one(store.pool())
        .await
        .unwrap()
        .get("data");
    assert!(after_use.starts_with("lk1:"));
}

async fn registered_owner_id(store: &SqliteStore) -> String {
    store.owner().await.unwrap().unwrap().id.to_string()
}

#[tokio::test]
async fn plaintext_totp_refuses_to_start_until_migrated() {
    let store = SqliteStore::in_memory().await.unwrap();
    let app = App::with_store(config(), store.clone()).await;
    let owner = setup_owner(&app).await;
    let owner_id = store.owner().await.unwrap().unwrap().id;
    let secret = raw_secret(&owner.totp_secret);
    store
        .set_totp_secrets(owner_id, Some(&secret), None)
        .await
        .unwrap();
    drop(app);

    let refused = start(&store, config()).await.unwrap_err();
    assert!(
        matches!(&refused, Error::Config(msg) if msg.contains("encrypt_plaintext_secrets")),
        "{refused:?}"
    );

    assert_eq!(
        Latchkey::encrypt_plaintext_secrets(&config(), &store)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        Latchkey::encrypt_plaintext_secrets(&config(), &store)
            .await
            .unwrap(),
        0,
        "running it again changes nothing"
    );

    let app = App::with_store(config(), store.clone()).await;
    let mut client = app.client();
    password_step(&mut client, OWNER, PASSWORD).await;
    app.advance(30);
    let code = app.totp_code(&owner.totp_secret);
    let signed_in = client
        .post("/auth/sign-in/code", json!({ "code": code }))
        .await;
    assert_eq!(signed_in.status, StatusCode::OK, "{:?}", signed_in.body);
}

#[tokio::test]
async fn plaintext_passkeys_refuse_to_start_until_migrated() {
    let store = SqliteStore::in_memory().await.unwrap();
    let app = App::with_store(config(), store.clone()).await;
    let owner_id = store.owner().await.unwrap().unwrap().id;
    let id = Uuid::new_v4();
    store
        .add_passkey(&PasskeyRecord {
            id,
            user_id: owner_id,
            credential_id: vec![1, 2, 3],
            name: "Legacy".into(),
            data: "{\"cred\":{}}".into(),
            created_at: app.now(),
            last_used_at: None,
        })
        .await
        .unwrap();
    drop(app);

    assert!(matches!(
        start(&store, config()).await.unwrap_err(),
        Error::Config(_)
    ));
    assert_eq!(
        Latchkey::encrypt_plaintext_secrets(&config(), &store)
            .await
            .unwrap(),
        1
    );
    let migrated = store.passkeys_for(owner_id).await.unwrap();
    assert!(migrated[0].data.starts_with("lk1:"));
    assert!(start(&store, config()).await.is_ok());
}

#[tokio::test]
async fn another_data_key_refuses_to_start() {
    let store = SqliteStore::in_memory().await.unwrap();
    let app = App::with_store(config(), store.clone()).await;
    setup_owner(&app).await;
    drop(app);

    let mut other = config();
    other.data_key = [44; 32];
    let refused = start(&store, other.clone()).await.unwrap_err();
    assert!(
        matches!(&refused, Error::Config(msg) if msg.contains("do not decrypt")),
        "{refused:?}"
    );
    assert!(
        Latchkey::encrypt_plaintext_secrets(&other, &store)
            .await
            .is_err(),
        "the migration does not paper over a wrong key"
    );
}

#[tokio::test]
async fn data_key_must_differ_from_the_secret_key() {
    let store = SqliteStore::in_memory().await.unwrap();
    let mut same = config();
    same.data_key = same.secret_key;
    assert!(matches!(
        start(&store, same).await.unwrap_err(),
        Error::Config(_)
    ));
}
