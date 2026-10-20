#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use latchkey::Store;
use latchkey::store::{NewAuditEvent, OneTimeToken, Role, SqliteStore, TokenKind, User};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_900_000_000).unwrap()
}

fn user(email: &str, role: Role) -> User {
    User {
        id: Uuid::new_v4(),
        email: email.into(),
        display_name: email.into(),
        role,
        password_hash: None,
        active: true,
        failed_attempts: 0,
        locked_until: None,
        created_at: now(),
    }
}

#[tokio::test]
async fn only_one_owner_and_unique_emails() {
    let store = SqliteStore::in_memory().await.unwrap();
    store
        .create_user(&user("a@x.test", Role::Owner))
        .await
        .unwrap();
    assert!(
        store
            .create_user(&user("b@x.test", Role::Owner))
            .await
            .is_err()
    );
    assert!(
        store
            .create_user(&user("a@x.test", Role::Member))
            .await
            .is_err()
    );
    store
        .create_user(&user("c@x.test", Role::Member))
        .await
        .unwrap();
}

#[tokio::test]
async fn tokens_are_consumed_once_and_respect_kind_and_expiry() {
    let store = SqliteStore::in_memory().await.unwrap();
    let owner = user("a@x.test", Role::Owner);
    store.create_user(&owner).await.unwrap();
    let token = OneTimeToken {
        hash: vec![1; 32],
        kind: TokenKind::SignIn,
        user_id: owner.id,
        created_at: now(),
        expires_at: now() + Duration::minutes(15),
    };
    store.insert_token(&token).await.unwrap();
    assert_eq!(
        store
            .consume_token(&token.hash, TokenKind::Setup, now())
            .await
            .unwrap(),
        None
    );
    assert_eq!(
        store
            .consume_token(&token.hash, TokenKind::SignIn, now())
            .await
            .unwrap(),
        Some(owner.id)
    );
    assert_eq!(
        store
            .consume_token(&token.hash, TokenKind::SignIn, now())
            .await
            .unwrap(),
        None
    );

    store.insert_token(&token).await.unwrap();
    let late = now() + Duration::minutes(15);
    assert_eq!(
        store
            .consume_token(&token.hash, TokenKind::SignIn, late)
            .await
            .unwrap(),
        None
    );
}

#[tokio::test]
async fn totp_steps_only_move_forward() {
    let store = SqliteStore::in_memory().await.unwrap();
    let owner = user("a@x.test", Role::Owner);
    store.create_user(&owner).await.unwrap();
    assert!(
        !store.use_totp_step(owner.id, 10).await.unwrap(),
        "no secret yet"
    );
    store.set_pending_totp(owner.id, &[7; 20]).await.unwrap();
    assert!(store.confirm_totp(owner.id, 10).await.unwrap());
    assert!(!store.use_totp_step(owner.id, 10).await.unwrap());
    assert!(!store.use_totp_step(owner.id, 9).await.unwrap());
    assert!(store.use_totp_step(owner.id, 11).await.unwrap());
}

#[tokio::test]
async fn recovery_codes_are_single_use() {
    let store = SqliteStore::in_memory().await.unwrap();
    let owner = user("a@x.test", Role::Owner);
    store.create_user(&owner).await.unwrap();
    store
        .replace_recovery_codes(owner.id, &[vec![1; 32], vec![2; 32]])
        .await
        .unwrap();
    assert!(
        store
            .use_recovery_code(owner.id, &[1; 32], now())
            .await
            .unwrap()
    );
    assert!(
        !store
            .use_recovery_code(owner.id, &[1; 32], now())
            .await
            .unwrap()
    );
    assert_eq!(store.unused_recovery_codes(owner.id).await.unwrap(), 1);
}

#[tokio::test]
async fn failures_count_up_and_clear() {
    let store = SqliteStore::in_memory().await.unwrap();
    let owner = user("a@x.test", Role::Owner);
    store.create_user(&owner).await.unwrap();
    assert_eq!(store.add_failure(owner.id).await.unwrap(), 1);
    assert_eq!(store.add_failure(owner.id).await.unwrap(), 2);
    store.clear_failures(owner.id).await.unwrap();
    assert_eq!(store.add_failure(owner.id).await.unwrap(), 1);
}

#[tokio::test]
async fn audit_log_is_append_only() {
    let store = SqliteStore::in_memory().await.unwrap();
    store
        .append_audit(&NewAuditEvent {
            at: now(),
            user_id: None,
            kind: "sign_in".into(),
            detail: None,
            ip: None,
        })
        .await
        .unwrap();
    let update = sqlx::query("UPDATE latchkey_audit SET kind = 'x'")
        .execute(store.pool())
        .await;
    assert!(update.is_err());
    let delete = sqlx::query("DELETE FROM latchkey_audit")
        .execute(store.pool())
        .await;
    assert!(delete.is_err());
    assert_eq!(store.audit(None, 10).await.unwrap().len(), 1);
}

#[tokio::test]
async fn file_database_migrates_once_and_reopens() {
    let dir = std::env::temp_dir().join(format!("latchkey-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let url = format!("sqlite://{}", dir.join("auth.db").display());
    {
        let store = SqliteStore::connect(&url).await.unwrap();
        store
            .create_user(&user("a@x.test", Role::Owner))
            .await
            .unwrap();
        store.pool().close().await;
    }
    let store = SqliteStore::connect(&url).await.unwrap();
    assert!(store.owner().await.unwrap().is_some());
    let applied: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM latchkey_migrations")
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(applied, 2);
    store.pool().close().await;
    std::fs::remove_dir_all(dir).unwrap();
}
