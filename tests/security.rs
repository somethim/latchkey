#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use axum::http::{Method, StatusCode};
use common::{App, Authenticator, OWNER, PASSWORD, Raw, enrol_totp, password_step, setup_owner};
use latchkey::{MailKind, TestMailer};
use serde_json::json;

#[tokio::test]
async fn unsafe_requests_need_the_csrf_token() {
    let app = App::new().await;
    let mut owner = setup_owner(&app).await;
    let csrf = owner.client.csrf.clone();

    for raw in [
        Raw {
            origin: Some(common::ORIGIN),
            csrf: None,
            sec_fetch_site: None,
        },
        Raw {
            origin: Some(common::ORIGIN),
            csrf: Some("wrong".into()),
            sec_fetch_site: None,
        },
    ] {
        let response = owner
            .client
            .raw(Method::POST, "/auth/sign-out", None, raw)
            .await;
        assert_eq!(response.status, StatusCode::FORBIDDEN);
        assert_eq!(response.error(), "csrf_rejected");
    }
    let app_route = owner
        .client
        .raw(
            Method::POST,
            "/app/private",
            None,
            Raw {
                origin: Some(common::ORIGIN),
                csrf: None,
                sec_fetch_site: None,
            },
        )
        .await;
    assert_eq!(
        app_route.status,
        StatusCode::FORBIDDEN,
        "app routes get the CSRF check too"
    );

    let reads = owner
        .client
        .raw(
            Method::GET,
            "/app/private",
            None,
            Raw {
                origin: None,
                csrf: None,
                sec_fetch_site: None,
            },
        )
        .await;
    assert_eq!(reads.status, StatusCode::OK, "safe methods need no token");

    let ok = owner
        .client
        .raw(
            Method::POST,
            "/app/private",
            None,
            Raw {
                origin: None,
                csrf,
                sec_fetch_site: Some("same-origin"),
            },
        )
        .await;
    assert_eq!(ok.status, StatusCode::OK);
}

#[tokio::test]
async fn cross_origin_requests_are_rejected() {
    let app = App::new().await;
    let mut owner = setup_owner(&app).await;
    let csrf = owner.client.csrf.clone();
    let foreign = owner
        .client
        .raw(
            Method::POST,
            "/app/private",
            None,
            Raw {
                origin: Some("https://evil.example"),
                csrf: csrf.clone(),
                sec_fetch_site: None,
            },
        )
        .await;
    assert_eq!(foreign.status, StatusCode::FORBIDDEN);

    let no_origin = owner
        .client
        .raw(
            Method::POST,
            "/app/private",
            None,
            Raw {
                origin: None,
                csrf,
                sec_fetch_site: Some("cross-site"),
            },
        )
        .await;
    assert_eq!(no_origin.status, StatusCode::FORBIDDEN);

    let mut anonymous = app.client();
    let login_csrf = anonymous
        .raw(
            Method::POST,
            "/auth/sign-in/password",
            Some(json!({ "email": OWNER, "password": PASSWORD })),
            Raw {
                origin: Some("https://evil.example"),
                csrf: None,
                sec_fetch_site: None,
            },
        )
        .await;
    assert_eq!(login_csrf.status, StatusCode::FORBIDDEN);
    assert!(login_csrf.set_cookie.is_none());
}

#[tokio::test]
async fn sensitive_changes_need_a_step_up_within_five_minutes() {
    let app = App::new().await;
    let mut owner = setup_owner(&app).await;
    assert_eq!(
        owner.client.get("/app/sensitive").await.status,
        StatusCode::OK
    );
    app.advance(5 * 60 + 1);
    let stale = owner.client.get("/app/sensitive").await;
    assert_eq!(stale.status, StatusCode::UNAUTHORIZED);
    assert_eq!(stale.error(), "step_up_required");

    let wrong = owner
        .client
        .post(
            "/auth/step-up/password",
            json!({ "password": PASSWORD, "code": "000000" }),
        )
        .await;
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED);

    let code = app.totp_code(&owner.totp_secret);
    let stepped = owner
        .client
        .post(
            "/auth/step-up/password",
            json!({ "password": PASSWORD, "code": code }),
        )
        .await;
    assert_eq!(stepped.status, StatusCode::OK, "{:?}", stepped.body);
    assert!(stepped.body["step_up_until"].is_string());
    assert_eq!(
        owner.client.get("/app/sensitive").await.status,
        StatusCode::OK
    );

    let audit = owner.client.get("/auth/audit").await;
    let kinds: Vec<&str> = audit.body["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|event| event["kind"].as_str().unwrap())
        .collect();
    assert!(kinds.contains(&"step_up"));
    assert!(kinds.contains(&"sign_in_failed"));
}

#[tokio::test]
async fn step_up_with_a_recovery_code() {
    let app = App::new().await;
    let mut owner = setup_owner(&app).await;
    app.advance(10 * 60);
    let code = owner.recovery_codes[0].clone();
    let stepped = owner
        .client
        .post(
            "/auth/step-up/password",
            json!({ "password": PASSWORD, "code": code }),
        )
        .await;
    assert_eq!(stepped.status, StatusCode::OK);
}

#[tokio::test]
async fn sessions_are_listed_and_revoked() {
    let app = App::new().await;
    let mut owner = setup_owner(&app).await;
    app.advance(30);
    let mut laptop = app.client();
    password_step(&mut laptop, OWNER, PASSWORD).await;
    let code = app.totp_code(&owner.totp_secret);
    laptop
        .post("/auth/sign-in/code", json!({ "code": code }))
        .await;

    let list = owner.client.get("/auth/sessions").await;
    let sessions = list.body["sessions"].as_array().unwrap();
    assert_eq!(sessions.len(), 2);
    let other = sessions
        .iter()
        .find(|session| session["current"] == false)
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();

    app.advance(5 * 60 + 1);
    let needs_step_up = owner
        .client
        .delete(&format!("/auth/sessions/{other}"))
        .await;
    assert_eq!(needs_step_up.status, StatusCode::UNAUTHORIZED);
    app.advance(30);
    let code = app.totp_code(&owner.totp_secret);
    owner
        .client
        .post(
            "/auth/step-up/password",
            json!({ "password": PASSWORD, "code": code }),
        )
        .await;
    let revoked = owner
        .client
        .delete(&format!("/auth/sessions/{other}"))
        .await;
    assert_eq!(revoked.status, StatusCode::NO_CONTENT);
    assert_eq!(
        laptop.get("/app/private").await.status,
        StatusCode::UNAUTHORIZED
    );
    let missing = owner
        .client
        .delete(&format!("/auth/sessions/{other}"))
        .await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn owner_invites_a_family_member() {
    let app = App::new().await;
    let mut owner = setup_owner(&app).await;
    let invited = owner
        .client
        .post(
            "/auth/invites",
            json!({ "email": "Kid@Example.test", "display_name": "Kid" }),
        )
        .await;
    assert_eq!(invited.status, StatusCode::CREATED, "{:?}", invited.body);
    assert_eq!(invited.body["account"]["role"], "member");
    let mail = app.mail(2).await;
    assert_eq!(mail.kind, MailKind::Invite);
    assert_eq!(mail.to, "kid@example.test");
    assert!(
        mail.link
            .as_str()
            .starts_with("https://home.example.test/invite?token=")
    );

    let duplicate = owner
        .client
        .post("/auth/invites", json!({ "email": "kid@example.test" }))
        .await;
    assert_eq!(duplicate.status, StatusCode::CONFLICT);

    let mut kid = app.client();
    let token = TestMailer::token_of(&mail).unwrap();
    let wrong_door = kid
        .post("/auth/setup/redeem", json!({ "token": token }))
        .await;
    assert_eq!(wrong_door.status, StatusCode::UNAUTHORIZED);
    let redeemed = kid
        .post("/auth/invites/redeem", json!({ "token": token }))
        .await;
    assert_eq!(redeemed.status, StatusCode::OK, "{:?}", redeemed.body);
    assert_eq!(redeemed.body["account"]["email"], "kid@example.test");
    kid.post(
        "/auth/setup/password",
        json!({ "password": "the kid's own long password" }),
    )
    .await;
    let mut key = Authenticator::new();
    key.register(&mut kid, "Tablet").await;
    let done = kid.post("/auth/setup/complete", json!({})).await;
    assert_eq!(done.status, StatusCode::OK, "{:?}", done.body);

    let forbidden = kid
        .post("/auth/invites", json!({ "email": "x@example.test" }))
        .await;
    assert_eq!(forbidden.status, StatusCode::FORBIDDEN);

    let own_audit = kid.get("/auth/audit").await;
    let events = own_audit.body["events"].as_array().unwrap();
    assert!(!events.is_empty());
    let kid_id = &redeemed.body["account"]["id"];
    assert!(events.iter().all(|event| &event["user_id"] == kid_id));

    let all = owner.client.get("/auth/audit?limit=500").await;
    assert!(all.body["events"].as_array().unwrap().len() > events.len());
}

#[tokio::test]
async fn invite_needs_the_owner_and_a_recent_sign_in() {
    let app = App::new().await;
    let mut owner = setup_owner(&app).await;
    app.advance(5 * 60 + 1);
    let stale = owner
        .client
        .post("/auth/invites", json!({ "email": "kid@example.test" }))
        .await;
    assert_eq!(stale.status, StatusCode::UNAUTHORIZED);
    assert_eq!(stale.error(), "step_up_required");
}

#[tokio::test]
async fn totp_reenrolment_needs_a_recent_sign_in_and_a_valid_code() {
    let app = App::new().await;
    let mut owner = setup_owner(&app).await;
    let enrol = owner.client.post("/auth/totp/enrol", json!({})).await;
    assert_eq!(enrol.status, StatusCode::OK);
    let wrong = owner
        .client
        .post("/auth/totp/confirm", json!({ "code": "123456" }))
        .await;
    assert_eq!(wrong.status, StatusCode::BAD_REQUEST);
    app.advance(30);
    let secret = enrol_totp(&app, &mut owner.client).await;
    assert_ne!(secret, owner.totp_secret);
    app.advance(5 * 60 + 1);
    let stale = owner.client.post("/auth/totp/enrol", json!({})).await;
    assert_eq!(stale.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn recovery_codes_can_be_regenerated() {
    let app = App::new().await;
    let mut owner = setup_owner(&app).await;
    let fresh = owner.client.post("/auth/recovery-codes", json!({})).await;
    assert_eq!(fresh.status, StatusCode::OK);
    assert_eq!(fresh.body["recovery_codes"].as_array().unwrap().len(), 10);
    let mut client = app.client();
    password_step(&mut client, OWNER, PASSWORD).await;
    let old = client
        .post(
            "/auth/sign-in/code",
            json!({ "code": owner.recovery_codes[0] }),
        )
        .await;
    assert_eq!(old.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn ip_addresses_are_stored_only_as_hmacs() {
    let mut config = common::config();
    config.trust_forwarded_for = true;
    let app = App::with_config(config).await;
    let mut owner = setup_owner(&app).await;
    let mut client = app.client();
    client.forwarded_for = Some("10.0.0.1, 203.0.113.9".into());
    let failed = password_step(&mut client, OWNER, "a wrong password here").await;
    assert_eq!(failed.status, StatusCode::UNAUTHORIZED);

    let events = app.latchkey.store().audit(None, 100).await.unwrap();
    let failure = events
        .iter()
        .find(|event| event.kind == "sign_in_failed")
        .unwrap();
    let tag = failure.ip.as_deref().unwrap();
    assert_eq!(tag.len(), 64);
    assert!(!tag.contains("203.0.113.9"));

    let body = owner.client.get("/auth/audit").await.body.to_string();
    assert!(!body.contains("203.0.113.9"));
}

#[tokio::test]
async fn forwarded_for_is_ignored_unless_trusted() {
    let app = App::new().await;
    setup_owner(&app).await;
    let mut client = app.client();
    client.forwarded_for = Some("203.0.113.9".into());
    password_step(&mut client, OWNER, "a wrong password here").await;
    let events = app.latchkey.store().audit(None, 100).await.unwrap();
    let failure = events
        .iter()
        .find(|event| event.kind == "sign_in_failed")
        .unwrap();
    assert!(failure.ip.is_none());
}
