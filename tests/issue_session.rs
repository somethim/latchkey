#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::net::IpAddr;

use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use common::{App, OWNER, Owner, PASSWORD, password_step, setup_owner};
use hmac::{Hmac, KeyInit, Mac};
use latchkey::store::{Role, User};
use latchkey::{Error, IssueSession, IssuedSession, MailKind};
use serde_json::json;
use sha2::Sha256;
use uuid::Uuid;

const METHOD: &str = "desktop_bridge";
const IP: &str = "203.0.113.7";

fn request() -> IssueSession {
    IssueSession {
        method: METHOD.into(),
        client_ip: Some(IP.parse().unwrap()),
        user_agent: Some("HomeDesktop/1.0".into()),
        device_cookie: None,
    }
}

async fn owner_id(app: &App) -> Uuid {
    app.latchkey.store().owner().await.unwrap().unwrap().id
}

async fn issue(app: &App, request: IssueSession) -> IssuedSession {
    app.latchkey
        .issue_session(owner_id(app).await, request)
        .await
        .unwrap()
}

/// A client that holds the issued session, as the desktop app would.
fn holder(app: &App, issued: &IssuedSession) -> common::Client {
    let mut client = app.client();
    client.cookie = Some(issued.session_cookie().value().to_owned());
    client.device = Some(issued.device_cookie().value().to_owned());
    client.csrf = Some(issued.csrf_token().to_owned());
    client
}

fn hmac_hex(data: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(&[42; 32]).unwrap();
    mac.update(data.as_bytes());
    mac.finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[tokio::test]
async fn issues_a_full_session_the_app_routes_accept() {
    let app = App::new().await;
    setup_owner(&app).await;
    let issued = issue(&app, request()).await;
    assert_eq!(issued.user_id(), owner_id(&app).await);

    let mut client = holder(&app, &issued);
    assert_eq!(client.get("/app/private").await.body, OWNER);
    let me = client.get("/auth/me").await;
    assert_eq!(me.body["stage"], "full");
    assert_eq!(me.body["method"], METHOD);
    assert_eq!(me.body["csrf_token"], issued.csrf_token());
    let post = client.post("/app/private", json!({})).await;
    assert_eq!(post.status, StatusCode::OK, "csrf token works");

    let sessions = app
        .latchkey
        .store()
        .sessions_for(issued.user_id(), app.now())
        .await
        .unwrap();
    let session = sessions
        .iter()
        .find(|session| session.id == issued.session_id())
        .unwrap();
    assert_eq!(session.method.as_deref(), Some(METHOD));
    assert_eq!(session.user_agent.as_deref(), Some("HomeDesktop/1.0"));
    assert_eq!(session.ip.as_deref(), Some(hmac_hex(IP).as_str()));
    assert_eq!(
        session.expires_at,
        app.now() + app.latchkey.config().session_ttl
    );
    assert_ne!(
        session.token_hash,
        issued.session_cookie().value().as_bytes(),
        "only the hash is stored"
    );
}

#[tokio::test]
async fn cookies_carry_latchkeys_attributes() {
    let app = App::new().await;
    setup_owner(&app).await;
    let issued = issue(&app, request()).await;
    let [session, device] = issued.set_cookie_headers().unwrap();
    let session = session.to_str().unwrap();
    let device = device.to_str().unwrap();
    assert!(session.starts_with(&format!(
        "__Host-latchkey={}; ",
        issued.session_cookie().value()
    )));
    assert!(device.starts_with(&format!(
        "__Host-latchkey_device={}; ",
        issued.device_cookie().value()
    )));
    for (cookie, max_age) in [(session, "Max-Age=2592000"), (device, "Max-Age=34560000")] {
        for attribute in ["Path=/", max_age, "HttpOnly", "Secure", "SameSite=Lax"] {
            assert!(cookie.contains(attribute), "{cookie} lacks {attribute}");
        }
    }
    assert_eq!(issued.session_cookie().name(), "__Host-latchkey");
    assert_eq!(
        issued.session_cookie().max_age(),
        app.latchkey.config().session_ttl
    );
    assert_eq!(
        issued.device_cookie().max_age(),
        app.latchkey.config().device_ttl
    );
    let debug = format!("{issued:?}");
    assert!(!debug.contains(issued.session_cookie().value()));
    assert!(!debug.contains(issued.csrf_token()));
}

#[tokio::test]
async fn the_step_up_window_starts_at_issue() {
    let app = App::new().await;
    setup_owner(&app).await;
    app.advance(600);
    let issued = issue(&app, request()).await;
    assert_eq!(issued.authenticated_at(), app.now());
    let mut client = holder(&app, &issued);
    let current = app
        .latchkey
        .session_from_cookie(issued.session_cookie().value())
        .await
        .unwrap();
    assert_eq!(current.authenticated_at(), Some(app.now()));
    assert_eq!(client.get("/app/sensitive").await.status, StatusCode::OK);
    app.advance(app.latchkey.config().step_up_window.whole_seconds() + 1);
    let late = client.get("/app/sensitive").await;
    assert_eq!(late.error(), "step_up_required");
}

#[tokio::test]
async fn the_sign_in_is_audited_with_its_method_and_ip_hmac() {
    let app = App::new().await;
    setup_owner(&app).await;
    let issued = issue(&app, request()).await;
    let events = app
        .latchkey
        .store()
        .audit(Some(issued.user_id()), 100)
        .await
        .unwrap();
    let sign_in = events
        .iter()
        .find(|event| event.kind == "sign_in" && event.detail.as_deref() == Some(METHOD))
        .expect("sign_in event");
    assert_eq!(sign_in.ip.as_deref(), Some(hmac_hex(IP).as_str()));
    assert_eq!(sign_in.at, app.now());
}

#[tokio::test]
async fn an_unknown_device_is_mailed_and_audited() {
    let app = App::new().await;
    setup_owner(&app).await;
    let issued = issue(&app, request()).await;
    let mail = app.mail(2).await;
    assert_eq!(mail.kind, MailKind::NewDevice);
    assert_eq!(mail.to, OWNER);
    let details = mail.sign_in.unwrap();
    assert_eq!(details.method, METHOD);
    assert_eq!(details.user_agent.as_deref(), Some("HomeDesktop/1.0"));
    let events = app.latchkey.store().audit(None, 100).await.unwrap();
    assert!(
        events
            .iter()
            .any(|event| event.kind == "new_device" && event.detail.as_deref() == Some(METHOD))
    );

    let again = issue(
        &app,
        IssueSession {
            device_cookie: Some(issued.device_cookie().value().to_owned()),
            ..request()
        },
    )
    .await;
    assert_eq!(
        again.device_cookie().value(),
        issued.device_cookie().value(),
        "a known device keeps its cookie"
    );
    app.no_mail(3).await;
}

#[tokio::test]
async fn the_browsers_device_cookie_counts_as_known() {
    let app = App::new().await;
    let owner = setup_owner(&app).await;
    let browser_device = owner.client.device.clone().unwrap();
    issue(
        &app,
        IssueSession {
            device_cookie: Some(browser_device),
            ..request()
        },
    )
    .await;
    app.no_mail(2).await;
}

#[tokio::test]
async fn a_locked_account_is_refused() {
    let app = App::new().await;
    setup_owner(&app).await;
    let id = owner_id(&app).await;
    app.latchkey
        .store()
        .set_locked_until(id, Some(app.now() + time::Duration::minutes(5)))
        .await
        .unwrap();
    let refused = app.latchkey.issue_session(id, request()).await;
    assert!(
        matches!(refused, Err(Error::TooManyAttempts { .. })),
        "{refused:?}"
    );
    assert!(
        app.latchkey
            .store()
            .sessions_for(id, app.now())
            .await
            .unwrap()
            .iter()
            .all(|session| session.method.as_deref() != Some(METHOD))
    );
    app.advance(301);
    assert!(app.latchkey.issue_session(id, request()).await.is_ok());
}

#[tokio::test]
async fn accounts_not_set_up_or_unknown_are_refused() {
    let app = App::new().await;
    let id = owner_id(&app).await;
    let refused = app.latchkey.issue_session(id, request()).await;
    assert!(matches!(refused, Err(Error::Forbidden)), "before setup");

    setup_owner(&app).await;
    let store = app.latchkey.store();
    let owner = store.owner().await.unwrap().unwrap();
    let member = User {
        id: Uuid::new_v4(),
        email: "member@example.test".into(),
        display_name: "Member".into(),
        role: Role::Member,
        active: true,
        ..owner.clone()
    };
    store.create_user(&member).await.unwrap();
    let refused = app.latchkey.issue_session(member.id, request()).await;
    assert!(
        matches!(refused, Err(Error::Forbidden)),
        "active but without a second factor"
    );
    let refused = app.latchkey.issue_session(Uuid::new_v4(), request()).await;
    assert!(matches!(refused, Err(Error::Forbidden)), "unknown");

    app.latchkey.reset_owner().await.unwrap();
    let refused = app.latchkey.issue_session(id, request()).await;
    assert!(matches!(refused, Err(Error::Forbidden)), "after a reset");
}

#[tokio::test]
async fn latchkeys_own_methods_cannot_be_claimed() {
    let app = App::new().await;
    setup_owner(&app).await;
    let id = owner_id(&app).await;
    for method in ["setup", "passkey", "password+totp", "", "Desktop"] {
        let refused = app
            .latchkey
            .issue_session(id, IssueSession::new(method))
            .await;
        assert!(
            matches!(refused, Err(Error::InvalidRequest("method"))),
            "{method:?}"
        );
    }
}

fn cookie_headers(cookie: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        HeaderValue::from_str(&format!("other=1; __Host-latchkey={cookie}")).unwrap(),
    );
    headers
}

#[tokio::test]
async fn the_browser_session_can_be_verified_from_its_cookie() {
    let app = App::new().await;
    let Owner { client, .. } = setup_owner(&app).await;
    let cookie = client.cookie.clone().unwrap();
    let current = app
        .latchkey
        .current_user_from_headers(&cookie_headers(&cookie))
        .await
        .unwrap();
    assert_eq!(current.email(), OWNER);
    assert!(current.csrf_matches(client.csrf.as_deref().unwrap()));
    assert!(!current.csrf_matches("nope"));
    assert_eq!(current.csrf_token(), client.csrf.as_deref().unwrap());

    let none = app
        .latchkey
        .current_user_from_headers(&HeaderMap::new())
        .await;
    assert!(matches!(none, Err(Error::Unauthorized)));
    let garbage = app.latchkey.session_from_cookie("garbage").await;
    assert!(matches!(garbage, Err(Error::Unauthorized)));

    app.advance(app.latchkey.config().session_ttl.whole_seconds() + 1);
    let expired = app.latchkey.session_from_cookie(&cookie).await;
    assert!(matches!(expired, Err(Error::Unauthorized)));
}

#[tokio::test]
async fn a_half_finished_sign_in_is_not_a_session() {
    let app = App::new().await;
    setup_owner(&app).await;
    let mut client = app.client();
    let first = password_step(&mut client, OWNER, PASSWORD).await;
    assert_eq!(first.body["stage"], "second_factor");
    let pending = app
        .latchkey
        .session_from_cookie(client.cookie.as_deref().unwrap())
        .await;
    assert!(matches!(pending, Err(Error::Unauthorized)));
}

#[tokio::test]
async fn issue_session_reads_the_client_like_the_endpoints_do() {
    let app = App::new().await;
    let mut headers = HeaderMap::new();
    headers.insert(header::USER_AGENT, HeaderValue::from_static("Agent/2"));
    headers.insert(
        header::COOKIE,
        HeaderValue::from_static("__Host-latchkey_device=dev; __Host-latchkey=s"),
    );
    headers.insert("x-forwarded-for", HeaderValue::from_static("198.51.100.1"));
    let peer: IpAddr = "192.0.2.9".parse().unwrap();
    let read = IssueSession::from_headers(&app.latchkey, METHOD, &headers, Some(peer));
    assert_eq!(read.method, METHOD);
    assert_eq!(read.client_ip, Some(peer), "X-Forwarded-For is not trusted");
    assert_eq!(read.user_agent.as_deref(), Some("Agent/2"));
    assert_eq!(read.device_cookie.as_deref(), Some("dev"));

    let mut config = common::config();
    config.trust_forwarded_for = true;
    let proxied = App::with_config(config).await;
    let read = IssueSession::from_headers(&proxied.latchkey, METHOD, &headers, Some(peer));
    assert_eq!(read.client_ip, Some("198.51.100.1".parse().unwrap()));
}
