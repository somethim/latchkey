#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::time::Duration as StdDuration;

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use axum::routing::get;
use http_body_util::BodyExt;
use latchkey::{
    Config, CurrentUser, Latchkey, ManualClock, PasswordParams, RecentAuth, SqliteStore, TestMailer,
};
use serde_json::{Value, json};
use time::OffsetDateTime;
use tower::ServiceExt;
use url::Url;
use webauthn_authenticator_rs::WebauthnAuthenticator;
use webauthn_authenticator_rs::softpasskey::SoftPasskey;
use webauthn_rs::prelude::{
    Base64UrlSafeData, CreationChallengeResponse, PublicKeyCredential, RequestChallengeResponse,
};

pub const ORIGIN: &str = "https://home.example.test";
pub const OWNER: &str = "owner@example.test";
pub const PASSWORD: &str = "correct horse battery staple";

pub struct App {
    pub latchkey: Latchkey,
    pub mailer: Arc<TestMailer>,
    pub clock: Arc<ManualClock>,
    pub router: Router,
}

pub fn config() -> Config {
    let mut config = Config::new(OWNER, ORIGIN, [42; 32]).unwrap();
    config.password = PasswordParams {
        memory_kib: 64,
        iterations: 1,
        parallelism: 1,
    };
    config
}

async fn private(user: CurrentUser) -> String {
    user.email().to_owned()
}

async fn sensitive(user: RecentAuth) -> String {
    format!("recent {}", user.email())
}

impl App {
    pub async fn new() -> Self {
        Self::with_config(config()).await
    }

    pub async fn with_config(config: Config) -> Self {
        let store = SqliteStore::in_memory().await.unwrap();
        let mailer = Arc::new(TestMailer::new());
        let clock = Arc::new(ManualClock::new(
            OffsetDateTime::from_unix_timestamp(1_900_000_000).unwrap(),
        ));
        let latchkey = Latchkey::with_clock(config, Arc::new(store), mailer.clone(), clock.clone())
            .await
            .unwrap();
        let router = Router::new()
            .nest("/auth", latchkey.router())
            .route("/app/private", get(private).post(private))
            .route("/app/sensitive", get(sensitive))
            .with_state(latchkey.clone());
        Self {
            latchkey,
            mailer,
            clock,
            router,
        }
    }

    pub fn client(&self) -> Client {
        Client {
            router: self.router.clone(),
            cookie: None,
            csrf: None,
            forwarded_for: None,
        }
    }

    pub fn advance(&self, seconds: i64) {
        self.clock.advance(time::Duration::seconds(seconds));
    }

    pub fn now(&self) -> OffsetDateTime {
        use latchkey::Clock;
        self.clock.now()
    }

    pub async fn mail(&self, n: usize) -> latchkey::Mail {
        self.mailer
            .wait_for(n, StdDuration::from_secs(2))
            .await
            .unwrap_or_else(|| panic!("mail #{n} never arrived"))
    }

    pub async fn no_mail(&self, n: usize) {
        assert!(
            self.mailer
                .wait_for(n, StdDuration::from_millis(200))
                .await
                .is_none(),
            "unexpected mail #{n}"
        );
    }

    pub fn totp_code(&self, secret_base32: &str) -> String {
        let secret = totp_rs::Secret::try_from_base32(secret_base32).unwrap();
        let totp = totp_rs::Builder::new()
            .with_secret(secret.as_bytes().to_vec())
            .build()
            .unwrap();
        totp.generate(u64::try_from(self.now().unix_timestamp()).unwrap())
            .to_string()
    }
}

pub struct Response {
    pub status: StatusCode,
    pub body: Value,
    pub set_cookie: Option<String>,
}

impl Response {
    pub fn error(&self) -> &str {
        self.body["error"].as_str().unwrap_or("")
    }
}

#[derive(Clone)]
pub struct Client {
    router: Router,
    pub cookie: Option<String>,
    pub csrf: Option<String>,
    pub forwarded_for: Option<String>,
}

pub struct Raw {
    pub origin: Option<&'static str>,
    pub csrf: Option<String>,
    pub sec_fetch_site: Option<&'static str>,
}

impl Client {
    pub async fn request(&mut self, method: Method, path: &str, body: Option<Value>) -> Response {
        let raw = Raw {
            origin: Some(ORIGIN),
            csrf: self.csrf.clone(),
            sec_fetch_site: None,
        };
        self.raw(method, path, body, raw).await
    }

    pub async fn raw(
        &mut self,
        method: Method,
        path: &str,
        body: Option<Value>,
        raw: Raw,
    ) -> Response {
        let mut request = Request::builder().method(method).uri(path);
        if let Some(origin) = raw.origin {
            request = request.header(header::ORIGIN, origin);
        }
        if let Some(site) = raw.sec_fetch_site {
            request = request.header("sec-fetch-site", site);
        }
        if let Some(csrf) = raw.csrf {
            request = request.header(latchkey::CSRF_HEADER, csrf);
        }
        if let Some(ip) = &self.forwarded_for {
            request = request.header("x-forwarded-for", ip);
        }
        if let Some(cookie) = &self.cookie {
            request = request.header(header::COOKIE, format!("__Host-latchkey={cookie}"));
        }
        let request = match body {
            Some(body) => request
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
            None => request.body(Body::empty()).unwrap(),
        };
        let response = self.router.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let set_cookie = response
            .headers()
            .get(header::SET_COOKIE)
            .map(|value| value.to_str().unwrap().to_owned());
        if let Some(cookie) = &set_cookie {
            let value = cookie
                .split(';')
                .next()
                .and_then(|pair| pair.split_once('='))
                .map(|(_, value)| value.to_owned())
                .unwrap();
            self.cookie = (!value.is_empty()).then_some(value);
        }
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let body: Value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes)
                .unwrap_or_else(|_| json!(String::from_utf8_lossy(&bytes)))
        };
        if let Some(csrf) = body["csrf_token"].as_str() {
            self.csrf = Some(csrf.to_owned());
        }
        Response {
            status,
            body,
            set_cookie,
        }
    }

    pub async fn get(&mut self, path: &str) -> Response {
        self.request(Method::GET, path, None).await
    }

    pub async fn post(&mut self, path: &str, body: Value) -> Response {
        self.request(Method::POST, path, Some(body)).await
    }

    pub async fn delete(&mut self, path: &str) -> Response {
        self.request(Method::DELETE, path, None).await
    }
}

pub struct Owner {
    pub client: Client,
    pub totp_secret: String,
    pub recovery_codes: Vec<String>,
}

/// Runs first-open setup with a password and TOTP.
pub async fn setup_owner(app: &App) -> Owner {
    let mut client = app.client();
    let before = app.mailer.sent().len();
    assert_eq!(
        client.post("/auth/setup/start", json!({})).await.status,
        StatusCode::ACCEPTED
    );
    let mail = app.mail(before + 1).await;
    assert_eq!(mail.to, OWNER);
    let token = TestMailer::token_of(&mail).unwrap();
    let redeemed = client
        .post("/auth/setup/redeem", json!({ "token": token }))
        .await;
    assert_eq!(redeemed.status, StatusCode::OK, "{:?}", redeemed.body);
    assert_eq!(redeemed.body["stage"], "setup");
    let password = client
        .post("/auth/setup/password", json!({ "password": PASSWORD }))
        .await;
    assert_eq!(
        password.status,
        StatusCode::NO_CONTENT,
        "{:?}",
        password.body
    );
    let totp_secret = enrol_totp(app, &mut client).await;
    let complete = client.post("/auth/setup/complete", json!({})).await;
    assert_eq!(complete.status, StatusCode::OK, "{:?}", complete.body);
    assert_eq!(complete.body["stage"], "full");
    let recovery_codes: Vec<String> = complete.body["recovery_codes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|code| code.as_str().unwrap().to_owned())
        .collect();
    assert_eq!(recovery_codes.len(), 10);
    Owner {
        client,
        totp_secret,
        recovery_codes,
    }
}

pub async fn enrol_totp(app: &App, client: &mut Client) -> String {
    let enrol = client.post("/auth/totp/enrol", json!({})).await;
    assert_eq!(enrol.status, StatusCode::OK, "{:?}", enrol.body);
    let secret = enrol.body["secret"].as_str().unwrap().to_owned();
    let confirm = client
        .post(
            "/auth/totp/confirm",
            json!({ "code": app.totp_code(&secret) }),
        )
        .await;
    assert_eq!(confirm.status, StatusCode::NO_CONTENT, "{:?}", confirm.body);
    secret
}

/// Signs in with email and password; leaves the client at the second-factor stage.
pub async fn password_step(client: &mut Client, email: &str, password: &str) -> Response {
    client
        .post(
            "/auth/sign-in/password",
            json!({ "email": email, "password": password }),
        )
        .await
}

/// A software passkey that claims user verification.
pub struct Authenticator {
    inner: WebauthnAuthenticator<SoftPasskey>,
    pub credential_id: Option<Base64UrlSafeData>,
}

impl Authenticator {
    pub fn new() -> Self {
        Self {
            inner: WebauthnAuthenticator::new(SoftPasskey::new(true)),
            credential_id: None,
        }
    }

    fn origin() -> Url {
        Url::parse(ORIGIN).unwrap()
    }

    pub async fn register(&mut self, client: &mut Client, name: &str) -> Response {
        let start = client
            .post("/auth/passkeys/register/start", json!({ "name": name }))
            .await;
        assert_eq!(start.status, StatusCode::OK, "{:?}", start.body);
        let options: CreationChallengeResponse =
            serde_json::from_value(start.body["options"].clone()).unwrap();
        let credential = self.inner.do_registration(Self::origin(), options).unwrap();
        self.credential_id = Some(credential.raw_id.clone());
        client
            .post(
                "/auth/passkeys/register/finish",
                json!({ "ceremony": start.body["ceremony"], "credential": credential }),
            )
            .await
    }

    pub fn assert(&mut self, options: &Value) -> PublicKeyCredential {
        let options: RequestChallengeResponse = serde_json::from_value(options.clone()).unwrap();
        self.inner
            .do_authentication(Self::origin(), options)
            .unwrap()
    }

    /// The soft token cannot discover its own credentials, so the test supplies the allow
    /// list and the user handle a platform passkey would return.
    pub fn assert_discoverable(&mut self, options: &Value, user_id: &str) -> PublicKeyCredential {
        let mut options: RequestChallengeResponse =
            serde_json::from_value(options.clone()).unwrap();
        let id = self.credential_id.clone().unwrap();
        options.public_key.allow_credentials = vec![webauthn_rs_proto::AllowCredentials {
            type_: "public-key".into(),
            id,
            transports: None,
        }];
        let mut credential = self
            .inner
            .do_authentication(Self::origin(), options)
            .unwrap();
        let user = uuid::Uuid::parse_str(user_id).unwrap();
        credential.response.user_handle = Some(user.as_bytes().to_vec().into());
        credential
    }
}
