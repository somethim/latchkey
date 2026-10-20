use std::net::{IpAddr, SocketAddr};

use axum::Json;
use axum::extract::{ConnectInfo, FromRef, FromRequest, FromRequestParts, Request};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, Method, header};
use serde::de::DeserializeOwned;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::crypto::{ct_eq, token_hash};
use crate::error::Error;
use crate::service::{Client, Latchkey};
use crate::store::{Role, Session, Stage, User};

pub const CSRF_HEADER: &str = "x-csrf-token";
const MAX_USER_AGENT: usize = 256;

pub(crate) fn is_unsafe(method: &Method) -> bool {
    !matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
}

/// Unsafe requests must come from the configured origin: `Origin` when the browser sends it,
/// otherwise `Sec-Fetch-Site: same-origin`.
pub(crate) fn origin_ok(latchkey: &Latchkey, headers: &HeaderMap) -> bool {
    if let Some(origin) = headers.get(header::ORIGIN) {
        return origin
            .to_str()
            .is_ok_and(|origin| origin == latchkey.config().origin_string());
    }
    headers
        .get("sec-fetch-site")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|site| site == "same-origin")
}

pub(crate) fn session_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(key, _)| *key == name)
        .map(|(_, value)| value.to_owned())
}

pub(crate) fn set_cookie(
    latchkey: &Latchkey,
    token: &str,
    max_age_secs: i64,
) -> Option<HeaderValue> {
    cookie_header(&latchkey.config().cookie_name, token, max_age_secs)
}

pub(crate) fn set_device_cookie(latchkey: &Latchkey, token: &str) -> Option<HeaderValue> {
    let config = latchkey.config();
    cookie_header(
        &config.device_cookie_name,
        token,
        config.device_ttl.whole_seconds(),
    )
}

pub(crate) fn cookie_header(name: &str, token: &str, max_age_secs: i64) -> Option<HeaderValue> {
    HeaderValue::from_str(&format!(
        "{name}={token}; Path=/; Max-Age={max_age_secs}; HttpOnly; Secure; SameSite=Lax"
    ))
    .ok()
}

pub(crate) fn client_from(latchkey: &Latchkey, parts: &Parts) -> Client {
    let socket = parts
        .extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip());
    client_from_headers(latchkey, &parts.headers, socket)
}

pub(crate) fn client_from_headers(
    latchkey: &Latchkey,
    headers: &HeaderMap,
    peer: Option<IpAddr>,
) -> Client {
    let forwarded = latchkey
        .config()
        .trust_forwarded_for
        .then(|| {
            headers
                .get_all("x-forwarded-for")
                .iter()
                .filter_map(|value| value.to_str().ok())
                .flat_map(|value| value.split(','))
                .map(str::trim)
                .rfind(|ip| !ip.is_empty())
                .map(str::to_owned)
        })
        .flatten();
    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .map(truncate_user_agent);
    Client {
        ip: forwarded.or_else(|| peer.map(|ip| ip.to_string())),
        user_agent,
        device: session_cookie(headers, &latchkey.config().device_cookie_name),
    }
}

pub(crate) fn truncate_user_agent(raw: &str) -> String {
    raw.chars().take(MAX_USER_AGENT).collect()
}

impl<S> FromRequestParts<S> for Client
where
    Latchkey: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        Ok(client_from(&Latchkey::from_ref(state), parts))
    }
}

/// A session at any stage, with CSRF checked on unsafe methods.
pub(crate) struct AnySession {
    pub(crate) session: Session,
    pub(crate) user: User,
}

impl AnySession {
    pub(crate) fn require(self, stage: Stage) -> Result<Self, Error> {
        if self.session.stage == stage {
            Ok(self)
        } else {
            Err(Error::Unauthorized)
        }
    }
}

async fn load_session(latchkey: &Latchkey, parts: &Parts) -> Result<AnySession, Error> {
    let token = session_cookie(&parts.headers, &latchkey.config().cookie_name)
        .ok_or(Error::Unauthorized)?;
    let found = session_by_token(latchkey, &token).await?;
    if is_unsafe(&parts.method) {
        let presented = parts
            .headers
            .get(CSRF_HEADER)
            .map(HeaderValue::as_bytes)
            .unwrap_or_default();
        if !origin_ok(latchkey, &parts.headers)
            || !ct_eq(presented, found.session.csrf_token.as_bytes())
        {
            return Err(Error::CsrfRejected);
        }
    }
    Ok(found)
}

/// The session a cookie value names, at any stage; no CSRF or origin check.
pub(crate) async fn session_by_token(
    latchkey: &Latchkey,
    token: &str,
) -> Result<AnySession, Error> {
    let hash = token_hash(token).ok_or(Error::Unauthorized)?;
    let store = latchkey.store();
    let session = store
        .session_by_hash(&hash)
        .await?
        .ok_or(Error::Unauthorized)?;
    if session.expires_at <= latchkey.now() {
        store.delete_session(&hash).await?;
        return Err(Error::Unauthorized);
    }
    let user = store
        .user_by_id(session.user_id)
        .await?
        .ok_or(Error::Unauthorized)?;
    if session.stage != Stage::Setup && !user.active {
        return Err(Error::Unauthorized);
    }
    Ok(AnySession { session, user })
}

impl<S> FromRequestParts<S> for AnySession
where
    Latchkey: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        load_session(&Latchkey::from_ref(state), parts).await
    }
}

/// The signed-in account. Rejects with 401 unless the session completed sign-in, and checks
/// the origin and `x-csrf-token` header on unsafe methods.
#[derive(Debug, Clone)]
pub struct CurrentUser {
    pub(crate) user: User,
    pub(crate) session: Session,
}

impl CurrentUser {
    pub fn id(&self) -> Uuid {
        self.user.id
    }

    pub fn email(&self) -> &str {
        &self.user.email
    }

    pub fn display_name(&self) -> &str {
        &self.user.display_name
    }

    pub fn role(&self) -> Role {
        self.user.role
    }

    pub fn is_owner(&self) -> bool {
        self.user.role == Role::Owner
    }

    pub fn session_id(&self) -> Uuid {
        self.session.id
    }

    pub fn authenticated_at(&self) -> Option<OffsetDateTime> {
        self.session.authenticated_at
    }

    /// The session's CSRF token, for a server-rendered form that posts back to the app.
    pub fn csrf_token(&self) -> &str {
        &self.session.csrf_token
    }

    /// Compares `presented` with the session's CSRF token in constant time.
    pub fn csrf_matches(&self, presented: &str) -> bool {
        ct_eq(presented.as_bytes(), self.session.csrf_token.as_bytes())
    }
}

impl<S> FromRequestParts<S> for CurrentUser
where
    Latchkey: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let latchkey = Latchkey::from_ref(state);
        let AnySession { session, user } =
            load_session(&latchkey, parts).await?.require(Stage::Full)?;
        Ok(CurrentUser { user, session })
    }
}

/// A [`CurrentUser`] who signed in or stepped up within the step-up window (5 minutes by
/// default). Rejects with 401 `step_up_required` otherwise.
#[derive(Debug, Clone)]
pub struct RecentAuth(pub CurrentUser);

impl std::ops::Deref for RecentAuth {
    type Target = CurrentUser;

    fn deref(&self) -> &CurrentUser {
        &self.0
    }
}

impl<S> FromRequestParts<S> for RecentAuth
where
    Latchkey: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let latchkey = Latchkey::from_ref(state);
        let current = CurrentUser::from_request_parts(parts, state).await?;
        if latchkey.step_up_valid_until(&current.session).is_none() {
            return Err(Error::StepUpRequired);
        }
        Ok(RecentAuth(current))
    }
}

/// JSON body whose rejection is the generic `invalid_request`.
pub(crate) struct Body<T>(pub(crate) T);

impl<S, T> FromRequest<S> for Body<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = Error;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        Json::<T>::from_request(req, state)
            .await
            .map(|Json(value)| Body(value))
            .map_err(|_| Error::InvalidRequest("body"))
    }
}
