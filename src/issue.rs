use std::net::IpAddr;

use axum::http::{HeaderMap, HeaderValue};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::error::Error;
use crate::extract::{
    AnySession, CurrentUser, client_from_headers, cookie_header, session_by_token, session_cookie,
    truncate_user_agent,
};
use crate::service::{Client, Latchkey};
use crate::store::Stage;

const MAX_METHOD_LEN: usize = 32;

/// Methods latchkey records for its own sign-ins; an app's hand-off must not pass as one.
const RESERVED_METHODS: &[&str] = &[
    "setup",
    "password",
    "passkey",
    "email_link",
    "totp",
    "recovery_code",
];

/// What [`Latchkey::issue_session`] records about the sign-in it completes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssueSession {
    /// Written to the session, the `sign_in` audit event and a new-device mail, e.g.
    /// `desktop_bridge`. 1 to 32 characters from `a-z`, `0-9` and `_`, and none of latchkey's
    /// own methods (`setup`, `password`, `passkey`, `email_link`, `totp`, `recovery_code`).
    pub method: String,
    /// Stored only as an HMAC under `secret_key`, like every other client IP.
    pub client_ip: Option<IpAddr>,
    /// Shortened to 256 characters.
    pub user_agent: Option<String>,
    /// The device cookie the client presented, if any. A value the account has not used
    /// before (or none) counts as a new device.
    pub device_cookie: Option<String>,
}

impl IssueSession {
    pub fn new(method: impl Into<String>) -> Self {
        Self {
            method: method.into(),
            client_ip: None,
            user_agent: None,
            device_cookie: None,
        }
    }

    /// Reads the client the way latchkey's own endpoints do: `peer` (the socket address)
    /// or, with `trust_forwarded_for`, the last `X-Forwarded-For` entry; `User-Agent`; and
    /// the device cookie from `Cookie`.
    pub fn from_headers(
        latchkey: &Latchkey,
        method: impl Into<String>,
        headers: &HeaderMap,
        peer: Option<IpAddr>,
    ) -> Self {
        let client = client_from_headers(latchkey, headers, peer);
        Self {
            method: method.into(),
            client_ip: client.ip.and_then(|ip| ip.parse().ok()),
            user_agent: client.user_agent,
            device_cookie: client.device,
        }
    }
}

/// A cookie for the client to store: `name=value; Path=/; Max-Age=…; HttpOnly; Secure;
/// SameSite=Lax`, host-only through the `__Host-` prefix.
#[derive(Clone, PartialEq, Eq)]
pub struct IssuedCookie {
    name: String,
    value: String,
    max_age: Duration,
}

impl IssuedCookie {
    pub fn name(&self) -> &str {
        &self.name
    }

    /// A bearer secret: hand it only to the client the session is for.
    pub fn value(&self) -> &str {
        &self.value
    }

    pub fn max_age(&self) -> Duration {
        self.max_age
    }

    /// The whole `Set-Cookie` header value.
    pub fn set_cookie(&self) -> Result<HeaderValue, Error> {
        cookie_header(&self.name, &self.value, self.max_age.whole_seconds())
            .ok_or_else(|| Error::Internal("cookie is not a valid header value".into()))
    }
}

impl std::fmt::Debug for IssuedCookie {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IssuedCookie")
            .field("name", &self.name)
            .field("max_age", &self.max_age)
            .finish_non_exhaustive()
    }
}

/// A full session started by [`Latchkey::issue_session`].
#[derive(Clone, PartialEq, Eq)]
pub struct IssuedSession {
    user_id: Uuid,
    session_id: Uuid,
    csrf_token: String,
    authenticated_at: OffsetDateTime,
    expires_at: OffsetDateTime,
    session_cookie: IssuedCookie,
    device_cookie: IssuedCookie,
}

impl IssuedSession {
    pub fn user_id(&self) -> Uuid {
        self.user_id
    }

    pub fn session_id(&self) -> Uuid {
        self.session_id
    }

    /// Send it back as the `x-csrf-token` header on unsafe requests, as from `GET /auth/me`.
    pub fn csrf_token(&self) -> &str {
        &self.csrf_token
    }

    /// The step-up window runs from here.
    pub fn authenticated_at(&self) -> OffsetDateTime {
        self.authenticated_at
    }

    pub fn expires_at(&self) -> OffsetDateTime {
        self.expires_at
    }

    /// `cookie_name`, valid for `session_ttl`.
    pub fn session_cookie(&self) -> &IssuedCookie {
        &self.session_cookie
    }

    /// `device_cookie_name`, valid for `device_ttl`; set again on every sign-in.
    pub fn device_cookie(&self) -> &IssuedCookie {
        &self.device_cookie
    }

    /// Both `Set-Cookie` header values, session cookie first.
    pub fn set_cookie_headers(&self) -> Result<[HeaderValue; 2], Error> {
        Ok([
            self.session_cookie.set_cookie()?,
            self.device_cookie.set_cookie()?,
        ])
    }
}

impl std::fmt::Debug for IssuedSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IssuedSession")
            .field("user_id", &self.user_id)
            .field("session_id", &self.session_id)
            .field("authenticated_at", &self.authenticated_at)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

fn method_ok(method: &str) -> bool {
    (1..=MAX_METHOD_LEN).contains(&method.len())
        && method
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        && !RESERVED_METHODS.contains(&method)
}

impl Latchkey {
    /// Starts a full session for an account whose sign-in the app completed itself, such as a
    /// desktop app handed off from a signed-in browser.
    ///
    /// **This checks no factor.** It is for an app that has already verified the user through
    /// latchkey, for instance with a [`CurrentUser`] from
    /// [`Latchkey::current_user_from_headers`] moments earlier. Never call it with a user id
    /// taken from a request, an email address or anything else a client can choose.
    ///
    /// The session is the same as after a normal sign-in: a fresh token stored as SHA-256,
    /// `session_ttl`, the client IP as an HMAC, the user agent, and `authenticated_at` set to
    /// now, so the step-up window starts. Failed-attempt counts are cleared, a `sign_in`
    /// audit event records `method`, and a device the account has not used before gets a
    /// `new_device` audit event and a [`MailKind::NewDevice`](crate::MailKind::NewDevice) mail.
    ///
    /// Errors: [`Error::InvalidRequest`] for a `method` outside the rules on
    /// [`IssueSession::method`]; [`Error::Forbidden`] for an unknown account or one that has
    /// not finished setup (inactive, or without a password and a second factor);
    /// [`Error::TooManyAttempts`] while the account is locked out.
    pub async fn issue_session(
        &self,
        user_id: Uuid,
        request: IssueSession,
    ) -> Result<IssuedSession, Error> {
        if !method_ok(&request.method) {
            return Err(Error::InvalidRequest("method"));
        }
        let user = self
            .inner
            .store
            .user_by_id(user_id)
            .await?
            .filter(|user| user.active && user.password_hash.is_some())
            .ok_or(Error::Forbidden)?;
        let (totp, passkeys) = self.factor_count(user.id).await?;
        if !totp && passkeys == 0 {
            return Err(Error::Forbidden);
        }
        self.check_lock(&user)?;
        let client = Client {
            ip: request.client_ip.map(|ip| ip.to_string()),
            user_agent: request.user_agent.as_deref().map(truncate_user_agent),
            device: request.device_cookie,
        };
        let issued = self
            .signed_in(&user, &request.method, &client, None)
            .await?;
        let config = &self.inner.config;
        let device = issued
            .device_token
            .ok_or_else(|| Error::Internal("sign-in issued no device token".into()))?;
        let session = issued.session;
        Ok(IssuedSession {
            user_id: user.id,
            session_id: session.id,
            authenticated_at: session.authenticated_at.unwrap_or(session.created_at),
            expires_at: session.expires_at,
            session_cookie: IssuedCookie {
                name: config.cookie_name.clone(),
                value: issued.token,
                max_age: session.expires_at - session.created_at,
            },
            device_cookie: IssuedCookie {
                name: config.device_cookie_name.clone(),
                value: device,
                max_age: config.device_ttl,
            },
            csrf_token: session.csrf_token,
        })
    }

    /// The signed-in account a session cookie value belongs to. Refuses (401) unknown,
    /// expired and not yet completed sessions and inactive accounts.
    ///
    /// Unlike the [`CurrentUser`] extractor this checks neither the origin nor a CSRF token:
    /// before acting on an unsafe request, check its origin and compare the token it carries
    /// with [`CurrentUser::csrf_matches`].
    pub async fn session_from_cookie(&self, value: &str) -> Result<CurrentUser, Error> {
        let AnySession { session, user } =
            session_by_token(self, value).await?.require(Stage::Full)?;
        Ok(CurrentUser { user, session })
    }

    /// [`Latchkey::session_from_cookie`] with the session cookie read from `Cookie` headers.
    pub async fn current_user_from_headers(
        &self,
        headers: &HeaderMap,
    ) -> Result<CurrentUser, Error> {
        let value =
            session_cookie(headers, &self.inner.config.cookie_name).ok_or(Error::Unauthorized)?;
        self.session_from_cookie(&value).await
    }
}

#[cfg(test)]
mod tests {
    use super::method_ok;

    #[test]
    fn methods_are_short_lowercase_and_not_latchkeys_own() {
        assert!(method_ok("desktop_bridge"));
        assert!(method_ok("app2"));
        for bad in [
            "",
            "Desktop",
            "desktop-bridge",
            "password+totp",
            "setup",
            "passkey",
            "email_link",
            "a\nb",
            &"x".repeat(33),
        ] {
            assert!(!method_ok(bad), "{bad:?} accepted");
        }
    }
}
