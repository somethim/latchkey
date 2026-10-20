//! HTTP helpers over plain header values: `__Host-` cookies, the Origin and CSRF checks, and
//! the client's IP address and user agent. No HTTP crate is involved; pass `&str` values from
//! whichever server library the app uses.
//!
//! ```
//! use latchkey::http::{self, RequestHeaders};
//!
//! let headers = RequestHeaders {
//!     method: "POST",
//!     origin: Some("https://home.example.com"),
//!     sec_fetch_site: None,
//!     csrf_token: Some("token-from-the-session"),
//! };
//! assert!(headers.check_origin("https://home.example.com").is_ok());
//! assert!(headers.check_origin("https://evil.example").is_err());
//!
//! let cookie = http::find_cookie(["theme=dark; __Host-latchkey=abc"], "__Host-latchkey");
//! assert_eq!(cookie, Some("abc"));
//! ```

use crate::error::ConfigReason;
use std::net::IpAddr;

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use time::Duration;
use zeroize::Zeroize;

use crate::Error;
use crate::token::{SecretToken, ct_eq};

/// The request header that carries the CSRF token on unsafe requests.
pub const CSRF_HEADER: &str = "x-csrf-token";
/// User agents are cut to this many characters before they are stored.
pub const MAX_USER_AGENT: usize = 256;

/// A cookie name with the `__Host-` prefix, which makes browsers keep the cookie host-only,
/// `Secure` and on path `/`.
///
/// The one exception is a [`Config`](crate::Config) built with
/// [`danger_insecure_localhost_cookies`](crate::ConfigBuilder::danger_insecure_localhost_cookies)
/// for plain-HTTP development on localhost: its cookie names lose the prefix and its cookies
/// are sent without `Secure` ([`is_secure`](Self::is_secure) is `false`). Such names cannot be
/// built any other way, and do not deserialize.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "String", into = "String"))]
pub struct CookieName {
    name: String,
    secure: bool,
}

const HOST_PREFIX: &str = "__Host-";

impl CookieName {
    /// Checks the prefix and that the name is a valid cookie token.
    ///
    /// # Errors
    ///
    /// [`Error::Config`] when it lacks `__Host-` or has characters a cookie name cannot.
    pub fn new(name: &str) -> Result<Self, Error> {
        if !name.starts_with(HOST_PREFIX) {
            return Err(Error::Config(ConfigReason::CookieNamePrefix));
        }
        check_token(name)?;
        Ok(Self {
            name: name.to_owned(),
            secure: true,
        })
    }

    /// The name without its `__Host-` prefix, for cookies without `Secure`: only for a
    /// config that checked its origin is plain-HTTP localhost.
    pub(crate) fn insecure_localhost(name: &str) -> Result<Self, Error> {
        let bare = name.strip_prefix(HOST_PREFIX).unwrap_or(name);
        if bare.is_empty() || bare.starts_with("__Secure-") || bare.starts_with(HOST_PREFIX) {
            return Err(Error::Config(ConfigReason::CookieNameCharacters));
        }
        check_token(bare)?;
        Ok(Self {
            name: bare.to_owned(),
            secure: false,
        })
    }

    /// The name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.name
    }

    /// Whether cookies under this name carry `Secure`: always, except under
    /// [`danger_insecure_localhost_cookies`](crate::ConfigBuilder::danger_insecure_localhost_cookies).
    #[must_use]
    pub const fn is_secure(&self) -> bool {
        self.secure
    }
}

fn check_token(name: &str) -> Result<(), Error> {
    let token = name
        .bytes()
        .all(|b| b.is_ascii_graphic() && !b"()<>@,;:\\\"/[]?={}".contains(&b));
    if token {
        Ok(())
    } else {
        Err(Error::Config(ConfigReason::CookieNameCharacters))
    }
}

impl TryFrom<String> for CookieName {
    type Error = Error;

    fn try_from(name: String) -> Result<Self, Error> {
        Self::new(&name)
    }
}

impl From<CookieName> for String {
    fn from(name: CookieName) -> String {
        name.name
    }
}

impl std::fmt::Display for CookieName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.name)
    }
}

/// A cookie for the client: `name=value; Path=/; Max-Age=…; HttpOnly; Secure; SameSite=Lax`
/// (without `Secure` only for a name from a config with
/// [`danger_insecure_localhost_cookies`](crate::ConfigBuilder::danger_insecure_localhost_cookies)).
/// The value is a bearer secret: `Debug` leaves it out and it is zeroed on drop.
#[derive(Clone, PartialEq, Eq)]
#[must_use = "a cookie does nothing until it is sent as a Set-Cookie header"]
pub struct SetCookie {
    name: CookieName,
    value: String,
    max_age: Duration,
}

impl SetCookie {
    /// A cookie that sets `value` for `max_age`.
    pub fn new(name: CookieName, value: &SecretToken, max_age: Duration) -> Self {
        Self {
            name,
            value: value.expose_secret().to_owned(),
            max_age,
        }
    }

    /// A cookie that deletes `name` (empty value, `Max-Age=0`).
    pub fn removal(name: CookieName) -> Self {
        Self {
            name,
            value: String::new(),
            max_age: Duration::ZERO,
        }
    }

    /// The cookie's name.
    #[must_use]
    pub fn name(&self) -> &CookieName {
        &self.name
    }

    /// The value: a bearer secret, hand it only to the client it is for.
    #[must_use]
    pub fn expose_value(&self) -> &str {
        &self.value
    }

    /// How long the browser keeps it.
    #[must_use]
    pub fn max_age(&self) -> Duration {
        self.max_age
    }

    /// The whole `Set-Cookie` header value.
    #[must_use]
    pub fn header_value(&self) -> String {
        let secure = if self.name.is_secure() {
            " Secure;"
        } else {
            ""
        };
        format!(
            "{}={}; Path=/; Max-Age={}; HttpOnly;{secure} SameSite=Lax",
            self.name,
            self.value,
            self.max_age.whole_seconds().max(0)
        )
    }
}

impl Drop for SetCookie {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

impl std::fmt::Debug for SetCookie {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SetCookie")
            .field("name", &self.name)
            .field("max_age", &self.max_age)
            .finish_non_exhaustive()
    }
}

/// The value of cookie `name` from the request's `Cookie` header values, if present.
#[must_use]
pub fn find_cookie<'a, I>(cookie_headers: I, name: &str) -> Option<&'a str>
where
    I: IntoIterator<Item = &'a str>,
{
    cookie_headers
        .into_iter()
        .flat_map(|value| value.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(key, _)| *key == name)
        .map(|(_, value)| value)
}

/// Whether a request method can change state: anything but `GET`, `HEAD` and `OPTIONS`.
#[must_use]
pub fn is_unsafe_method(method: &str) -> bool {
    !matches!(method, "GET" | "HEAD" | "OPTIONS")
}

/// The headers the Origin and CSRF checks read.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RequestHeaders<'a> {
    /// The request method, such as `POST`.
    pub method: &'a str,
    /// The `Origin` header.
    pub origin: Option<&'a str>,
    /// The `Sec-Fetch-Site` header.
    pub sec_fetch_site: Option<&'a str>,
    /// The [`CSRF_HEADER`] header.
    pub csrf_token: Option<&'a str>,
}

impl RequestHeaders<'_> {
    /// For unsafe methods: `Origin` must equal `expected_origin` (as
    /// [`Config::origin_string`](crate::Config::origin_string) gives it) or, when the browser
    /// sent no `Origin`, `Sec-Fetch-Site` must be `same-origin`. Safe methods always pass.
    ///
    /// # Errors
    ///
    /// [`Error::CsrfRejected`].
    pub fn check_origin(&self, expected_origin: &str) -> Result<(), Error> {
        if !is_unsafe_method(self.method) {
            return Ok(());
        }
        let allowed = match self.origin {
            Some(origin) => origin == expected_origin,
            None => self.sec_fetch_site == Some("same-origin"),
        };
        if allowed {
            Ok(())
        } else {
            Err(Error::CsrfRejected)
        }
    }

    /// [`check_origin`](Self::check_origin), and for unsafe methods the CSRF header must
    /// equal the session's token (constant-time). Run this on every unsafe request that a
    /// session cookie authorises.
    ///
    /// # Errors
    ///
    /// [`Error::CsrfRejected`].
    pub fn check_session_request(
        &self,
        expected_origin: &str,
        session_csrf: &SecretToken,
    ) -> Result<(), Error> {
        self.check_origin(expected_origin)?;
        if !is_unsafe_method(self.method) {
            return Ok(());
        }
        let presented = self.csrf_token.unwrap_or_default();
        if ct_eq(
            presented.as_bytes(),
            session_csrf.expose_secret().as_bytes(),
        ) {
            Ok(())
        } else {
            Err(Error::CsrfRejected)
        }
    }
}

/// The client's address: with `trust_forwarded_for`, the last non-empty entry of the
/// `X-Forwarded-For` header values (the one your own proxy appended), otherwise `peer`.
/// Only trust the header behind a proxy you run.
#[must_use]
pub fn client_ip<'a, I>(
    peer: Option<IpAddr>,
    forwarded_for: I,
    trust_forwarded_for: bool,
) -> Option<IpAddr>
where
    I: IntoIterator<Item = &'a str>,
{
    if trust_forwarded_for
        && let Some(forwarded) = forwarded_for
            .into_iter()
            .flat_map(|value| value.split(','))
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
            .last()
            .and_then(|entry| entry.parse().ok())
    {
        return Some(forwarded);
    }
    peer
}

/// A `User-Agent` cut to [`MAX_USER_AGENT`] characters.
#[must_use]
pub fn truncate_user_agent(raw: &str) -> String {
    raw.chars().take(MAX_USER_AGENT).collect()
}

/// The key for [`IpTag`]s. Zeroed on drop.
#[derive(Clone)]
pub struct IpTagKey([u8; 32]);

impl IpTagKey {
    /// A key from 32 secret bytes (latchkey 0.2's `secret_key`).
    #[must_use]
    pub fn new(key: &[u8; 32]) -> Self {
        Self(*key)
    }

    /// The HMAC-SHA256 of the address's text form, in hex: the same value latchkey 0.2 stored.
    #[must_use]
    pub fn tag(&self, ip: IpAddr) -> IpTag {
        let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(&self.0) else {
            return IpTag(String::new());
        };
        mac.update(ip.to_string().as_bytes());
        IpTag(crate::hex(&mac.finalize().into_bytes()))
    }
}

impl Drop for IpTagKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for IpTagKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("IpTagKey(<redacted>)")
    }
}

/// A pseudonymised client IP address, for sessions and the audit log.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct IpTag(String);

impl IpTag {
    /// Rebuilds a tag read back from storage.
    #[must_use]
    pub fn from_stored(tag: String) -> Self {
        Self(tag)
    }

    /// The hex text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(raw: &str) -> CookieName {
        CookieName::new(raw).unwrap_or_else(|_| CookieName {
            name: String::from("__Host-x"),
            secure: true,
        })
    }

    #[test]
    fn cookie_names_need_the_host_prefix() {
        assert!(CookieName::new("__Host-latchkey").is_ok());
        assert!(CookieName::new("session").is_err());
        assert!(CookieName::new("__Host-a;b").is_err());
        assert!(CookieName::new("__Host-a b").is_err());
    }

    #[test]
    fn set_cookie_is_host_only_and_locked_down() {
        let token = SecretToken::from_presented("abc");
        let cookie = SetCookie::new(name("__Host-latchkey"), &token, Duration::days(30));
        assert_eq!(
            cookie.header_value(),
            "__Host-latchkey=abc; Path=/; Max-Age=2592000; HttpOnly; Secure; SameSite=Lax"
        );
        assert!(!format!("{cookie:?}").contains("abc"));
        let removal = SetCookie::removal(name("__Host-latchkey"));
        assert!(
            removal
                .header_value()
                .starts_with("__Host-latchkey=; Path=/; Max-Age=0;")
        );
    }

    #[test]
    fn insecure_localhost_names_drop_the_prefix_and_secure() -> Result<(), Error> {
        let name = CookieName::insecure_localhost("__Host-latchkey")?;
        assert_eq!(name.as_str(), "latchkey");
        assert!(!name.is_secure());
        assert!(CookieName::new("__Host-latchkey")?.is_secure());
        let token = SecretToken::from_presented("abc");
        assert_eq!(
            SetCookie::new(name.clone(), &token, Duration::days(1)).header_value(),
            "latchkey=abc; Path=/; Max-Age=86400; HttpOnly; SameSite=Lax"
        );
        assert_eq!(
            SetCookie::removal(name).header_value(),
            "latchkey=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax"
        );
        assert_eq!(CookieName::insecure_localhost("plain")?.as_str(), "plain");
        for bad in ["__Host-", "__Host-__Secure-x", "__Host-a;b", ""] {
            assert!(CookieName::insecure_localhost(bad).is_err(), "{bad:?}");
        }
        Ok(())
    }

    #[test]
    fn finds_the_named_cookie_across_headers() {
        let headers = [
            "a=1; b=2",
            "__Host-latchkey=xyz; __Host-latchkey_device=dev",
        ];
        assert_eq!(find_cookie(headers, "__Host-latchkey"), Some("xyz"));
        assert_eq!(find_cookie(headers, "__Host-latchkey_device"), Some("dev"));
        assert_eq!(find_cookie(headers, "missing"), None);
    }

    #[test]
    fn unsafe_requests_need_the_origin() {
        let expected = "https://home.example.com";
        let check = |method, origin, site| {
            RequestHeaders {
                method,
                origin,
                sec_fetch_site: site,
                csrf_token: None,
            }
            .check_origin(expected)
        };
        assert!(check("GET", Some("https://evil.example"), None).is_ok());
        assert!(check("POST", Some(expected), None).is_ok());
        assert_eq!(
            check("POST", Some("https://evil.example"), Some("same-origin")),
            Err(Error::CsrfRejected),
            "a wrong Origin is not rescued by Sec-Fetch-Site"
        );
        assert!(check("DELETE", None, Some("same-origin")).is_ok());
        assert_eq!(
            check("POST", None, Some("cross-site")),
            Err(Error::CsrfRejected)
        );
        assert_eq!(check("POST", None, None), Err(Error::CsrfRejected));
        assert_eq!(check("POST", Some("null"), None), Err(Error::CsrfRejected));
    }

    #[test]
    fn unsafe_session_requests_need_the_csrf_token() {
        let expected = "https://home.example.com";
        let csrf = SecretToken::from_presented("the-token");
        let request = |method, csrf_token| RequestHeaders {
            method,
            origin: Some(expected),
            sec_fetch_site: None,
            csrf_token,
        };
        assert!(
            request("GET", None)
                .check_session_request(expected, &csrf)
                .is_ok()
        );
        assert!(
            request("POST", Some("the-token"))
                .check_session_request(expected, &csrf)
                .is_ok()
        );
        assert_eq!(
            request("POST", Some("wrong")).check_session_request(expected, &csrf),
            Err(Error::CsrfRejected)
        );
        assert_eq!(
            request("POST", None).check_session_request(expected, &csrf),
            Err(Error::CsrfRejected)
        );
    }

    #[test]
    fn forwarded_for_is_ignored_unless_trusted() {
        let peer: Option<IpAddr> = "10.0.0.1".parse().ok();
        let forwarded = ["1.1.1.1, 203.0.113.9"];
        assert_eq!(client_ip(peer, forwarded, false), peer);
        assert_eq!(client_ip(peer, forwarded, true), "203.0.113.9".parse().ok());
        assert_eq!(client_ip(peer, ["garbage"], true), peer);
        assert_eq!(client_ip(None, [], true), None);
    }

    #[test]
    fn ip_tags_are_keyed_and_stable() {
        let ip: IpAddr = "203.0.113.9".parse().unwrap_or(IpAddr::from([0, 0, 0, 0]));
        let a = IpTagKey::new(&[1; 32]);
        let b = IpTagKey::new(&[2; 32]);
        assert_eq!(a.tag(ip), a.tag(ip));
        assert_ne!(a.tag(ip), b.tag(ip));
        assert_eq!(a.tag(ip).as_str().len(), 64);
        assert!(!a.tag(ip).as_str().contains("203"));
    }

    #[test]
    fn user_agents_are_truncated() {
        assert_eq!(truncate_user_agent(&"x".repeat(1000)).len(), MAX_USER_AGENT);
    }
}
