//! Sign-in building blocks and sign-in policy, without I/O.
//!
//! latchkey hashes passwords, checks TOTP and recovery codes, runs passkey ceremonies, issues
//! tokens, seals secrets, builds cookies, and decides what a sign-in flow does next. It
//! never reads a database, sends mail, reads the clock or draws hidden randomness: every
//! function takes its inputs (including `now` and an explicit [`CryptoRng`]) and returns
//! values. The app stores what it is told to store, sends what it is told to send, and
//! answers its clients.
//!
//! # Modules
//!
//! | Module | What it does |
//! |---|---|
//! | [`password`] | Argon2id hashing and verification, with a dummy hash for unknown accounts |
//! | [`totp`] | TOTP secrets, `otpauth://` URLs, QR codes (feature `qr`), replay-safe verification |
//! | [`recovery`] | Recovery codes: plain text to show once, hashes to store |
//! | `passkey` | `WebAuthn` ceremonies through `webauthn-rs` (feature `passkeys`) |
//! | [`token`] | Session, link, device and CSRF tokens: the token for the client, the hash to store |
//! | [`seal`] | AES-256-GCM for secrets at rest, bound to their owner |
//! | [`http`] | `__Host-` cookies, Origin and CSRF checks, client IP and user agent |
//! | [`account`] | Accounts, emails, factors and the lockout rule |
//! | [`limits`] | Rate limits and the wrong-password throttle as state machines |
//! | [`session`] | Session records, stages and access rules (step-up window) |
//! | [`flow`] | Setup, invite, sign-in, email link and code, sign-in reset and step-up as `advance(state, event, now)` |
//! | [`mail`] | Mail subjects and bodies |
//! | [`audit`] | Audit events |
//!
//! # A sign-in step
//!
//! ```
//! use latchkey::flow::sign_in::{SignIn, SignInEvent};
//! use latchkey::limits::FailureWindow;
//! use latchkey::Config;
//! use time::OffsetDateTime;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let config = Config::builder("owner@example.com", "https://home.example.com").build()?;
//! let mut rng = latchkey::os_rng()?;
//! let now = OffsetDateTime::from_unix_timestamp(1_800_000_000)?;
//!
//! // Someone types an unknown address: latchkey still asks for a (dummy) password check.
//! let step = SignIn::Start.advance(
//!     &config,
//!     SignInEvent::Password {
//!         login: "nobody@example.com".into(),
//!         account: None,
//!         wrong_passwords: FailureWindow::default(),
//!     },
//!     now,
//!     &mut rng,
//! )?;
//! assert!(matches!(step.state, SignIn::VerifyPassword { account: None, .. }));
//! # Ok(())
//! # }
//! ```
//!
//! # Features
//!
//! | Feature | Default | Adds |
//! |---|---|---|
//! | `os-rng` | yes | [`os_rng`], a generator seeded from the operating system |
//! | `serde` | no | `Serialize`/`Deserialize` on ids, hashes, records and states |
//! | `passkeys` | no | the `passkey` module and passkey sealing (webauthn-rs, OpenSSL); implies `serde` |
//! | `qr` | no | `totp::qr_svg` |
//! | `qr-png` | no | `totp::qr_png` (pulls in `image`) |
//!
//! # Public dependencies
//!
//! Types from these crates appear in the API, so their breaking releases are latchkey's:
//! [`time`] 0.3 (`OffsetDateTime`, `Duration`), `rand_core` 0.10 ([`CryptoRng`], re-exported
//! here), [`uuid`] 1 (the id newtypes convert from and to `Uuid`) and, with `passkeys`,
//! `webauthn-rs` 0.5 (re-exported as `passkey::webauthn_rs`). Other dependencies stay
//! private: URLs are `&str` and [`os_rng`] returns `impl CryptoRng`.
//!
//! # Security
//!
//! - Store only hashes of tokens and recovery codes ([`token::TokenHash`],
//!   [`recovery::RecoveryCodeHash`]); seal TOTP secrets and passkeys with a [`seal::DataKey`]
//!   kept apart from the [`http::IpTagKey`] and out of the database.
//! - Carry out every [`flow::Effect`], including those of a [`flow::Refusal`]: they count
//!   failures, lock accounts, mail new-device notices and write the audit log.
//! - Persist the TOTP step and recovery-code use with a compare-and-set, consume one-time
//!   links, email codes and passkey ceremonies atomically, and refuse when the compare-and-set
//!   loses. Count an email-code guess before checking it.
//! - Run the throttle and lockout checks (the first step of each password flow) before
//!   hashing, and hash on a blocking thread with limited concurrency.
//! - Never pass a client-chosen user id to [`flow::issue_session`].
//! - Secret types redact `Debug`, have no `Display`, and zero their memory on drop.
//!
//! The crate forbids `unsafe` and denies `unwrap`, `expect`, `panic!` and indexing outside
//! tests.

#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

pub mod account;
pub mod audit;
mod config;
pub mod error;
pub mod flow;
pub mod http;
mod ids;
pub mod limits;
pub mod mail;
#[cfg(feature = "passkeys")]
#[cfg_attr(docsrs, doc(cfg(feature = "passkeys")))]
pub mod passkey;
pub mod password;
pub mod recovery;
pub mod seal;
pub mod session;
pub mod token;
pub mod totp;

pub use account::{Account, Email, Factors, Lockout, LockoutPolicy, PasswordOnly, Role};
pub use config::{Config, ConfigBuilder};
pub use error::Error;
pub use flow::step_up::StepUpFailures;
pub use ids::{CeremonyId, PasskeyId, SessionId, UserId};
pub use rand_core::CryptoRng;

#[cfg(test)]
mod proptests;

/// Compiles and runs the README's examples as doctests.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;

/// A `ChaCha12` generator seeded once from the operating system: a convenient
/// [`CryptoRng`] to pass to latchkey. Keep one per thread or behind a lock (store it as
/// `Box<dyn CryptoRng + Send>` if you need to name its type), or create one per request.
///
/// # Errors
///
/// [`Error::Rng`] when the operating system provides no randomness.
#[cfg(feature = "os-rng")]
#[cfg_attr(docsrs, doc(cfg(feature = "os-rng")))]
pub fn os_rng() -> Result<impl CryptoRng + Send + Sync + 'static, Error> {
    use rand::SeedableRng;
    rand::rngs::StdRng::try_from_rng(&mut rand::rngs::SysRng).map_err(|_| Error::Rng)
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        })
}

#[cfg(test)]
pub(crate) fn test_rng() -> rand::rngs::StdRng {
    use rand::SeedableRng;
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEED: AtomicU64 = AtomicU64::new(1);
    rand::rngs::StdRng::seed_from_u64(SEED.fetch_add(1, Ordering::Relaxed))
}

/// Entry points for the cargo-fuzz target in `fuzz/`; not a public API.
#[cfg(feature = "_fuzzing")]
#[doc(hidden)]
pub mod fuzzing {
    use time::OffsetDateTime;

    /// Feeds `data` to every parser of untrusted input.
    pub fn untrusted_inputs(data: &[u8]) {
        let text = String::from_utf8_lossy(data);
        let now = OffsetDateTime::UNIX_EPOCH;
        let _ = crate::token::TokenHash::of(&text);
        let _ = crate::token::TokenHash::of_foreign(&text);
        let _ = crate::flow::email_link::EmailCodeHash::of(&text, &text);
        let _ = crate::flow::email_link::EmailCodeHash::of(
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            &text,
        );
        let _ = crate::recovery::RecoveryCodeHash::of(&text);
        if let Ok(secret) = crate::totp::TotpSecret::from_bytes(vec![0; 20]) {
            let _ = crate::totp::verify(
                &secret,
                &text,
                None,
                now,
                crate::totp::TotpParams::default(),
            );
        }
        let _ = crate::totp::TotpSecret::from_base32(&text);
        let _ = crate::password::PasswordHash::from_legacy_argon2(&text);
        let _ = crate::account::Email::parse(&text);
        let _ = crate::account::AccountKey::from_login(&text);
        let _ = crate::password::check_policy(&text, crate::password::PasswordLength::default());
        let _ = crate::http::find_cookie([text.as_ref()], "__Host-latchkey");
        let _ = crate::http::client_ip(None, [text.as_ref()], true);
        let _ = crate::http::CookieName::new(&text);
        let _ = text.parse::<crate::session::SignInMethod>();
        let _ = crate::flow::invite::optional_name(Some(text.to_string()), 100);
        let key = crate::seal::DataKey::new(&[3; 32]);
        let aad = crate::seal::Aad::app("fuzz");
        let _ = key.open_bytes(&aad, data);
        let _ = key.open_text(&aad, &text);
        let _ = crate::password::PasswordHash::try_from(text.as_ref());
    }
}
