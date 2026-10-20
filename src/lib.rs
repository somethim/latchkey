#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

mod audit;
mod ceremony;
mod clock;
mod config;
mod crypto;
mod error;
mod extract;
mod limiter;
mod mail;
mod password;
mod recovery;
mod routes;
mod seal;
mod service;
pub mod store;
mod totp;

pub use audit::AuditKind;
pub use clock::{Clock, ManualClock, SystemClock};
pub use config::{Config, LockoutPolicy, PasswordParams, RateLimits};
pub use error::Error;
pub use extract::{CSRF_HEADER, CurrentUser, RecentAuth};
pub use mail::{Mail, MailError, MailKind, Mailer, TestMailer};
pub use service::Latchkey;
pub use store::{Role, SqliteStore, Store};

pub use async_trait::async_trait;
pub use webauthn_rs;
