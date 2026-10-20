mod sqlite;

pub use sqlite::SqliteStore;

use async_trait::async_trait;
use serde::Serialize;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("unique constraint violated")]
    Conflict,
    #[error("corrupt row: {0}")]
    Corrupt(String),
    #[error("database: {0}")]
    Database(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Owner,
    Member,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Owner => "owner",
            Role::Member => "member",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "owner" => Some(Role::Owner),
            "member" => Some(Role::Member),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub display_name: String,
    pub role: Role,
    pub password_hash: Option<String>,
    /// False until setup is complete; inactive accounts cannot sign in.
    pub active: bool,
    pub failed_attempts: u32,
    pub locked_until: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
}

/// Where a session is in the sign-in process; every change of stage issues a new token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    Setup,
    SecondFactor,
    Full,
}

impl Stage {
    pub fn as_str(self) -> &'static str {
        match self {
            Stage::Setup => "setup",
            Stage::SecondFactor => "second_factor",
            Stage::Full => "full",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "setup" => Some(Stage::Setup),
            "second_factor" => Some(Stage::SecondFactor),
            "full" => Some(Stage::Full),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    pub id: Uuid,
    pub token_hash: Vec<u8>,
    pub user_id: Uuid,
    pub stage: Stage,
    pub csrf_token: String,
    pub method: Option<String>,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub authenticated_at: Option<OffsetDateTime>,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenKind {
    Setup,
    Invite,
    SignIn,
}

impl TokenKind {
    pub fn as_str(self) -> &'static str {
        match self {
            TokenKind::Setup => "setup",
            TokenKind::Invite => "invite",
            TokenKind::SignIn => "sign_in",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OneTimeToken {
    pub hash: Vec<u8>,
    pub kind: TokenKind,
    pub user_id: Uuid,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TotpRecord {
    pub secret: Option<Vec<u8>>,
    pub pending_secret: Option<Vec<u8>>,
    pub last_step: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasskeyRecord {
    pub id: Uuid,
    pub user_id: Uuid,
    pub credential_id: Vec<u8>,
    pub name: String,
    /// The serialised `webauthn_rs::prelude::Passkey`.
    pub data: String,
    pub created_at: OffsetDateTime,
    pub last_used_at: Option<OffsetDateTime>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuditEvent {
    pub id: i64,
    #[serde(with = "time::serde::rfc3339")]
    pub at: OffsetDateTime,
    pub user_id: Option<Uuid>,
    pub kind: String,
    pub detail: Option<String>,
    /// HMAC of the client IP, never the address itself.
    pub ip: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewAuditEvent {
    pub at: OffsetDateTime,
    pub user_id: Option<Uuid>,
    pub kind: String,
    pub detail: Option<String>,
    pub ip: Option<String>,
}

/// Persistence for accounts, sessions and factors. Methods documented as atomic must not let
/// two concurrent callers both succeed.
#[async_trait]
pub trait Store: Send + Sync + 'static {
    async fn create_user(&self, user: &User) -> Result<(), StoreError>;
    async fn user_by_id(&self, id: Uuid) -> Result<Option<User>, StoreError>;
    async fn user_by_email(&self, email: &str) -> Result<Option<User>, StoreError>;
    async fn owner(&self) -> Result<Option<User>, StoreError>;
    async fn set_password(&self, user: Uuid, hash: &str) -> Result<(), StoreError>;
    async fn set_active(&self, user: Uuid, active: bool) -> Result<(), StoreError>;
    /// Atomic; returns the new consecutive failure count.
    async fn add_failure(&self, user: Uuid) -> Result<u32, StoreError>;
    async fn set_locked_until(
        &self,
        user: Uuid,
        until: Option<OffsetDateTime>,
    ) -> Result<(), StoreError>;
    async fn clear_failures(&self, user: Uuid) -> Result<(), StoreError>;
    /// Removes the password, every factor, every session and deactivates the account.
    async fn reset_user(&self, user: Uuid) -> Result<(), StoreError>;

    async fn insert_token(&self, token: &OneTimeToken) -> Result<(), StoreError>;
    /// Atomic single use: returns the owner of an unexpired token of `kind` and deletes it.
    async fn consume_token(
        &self,
        hash: &[u8],
        kind: TokenKind,
        now: OffsetDateTime,
    ) -> Result<Option<Uuid>, StoreError>;
    async fn latest_token_at(
        &self,
        user: Uuid,
        kind: TokenKind,
    ) -> Result<Option<OffsetDateTime>, StoreError>;

    async fn insert_session(&self, session: &Session) -> Result<(), StoreError>;
    /// Atomic: deletes `old_hash` and inserts `session`.
    async fn replace_session(&self, old_hash: &[u8], session: &Session) -> Result<(), StoreError>;
    async fn session_by_hash(&self, hash: &[u8]) -> Result<Option<Session>, StoreError>;
    async fn set_session_authenticated(
        &self,
        hash: &[u8],
        at: OffsetDateTime,
        method: &str,
    ) -> Result<(), StoreError>;
    async fn delete_session(&self, hash: &[u8]) -> Result<(), StoreError>;
    async fn delete_session_by_id(&self, user: Uuid, id: Uuid) -> Result<bool, StoreError>;
    async fn delete_user_sessions(&self, user: Uuid) -> Result<(), StoreError>;
    async fn sessions_for(
        &self,
        user: Uuid,
        now: OffsetDateTime,
    ) -> Result<Vec<Session>, StoreError>;

    async fn totp(&self, user: Uuid) -> Result<Option<TotpRecord>, StoreError>;
    async fn set_pending_totp(&self, user: Uuid, secret: &[u8]) -> Result<(), StoreError>;
    /// Moves the pending secret into place and records `step` as used.
    async fn confirm_totp(&self, user: Uuid, step: i64) -> Result<bool, StoreError>;
    /// Atomic: records `step` only if it is newer than the last accepted one.
    async fn use_totp_step(&self, user: Uuid, step: i64) -> Result<bool, StoreError>;
    async fn delete_totp(&self, user: Uuid) -> Result<(), StoreError>;

    async fn add_passkey(&self, passkey: &PasskeyRecord) -> Result<(), StoreError>;
    async fn passkeys_for(&self, user: Uuid) -> Result<Vec<PasskeyRecord>, StoreError>;
    async fn update_passkey(
        &self,
        id: Uuid,
        data: &str,
        used_at: OffsetDateTime,
    ) -> Result<(), StoreError>;
    async fn delete_passkey(&self, user: Uuid, id: Uuid) -> Result<bool, StoreError>;

    async fn replace_recovery_codes(
        &self,
        user: Uuid,
        hashes: &[Vec<u8>],
    ) -> Result<(), StoreError>;
    /// Atomic single use.
    async fn use_recovery_code(
        &self,
        user: Uuid,
        hash: &[u8],
        now: OffsetDateTime,
    ) -> Result<bool, StoreError>;
    async fn unused_recovery_codes(&self, user: Uuid) -> Result<u32, StoreError>;

    async fn append_audit(&self, event: &NewAuditEvent) -> Result<(), StoreError>;
    async fn audit(&self, user: Option<Uuid>, limit: u32) -> Result<Vec<AuditEvent>, StoreError>;

    async fn purge_expired(&self, now: OffsetDateTime) -> Result<(), StoreError>;
}
