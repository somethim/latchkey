//! Audit events as values, for the app's append-only log.
//!
//! ```
//! use latchkey::audit::{AuditEvent, AuditKind};
//!
//! let event = AuditEvent::new(AuditKind::Lockout, None, time::OffsetDateTime::UNIX_EPOCH, None)
//!     .with_detail("300s");
//! assert_eq!(event.kind.as_str(), "lockout");
//! ```

use time::OffsetDateTime;

use crate::http::IpTag;
use crate::ids::UserId;

/// What happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum AuditKind {
    /// A sign-in completed.
    SignIn,
    /// A password or code was wrong.
    SignInFailed,
    /// The account was locked.
    Lockout,
    /// A session was signed out.
    SignOut,
    /// A session was revoked: from the sessions list, or (with detail `step_up_failures`) by
    /// the per-session step-up limit.
    SessionRevoked,
    /// A step-up re-authentication.
    StepUp,
    /// A setup link was mailed.
    SetupLinkSent,
    /// Setup completed.
    SetupCompleted,
    /// A sign-in link was mailed.
    SignInLinkSent,
    /// An invite was mailed.
    InviteSent,
    /// A password was set or changed.
    PasswordSet,
    /// TOTP was enrolled.
    TotpEnrolled,
    /// TOTP was removed.
    TotpRemoved,
    /// A passkey was added.
    PasskeyAdded,
    /// A passkey was removed.
    PasskeyRemoved,
    /// New recovery codes were issued.
    RecoveryCodesIssued,
    /// A recovery code was used.
    RecoveryCodeUsed,
    /// The owner was reset to first-open setup.
    OwnerReset,
    /// A sign-in completed on a device the account had not used.
    NewDevice,
}

impl AuditKind {
    /// The stored name, as latchkey 0.2 wrote it, e.g. `sign_in_failed`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            AuditKind::SignIn => "sign_in",
            AuditKind::SignInFailed => "sign_in_failed",
            AuditKind::Lockout => "lockout",
            AuditKind::SignOut => "sign_out",
            AuditKind::SessionRevoked => "session_revoked",
            AuditKind::StepUp => "step_up",
            AuditKind::SetupLinkSent => "setup_link_sent",
            AuditKind::SetupCompleted => "setup_completed",
            AuditKind::SignInLinkSent => "sign_in_link_sent",
            AuditKind::InviteSent => "invite_sent",
            AuditKind::PasswordSet => "password_set",
            AuditKind::TotpEnrolled => "totp_enrolled",
            AuditKind::TotpRemoved => "totp_removed",
            AuditKind::PasskeyAdded => "passkey_added",
            AuditKind::PasskeyRemoved => "passkey_removed",
            AuditKind::RecoveryCodesIssued => "recovery_codes_issued",
            AuditKind::RecoveryCodeUsed => "recovery_code_used",
            AuditKind::OwnerReset => "owner_reset",
            AuditKind::NewDevice => "new_device",
        }
    }
}

impl std::fmt::Display for AuditKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An event to append to the audit log.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AuditEvent {
    /// When.
    pub at: OffsetDateTime,
    /// Whose account, if known.
    pub user_id: Option<UserId>,
    /// What.
    pub kind: AuditKind,
    /// Extra detail such as the method or the lock length (`300s`).
    pub detail: Option<String>,
    /// The client's IP address as an HMAC; never the address itself.
    pub ip_tag: Option<IpTag>,
}

impl AuditEvent {
    /// An event with no detail.
    #[must_use]
    pub fn new(
        kind: AuditKind,
        user_id: Option<UserId>,
        at: OffsetDateTime,
        ip_tag: Option<IpTag>,
    ) -> Self {
        Self {
            at,
            user_id,
            kind,
            detail: None,
            ip_tag,
        }
    }

    /// Adds a detail.
    #[must_use]
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }
}
