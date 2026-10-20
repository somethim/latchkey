/// Kinds written to the audit log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditKind {
    SignIn,
    SignInFailed,
    Lockout,
    SignOut,
    SessionRevoked,
    StepUp,
    SetupLinkSent,
    SetupCompleted,
    SignInLinkSent,
    InviteSent,
    PasswordSet,
    TotpEnrolled,
    TotpRemoved,
    PasskeyAdded,
    PasskeyRemoved,
    RecoveryCodesIssued,
    RecoveryCodeUsed,
    OwnerReset,
    NewDevice,
}

impl AuditKind {
    pub fn as_str(self) -> &'static str {
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
