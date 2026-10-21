//! The error type shared by every module, and the typed reasons some of its variants carry.

/// Defines a reason enum with a stable `snake_case` code and a message.
macro_rules! reasons {
    (
        $(#[$doc:meta])*
        $name:ident {
            $( $(#[$vdoc:meta])* $variant:ident => $code:literal, $message:literal ),* $(,)?
        }
    ) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        #[non_exhaustive]
        pub enum $name {
            $( $(#[$vdoc])* $variant, )*
        }

        impl $name {
            /// A short, stable, machine-readable code, such as the ones latchkey 0.2 sent.
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self {
                    $( $name::$variant => $code, )*
                }
            }

            /// A sentence for logs.
            #[must_use]
            pub const fn message(self) -> &'static str {
                match self {
                    $( $name::$variant => $message, )*
                }
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(self.message())
            }
        }
    };
}

reasons!(
    /// Why a request was malformed: [`Error::InvalidRequest`]. [`as_str`](Self::as_str) is
    /// the detail to show the client ([`Error::detail`]).
    InvalidRequestReason {
        /// Not an email address.
        Email => "email", "not an email address",
        /// Not a valid app sign-in method name.
        Method => "method", "not a valid sign-in method name",
        /// An invitee's name is too long.
        NameTooLong => "name_too_long", "the name is too long",
        /// A stored TOTP step is negative.
        NegativeTotpStep => "negative_totp_step", "the stored TOTP step is negative",
        /// The account has no passkey to ask for.
        NoPasskey => "no_passkey", "the account has no passkey",
        /// A passkey registration did not verify.
        PasskeyRejected => "passkey_rejected", "the passkey registration did not verify",
        /// Setup cannot finish without a password.
        PasswordRequired => "password_required", "a password is required",
        /// The new password is longer than the policy allows.
        PasswordTooLong => "password_too_long", "the password is too long",
        /// The new password is shorter than the policy allows.
        PasswordTooShort => "password_too_short", "the password is too short",
        /// The QR code could not be drawn as a PNG.
        QrPng => "qr_png", "the QR code could not be drawn",
        /// The text is too long for a QR code.
        QrTooLong => "qr_too_long", "the text is too long for a QR code",
        /// Stored recovery-code hash bytes have the wrong length.
        RecoveryHashLength => "recovery_hash_length", "a recovery code hash is 32 bytes",
        /// Not a role name.
        Role => "role", "not a role",
        /// Setup cannot finish without a second factor.
        SecondFactorRequired => "second_factor_required", "a second factor is required",
        /// Not a session stage name.
        Stage => "stage", "not a session stage",
        /// A time before 1970.
        TimeBeforeEpoch => "time_before_epoch", "the time is before 1970",
        /// Stored token hash bytes have the wrong length.
        TokenHashLength => "token_hash_length", "a token hash is 32 bytes",
        /// The TOTP secret is unusable.
        TotpSecret => "totp_secret", "the TOTP secret is unusable",
        /// The TOTP secret is not base32.
        TotpSecretBase32 => "totp_secret_base32", "the TOTP secret is not base32",
        /// The TOTP secret is shorter than 128 bits.
        TotpSecretTooShort => "totp_secret_too_short", "the TOTP secret is shorter than 128 bits",
        /// A TOTP step does not fit the stored column.
        TotpStepOverflow => "totp_step_overflow", "the TOTP step does not fit",
        /// The `otpauth://` URL could not be built.
        TotpUrl => "totp_url", "the otpauth URL could not be built",
        /// The flow's current state does not take this event.
        UnexpectedFlowEvent => "unexpected_flow_event", "the flow does not take this event now",
        /// The passkey ceremony is unknown, expired or bound to someone else.
        UnknownCeremony => "unknown_ceremony", "unknown passkey ceremony",
    }
);

reasons!(
    /// Why a request conflicts with the current state: [`Error::Conflict`].
    ConflictReason {
        /// An account with this address exists.
        EmailTaken => "email_taken", "the address is taken",
        /// The last second factor cannot be removed.
        LastFactor => "last_factor", "the last second factor cannot be removed",
        /// This passkey is registered already.
        PasskeyExists => "passkey_exists", "the passkey is registered already",
    }
);

reasons!(
    /// What is wrong with a configuration value: [`Error::Config`].
    ConfigReason {
        /// The origin does not parse.
        OriginNotUrl => "origin_not_url", "origin is not a URL",
        /// The origin has no host.
        OriginHasNoHost => "origin_has_no_host", "origin has no host",
        /// The origin is not `https` (or `http` on this machine).
        OriginNotHttps => "origin_not_https", "origin must be https",
        /// Insecure localhost cookies were asked for another origin.
        InsecureCookiesNotLocalhost => "insecure_cookies_not_localhost",
            "insecure localhost cookies need an http://localhost, http://127.0.0.1 or http://[::1] origin",
        /// The owner address is not an email address.
        OwnerEmail => "owner_email", "owner email",
        /// A cookie name lacks `__Host-`.
        CookieNamePrefix => "cookie_name_prefix", "cookie name must start with __Host-",
        /// A cookie name has characters a cookie name cannot.
        CookieNameCharacters => "cookie_name_characters", "cookie name has invalid characters",
        /// Two cookie names are equal.
        CookieNamesEqual => "cookie_names_equal", "cookie names must differ",
        /// A path does not join onto the origin.
        PathDoesNotJoin => "path_does_not_join", "a path does not join onto the origin",
        /// A per-session step-up failure limit of 0.
        StepUpLimitZero => "step_up_limit_zero", "the step-up failure limit must be at least 1",
        /// Argon2 rejects the parameters.
        Argon2Parameters => "argon2_parameters", "argon2 parameters",
        /// The password length limits are outside 8 to 128 (shortest) and 64 to 1024
        /// (longest), or the shortest exceeds the longest.
        PasswordLength => "password_length", "password length limits out of bounds",
        /// TOTP digits other than 6 or 8.
        TotpDigits => "totp_digits", "TOTP digits must be 6 or 8",
        /// A TOTP step outside 15 to 120 seconds.
        TotpStep => "totp_step", "the TOTP step must be 15 to 120 seconds",
        /// A TOTP skew above 3 steps.
        TotpSkew => "totp_skew", "the TOTP skew must be 0 to 3 steps",
        /// Email sign-in code digits outside 6 to 10.
        EmailCodeDigits => "email_code_digits", "email code digits must be 6 to 10",
        /// Email sign-in code attempts outside 1 to 20.
        EmailCodeAttempts => "email_code_attempts", "email code attempts must be 1 to 20",
        /// A recovery code count outside 4 to 32.
        RecoveryCodeCount => "recovery_code_count", "recovery code count must be 4 to 32",
        /// A display-name limit outside 1 to 1000 characters.
        DisplayNameLength => "display_name_length", "display name limit must be 1 to 1000",
        /// The relying party id does not match the origin.
        RpIdMismatch => "rp_id_mismatch", "rp_id does not match the origin",
        /// The data key is all zeroes.
        DataKeyZero => "data_key_zero", "data key is all zeroes",
        /// The secret key is all zeroes.
        SecretKeyZero => "secret_key_zero", "secret key is all zeroes",
        /// The data key equals the secret key.
        KeysEqual => "keys_equal", "data key must differ from the secret key",
    }
);

reasons!(
    /// Which cryptographic operation failed: [`Error::Crypto`].
    CryptoReason {
        /// Sealing a value failed.
        Encryption => "encryption", "encryption failed",
        /// A sealed TOTP secret does not open with this key and owner.
        TotpDecrypt => "totp_decrypt", "a TOTP secret does not decrypt",
        /// A sealed passkey does not open with this key and owner.
        PasskeyDecrypt => "passkey_decrypt", "a passkey does not decrypt",
        /// An opened passkey does not parse.
        PasskeyParse => "passkey_parse", "a passkey does not parse",
        /// A passkey does not serialise.
        PasskeySerialisation => "passkey_serialisation", "passkey serialisation",
        /// Argon2 failed to hash.
        PasswordHashing => "password_hashing", "argon2 hashing failed",
        /// A stored password hash is not an Argon2id PHC string.
        StoredPasswordHash => "stored_password_hash", "stored password hash is not an Argon2id PHC string",
        /// webauthn-rs failed to start a registration.
        WebauthnRegistrationStart => "webauthn_registration_start", "webauthn registration start",
        /// webauthn-rs failed to start an authentication.
        WebauthnAuthenticationStart => "webauthn_authentication_start", "webauthn authentication start",
        /// webauthn-rs failed to start a discoverable authentication.
        WebauthnDiscoverableStart => "webauthn_discoverable_start", "webauthn discoverable start",
    }
);

/// Why latchkey refused a request or could not compute a value.
///
/// Refusals carry a stable machine [`code`](Error::code) for clients and a suggested
/// [`http_status`](Error::http_status); details stay out of what the client sees.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// No session, or the session is unknown, expired, at the wrong stage or for an inactive
    /// account.
    #[error("not signed in")]
    Unauthorized,
    /// A password, code, link or passkey was rejected. Deliberately says no more than that.
    #[error("sign-in failed")]
    SignInFailed,
    /// The action needs a sign-in or step-up within the step-up window.
    #[error("a recent sign-in is required")]
    StepUpRequired,
    /// Signed in, but not allowed to do this.
    #[error("not allowed")]
    Forbidden,
    /// An unsafe request failed the Origin, `Sec-Fetch-Site` or CSRF token check.
    #[error("request rejected by the origin or CSRF check")]
    CsrfRejected,
    /// The thing to act on does not exist.
    #[error("not found")]
    NotFound,
    /// The input is malformed; the reason's code is the detail for the client.
    #[error("invalid request: {0}")]
    InvalidRequest(InvalidRequestReason),
    /// The request conflicts with the current state, such as removing the last factor.
    #[error("conflict: {0}")]
    Conflict(ConflictReason),
    /// A rate limit, the wrong-password throttle or a lockout applies.
    #[error("too many attempts, retry after {retry_after_secs} s")]
    TooManyAttempts {
        /// Seconds until the next attempt can succeed; at least 1.
        retry_after_secs: u64,
    },
    /// The session made too many wrong step-up guesses and was ended (see
    /// [`StepUpFailures::PerSession`](crate::flow::step_up::StepUpFailures::PerSession)): sign
    /// in again.
    #[error("the session was ended after too many wrong step-up attempts")]
    SessionEnded,
    /// A configuration value is unusable.
    #[error("configuration: {0}")]
    Config(ConfigReason),
    /// A cryptographic operation failed, such as sealing or hashing.
    #[error("cryptography: {0}")]
    Crypto(CryptoReason),
    /// The operating system did not provide randomness.
    #[error("the operating system random number generator failed")]
    Rng,
}

impl Error {
    /// A short, stable code to show to clients, such as `sign_in_failed`.
    ///
    /// ```
    /// assert_eq!(latchkey::Error::StepUpRequired.code(), "step_up_required");
    /// ```
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Error::Unauthorized => "unauthorized",
            Error::SignInFailed => "sign_in_failed",
            Error::StepUpRequired => "step_up_required",
            Error::Forbidden => "forbidden",
            Error::CsrfRejected => "csrf_rejected",
            Error::NotFound => "not_found",
            Error::InvalidRequest(_) => "invalid_request",
            Error::Conflict(_) => "conflict",
            Error::TooManyAttempts { .. } => "too_many_attempts",
            Error::SessionEnded => "session_ended",
            Error::Config(_) | Error::Crypto(_) | Error::Rng => "internal",
        }
    }

    /// The HTTP status code latchkey 0.2 answered with for this error.
    ///
    /// ```
    /// assert_eq!(latchkey::Error::SignInFailed.http_status(), 401);
    /// ```
    #[must_use]
    pub fn http_status(&self) -> u16 {
        match self {
            Error::Unauthorized
            | Error::SignInFailed
            | Error::StepUpRequired
            | Error::SessionEnded => 401,
            Error::Forbidden | Error::CsrfRejected => 403,
            Error::NotFound => 404,
            Error::InvalidRequest(_) => 400,
            Error::Conflict(_) => 409,
            Error::TooManyAttempts { .. } => 429,
            Error::Config(_) | Error::Crypto(_) | Error::Rng => 500,
        }
    }

    /// The detail to show next to the code, for [`Error::InvalidRequest`] and
    /// [`Error::Conflict`].
    #[must_use]
    pub fn detail(&self) -> Option<&'static str> {
        match self {
            Error::InvalidRequest(reason) => Some(reason.as_str()),
            Error::Conflict(reason) => Some(reason.as_str()),
            _ => None,
        }
    }

    /// Seconds to send as `Retry-After`, for [`Error::TooManyAttempts`].
    #[must_use]
    pub fn retry_after_secs(&self) -> Option<u64> {
        match self {
            Error::TooManyAttempts { retry_after_secs } => Some(*retry_after_secs),
            _ => None,
        }
    }

    pub(crate) fn too_many(retry_after_secs: u64) -> Self {
        Error::TooManyAttempts {
            retry_after_secs: retry_after_secs.max(1),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ConfigReason, ConflictReason, CryptoReason, Error, InvalidRequestReason};

    #[test]
    fn details_keep_their_stored_codes() {
        assert_eq!(
            Error::InvalidRequest(InvalidRequestReason::PasswordTooShort).detail(),
            Some("password_too_short")
        );
        assert_eq!(
            Error::Conflict(ConflictReason::LastFactor).detail(),
            Some("last_factor")
        );
        assert_eq!(
            Error::Config(ConfigReason::OriginNotHttps).to_string(),
            "configuration: origin must be https"
        );
        assert_eq!(Error::Config(ConfigReason::OriginNotHttps).detail(), None);
    }

    #[test]
    fn server_side_failures_share_one_code() {
        for error in [
            Error::Config(ConfigReason::OriginNotUrl),
            Error::Crypto(CryptoReason::Encryption),
            Error::Rng,
        ] {
            assert_eq!(error.code(), "internal");
            assert_eq!(error.http_status(), 500);
        }
    }

    #[test]
    fn retry_after_is_at_least_one_second() {
        assert_eq!(Error::too_many(0).retry_after_secs(), Some(1));
        assert_eq!(Error::too_many(7).retry_after_secs(), Some(7));
    }
}
