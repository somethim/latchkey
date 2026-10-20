//! The error type shared by every module.

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
    /// The input is malformed; the detail is a short machine-readable reason.
    #[error("invalid request: {0}")]
    InvalidRequest(&'static str),
    /// The request conflicts with the current state, such as removing the last factor.
    #[error("conflict: {0}")]
    Conflict(&'static str),
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
    Config(&'static str),
    /// A cryptographic operation failed, such as sealing or hashing.
    #[error("cryptography: {0}")]
    Crypto(&'static str),
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
            Error::InvalidRequest(detail) | Error::Conflict(detail) => Some(detail),
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
    use super::Error;

    #[test]
    fn server_side_failures_share_one_code() {
        for error in [Error::Config("x"), Error::Crypto("y"), Error::Rng] {
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
