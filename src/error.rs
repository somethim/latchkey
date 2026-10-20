use axum::Json;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;

use crate::store::StoreError;

/// Errors carry a stable machine code for clients; details stay in the server log.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("not signed in")]
    Unauthorized,
    #[error("sign-in failed")]
    SignInFailed,
    #[error("a recent sign-in is required")]
    StepUpRequired,
    #[error("not allowed")]
    Forbidden,
    #[error("request rejected by the origin or CSRF check")]
    CsrfRejected,
    #[error("not found")]
    NotFound,
    #[error("invalid request: {0}")]
    InvalidRequest(&'static str),
    #[error("conflict: {0}")]
    Conflict(&'static str),
    #[error("too many attempts")]
    TooManyAttempts { retry_after_secs: u64 },
    #[error("storage: {0}")]
    Store(#[from] StoreError),
    #[error("configuration: {0}")]
    Config(&'static str),
    #[error("internal: {0}")]
    Internal(String),
}

#[derive(Serialize)]
struct Body {
    error: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<&'static str>,
}

impl Error {
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
            Error::Store(_) | Error::Config(_) | Error::Internal(_) => "internal",
        }
    }

    pub fn status(&self) -> StatusCode {
        match self {
            Error::Unauthorized | Error::SignInFailed | Error::StepUpRequired => {
                StatusCode::UNAUTHORIZED
            }
            Error::Forbidden | Error::CsrfRejected => StatusCode::FORBIDDEN,
            Error::NotFound => StatusCode::NOT_FOUND,
            Error::InvalidRequest(_) => StatusCode::BAD_REQUEST,
            Error::Conflict(_) => StatusCode::CONFLICT,
            Error::TooManyAttempts { .. } => StatusCode::TOO_MANY_REQUESTS,
            Error::Store(_) | Error::Config(_) | Error::Internal(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        }
    }

    pub(crate) fn internal(err: impl std::fmt::Display) -> Self {
        Error::Internal(err.to_string())
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let status = self.status();
        if status.is_server_error() {
            tracing::error!(error = %self, "latchkey request failed");
        }
        let detail = match &self {
            Error::InvalidRequest(detail) | Error::Conflict(detail) => Some(*detail),
            _ => None,
        };
        let mut response = (
            status,
            Json(Body {
                error: self.code(),
                detail,
            }),
        )
            .into_response();
        if let Error::TooManyAttempts { retry_after_secs } = self
            && let Ok(value) = HeaderValue::from_str(&retry_after_secs.to_string())
        {
            response.headers_mut().insert(header::RETRY_AFTER, value);
        }
        response
    }
}
