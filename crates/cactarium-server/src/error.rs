//! Errors: rendered as an HTML page for the site, as JSON for the API.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};

use cactup_ecosystem_common::api::{ErrorBody, ErrorDetail};

use crate::templates::{ErrorPage, PageCtx, render};

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("not found")]
    NotFound,
    /// Not found, with the reason shown (a commit the repo doesn't have).
    #[error("{0}")]
    Missing(String),
    #[error("sign in to do that")]
    Unauthorized,
    #[error("you are not allowed to do that")]
    Forbidden,
    /// Forbidden, with the reason shown.
    #[error("{0}")]
    Denied(String),
    #[error("{0}")]
    BadRequest(String),
    #[error("{0}")]
    Conflict(String),
    /// With the whole seconds until the client may try again (sent as `Retry-After`).
    #[error("too many requests; try again in {}", in_seconds(*.0))]
    TooManyRequests(u64),
    /// Something we depend on (an author's repo host) failed; the message is shown, so keep it
    /// generic and log the details.
    #[error("{0}")]
    Upstream(String),
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

impl From<sqlx::Error> for AppError {
    fn from(e: sqlx::Error) -> Self {
        // A check-then-insert that lost a race with an identical request: the constraint caught it.
        if e.as_database_error().is_some_and(|d| d.is_unique_violation()) {
            return AppError::Conflict(
                "that already exists (perhaps a moment ago, from another request); reload and check".into(),
            );
        }
        AppError::Internal(e.into())
    }
}

impl AppError {
    pub fn bad(msg: impl std::fmt::Display) -> Self {
        AppError::BadRequest(msg.to_string())
    }

    pub fn status(&self) -> StatusCode {
        match self {
            AppError::NotFound | AppError::Missing(_) => StatusCode::NOT_FOUND,
            AppError::Unauthorized => StatusCode::UNAUTHORIZED,
            AppError::Forbidden | AppError::Denied(_) => StatusCode::FORBIDDEN,
            AppError::BadRequest(_) => StatusCode::BAD_REQUEST,
            AppError::Conflict(_) => StatusCode::CONFLICT,
            AppError::TooManyRequests(_) => StatusCode::TOO_MANY_REQUESTS,
            AppError::Upstream(_) => StatusCode::BAD_GATEWAY,
            AppError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// What the visitor may see. Internal errors are logged, never shown.
    fn public_message(&self) -> String {
        match self {
            AppError::Internal(e) => {
                tracing::error!("internal error: {e:#}");
                "Something went wrong on our side.".into()
            }
            other => capitalize(&other.to_string()),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = self.status();
        let page = ErrorPage {
            ctx: PageCtx::anonymous(),
            status: status.as_u16(),
            message: self.public_message(),
        };
        let retry = axum::response::AppendHeaders(self.retry_after());
        match render(&page) {
            Ok(html) => (status, retry, Html(html)).into_response(),
            Err(_) => (status, retry, "error").into_response(),
        }
    }
}

pub type AppResult<T> = Result<T, AppError>;

/// `1 second`, `30 seconds`, for a message.
fn in_seconds(n: u64) -> String {
    if n == 1 { "1 second".to_owned() } else { format!("{n} seconds") }
}

impl AppError {
    /// The `Retry-After` header of a refusal for too many requests.
    fn retry_after(&self) -> Option<(axum::http::HeaderName, axum::http::HeaderValue)> {
        match self {
            AppError::TooManyRequests(s) => Some((axum::http::header::RETRY_AFTER, axum::http::HeaderValue::from(*s))),
            _ => None,
        }
    }
}

/// Capitalizes a message, unless it starts with something case-significant: a slug, a path, a
/// version, a quoted name, an identifier.
fn capitalize(m: &str) -> String {
    let first = m.split_whitespace().next().unwrap_or("");
    let literal = first.contains(['/', '@', ':', '.', '_', '\'', '"', '`'])
        || first.chars().skip(1).any(|c| c.is_uppercase());
    let mut c = m.chars();
    match c.next() {
        Some(f) if !literal => f.to_uppercase().collect::<String>() + c.as_str(),
        _ => m.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn slugs_keep_their_case() {
        assert_eq!(
            super::capitalize("max/et-lite@1.0.0 already exists"),
            "max/et-lite@1.0.0 already exists"
        );
        assert_eq!(super::capitalize("the form expired"), "The form expired");
        assert_eq!(super::capitalize("'carpetx' is taken"), "'carpetx' is taken");
    }
}

/// The API's error: `{"error": "..."}` with the right status.
#[derive(Debug)]
pub struct ApiError(pub AppError);

impl<E: Into<AppError>> From<E> for ApiError {
    fn from(e: E) -> Self {
        ApiError(e.into())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.0.status();
        let code = match &self.0 {
            AppError::NotFound | AppError::Missing(_) => "not-found",
            AppError::Unauthorized => "unauthorized",
            AppError::Forbidden | AppError::Denied(_) => "forbidden",
            AppError::BadRequest(_) => "bad-request",
            AppError::Conflict(_) => "conflict",
            AppError::TooManyRequests(_) => "rate-limited",
            AppError::Upstream(_) => "upstream",
            AppError::Internal(_) => "internal",
        };
        let body =
            ErrorBody { error: ErrorDetail { code: code.into(), message: self.0.public_message() } };
        (status, axum::response::AppendHeaders(self.0.retry_after()), Json(body)).into_response()
    }
}

pub type ApiResult<T> = Result<T, ApiError>;
