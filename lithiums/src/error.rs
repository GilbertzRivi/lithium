use std::fmt;
use tracing::{error, warn};
use poem::{http::StatusCode, IntoResponse, Response};
use serde_json::json;

use lithium_core::error::LithiumError;

pub type AppResult<T> = Result<T, AppError>;

#[derive(Debug)]
pub struct AppError {
    pub code: StatusCode,
    pub msg: &'static str,
    pub source: Option<anyhow::Error>,
}

impl AppError {
    pub fn bad_request(msg: &'static str) -> Self {
        Self { code: StatusCode::BAD_REQUEST, msg, source: None }
    }

    pub fn unauthorized(msg: &'static str) -> Self {
        Self { code: StatusCode::UNAUTHORIZED, msg, source: None }
    }

    pub fn too_many_requests(msg: &'static str) -> Self {
        Self { code: StatusCode::TOO_MANY_REQUESTS, msg, source: None }
    }

    pub fn internal(msg: &'static str) -> Self {
        Self { code: StatusCode::INTERNAL_SERVER_ERROR, msg, source: None }
    }

    pub fn from_source(code: StatusCode, msg: &'static str, source: impl Into<anyhow::Error>) -> Self {
        Self { code, msg, source: Some(source.into()) }
    }
}
impl From<LithiumError> for AppError {
    fn from(e: LithiumError) -> Self {
        AppError::from_source(StatusCode::INTERNAL_SERVER_ERROR, "internal_error", e)
    }
}

impl From<sea_orm::DbErr> for AppError {
    fn from(e: sea_orm::DbErr) -> Self {
        AppError::from_source(StatusCode::INTERNAL_SERVER_ERROR, "db_error", e)
    }
}

impl From<serde_json::Error> for AppError {
    fn from(e: serde_json::Error) -> Self {
        AppError::from_source(StatusCode::BAD_REQUEST, "invalid_json", e)
    }
}

impl From<poem::Error> for AppError {
    fn from(e: poem::Error) -> Self {
        AppError::from_source(StatusCode::BAD_REQUEST, "request_error", e)
    }
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.msg)
    }
}
impl std::error::Error for AppError {}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        if self.code.is_server_error() {
            match &self.source {
                Some(src) => error!(
                    status = %self.code,
                    msg = self.msg,
                    error = ?src,
                    "app error"
                ),
                None => error!(
                    status = %self.code,
                    msg = self.msg,
                    "app error"
                ),
            }
        } else {
            match &self.source {
                Some(src) => warn!(
                    status = %self.code,
                    msg = self.msg,
                    error = ?src,
                    "client error"
                ),
                None => warn!(
                    status = %self.code,
                    msg = self.msg,
                    "client error"
                ),
            }
        }

        let body = json!({
            "ok": false,
            "error": self.msg,
        });

        Response::builder()
            .status(self.code)
            .content_type("application/json")
            .body(body.to_string())
    }
}

impl From<AppError> for poem::Error {
    fn from(err: AppError) -> Self {
        poem::Error::from_response(err.into_response())
    }
}