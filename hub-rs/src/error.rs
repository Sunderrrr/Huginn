//! FastAPI-compatible HTTP errors for the axum API.
//!
//! Every failure renders exactly like a FastAPI `HTTPException`: a JSON body of
//! `{"detail": "<message>"}` with the matching status code (FastAPI's default
//! `HTTPException` handler renders just that key).
//!
//! The status helpers cover the codes the hub's handlers raise: 400/401/403/
//! 404/409/429 plus the two complements used by the request pipeline — 413
//! (`enforce_body_size` / the global body cap in `app/main.py`) and 422
//! (pydantic schema validation, which FastAPI answers with 422).

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

/// An API error: a status code plus the `detail` string FastAPI would render.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiError {
    status: StatusCode,
    detail: String,
}

impl ApiError {
    /// Build an error with an explicit status code.
    pub fn new(status: StatusCode, detail: impl Into<String>) -> Self {
        Self {
            status,
            detail: detail.into(),
        }
    }

    /// 400 — malformed request (also `_enforce_tls`'s TLS refusal).
    pub fn bad_request(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, detail)
    }

    /// 401 — missing or invalid credentials.
    pub fn unauthorized(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, detail)
    }

    /// 403 — authenticated but not allowed (e.g. a worker still PENDING).
    pub fn forbidden(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, detail)
    }

    /// 404 — unknown resource (e.g. "task not found for this worker").
    pub fn not_found(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, detail)
    }

    /// 409 — conflicting state (e.g. idempotency clashes).
    pub fn conflict(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, detail)
    }

    /// 429 — rate limit exceeded.
    pub fn too_many_requests(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::TOO_MANY_REQUESTS, detail)
    }

    /// 413 — request body over the cap (`enforce_body_size` / global cap).
    pub fn payload_too_large(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::PAYLOAD_TOO_LARGE, detail)
    }

    /// 422 — schema validation failure (pydantic's status in FastAPI).
    pub fn unprocessable_entity(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::UNPROCESSABLE_ENTITY, detail)
    }

    /// 500 — unexpected server-side failure.
    pub fn internal(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, detail)
    }

    pub fn status(&self) -> StatusCode {
        self.status
    }

    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.status, self.detail)
    }
}

impl std::error::Error for ApiError {}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({ "detail": self.detail }))).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use http_body_util::BodyExt;

    async fn body_json(response: Response) -> serde_json::Value {
        let bytes = Body::collect(response.into_body())
            .await
            .unwrap()
            .to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[test]
    fn helpers_map_to_the_fastapi_status_codes() {
        assert_eq!(ApiError::bad_request("x").status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            ApiError::unauthorized("x").status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(ApiError::forbidden("x").status(), StatusCode::FORBIDDEN);
        assert_eq!(ApiError::not_found("x").status(), StatusCode::NOT_FOUND);
        assert_eq!(ApiError::conflict("x").status(), StatusCode::CONFLICT);
        assert_eq!(
            ApiError::too_many_requests("x").status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            ApiError::payload_too_large("x").status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
        assert_eq!(
            ApiError::unprocessable_entity("x").status(),
            StatusCode::UNPROCESSABLE_ENTITY
        );
        assert_eq!(
            ApiError::internal("x").status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[tokio::test]
    async fn response_body_is_the_fastapi_detail_shape() {
        let response = ApiError::unauthorized("worker authentication failed").into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            body_json(response).await,
            serde_json::json!({"detail": "worker authentication failed"})
        );
    }

    #[tokio::test]
    async fn response_body_renders_unicode_detail_verbatim() {
        let response =
            ApiError::bad_request("TLS is required for worker communication").into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            body_json(response).await,
            serde_json::json!({"detail": "TLS is required for worker communication"})
        );
    }

    #[test]
    fn display_includes_status_and_detail() {
        let err = ApiError::not_found("task not found for this worker");
        assert_eq!(
            err.to_string(),
            "404 Not Found: task not found for this worker"
        );
    }
}
