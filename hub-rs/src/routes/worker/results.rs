//! `POST /api/worker/tasks/{id}/result` — task result submission.

use axum::extract::{rejection::JsonRejection, OriginalUri, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde::Deserialize;
use uuid::Uuid;

use crate::error::ApiError;
use crate::models::task::SubmitResult;
use crate::models::TaskStatus;

use super::{current_worker, db_err, enforce_tls, map_json_rejection, WorkerState};

/// Pydantic `TaskResultSubmit` per-field bound (2× the truncation cap).
const MAX_RESULT_FIELD_CHARS: usize = 2_097_152;

/// `TaskResultSubmit`.
#[derive(Debug, Clone, Deserialize)]
pub struct TaskResultSubmit {
    pub status: TaskStatus,
    #[serde(default)]
    pub exit_code: Option<i32>,
    #[serde(default)]
    pub stdout: Option<String>,
    #[serde(default)]
    pub stderr: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
}

impl TaskResultSubmit {
    fn validate(&self) -> Result<(), ApiError> {
        for (field, value) in [
            ("stdout", &self.stdout),
            ("stderr", &self.stderr),
            ("error", &self.error),
        ] {
            if let Some(v) = value {
                if v.chars().count() > MAX_RESULT_FIELD_CHARS {
                    return Err(ApiError::unprocessable_entity(format!(
                        "{field} must be at most {MAX_RESULT_FIELD_CHARS} characters"
                    )));
                }
            }
        }
        Ok(())
    }
}

/// `POST /api/worker/tasks/{id}/result` — record a task result (204).
pub(super) async fn submit_task_result(
    State(state): State<WorkerState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    Path(task_id): Path<String>,
    body: Result<Json<TaskResultSubmit>, JsonRejection>,
) -> Result<StatusCode, ApiError> {
    enforce_tls(&headers, &uri, &state.config)?;
    // The result body legitimately carries up to max_output_bytes per field;
    // only the global body cap (router layer) applies here.
    let body = body.map_err(map_json_rejection)?.0;
    body.validate()?;
    // Path shape validation before auth (FastAPI validates params first).
    let task_id: Uuid = task_id
        .parse()
        .map_err(|_| ApiError::unprocessable_entity("task id must be a valid UUID"))?;
    let vm = current_worker(&state, &headers).await?;

    let res = SubmitResult {
        task_id,
        vm_id: vm.id,
        status: body.status,
        exit_code: body.exit_code,
        stdout: body.stdout.clone(),
        stderr: body.stderr.clone(),
        error: body.error.clone(),
        output_cap_bytes: state.config.max_output_bytes,
    };
    let task = crate::models::task::submit_result(&state.pool, res)
        .await
        .map_err(db_err)?;
    let Some(task) = task else {
        return Err(ApiError::not_found("task not found for this worker"));
    };

    // The result is committed (the data layer commits per call): now wake
    // anyone blocked in wait_for_terminal (e.g. an agent that called
    // /tasks/{id}/wait or an execute with wait=true).
    state.events.notify(&task_id.to_string());
    // A result that re-queues the task (status=pending) makes it claimable
    // again — wake this VM's parked long-polls too. The Python port gets this
    // from `notify_queue_on_commit` at task creation; the wake is only valid
    // once the re-queued row is committed, which it now is.
    if task.status == TaskStatus::Pending {
        state.events.notify_queue_on_commit(&vm.id.to_string());
    }
    // Push a live hint to connected dashboards (events.publish({"type":
    // "tasks"}) in Python) and notify external integrations on failure.
    state.bus.publish_hint("tasks");
    if matches!(
        task.status,
        crate::models::enums::TaskStatus::Failed
            | crate::models::enums::TaskStatus::Timeout
            | crate::models::enums::TaskStatus::DeadLetter
    ) {
        crate::services::notifications::notify_task_failure(&state.pool, &vm, &task).await;
    }

    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::super::router;
    use super::super::testing::*;
    use super::*;
    use serde_json::json;
    use tower::ServiceExt;

    #[test]
    fn result_fields_are_capped_at_two_mebibytes() {
        let mut body = TaskResultSubmit {
            status: TaskStatus::Succeeded,
            exit_code: Some(0),
            stdout: Some("ok".into()),
            stderr: None,
            error: None,
        };
        assert!(body.validate().is_ok());
        body.stdout = Some("x".repeat(MAX_RESULT_FIELD_CHARS + 1));
        assert!(body.validate().is_err());
    }

    #[tokio::test]
    async fn result_route_validates_the_task_id_before_the_db() {
        let app = router(test_state(false));
        let mut request = json_request(
            "POST",
            "/api/worker/tasks/not-a-uuid/result",
            json!({"status": "succeeded"}),
        );
        request
            .headers_mut()
            .insert("x-worker-id", Uuid::new_v4().to_string().parse().unwrap());
        request
            .headers_mut()
            .insert("x-worker-secret", "s3cret".parse().unwrap());
        let response = app.oneshot(request).await.unwrap();
        // Bad body → 422 before auth/DB; with a valid body this same request
        // would fall through to worker authentication.
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }
}
