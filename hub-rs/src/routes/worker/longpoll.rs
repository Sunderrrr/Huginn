//! The task hand-out: `GET /api/worker/tasks/next` and the event-driven
//! long-poll state machine behind it.

use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{OriginalUri, Query, State};
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use axum::Json;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::ApiError;
use crate::models::task::Task;
use crate::models::TaskType;
use crate::services::task_events::TaskEvents;

use super::{current_worker, db_err, enforce_tls, WorkerState, MAX_WAIT_SECONDS};

/// `WorkerTask` — a task as handed to a worker for execution.
#[derive(Debug, Clone, Serialize)]
pub struct WorkerTask {
    pub id: Uuid,
    #[serde(rename = "type")]
    pub task_type: TaskType,
    pub action_name: Option<String>,
    pub payload: serde_json::Value,
}

impl From<Task> for WorkerTask {
    fn from(task: Task) -> Self {
        Self {
            id: task.id,
            task_type: task.task_type,
            action_name: task.action_name,
            payload: task.payload,
        }
    }
}

/// Query for `GET /tasks/next` (`wait` defaults to 0.0, like the Python
/// handler's signature).
#[derive(Debug, Clone, Copy, Deserialize)]
pub struct NextTaskQuery {
    #[serde(default)]
    pub wait: f64,
}

/// `GET /api/worker/tasks/next` — hand the worker its next queued task.
///
/// With `wait>0` this long-polls: if the queue is empty it parks on the
/// in-process queue event (`services::task_events`) that fires the moment a
/// task for this VM becomes claimable, so pickup is instant and idle workers
/// cost zero database queries. After `wait` seconds (capped at
/// [`MAX_WAIT_SECONDS`]) without a task, `null` is returned.
///
/// Subscribe before the first claim so a task committed in the gap still wakes
/// us. If several workers of the same VM are parked, every wake re-claims and
/// `claim_next_task` (`FOR UPDATE SKIP LOCKED`) stays the transactional
/// arbiter: the first claim wins, the others find nothing and re-park.
pub(super) async fn next_task(
    State(state): State<WorkerState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    query: Result<Query<NextTaskQuery>, axum::extract::rejection::QueryRejection>,
) -> Result<impl IntoResponse, ApiError> {
    enforce_tls(&headers, &uri, &state.config)?;
    let vm = current_worker(&state, &headers).await?;
    let query = query.map_err(|e| ApiError::unprocessable_entity(e.body_text()))?;
    let wait = clamp_wait(query.wait);

    // The long-poll records the heartbeat up front (Python sets
    // `vm.last_heartbeat_at` and commits the session inside the loop).
    crate::models::vm::update_heartbeat(&state.pool, vm.id, Utc::now())
        .await
        .map_err(db_err)?;

    let vm_id = vm.id;
    let task = long_poll(
        &state.events,
        &vm_id.to_string(),
        Duration::from_secs_f64(wait),
        Duration::from_secs_f64(MAX_WAIT_SECONDS),
        || {
            let pool = state.pool.clone();
            async move {
                crate::models::task::claim_next_task(&pool, vm_id)
                    .await
                    .map_err(db_err)
            }
        },
    )
    .await?;

    Ok(Json(task.map(WorkerTask::from)))
}

// ---------------------------------------------------------------------------
// The event-driven long-poll (testable state machine)
// ---------------------------------------------------------------------------

/// Hand out the next task for `vm_id`, parking up to `min(wait, max_wait)` on
/// the queue wake when the queue is empty. Returns `None` when the wait
/// expires without a claimable task.
///
/// `claim` is the transactional arbiter (e.g. `models::task::claim_next_task`):
/// it is called once up front and again after every wake. It runs its own short
/// transaction, so the read snapshot is dropped between checks — the reason the
/// Python loop calls `session.commit()` before parking.
pub(crate) async fn long_poll<T, F, Fut>(
    events: &Arc<TaskEvents>,
    vm_id: &str,
    wait: Duration,
    max_wait: Duration,
    mut claim: F,
) -> Result<Option<T>, ApiError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<Option<T>, ApiError>>,
{
    // Subscribe BEFORE the first claim so a task committed in the gap still
    // wakes us instead of stalling until the wait elapses.
    let wake = events.subscribe_queue(vm_id);
    let mut task = claim().await?;
    let deadline = Instant::now() + wait.min(max_wait);
    while task.is_none() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        if !wake.wait(remaining).await {
            break; // timed out
        }
        wake.clear(); // consume this wake round, like `wake.clear()` in Python
        task = claim().await?;
    }
    drop(wake); // unsubscribe (Python's `finally: unsubscribe_queue`)
    Ok(task)
}

/// `min(wait, MAX_WAIT_SECONDS)`, clamped to a sane non-negative value so a
/// negative/NaN `wait` degrades to "claim once" instead of panicking.
fn clamp_wait(wait: f64) -> f64 {
    if !wait.is_finite() {
        return 0.0;
    }
    wait.clamp(0.0, MAX_WAIT_SECONDS)
}

#[cfg(test)]
mod tests {
    use super::super::router;
    use super::super::testing::*;
    use super::*;
    use axum::body::Body;
    use axum::http::StatusCode;
    use tower::ServiceExt;

    // ---- long-poll state machine -------------------------------------------

    fn no_error<T>(
        value: Option<T>,
    ) -> impl FnMut() -> std::future::Ready<Result<Option<T>, ApiError>> {
        let mut value = Some(value);
        move || std::future::ready(Ok(value.take().flatten()))
    }

    #[tokio::test]
    async fn long_poll_claims_once_when_a_task_is_available() {
        let events = TaskEvents::new();
        let claims = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let task = long_poll(
            &events,
            "vm-1",
            Duration::from_secs(5),
            Duration::from_secs(5),
            {
                let claims = Arc::clone(&claims);
                move || {
                    claims.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    async move { Ok(Some("task")) }
                }
            },
        )
        .await
        .unwrap();
        assert_eq!(task, Some("task"));
        assert_eq!(claims.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn long_poll_wakes_on_queue_event_and_reclaims() {
        let events = TaskEvents::new();
        let queue = Arc::new(std::sync::Mutex::new(None::<&'static str>));
        let claims = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        let driver = {
            let events = Arc::clone(&events);
            let queue = Arc::clone(&queue);
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(20)).await;
                // The task becomes visible with its COMMIT, then the wake fires
                // (notify_queue_on_commit discipline).
                *queue.lock().unwrap() = Some("task");
                events.notify_queue("vm-1");
            })
        };

        let task = long_poll(
            &events,
            "vm-1",
            Duration::from_secs(5),
            Duration::from_secs(5),
            {
                let queue = Arc::clone(&queue);
                let claims = Arc::clone(&claims);
                move || {
                    let n = claims.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let queue = Arc::clone(&queue);
                    // First claim misses (the task is not committed yet) — the
                    // wake is what makes it claimable.
                    async move {
                        Ok(if n == 0 {
                            None
                        } else {
                            queue.lock().unwrap().take()
                        })
                    }
                }
            },
        )
        .await
        .unwrap();

        driver.await.unwrap();
        assert_eq!(task, Some("task"));
        assert_eq!(
            claims.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "claim after the wake"
        );
    }

    #[tokio::test]
    async fn long_poll_times_out_with_none() {
        let events = TaskEvents::new();
        let claims = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let started = Instant::now();
        let task: Option<&str> = long_poll(
            &events,
            "vm-1",
            Duration::from_millis(50),
            Duration::from_millis(50),
            {
                let claims = Arc::clone(&claims);
                move || {
                    claims.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    async move { Ok(None) }
                }
            },
        )
        .await
        .unwrap();
        assert_eq!(task, None);
        assert!(
            started.elapsed() >= Duration::from_millis(50),
            "parks the full wait"
        );
        assert_eq!(claims.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn long_poll_caps_the_wait_at_max_wait() {
        let events = TaskEvents::new();
        let started = Instant::now();
        let task: Option<&str> = long_poll(
            &events,
            "vm-1",
            Duration::from_secs(3600), // asks for an hour...
            Duration::from_millis(50), // ...but is capped
            no_error(None),
        )
        .await
        .unwrap();
        assert_eq!(task, None);
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "returns at the cap"
        );
    }

    #[tokio::test]
    async fn long_poll_with_zero_wait_claims_exactly_once() {
        let events = TaskEvents::new();
        let claims = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let task: Option<&str> = long_poll(&events, "vm-1", Duration::ZERO, Duration::ZERO, {
            let claims = Arc::clone(&claims);
            move || {
                claims.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                async move { Ok(None) }
            }
        })
        .await
        .unwrap();
        assert_eq!(task, None);
        assert_eq!(claims.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn concurrent_long_polls_never_double_deliver_a_task() {
        // Two workers of one VM poll at once over a single queued task: the
        // claim is the transactional arbiter, so exactly one gets it.
        let events = TaskEvents::new();
        let queue = Arc::new(std::sync::Mutex::new(Some("task")));

        let poll = {
            let events = Arc::clone(&events);
            let queue = Arc::clone(&queue);
            move || {
                let events = Arc::clone(&events);
                let queue = Arc::clone(&queue);
                tokio::spawn(async move {
                    long_poll(
                        &events,
                        "vm-1",
                        Duration::from_millis(200),
                        Duration::from_millis(200),
                        {
                            let queue = Arc::clone(&queue);
                            move || {
                                let queue = Arc::clone(&queue);
                                async move { Ok(queue.lock().unwrap().take()) }
                            }
                        },
                    )
                    .await
                })
            }
        };

        let (a, b) = tokio::join!(poll(), poll());
        let results = [a.unwrap(), b.unwrap()];
        let winners = results
            .iter()
            .filter(|r| r.as_ref().unwrap().is_some())
            .count();
        assert_eq!(winners, 1, "exactly one worker receives the task");
    }

    #[tokio::test]
    async fn tasks_next_requires_credentials() {
        let app = router(test_state(false));
        let request = axum::http::Request::builder()
            .method("GET")
            .uri("/api/worker/tasks/next?wait=1")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn clamp_wait_needs_no_awkward_values() {
        assert_eq!(clamp_wait(0.0), 0.0);
        assert_eq!(clamp_wait(5.0), 5.0);
        assert_eq!(clamp_wait(1_000.0), MAX_WAIT_SECONDS);
        assert_eq!(clamp_wait(-3.0), 0.0);
        assert_eq!(clamp_wait(f64::NAN), 0.0);
    }
}
