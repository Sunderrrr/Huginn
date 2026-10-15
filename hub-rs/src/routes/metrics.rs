//! `GET /metrics` — Prometheus exposition endpoint (ops visibility).
//!
//! Renders [`crate::services::metrics::Metrics`] in the Prometheus text
//! exposition format (0.0.4) and serves it without authentication, like
//! Prometheus expects of a scrape target.
//!
//! # Security decision (read before exposing this)
//!
//! `/metrics` is **unauthenticated by design** (the Prometheus scrape model —
//! a scraper sends no interactive credentials) but it is **sensitive**: the
//! output reveals request patterns and rates, task throughput and failures,
//! fleet size and worker liveness. The hub therefore keeps it out of the
//! authenticated API surface and the deployment keeps it off the public one:
//!
//! - **recommended**: expose it only on the internal network — e.g. bind the
//!   hub's metrics listener (or the whole hub) to the management interface, or
//!   have the reverse proxy (Caddy) refuse `/metrics` from outside
//!   (`route /metrics { @denied not remote_ip 10.0.0.0/8; abort @denied }`);
//! - alternatively mount this router on a second `axum::serve` bound to
//!   `127.0.0.1` (or a unix socket) that only Prometheus reaches;
//! - a bearer check is possible but pointless unless the scrape config is
//!   changed too — at that point prefer network-level restriction.
//!
//! The endpoint itself does no database write and is safe to poll as often as
//! Prometheus likes (the `workers_active` count runs one indexed `count(*)`
//! per scrape).
//!
//! # Wiring (what the app assembly has to do)
//!
//! ```ignore
//! // 1. one registry for the process
//! let metrics = Arc::new(services::metrics::Metrics::new());
//!
//! // 2. the metrics state: pool for huginn_db_pool / huginn_workers_active,
//! //    the shared TaskEvents bus for huginn_longpoll_waiting
//! let metrics_state = routes::metrics::MetricsState::new(metrics.clone())
//!     .with_pool(pool.clone())
//!     .with_events(events.clone())
//!     .workers_window(config.heartbeat_offline_seconds);
//!
//! // 3. mount the endpoint AND wrap the router with the recording layer
//! let app: Router = routes::worker::router(worker_state)
//!     .merge(routes::authapi::router(auth_state))
//!     .merge(routes::fleet::router(fleet_state))
//!     .merge(routes::admin::router(admin_state))
//!     .merge(routes::metrics::router(metrics_state))   // GET /metrics
//!     .route("/healthz", get(healthz))
//!     .layer(MetricsLayer::new(metrics.clone()));      // feeds the counters
//! ```
//!
//! Alternatively feed the counters by hand with
//! [`crate::services::metrics::record_request`] and the task counter with
//! [`Metrics::record_task`]. The metric catalog and the exact recording
//! contract live in [`crate::services::metrics`].

use std::sync::Arc;

use axum::extract::State;
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE};
use axum::http::{HeaderMap, HeaderValue};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;

use crate::services::metrics::{gather, GaugeSnapshot, Metrics};
use crate::services::task_events::TaskEvents;

/// One-stop wiring surface for the app assembly: `routes::metrics::{router,
/// MetricsState, MetricsLayer, record_request}`. The re-exports become "used"
/// as soon as `main.rs` wires them in.
#[allow(unused_imports)]
pub use crate::services::metrics::{record_request, route_label, MetricsLayer, MetricsMiddleware};

/// Prometheus text exposition format 0.0.4.
pub const CONTENT_TYPE_PROMETHEUS: &str = "text/plain; version=0.0.4; charset=utf-8";

/// Default recency window for `huginn_workers_active` when the coordinator
/// does not set one; wire `config.heartbeat_offline_seconds` so the gauge
/// agrees with the sweeper's notion of a live worker.
pub const DEFAULT_WORKERS_WINDOW_SECONDS: i64 = 90;

/// Everything the metrics endpoint needs. Cheap to clone.
#[derive(Debug, Clone)]
pub struct MetricsState {
    /// The process-wide registry fed by [`MetricsLayer`] / [`record_request`].
    pub metrics: Arc<Metrics>,
    /// The shared task-event bus: `huginn_longpoll_waiting` is read live from
    /// it at scrape time. `None` reports
    /// [`Metrics::set_longpoll_waiting`] instead.
    pub events: Option<Arc<TaskEvents>>,
    /// The sqlx pool for `huginn_db_pool` and `huginn_workers_active`.
    /// `None`: no pool family, and `huginn_workers_active` reports
    /// [`Metrics::set_workers_active`].
    pub pool: Option<sqlx::PgPool>,
    /// Heartbeat recency window (seconds) for `huginn_workers_active`.
    pub workers_window_seconds: i64,
}

impl MetricsState {
    /// A state with no live sources (manual gauges only) — enough for the
    /// endpoint to serve the registry.
    pub fn new(metrics: Arc<Metrics>) -> Self {
        Self {
            metrics,
            events: None,
            pool: None,
            workers_window_seconds: DEFAULT_WORKERS_WINDOW_SECONDS,
        }
    }

    /// Read `huginn_db_pool` and `huginn_workers_active` from the pool.
    pub fn with_pool(mut self, pool: sqlx::PgPool) -> Self {
        self.pool = Some(pool);
        self
    }

    /// Read `huginn_longpoll_waiting` live from the task-event bus.
    pub fn with_events(mut self, events: Arc<TaskEvents>) -> Self {
        self.events = Some(events);
        self
    }

    /// Heartbeat recency window for `huginn_workers_active`
    /// (see [`DEFAULT_WORKERS_WINDOW_SECONDS`]).
    pub fn workers_window(mut self, seconds: u64) -> Self {
        self.workers_window_seconds = seconds as i64;
        self
    }

    /// Gather the live gauges for one scrape.
    pub async fn snapshot(&self) -> GaugeSnapshot {
        gather(
            &self.metrics,
            self.events.as_ref(),
            self.pool.as_ref(),
            self.workers_window_seconds,
        )
        .await
    }

    /// Render the full exposition text for one scrape.
    pub async fn render(&self) -> String {
        let gauges = self.snapshot().await;
        self.metrics.render(&gauges)
    }
}

/// The `GET /metrics` router (path included, so it can be merged as-is).
///
/// Deliberately unauthenticated — see the security note in the module docs.
pub fn router(state: MetricsState) -> Router {
    Router::new()
        .route("/metrics", get(scrape))
        .with_state(state)
}

/// `GET /metrics` — the Prometheus scrape handler.
async fn scrape(State(state): State<MetricsState>) -> impl IntoResponse {
    let body = state.render().await;
    let mut headers = HeaderMap::new();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static(CONTENT_TYPE_PROMETHEUS),
    );
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    (headers, body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use std::time::Duration;
    use tower::ServiceExt;

    fn lazy_pool() -> sqlx::PgPool {
        crate::db::pool_options(1)
            .connect_lazy("postgres://huginn@localhost/huginn_test")
            .unwrap()
    }

    async fn body_text(response: axum::response::Response) -> String {
        let bytes = Body::collect(response.into_body())
            .await
            .unwrap()
            .to_bytes();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn metrics_endpoint_needs_no_authentication() {
        let metrics = Arc::new(Metrics::new());
        metrics.record_http("GET", "/api/tasks/{id}", 200, Duration::from_millis(12));
        metrics.record_task("action", "succeeded");
        let state = MetricsState::new(metrics)
            .with_pool(lazy_pool())
            .with_events(TaskEvents::new());
        let app = router(state);
        // No Authorization header at all: Prometheus scrapes unauthenticated.
        let request = Request::builder()
            .uri("/metrics")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            CONTENT_TYPE_PROMETHEUS
        );
        let text = body_text(response).await;
        for needle in [
            "# TYPE huginn_http_requests_total counter",
            "# TYPE huginn_http_request_duration_seconds histogram",
            "# TYPE huginn_longpoll_waiting gauge",
            "# TYPE huginn_tasks_total counter",
            "# TYPE huginn_workers_active gauge",
            "# TYPE huginn_db_pool gauge",
            "# TYPE huginn_build_info gauge",
            "huginn_http_requests_total{method=\"GET\",route=\"/api/tasks/{id}\",status=\"200\"} 1",
            "huginn_tasks_total{type=\"action\",status=\"succeeded\"} 1",
            "huginn_db_pool{state=\"in_use\"} 0",
            &format!(
                "huginn_build_info{{version=\"{}\"}} 1",
                env!("CARGO_PKG_VERSION")
            ),
        ] {
            assert!(text.contains(needle), "missing `{needle}` in:\n{text}");
        }
    }

    #[tokio::test]
    async fn layer_records_method_route_and_status() {
        let metrics = Arc::new(Metrics::new());
        let app = Router::new()
            .route("/things/{id}", get(|| async { StatusCode::NO_CONTENT }))
            .route("/boom", get(|| async { StatusCode::IM_A_TEAPOT }))
            .layer(MetricsLayer::new(metrics.clone()));

        for (uri, status) in [
            ("/things/42", StatusCode::NO_CONTENT),
            ("/boom", StatusCode::IM_A_TEAPOT),
        ] {
            let request = Request::builder().uri(uri).body(Body::empty()).unwrap();
            let response = app.clone().oneshot(request).await.unwrap();
            assert_eq!(response.status(), status);
        }

        let gauges = GaugeSnapshot::default();
        let text = metrics.render(&gauges);
        for needle in [
            "huginn_http_requests_total{method=\"GET\",route=\"/things/{id}\",status=\"204\"} 1",
            "huginn_http_requests_total{method=\"GET\",route=\"/boom\",status=\"418\"} 1",
            "huginn_http_request_duration_seconds_bucket{route=\"/things/{id}\",le=\"+Inf\"} 1",
            "huginn_http_request_duration_seconds_count{route=\"/things/{id}\"} 1",
        ] {
            assert!(text.contains(needle), "missing `{needle}` in:\n{text}");
        }
    }

    #[test]
    fn unmatched_requests_get_the_fixed_route_label() {
        let request = Request::builder()
            .uri("/nope/0b1f0000-0000-4000-8000-000000000000")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            route_label(&request),
            crate::services::metrics::UNMATCHED_ROUTE
        );
    }

    #[tokio::test]
    async fn manual_record_request_feeds_the_same_counters() {
        let metrics = Arc::new(Metrics::new());
        record_request(&metrics, "PUT", "/manual", 201, Duration::from_millis(5));
        let text = metrics.render(&GaugeSnapshot::default());
        assert!(text.contains(
            "huginn_http_requests_total{method=\"PUT\",route=\"/manual\",status=\"201\"} 1"
        ));
    }

    #[tokio::test]
    async fn state_renders_the_db_pool_gauges() {
        let state = MetricsState::new(Arc::new(Metrics::new())).with_pool(lazy_pool());
        let text = state.render().await;
        for state_label in ["size", "idle", "in_use"] {
            assert!(
                text.contains(&format!("huginn_db_pool{{state=\"{state_label}\"}}")),
                "missing pool state {state_label} in:\n{text}"
            );
        }
    }
}
