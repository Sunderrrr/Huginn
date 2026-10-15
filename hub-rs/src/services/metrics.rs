//! Prometheus metrics for ops visibility: an in-process registry, the
//! Prometheus text-exposition rendering (format 0.0.4, written by hand — no
//! `prometheus`/`metrics` crate, no new dependency at all), and a reusable
//! `tower::Layer` that feeds the HTTP counters.
//!
//! # Exposed metrics
//!
//! | metric                                          | type      | labels                       |
//! |-------------------------------------------------|-----------|------------------------------|
//! | `huginn_http_requests_total`                    | counter   | `method`, `route`, `status`  |
//! | `huginn_http_request_duration_seconds`          | histogram | `route`                      |
//! | `huginn_longpoll_waiting`                       | gauge     | —                            |
//! | `huginn_tasks_total`                            | counter   | `type`, `status`             |
//! | `huginn_workers_active`                         | gauge     | —                            |
//! | `huginn_db_pool`                                | gauge     | `state` (`size`/`idle`/`in_use`) |
//! | `huginn_build_info`                             | gauge=1   | `version`                    |
//!
//! # Wiring (what the app assembly has to do)
//!
//! 1. Build ONE registry for the process: `let metrics = Arc::new(Metrics::new())`.
//! 2. Feed it with [`MetricsLayer`] on the merged router — this records
//!    `method`/`route`/`status` and the duration of every request:
//!
//!    ```ignore
//!    let app: Router = /* ...merged routers... */
//!        .layer(MetricsLayer::new(metrics.clone()));
//!    ```
//!
//!    The layer must wrap the *axum* router (`Router::layer` or
//!    `Router::route_layer`); then `route` is the matched route pattern
//!    (`/api/tasks/{id}`), read from axum's `MatchedPath` extension, which is
//!    inserted before the layered route service runs. Requests that match no
//!    route get the fixed label [`UNMATCHED_ROUTE`] (never the raw URI path —
//!    that would leak unbounded cardinality). If the layer is mounted outside
//!    the router (e.g. on the make-service) `MatchedPath` is unavailable and
//!    every request is labelled [`UNMATCHED_ROUTE`].
//!
//!    Without a layer, record manually with [`record_request`] — one call per
//!    completed request, e.g. from a handler or a `map_response` hook.
//! 3. For `huginn_tasks_total`, call [`Metrics::record_task`] where task state
//!    changes (recommended: once at creation with the initial status, once at
//!    the terminal transition).
//! 4. For `huginn_longpoll_waiting`, hand the shared `Arc<TaskEvents>` to
//!    `MetricsState::with_events` (see `routes/metrics.rs`); the gauge is read
//!    live from the bus at scrape time. If the bus is not available to the
//!    metrics state, call [`Metrics::set_longpoll_waiting`] from wherever the
//!    long-poll is parked/unparked instead — the gauge then reports that
//!    manual value.
//! 5. For `huginn_workers_active` and `huginn_db_pool`, hand the pool to
//!    `MetricsState::with_pool`. Without a pool, `huginn_db_pool` is omitted
//!    and `huginn_workers_active` reports [`Metrics::set_workers_active`]
//!    (a fallback for deployments that keep worker liveness in a cache).
//!
//! `routes/metrics.rs` owns `GET /metrics` and the `MetricsState` that ties
//! these pieces together; the security decision (unauthenticated endpoint,
//! internal-only exposure) is documented there.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use axum::extract::MatchedPath;
use axum::http::Request;
use axum::response::Response;
use tower::{Layer, Service};

use crate::services::task_events::TaskEvents;

/// Duration buckets for `huginn_http_request_duration_seconds`, in seconds —
/// the classic HTTP latency buckets: sub-millisecond noise up to slow
/// long-polls/sweeps.
pub const DURATION_BUCKETS: [f64; 11] = [
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

const BUCKET_COUNT: usize = DURATION_BUCKETS.len();

/// The `route` label of a request that matched no route (404 through the
/// fallback). A fixed label keeps the metric cardinality bounded.
pub const UNMATCHED_ROUTE: &str = "unmatched";

/// One `huginn_http_requests_total` series.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct HttpKey {
    method: String,
    route: String,
    status: u16,
}

/// One `huginn_tasks_total` series.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct TaskKey {
    task_type: String,
    status: String,
}

/// Per-route histogram state (plain counters + sum; rendered cumulative).
#[derive(Debug, Default)]
struct Histogram {
    buckets: [u64; BUCKET_COUNT],
    count: u64,
    sum: f64,
}

impl Histogram {
    fn observe(&mut self, seconds: f64) {
        // Bucket counts are per-bucket (not cumulative): the observation lands
        // in the first bucket it fits under; `render` sums them cumulatively.
        for (i, le) in DURATION_BUCKETS.iter().enumerate() {
            if seconds <= *le {
                self.buckets[i] += 1;
                break;
            }
        }
        self.count += 1;
        self.sum += seconds;
    }
}

/// sqlx pool sizes at scrape time (`Pool::size`/`Pool::num_idle`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DbPoolGauges {
    /// Open connections, idle ones included (`pool.size()`).
    pub size: u64,
    /// Idle connections (`pool.num_idle()`).
    pub idle: u64,
    /// Checked-out connections (`size - idle`).
    pub in_use: u64,
}

impl DbPoolGauges {
    pub fn from_pool(pool: &sqlx::PgPool) -> Self {
        let size = u64::from(pool.size());
        let idle = pool.num_idle() as u64;
        Self {
            size,
            idle,
            in_use: size.saturating_sub(idle),
        }
    }
}

/// Live gauges the registry cannot observe by itself, gathered at scrape time
/// (see [`gather`]) and handed to [`Metrics::render`].
#[derive(Debug, Clone, Default)]
pub struct GaugeSnapshot {
    /// Parked worker long-polls (`huginn_longpoll_waiting`).
    pub longpoll_waiting: u64,
    /// VMs with a recent heartbeat (`huginn_workers_active`).
    pub workers_active: u64,
    /// Pool sizes; `None` renders no `huginn_db_pool` family at all.
    pub db_pool: Option<DbPoolGauges>,
}

/// The metrics registry: label-keyed counters + one histogram per route, plus
/// the manual fallbacks for the gauges that normally come from live sources.
#[derive(Debug, Default)]
pub struct Metrics {
    http_requests: Mutex<HashMap<HttpKey, u64>>,
    http_durations: Mutex<HashMap<String, Histogram>>,
    tasks_total: Mutex<HashMap<TaskKey, u64>>,
    longpoll_waiting: AtomicU64,
    workers_active: AtomicU64,
}

impl Metrics {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one completed HTTP request (count + duration histogram).
    ///
    /// `route` must be a bounded label: a matched route pattern, or
    /// [`UNMATCHED_ROUTE`] — never a raw URI path.
    pub fn record_http(&self, method: &str, route: &str, status: u16, duration: Duration) {
        let key = HttpKey {
            method: method.to_owned(),
            route: route.to_owned(),
            status,
        };
        *self
            .http_requests
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(key)
            .or_insert(0) += 1;
        self.http_durations
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(route.to_owned())
            .or_default()
            .observe(duration.as_secs_f64());
    }

    /// Record one task lifecycle event on `huginn_tasks_total`.
    ///
    /// Call it at creation (initial `status`, usually `pending`) and at the
    /// terminal transition (`succeeded`, `failed`, ...). Pass
    /// [`crate::models::enums::TaskType::as_str`] /
    /// [`crate::models::enums::TaskStatus::as_str`] values so the label set
    /// stays bounded.
    pub fn record_task(&self, task_type: &str, status: &str) {
        let key = TaskKey {
            task_type: task_type.to_owned(),
            status: status.to_owned(),
        };
        *self
            .tasks_total
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(key)
            .or_insert(0) += 1;
    }

    /// Set `huginn_longpoll_waiting` manually — the fallback used when no
    /// [`TaskEvents`] bus is wired into the metrics state (see [`gather`]).
    pub fn set_longpoll_waiting(&self, waiting: u64) {
        self.longpoll_waiting.store(waiting, Ordering::Relaxed);
    }

    /// The manually set `huginn_longpoll_waiting` value.
    pub fn longpoll_waiting(&self) -> u64 {
        self.longpoll_waiting.load(Ordering::Relaxed)
    }

    /// Set `huginn_workers_active` manually — the fallback used when no
    /// database pool is wired into the metrics state (see [`gather`]).
    pub fn set_workers_active(&self, active: u64) {
        self.workers_active.store(active, Ordering::Relaxed);
    }

    /// The manually set `huginn_workers_active` value.
    pub fn workers_active(&self) -> u64 {
        self.workers_active.load(Ordering::Relaxed)
    }

    /// Render the registry plus `gauges` in the Prometheus text exposition
    /// format (0.0.4). Series are sorted so the output is deterministic.
    pub fn render(&self, gauges: &GaugeSnapshot) -> String {
        let mut out = String::with_capacity(4096);

        out.push_str(
            "# HELP huginn_http_requests_total Total HTTP requests handled by the hub, by method, route and status.\n\
             # TYPE huginn_http_requests_total counter\n",
        );
        {
            let guard = self.http_requests.lock().unwrap_or_else(|e| e.into_inner());
            let mut series: Vec<(&HttpKey, u64)> = guard.iter().map(|(k, v)| (k, *v)).collect();
            series.sort_by(|a, b| {
                (a.0.method.as_str(), a.0.route.as_str(), a.0.status).cmp(&(
                    b.0.method.as_str(),
                    b.0.route.as_str(),
                    b.0.status,
                ))
            });
            for (key, value) in series {
                out.push_str(&format!(
                    "huginn_http_requests_total{{method=\"{}\",route=\"{}\",status=\"{}\"}} {}\n",
                    escape_label_value(&key.method),
                    escape_label_value(&key.route),
                    key.status,
                    value
                ));
            }
        }

        out.push_str(
            "# HELP huginn_http_request_duration_seconds HTTP request duration in seconds, by route.\n\
             # TYPE huginn_http_request_duration_seconds histogram\n",
        );
        {
            let guard = self
                .http_durations
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let mut series: Vec<(&String, &Histogram)> = guard.iter().collect();
            series.sort_by(|a, b| a.0.cmp(b.0));
            for (route, hist) in series {
                let route = escape_label_value(route);
                let mut cumulative = 0u64;
                for (i, le) in DURATION_BUCKETS.iter().enumerate() {
                    cumulative += hist.buckets[i];
                    out.push_str(&format!(
                        "huginn_http_request_duration_seconds_bucket{{route=\"{route}\",le=\"{}\"}} {cumulative}\n",
                        fmt_f64(*le)
                    ));
                }
                out.push_str(&format!(
                    "huginn_http_request_duration_seconds_bucket{{route=\"{route}\",le=\"+Inf\"}} {}\n",
                    hist.count
                ));
                out.push_str(&format!(
                    "huginn_http_request_duration_seconds_sum{{route=\"{route}\"}} {}\n",
                    fmt_f64(hist.sum)
                ));
                out.push_str(&format!(
                    "huginn_http_request_duration_seconds_count{{route=\"{route}\"}} {}\n",
                    hist.count
                ));
            }
        }

        out.push_str(
            "# HELP huginn_longpoll_waiting Worker long-polls currently parked on the task queue.\n\
             # TYPE huginn_longpoll_waiting gauge\n",
        );
        out.push_str(&format!(
            "huginn_longpoll_waiting {}\n",
            gauges.longpoll_waiting
        ));

        out.push_str(
            "# HELP huginn_tasks_total Tasks observed by the hub, by type and status.\n\
             # TYPE huginn_tasks_total counter\n",
        );
        {
            let guard = self.tasks_total.lock().unwrap_or_else(|e| e.into_inner());
            let mut series: Vec<(&TaskKey, u64)> = guard.iter().map(|(k, v)| (k, *v)).collect();
            series.sort_by(|a, b| {
                (a.0.task_type.as_str(), a.0.status.as_str())
                    .cmp(&(b.0.task_type.as_str(), b.0.status.as_str()))
            });
            for (key, value) in series {
                out.push_str(&format!(
                    "huginn_tasks_total{{type=\"{}\",status=\"{}\"}} {}\n",
                    escape_label_value(&key.task_type),
                    escape_label_value(&key.status),
                    value
                ));
            }
        }

        out.push_str(
            "# HELP huginn_workers_active VMs with a recent heartbeat.\n\
             # TYPE huginn_workers_active gauge\n",
        );
        out.push_str(&format!(
            "huginn_workers_active {}\n",
            gauges.workers_active
        ));

        if let Some(pool) = &gauges.db_pool {
            out.push_str(
                "# HELP huginn_db_pool SQLx PostgreSQL pool connections, by state.\n\
                 # TYPE huginn_db_pool gauge\n",
            );
            out.push_str(&format!("huginn_db_pool{{state=\"size\"}} {}\n", pool.size));
            out.push_str(&format!("huginn_db_pool{{state=\"idle\"}} {}\n", pool.idle));
            out.push_str(&format!(
                "huginn_db_pool{{state=\"in_use\"}} {}\n",
                pool.in_use
            ));
        }

        out.push_str(
            "# HELP huginn_build_info Build information of the hub binary.\n\
             # TYPE huginn_build_info gauge\n",
        );
        out.push_str(&format!(
            "huginn_build_info{{version=\"{}\"}} 1\n",
            escape_label_value(env!("CARGO_PKG_VERSION"))
        ));

        out
    }
}

/// Record one completed HTTP request — the manual alternative to
/// [`MetricsLayer`] when the coordinator prefers not to wrap the router in a
/// tower layer. Exactly what the layer records per request.
pub fn record_request(
    metrics: &Metrics,
    method: &str,
    route: &str,
    status: u16,
    duration: Duration,
) {
    metrics.record_http(method, route, status, duration);
}

/// The `route` label of a request: the matched route pattern when the request
/// was routed by axum with the `matched-path` feature (the default), else the
/// fixed [`UNMATCHED_ROUTE`] label.
pub fn route_label<B>(req: &Request<B>) -> String {
    req.extensions()
        .get::<MatchedPath>()
        .map(|p| p.as_str().to_owned())
        .unwrap_or_else(|| UNMATCHED_ROUTE.to_owned())
}

/// `tower::Layer` feeding [`Metrics::record_http`] from every request/response
/// pair that passes through it. See the module docs for how to mount it.
#[derive(Debug, Clone)]
pub struct MetricsLayer {
    metrics: Arc<Metrics>,
}

impl MetricsLayer {
    pub fn new(metrics: Arc<Metrics>) -> Self {
        Self { metrics }
    }
}

impl<S> Layer<S> for MetricsLayer {
    type Service = MetricsMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        MetricsMiddleware {
            inner,
            metrics: Arc::clone(&self.metrics),
        }
    }
}

/// The service produced by [`MetricsLayer`]: passes the request through
/// untouched and records `method`/`route`/`status`/duration when the response
/// (or the error) comes back. Requests cancelled before the response is ready
/// are not recorded.
#[derive(Debug, Clone)]
pub struct MetricsMiddleware<S> {
    inner: S,
    metrics: Arc<Metrics>,
}

impl<S, B> Service<Request<B>> for MetricsMiddleware<S>
where
    S: Service<Request<B>, Response = Response>,
    S::Future: Send + 'static,
{
    type Response = Response;
    type Error = S::Error;
    type Future = RecordFuture<S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        let started = std::time::Instant::now();
        let method = req.method().as_str().to_owned();
        let route = route_label(&req);
        RecordFuture {
            inner: Box::pin(self.inner.call(req)),
            metrics: Arc::clone(&self.metrics),
            method,
            route,
            started,
        }
    }
}

/// Response future of [`MetricsMiddleware`] (boxed to avoid pin projection).
pub struct RecordFuture<F> {
    inner: Pin<Box<F>>,
    metrics: Arc<Metrics>,
    method: String,
    route: String,
    started: std::time::Instant,
}

impl<F, E> Future for RecordFuture<F>
where
    F: Future<Output = Result<Response, E>>,
{
    type Output = Result<Response, E>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        match this.inner.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(response)) => {
                record_request(
                    &this.metrics,
                    &this.method,
                    &this.route,
                    response.status().as_u16(),
                    this.started.elapsed(),
                );
                Poll::Ready(Ok(response))
            }
            Poll::Ready(Err(err)) => {
                // The error carries no status; a request the hub could not
                // answer is counted as a 500.
                record_request(
                    &this.metrics,
                    &this.method,
                    &this.route,
                    500,
                    this.started.elapsed(),
                );
                Poll::Ready(Err(err))
            }
        }
    }
}

/// Gather the live gauges at scrape time: parked long-polls from the event
/// bus (or the manual fallback), worker liveness from a light `vms` count (or
/// the manual fallback), pool sizes from sqlx.
///
/// The long-poll count comes from [`TaskEvents::waiter_counts`], whose queue
/// figure counts each parked long-poll twice (each waiter registers under its
/// VM id *and* under the broadcast key), so it is halved here. VM ids are
/// UUIDs, so the broadcast key cannot collide with a real registration.
pub async fn gather(
    metrics: &Metrics,
    events: Option<&Arc<TaskEvents>>,
    pool: Option<&sqlx::PgPool>,
    workers_window_seconds: i64,
) -> GaugeSnapshot {
    let longpoll_waiting = match events {
        Some(events) => {
            let (_task_waiters, queue_registrations) = events.waiter_counts();
            (queue_registrations / 2) as u64
        }
        None => metrics.longpoll_waiting(),
    };
    let workers_active = match pool {
        Some(pool) => match count_recent_workers(pool, workers_window_seconds).await {
            Ok(count) => count,
            Err(e) => {
                tracing::debug!("huginn_workers_active fell back to the manual gauge: {e}");
                metrics.workers_active()
            }
        },
        None => metrics.workers_active(),
    };
    GaugeSnapshot {
        longpoll_waiting,
        workers_active,
        db_pool: pool.map(DbPoolGauges::from_pool),
    }
}

/// `huginn_workers_active`: ACTIVE VMs whose heartbeat is younger than
/// `window_seconds` (one indexed count — cheap enough to run per scrape).
async fn count_recent_workers(
    pool: &sqlx::PgPool,
    window_seconds: i64,
) -> Result<u64, sqlx::Error> {
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM vms \
         WHERE state = 'active'::vm_state \
           AND last_heartbeat_at IS NOT NULL \
           AND last_heartbeat_at > now() - make_interval(secs => $1)",
    )
    .bind(window_seconds as f64)
    .fetch_one(pool)
    .await?;
    Ok(count.max(0) as u64)
}

/// Prometheus text format label-value escaping: `\`, `"` and newlines.
fn escape_label_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }
    out
}

/// Shortest round-trip float rendering, with the exposition spellings for
/// non-finite values.
fn fmt_f64(value: f64) -> String {
    if value.is_nan() {
        "NaN".to_owned()
    } else if value.is_infinite() {
        if value.is_sign_negative() {
            "-Inf".to_owned()
        } else {
            "+Inf".to_owned()
        }
    } else {
        format!("{value}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_line(text: &str, line: &str) {
        assert!(
            text.lines().any(|l| l == line),
            "missing line `{line}` in:\n{text}"
        );
    }

    #[test]
    fn exposition_lists_every_metric_family() {
        let metrics = Metrics::new();
        metrics.record_http("GET", "/api/tasks/{id}", 200, Duration::from_millis(12));
        metrics.record_task("action", "succeeded");
        let gauges = GaugeSnapshot {
            longpoll_waiting: 2,
            workers_active: 3,
            db_pool: Some(DbPoolGauges {
                size: 5,
                idle: 3,
                in_use: 2,
            }),
        };
        let text = metrics.render(&gauges);
        for (family, kind) in [
            ("huginn_http_requests_total", "counter"),
            ("huginn_http_request_duration_seconds", "histogram"),
            ("huginn_longpoll_waiting", "gauge"),
            ("huginn_tasks_total", "counter"),
            ("huginn_workers_active", "gauge"),
            ("huginn_db_pool", "gauge"),
            ("huginn_build_info", "gauge"),
        ] {
            assert_line(&text, &format!("# TYPE {family} {kind}"));
        }
        assert_line(
            &text,
            &format!(
                "huginn_build_info{{version=\"{}\"}} 1",
                env!("CARGO_PKG_VERSION")
            ),
        );
        assert_line(&text, "huginn_longpoll_waiting 2");
        assert_line(&text, "huginn_workers_active 3");
        assert_line(&text, "huginn_db_pool{state=\"size\"} 5");
        assert_line(&text, "huginn_db_pool{state=\"idle\"} 3");
        assert_line(&text, "huginn_db_pool{state=\"in_use\"} 2");
    }

    #[test]
    fn without_a_pool_the_db_family_is_omitted() {
        let text = Metrics::new().render(&GaugeSnapshot::default());
        assert!(!text.contains("huginn_db_pool"));
    }

    #[test]
    fn label_values_are_escaped() {
        let metrics = Metrics::new();
        // `we"ird\ro<newline>ute` — quote, backslash and newline in one label.
        let route = "we\"ird\\ro\nute";
        metrics.record_http("GET", route, 200, Duration::from_millis(1));
        let text = metrics.render(&GaugeSnapshot::default());
        assert_line(
            &text,
            "huginn_http_requests_total{method=\"GET\",route=\"we\\\"ird\\\\ro\\nute\",status=\"200\"} 1",
        );
    }

    #[test]
    fn request_counters_increment_per_label_set() {
        let metrics = Metrics::new();
        metrics.record_http("GET", "/a", 200, Duration::from_millis(1));
        metrics.record_http("GET", "/a", 200, Duration::from_millis(1));
        metrics.record_http("GET", "/a", 500, Duration::from_millis(1));
        metrics.record_http("POST", "/a", 200, Duration::from_millis(1));
        let text = metrics.render(&GaugeSnapshot::default());
        assert_line(
            &text,
            "huginn_http_requests_total{method=\"GET\",route=\"/a\",status=\"200\"} 2",
        );
        assert_line(
            &text,
            "huginn_http_requests_total{method=\"GET\",route=\"/a\",status=\"500\"} 1",
        );
        assert_line(
            &text,
            "huginn_http_requests_total{method=\"POST\",route=\"/a\",status=\"200\"} 1",
        );
    }

    #[test]
    fn duration_buckets_are_cumulative() {
        let metrics = Metrics::new();
        metrics.record_http("GET", "/x", 200, Duration::from_millis(3));
        metrics.record_http("GET", "/x", 200, Duration::from_millis(300));
        metrics.record_http("GET", "/x", 200, Duration::from_millis(20_000));
        let text = metrics.render(&GaugeSnapshot::default());
        assert_line(
            &text,
            "huginn_http_request_duration_seconds_bucket{route=\"/x\",le=\"0.005\"} 1",
        );
        assert_line(
            &text,
            "huginn_http_request_duration_seconds_bucket{route=\"/x\",le=\"0.5\"} 2",
        );
        assert_line(
            &text,
            "huginn_http_request_duration_seconds_bucket{route=\"/x\",le=\"1\"} 2",
        );
        assert_line(
            &text,
            "huginn_http_request_duration_seconds_bucket{route=\"/x\",le=\"10\"} 2",
        );
        assert_line(
            &text,
            "huginn_http_request_duration_seconds_bucket{route=\"/x\",le=\"+Inf\"} 3",
        );
        assert_line(
            &text,
            "huginn_http_request_duration_seconds_count{route=\"/x\"} 3",
        );
        let sum: f64 = text
            .lines()
            .find_map(|l| l.strip_prefix("huginn_http_request_duration_seconds_sum{route=\"/x\"} "))
            .expect("sum line")
            .parse()
            .unwrap();
        assert!((sum - 20.303).abs() < 1e-9, "sum = {sum}");
    }

    #[test]
    fn task_counter_increments_per_type_and_status() {
        let metrics = Metrics::new();
        metrics.record_task("action", "succeeded");
        metrics.record_task("action", "succeeded");
        metrics.record_task("command", "failed");
        let text = metrics.render(&GaugeSnapshot::default());
        assert_line(
            &text,
            "huginn_tasks_total{type=\"action\",status=\"succeeded\"} 2",
        );
        assert_line(
            &text,
            "huginn_tasks_total{type=\"command\",status=\"failed\"} 1",
        );
    }

    #[tokio::test]
    async fn manual_gauge_fallbacks_are_reported() {
        let metrics = Metrics::new();
        metrics.set_longpoll_waiting(4);
        metrics.set_workers_active(7);
        let gauges = gather(&metrics, None, None, 90).await;
        assert_eq!(gauges.longpoll_waiting, 4);
        assert_eq!(gauges.workers_active, 7);
    }

    #[tokio::test]
    async fn longpoll_gauge_reads_the_event_bus() {
        let metrics = Metrics::new();
        let events = TaskEvents::new();
        let _a = events.subscribe_queue("vm-a");
        let _b = events.subscribe_queue("vm-b");
        let gauges = gather(&metrics, Some(&events), None, 90).await;
        assert_eq!(gauges.longpoll_waiting, 2, "two parked long-polls");
    }

    #[tokio::test]
    async fn db_pool_gauges_are_consistent() {
        let pool = crate::db::pool_options(3)
            .connect_lazy("postgres://huginn@localhost/huginn_test")
            .unwrap();
        let gauges = DbPoolGauges::from_pool(&pool);
        assert_eq!(gauges.size, gauges.idle + gauges.in_use);
        assert!(gauges.size <= 3);
    }

    #[tokio::test]
    async fn workers_gauge_counts_recent_heartbeats() {
        let Ok(url) = std::env::var("HUGINN_TEST_DATABASE_URL") else {
            eprintln!("skipped: HUGINN_TEST_DATABASE_URL not set");
            return;
        };
        let _guard = crate::db::LIVE_DB_GUARD.lock().await;
        let pool = crate::db::pool_options(2)
            .connect(&url)
            .await
            .expect("connect");
        crate::db::run_migrations(&pool).await.expect("migrations");
        sqlx::query("DELETE FROM vms")
            .execute(&pool)
            .await
            .expect("clear vms");
        let now = chrono::Utc::now();
        for (name, heartbeat) in [
            ("fresh", now - chrono::Duration::seconds(5)),
            ("stale", now - chrono::Duration::seconds(3600)),
        ] {
            let mut new =
                crate::models::vm::VmNew::new(name, crate::models::enums::WorkerArch::Amd64);
            new.state = crate::models::enums::VMState::Active;
            new.last_heartbeat_at = Some(heartbeat);
            crate::models::vm::create(&pool, new)
                .await
                .expect("insert vm");
        }
        // A VM whose heartbeat is too old, and a pending one, do not count.
        assert_eq!(count_recent_workers(&pool, 90).await.unwrap(), 1);
        let gauges = gather(&Metrics::new(), None, Some(&pool), 90).await;
        assert_eq!(gauges.workers_active, 1);
        let pool_gauges = gauges.db_pool.expect("pool gauges");
        assert_eq!(pool_gauges.size, pool_gauges.idle + pool_gauges.in_use);
    }
}
