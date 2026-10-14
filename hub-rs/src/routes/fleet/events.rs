//! Server-Sent Events stream for the dashboard's live updates
//! (`app/api/routes/events.py` + `app/core/events.py`).
//!
//! Connected dashboards receive tiny hints (`{"type": "tasks"}` /
//! `{"type": "vms"}`) and invalidate the matching query cache, so the UI
//! refreshes the instant something changes instead of waiting for its periodic
//! poll. The stream is authenticated like every other route (`Authorization:
//! Bearer` — the dashboard reads it via fetch, not EventSource, so no token
//! ever appears in a URL or access log) and never touches the database.
//!
//! The in-process bus is a `tokio::sync::broadcast` channel: it fans events out
//! to every connected dashboard and drops the oldest hints for a slow consumer
//! (the client's fallback poll covers the gap) — the same bounded-queue
//! behaviour as the Python `asyncio.Queue(maxsize=100)` bus. Single-process
//! only: with multiple hub replicas a browser connected to one replica won't
//! see events published on another; the dashboard keeps its periodic refetch as
//! a fallback, so this degrades to polling rather than breaking.

use std::convert::Infallible;
use std::pin::Pin;
use std::sync::OnceLock;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::header::{HeaderName, HeaderValue, CACHE_CONTROL, CONTENT_TYPE};
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use tokio::sync::{broadcast, mpsc};
use tokio_stream::Stream;

use super::{authenticate, client_ip, peer_addr, FleetState, Peer, RouteError};

/// One dashboard hint (`{"type": "tasks"}`), as published by the mutation points.
pub type Event = serde_json::Value;

/// Bounded so a slow/stalled consumer can't grow memory without limit
/// (`events._QUEUE_MAXSIZE`).
pub const QUEUE_MAXSIZE: usize = 100;

/// Send a keepalive comment when the stream has been idle this long
/// (`events_stream._KEEPALIVE_SECONDS`).
pub const KEEPALIVE_SECONDS: f64 = 20.0;

/// In-process pub/sub for the dashboard's live event stream.
#[derive(Debug)]
pub struct EventBus {
    tx: broadcast::Sender<Event>,
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new_default()
    }
}

impl EventBus {
    /// A bus whose per-subscriber backlog is `capacity` hints deep.
    pub fn new(capacity: usize) -> Self {
        let (tx, _) = broadcast::channel(capacity.max(1));
        Self { tx }
    }

    /// The production bus (`_QUEUE_MAXSIZE` deep).
    pub fn new_default() -> Self {
        Self::new(QUEUE_MAXSIZE)
    }

    /// Register a subscriber; drop the receiver to unsubscribe.
    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.tx.subscribe()
    }

    /// Fan an event out to all connected dashboards (non-blocking).
    pub fn publish(&self, event: Event) {
        // No receiver is the normal state when no dashboard is connected.
        let _ = self.tx.send(event);
    }

    /// Publish a `{"type": <kind>}` hint (`events.publish({"type": "tasks"})`).
    pub fn publish_hint(&self, kind: &str) {
        self.publish(serde_json::json!({ "type": kind }));
    }

    /// Live subscriber count (tests and diagnostics only).
    pub fn receiver_count(&self) -> usize {
        self.tx.receiver_count()
    }
}

/// The process-wide bus, for mutation points outside the route layer.
pub fn global() -> &'static EventBus {
    static GLOBAL: OnceLock<EventBus> = OnceLock::new();
    GLOBAL.get_or_init(EventBus::new_default)
}

// ---------------------------------------------------------------------------
// SSE framing
// ---------------------------------------------------------------------------

/// The frame sent on connect (`gen()` yields `": connected\n\n"` first).
pub fn connected_frame() -> Bytes {
    Bytes::from_static(b": connected\n\n")
}

/// The frame carrying one hint (`f"data: {json.dumps(event)}\n\n"`).
pub fn data_frame(event: &Event) -> Bytes {
    Bytes::from(format!("data: {}\n\n", py_json_dumps(event)))
}

/// `json.dumps(event)` — Python's default separators (`", "` / `": "`), so the
/// hints the hub publishes (`{"type": "tasks"}`) are byte-identical to the
/// Python stream. Object keys render in map order; the hub's hints are
/// single-key, so this never diverges in practice.
fn py_json_dumps(value: &Event) -> String {
    let mut out = String::new();
    write_py_json(value, &mut out);
    out
}

fn write_py_json(value: &Event, out: &mut String) {
    match value {
        serde_json::Value::Null => out.push_str("null"),
        serde_json::Value::Bool(true) => out.push_str("true"),
        serde_json::Value::Bool(false) => out.push_str("false"),
        serde_json::Value::Number(n) => out.push_str(&n.to_string()),
        serde_json::Value::String(s) => out.push_str(&serde_json::to_string(s).unwrap_or_default()),
        serde_json::Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                write_py_json(item, out);
            }
            out.push(']');
        }
        serde_json::Value::Object(map) => {
            out.push('{');
            for (i, (key, item)) in map.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                out.push_str(&serde_json::to_string(key).unwrap_or_default());
                out.push_str(": ");
                write_py_json(item, out);
            }
            out.push('}');
        }
    }
}

/// The idle comment that keeps the connection (and proxies) warm.
pub fn keepalive_frame() -> Bytes {
    Bytes::from_static(b": keepalive\n\n")
}

/// The `text/event-stream` body of `/api/events`.
///
/// A spawned pump turns the broadcast subscription into frames, so the body is
/// a plain stream of ready chunks: it ends (and unsubscribes) as soon as the
/// client disconnects and the channel closes.
pub struct SseStream {
    rx: mpsc::Receiver<Bytes>,
}

impl SseStream {
    /// Subscribe to `bus` and start pumping frames every `keepalive` idle.
    pub fn start(bus: &EventBus, keepalive: Duration) -> Self {
        let (tx, rx) = mpsc::channel(8);
        let mut subscription = bus.subscribe();
        tokio::spawn(async move {
            if tx.send(connected_frame()).await.is_err() {
                return;
            }
            loop {
                tokio::select! {
                    event = subscription.recv() => match event {
                        Ok(event) => {
                            if tx.send(data_frame(&event)).await.is_err() {
                                break;
                            }
                        }
                        // A slow consumer loses the oldest hints; its fallback
                        // poll covers the gap.
                        Err(broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(broadcast::error::RecvError::Closed) => break,
                    },
                    _ = tokio::time::sleep(keepalive) => {
                        if tx.send(keepalive_frame()).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });
        Self { rx }
    }
}

impl Stream for SseStream {
    type Item = Result<Bytes, Infallible>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.rx.poll_recv(cx).map(|chunk| chunk.map(Ok))
    }
}

// ---------------------------------------------------------------------------
// Route
// ---------------------------------------------------------------------------

/// The `/api/events` router (`app/api/routes/events.py`).
pub fn router(state: FleetState) -> Router {
    Router::new()
        .route("/api/events", get(events_stream))
        .with_state(state)
}

async fn events_stream(
    State(state): State<FleetState>,
    headers: HeaderMap,
    peer: Peer,
) -> Result<impl IntoResponse, RouteError> {
    let ip = client_ip(&headers, &state.config, peer_addr(peer));
    // Authenticated via the Authorization header, like every other route.
    let _principal = authenticate(&state, &headers, ip.as_deref()).await?;

    let stream = SseStream::start(&state.bus, Duration::from_secs_f64(KEEPALIVE_SECONDS));
    let mut response_headers = HeaderMap::new();
    response_headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/event-stream; charset=utf-8"),
    );
    response_headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    response_headers.insert(
        HeaderName::from_static("x-accel-buffering"),
        HeaderValue::from_static("no"),
    );
    Ok((response_headers, Body::from_stream(stream)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_stream::StreamExt;

    async fn next_frame(stream: &mut SseStream) -> String {
        let chunk = stream
            .next()
            .await
            .expect("stream ended")
            .expect("infallible");
        String::from_utf8(chunk.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn stream_opens_with_the_connected_comment() {
        let bus = EventBus::new_default();
        let mut stream = SseStream::start(&bus, Duration::from_secs(60));
        assert_eq!(next_frame(&mut stream).await, ": connected\n\n");
    }

    #[tokio::test]
    async fn hints_reach_every_subscriber() {
        let bus = EventBus::new_default();
        let mut one = SseStream::start(&bus, Duration::from_secs(60));
        let mut two = SseStream::start(&bus, Duration::from_secs(60));
        next_frame(&mut one).await;
        next_frame(&mut two).await;

        bus.publish_hint("tasks");
        assert_eq!(
            next_frame(&mut one).await,
            "data: {\"type\": \"tasks\"}\n\n"
        );
        assert_eq!(
            next_frame(&mut two).await,
            "data: {\"type\": \"tasks\"}\n\n"
        );

        bus.publish(serde_json::json!({"type": "vms", "n": 1}));
        assert_eq!(
            next_frame(&mut one).await,
            "data: {\"n\": 1, \"type\": \"vms\"}\n\n",
            "json.dumps separators; keys render in map order"
        );
    }

    #[tokio::test]
    async fn idle_streams_get_keepalives() {
        let bus = EventBus::new_default();
        let mut stream = SseStream::start(&bus, Duration::from_millis(20));
        next_frame(&mut stream).await;
        assert_eq!(next_frame(&mut stream).await, ": keepalive\n\n");
    }

    #[tokio::test]
    async fn slow_consumers_lose_the_oldest_hints_and_keep_the_newest() {
        let bus = EventBus::new(2);
        let mut stream = SseStream::start(&bus, Duration::from_secs(60));
        next_frame(&mut stream).await;

        // Fill far past capacity before the consumer polls: the backlog is
        // dropped oldest-first, the newest hint always survives.
        for i in 0..(QUEUE_MAXSIZE as u64 + 5) {
            bus.publish(serde_json::json!({"type": "tasks", "n": i}));
        }
        let mut seen = Vec::new();
        while let Ok(frame) =
            tokio::time::timeout(Duration::from_millis(100), next_frame(&mut stream)).await
        {
            seen.push(frame);
        }
        assert!(
            seen.iter()
                .any(|f| f.contains(&format!("\"n\": {}", QUEUE_MAXSIZE as u64 + 4))),
            "the most recent hint is retained: {seen:?}"
        );
    }

    #[tokio::test]
    async fn stream_ends_when_the_bus_shuts_down() {
        let bus = EventBus::new_default();
        let mut stream = SseStream::start(&bus, Duration::from_secs(60));
        next_frame(&mut stream).await;
        drop(bus);
        assert!(stream.next().await.is_none(), "closed bus ends the stream");
    }

    #[test]
    fn data_lines_use_python_json_dumps_separators() {
        assert_eq!(
            py_json_dumps(&serde_json::json!({"type": "tasks"})),
            "{\"type\": \"tasks\"}"
        );
        assert_eq!(
            py_json_dumps(&serde_json::json!([1, "a", true, null, {"k": 2}])),
            "[1, \"a\", true, null, {\"k\": 2}]"
        );
    }

    #[tokio::test]
    async fn events_requires_authentication() {
        use tower::ServiceExt;
        let pool = crate::db::pool_options(1)
            .connect_lazy("postgres://huginn@localhost/huginn_test")
            .unwrap();
        let app = router(FleetState::new(pool, crate::config::Config::default()));
        let request = axum::http::Request::builder()
            .uri("/api/events")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
    }
}
