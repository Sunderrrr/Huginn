//! Task/queue event services (port of `hub/app/core/task_events.py`).
//!
//! [`task_events`] is the in-process notifier that connects task creation,
//! result submission and the worker long-poll: waiters park on per-VM queue
//! wakes and per-task completion wakes instead of polling the database.
// Facade re-exports of the event bus (shared contract of routes/*).
#![allow(unused_imports)]
// The wake API is consumed by the routes/services layers landing later in the
// migration (sweepers, /tasks/{id}/wait); suppress dead-code noise in this
// self-contained module so `cargo clippy -- -D warnings` stays clean meanwhile.
#![allow(dead_code)]

pub mod task_events;

pub use task_events::{PendingQueueWakes, QueueWaiter, TaskEvents, TaskWaiter};
pub mod backup;
pub mod ldap;
pub mod metrics;
pub mod notifications;
pub mod oidc;
pub mod versioning;
pub mod webauthn;
