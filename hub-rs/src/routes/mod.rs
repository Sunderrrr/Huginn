//! HTTP routes of the hub API (port of `hub/app/api/routes/`).
//!
//! [`worker`] is the worker-facing API (`/api/worker`): enrollment, heartbeat,
//! the event-driven task long-poll and result submission.
//!
//! [`admin`] is the administration CRUD API (`/api/settings`, `/api/mcp`,
//! `/api/tags`, `/api/schedules`, `/api/actions`, `/api/enrollment-tokens`).
//!
//! [`fleet`] is the fleet/execution/task/audit/event API (`/api/vms`,
//! `/api/tasks`, `/api/audit`, `/api/events`).

// The route API is consumed by the app assembly (`main.py` port) landing later
// in the migration; suppress dead-code noise in this self-contained module so
// `cargo clippy -- -D warnings` stays clean in the meantime.
#![allow(dead_code)]

pub mod admin;
pub mod authapi;
pub mod fleet;
pub mod worker;
