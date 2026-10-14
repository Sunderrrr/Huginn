//! HTTP routes of the hub API (port of `hub/app/api/routes/`).
//!
//! [`worker`] is the worker-facing API (`/api/worker`): enrollment, heartbeat,
//! the event-driven task long-poll and result submission.

// The route API is consumed by the app assembly (`main.py` port) landing later
// in the migration; suppress dead-code noise in this self-contained module so
// `cargo clippy -- -D warnings` stays clean in the meantime.
#![allow(dead_code)]

pub mod worker;
