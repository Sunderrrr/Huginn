//! `/api/schedules` — port of `hub/app/api/routes/schedules.py` +
//! the CRUD half of `app/services/scheduled_commands.py`.
//!
//! A schedule is a recurring action/command definition: a cron expression plus
//! a target (`vm` / `tag` / `all_active`) and a task (`action` / `command`).
//! The response model carries `next_run_at`, computed exactly like
//! `scheduled_commands.next_run_at` — the next cron occurrence after
//! `last_run_at` (or `created_at`), evaluated in UTC — so the cron grammar of
//! `croniter` is ported here too ([`is_valid`], [`next_after`]).
//!
//! Validation mirrors `schemas/scheduled_command.py` (pydantic → 422) while
//! the service-layer `validate_action` re-check in `create` raises 400. The
//! update body is applied with `exclude_unset` semantics: a field the client
//! did not send is left untouched, and a field sent as `null` **clears** the
//! column (the "switch target kind" case).

use axum::extract::{ConnectInfo, Extension, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use uuid::Uuid;

use super::custom_actions::validate_action;
use super::{
    audit_record, authenticate, enforce_body_size, json_body, path_uuid, peer_addr, AdminState,
    RouteError,
};
use crate::models::scheduled_command::{ScheduledCommand, ScheduledCommandNew};

// ---------------------------------------------------------------------------
// Submodules — the cron engine
// ---------------------------------------------------------------------------

mod cron;

use self::cron::is_valid;
pub use self::cron::next_run_at;

// ---------------------------------------------------------------------------
// Wire schemas (app/schemas/scheduled_command.py)
// ---------------------------------------------------------------------------

/// Accept an explicitly-`null` field as "clear this column" while still
/// distinguishing it from a field the client did not send
/// (`model_dump(exclude_unset=True)`).
fn double_option<'de, T, D>(de: D) -> Result<Option<Option<T>>, D::Error>
where
    T: serde::Deserialize<'de>,
    D: serde::Deserializer<'de>,
{
    serde::Deserialize::deserialize(de).map(Some)
}

fn check_target_kind(value: &str) -> Result<(), RouteError> {
    match value {
        "vm" | "tag" | "all_active" => Ok(()),
        _ => Err(RouteError::unprocessable_entity(
            "target_kind must be one of: vm, tag, all_active",
        )),
    }
}

fn check_task_kind(value: &str) -> Result<(), RouteError> {
    match value {
        "action" | "command" => Ok(()),
        _ => Err(RouteError::unprocessable_entity(
            "task_kind must be one of: action, command",
        )),
    }
}

/// Cross-field rules of the `ScheduleCreate`/`ScheduleUpdate` model validators.
/// The `Option<Option<T>>` request fields are flattened first: Python's checks
/// fire on `is None`, so "not sent" and "sent as null" behave the same.
fn check_cross_fields(
    target_kind: Option<&str>,
    target_vm_id: Option<Uuid>,
    target_tag_id: Option<Uuid>,
    task_kind: Option<&str>,
    action_name: Option<&str>,
    command: Option<&str>,
) -> Result<(), RouteError> {
    if target_kind == Some("vm") && target_vm_id.is_none() {
        return Err(RouteError::unprocessable_entity(
            "target_vm_id required when target_kind=vm",
        ));
    }
    if target_kind == Some("tag") && target_tag_id.is_none() {
        return Err(RouteError::unprocessable_entity(
            "target_tag_id required when target_kind=tag",
        ));
    }
    if task_kind == Some("action") && action_name.unwrap_or_default().is_empty() {
        return Err(RouteError::unprocessable_entity(
            "action_name required when task_kind=action",
        ));
    }
    if task_kind == Some("command") && command.unwrap_or_default().is_empty() {
        return Err(RouteError::unprocessable_entity(
            "command required when task_kind=command",
        ));
    }
    Ok(())
}

/// `ScheduleCreate`.
#[derive(Debug, Clone, Deserialize)]
pub struct ScheduleCreate {
    pub name: String,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    pub target_kind: String,
    #[serde(default)]
    pub target_vm_id: Option<Uuid>,
    #[serde(default)]
    pub target_tag_id: Option<Uuid>,
    pub task_kind: String,
    #[serde(default)]
    pub action_name: Option<String>,
    #[serde(default)]
    pub params: BTreeMap<String, String>,
    #[serde(default)]
    pub command: Option<String>,
    pub cron_expression: String,
}

fn default_enabled() -> bool {
    true
}

impl ScheduleCreate {
    pub fn validate(&self) -> Result<(), RouteError> {
        check_len("name", &Some(self.name.as_str()), 1, 128)?;
        check_target_kind(&self.target_kind)?;
        check_task_kind(&self.task_kind)?;
        check_len("action_name", &self.action_name.as_deref(), 0, 64)?;
        check_len("command", &self.command.as_deref(), 0, 65_536)?;
        check_len(
            "cron_expression",
            &Some(self.cron_expression.as_str()),
            0,
            128,
        )?;
        if !is_valid(&self.cron_expression) {
            return Err(RouteError::unprocessable_entity("invalid cron expression"));
        }
        check_cross_fields(
            Some(&self.target_kind),
            self.target_vm_id,
            self.target_tag_id,
            Some(&self.task_kind),
            self.action_name.as_deref(),
            self.command.as_deref(),
        )
    }
}

/// `ScheduleUpdate` — unset fields are untouched, `null` clears nullable ones.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ScheduleUpdate {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub target_kind: Option<String>,
    #[serde(default, deserialize_with = "double_option")]
    pub target_vm_id: Option<Option<Uuid>>,
    #[serde(default, deserialize_with = "double_option")]
    pub target_tag_id: Option<Option<Uuid>>,
    #[serde(default)]
    pub task_kind: Option<String>,
    #[serde(default, deserialize_with = "double_option")]
    pub action_name: Option<Option<String>>,
    #[serde(default)]
    pub params: Option<BTreeMap<String, String>>,
    #[serde(default, deserialize_with = "double_option")]
    pub command: Option<Option<String>>,
    #[serde(default)]
    pub cron_expression: Option<String>,
}

impl ScheduleUpdate {
    pub fn validate(&self) -> Result<(), RouteError> {
        check_len("name", &self.name.as_deref(), 1, 128)?;
        if let Some(target_kind) = self.target_kind.as_deref() {
            check_target_kind(target_kind)?;
        }
        if let Some(task_kind) = self.task_kind.as_deref() {
            check_task_kind(task_kind)?;
        }
        let action_name = self.action_name.as_ref().and_then(|v| v.as_deref());
        let command = self.command.as_ref().and_then(|v| v.as_deref());
        check_len("action_name", &action_name, 0, 64)?;
        check_len("command", &command, 0, 65_536)?;
        if let Some(cron) = self.cron_expression.as_deref() {
            check_len("cron_expression", &Some(cron), 0, 128)?;
            if !is_valid(cron) {
                return Err(RouteError::unprocessable_entity("invalid cron expression"));
            }
        }
        check_cross_fields(
            self.target_kind.as_deref(),
            self.target_vm_id.flatten(),
            self.target_tag_id.flatten(),
            self.task_kind.as_deref(),
            action_name,
            command,
        )
    }

    /// The row patch implied by the fields the client actually sent
    /// (`model_dump(exclude_unset=True)`).
    pub fn patch(&self) -> SchedulePatch {
        SchedulePatch {
            name: self.name.clone(),
            enabled: self.enabled,
            target_kind: self.target_kind.clone(),
            target_vm_id: self.target_vm_id,
            target_tag_id: self.target_tag_id,
            task_kind: self.task_kind.clone(),
            action_name: self.action_name.clone(),
            params: self.params.as_ref().map(|p| serde_json::json!(p)),
            command: self.command.clone(),
            cron_expression: self.cron_expression.clone(),
        }
    }
}

/// Row patch with "explicitly cleared" semantics (see `ScheduleUpdate`).
#[derive(Debug, Clone, Default)]
pub struct SchedulePatch {
    pub name: Option<String>,
    pub enabled: Option<bool>,
    pub target_kind: Option<String>,
    /// `Some(None)` clears the column.
    pub target_vm_id: Option<Option<Uuid>>,
    pub target_tag_id: Option<Option<Uuid>>,
    pub task_kind: Option<String>,
    pub action_name: Option<Option<String>>,
    pub params: Option<serde_json::Value>,
    pub command: Option<Option<String>>,
    pub cron_expression: Option<String>,
}

/// `ScheduleOut`.
#[derive(Debug, Clone, Serialize)]
pub struct ScheduleOut {
    pub id: Uuid,
    pub name: String,
    pub enabled: bool,
    pub target_kind: String,
    pub target_vm_id: Option<Uuid>,
    pub target_tag_id: Option<Uuid>,
    pub task_kind: String,
    pub action_name: Option<String>,
    pub params: serde_json::Value,
    pub command: Option<String>,
    pub cron_expression: String,
    pub last_run_at: Option<DateTime<Utc>>,
    pub next_run_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl ScheduleOut {
    /// `schedules.py:_to_out` — validate the row, then compute `next_run_at`
    /// (a broken cron never breaks the listing: it falls back to `null`).
    fn from_row(sched: &ScheduledCommand) -> Self {
        Self {
            id: sched.id,
            name: sched.name.clone(),
            enabled: sched.enabled,
            target_kind: sched.target_kind.clone(),
            target_vm_id: sched.target_vm_id,
            target_tag_id: sched.target_tag_id,
            task_kind: sched.task_kind.clone(),
            action_name: sched.action_name.clone(),
            params: sched.params.clone(),
            command: sched.command.clone(),
            cron_expression: sched.cron_expression.clone(),
            last_run_at: sched.last_run_at,
            next_run_at: next_run_at(sched, None),
            created_at: sched.created_at,
        }
    }
}

/// Field-bound helper (pydantic `min_length`/`max_length`).
fn check_len(field: &str, value: &Option<&str>, min: usize, max: usize) -> Result<(), RouteError> {
    let Some(value) = value else {
        return Ok(());
    };
    let len = value.chars().count();
    if len < min {
        return Err(RouteError::unprocessable_entity(format!(
            "{field} must be at least {min} character(s)"
        )));
    }
    if len > max {
        return Err(RouteError::unprocessable_entity(format!(
            "{field} must be at most {max} characters"
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

/// The `/api/schedules` router (prefix included).
pub fn routes() -> Router<AdminState> {
    Router::new()
        .route("/api/schedules", get(list_schedules))
        .route("/api/schedules", post(create_schedule))
        .route("/api/schedules/{schedule_id}", put(update_schedule))
        .route("/api/schedules/{schedule_id}", delete(delete_schedule))
}

/// `GET /api/schedules` — admin only.
async fn list_schedules(
    State(state): State<AdminState>,
    headers: HeaderMap,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
) -> Result<impl IntoResponse, RouteError> {
    enforce_body_size(&headers, state.global_body_cap())?;
    let caller = authenticate(&state, &headers, peer_addr(peer)).await?;
    caller.require_admin()?;
    let rows = state.store.list_schedules().await?;
    Ok(Json(
        rows.iter().map(ScheduleOut::from_row).collect::<Vec<_>>(),
    ))
}

/// `POST /api/schedules` — admin only (201).
async fn create_schedule(
    State(state): State<AdminState>,
    headers: HeaderMap,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    body: Result<Json<ScheduleCreate>, axum::extract::rejection::JsonRejection>,
) -> Result<impl IntoResponse, RouteError> {
    enforce_body_size(&headers, state.global_body_cap())?;
    let caller = authenticate(&state, &headers, peer_addr(peer)).await?;
    caller.require_admin()?;
    let body = json_body(body)?;
    body.validate()?;

    // Defensive: validate the action again at persistence time (the service
    // raises ValueError → 400).
    if body.task_kind == "action" {
        validate_action(
            body.action_name.as_deref().unwrap_or_default(),
            &body.params,
        )
        .map_err(RouteError::bad_request)?;
    }

    let created_by = caller.principal.user.as_ref().map(|u| u.id);
    let sched = state
        .store
        .create_schedule(ScheduledCommandNew {
            name: body.name.clone(),
            enabled: body.enabled,
            target_kind: body.target_kind.clone(),
            target_vm_id: body.target_vm_id,
            target_tag_id: body.target_tag_id,
            task_kind: body.task_kind.clone(),
            action_name: body.action_name.clone(),
            params: serde_json::json!(body.params),
            command: body.command.clone(),
            cron_expression: body.cron_expression.clone(),
            created_by,
        })
        .await?;
    audit_record(
        &state,
        &caller,
        "schedule_create",
        serde_json::json!({"name": sched.name, "cron": sched.cron_expression}),
    )
    .await?;
    Ok((StatusCode::CREATED, Json(ScheduleOut::from_row(&sched))))
}

/// `PUT /api/schedules/{schedule_id}` — admin only.
async fn update_schedule(
    State(state): State<AdminState>,
    headers: HeaderMap,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    Path(schedule_id): Path<String>,
    body: Result<Json<ScheduleUpdate>, axum::extract::rejection::JsonRejection>,
) -> Result<impl IntoResponse, RouteError> {
    enforce_body_size(&headers, state.global_body_cap())?;
    let caller = authenticate(&state, &headers, peer_addr(peer)).await?;
    caller.require_admin()?;
    let schedule_id = path_uuid(&schedule_id, "schedule id")?;
    let body = json_body(body)?;
    body.validate()?;

    if state.store.get_schedule(schedule_id).await?.is_none() {
        return Err(RouteError::not_found("schedule not found"));
    }
    // `exclude_unset` so a PATCH-like edit only touches the fields the client
    // sent (and can explicitly clear target ids by sending null).
    let sched = state
        .store
        .update_schedule(schedule_id, body.patch())
        .await?;
    let Some(sched) = sched else {
        return Err(RouteError::not_found("schedule not found"));
    };
    audit_record(
        &state,
        &caller,
        "schedule_update",
        serde_json::json!({"schedule_id": schedule_id.to_string()}),
    )
    .await?;
    Ok(Json(ScheduleOut::from_row(&sched)))
}

/// `DELETE /api/schedules/{schedule_id}` — admin only (204).
async fn delete_schedule(
    State(state): State<AdminState>,
    headers: HeaderMap,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    Path(schedule_id): Path<String>,
) -> Result<impl IntoResponse, RouteError> {
    enforce_body_size(&headers, state.global_body_cap())?;
    let caller = authenticate(&state, &headers, peer_addr(peer)).await?;
    caller.require_admin()?;
    let schedule_id = path_uuid(&schedule_id, "schedule id")?;

    let sched = state.store.get_schedule(schedule_id).await?;
    let Some(sched) = sched else {
        return Err(RouteError::not_found("schedule not found"));
    };
    state.store.delete_schedule(schedule_id).await?;
    audit_record(
        &state,
        &caller,
        "schedule_delete",
        serde_json::json!({"schedule_id": schedule_id.to_string(), "name": sched.name}),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
pub(crate) mod testing {
    use super::super::testing::*;
    use super::*;
    use std::sync::Arc;

    use chrono::{DateTime, NaiveDate, TimeZone, Utc};

    use crate::models::user::User;
    use crate::models::UserRole;

    pub(crate) fn setup() -> (Arc<MockStore>, AdminState, User) {
        let store = Arc::new(MockStore::default());
        let state = test_state(store.clone());
        let admin = seed_user(&store, make_user("admin", UserRole::Admin));
        (store, state, admin)
    }

    pub(crate) fn auth(state: &AdminState, user: &User) -> (&'static str, String) {
        ("authorization", format!("Bearer {}", bearer(state, user)))
    }

    pub(crate) fn at(y: i32, mo: u32, d: u32, h: u32, mi: u32) -> DateTime<Utc> {
        Utc.from_utc_datetime(
            &NaiveDate::from_ymd_opt(y, mo, d)
                .unwrap()
                .and_hms_opt(h, mi, 0)
                .unwrap(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::super::router;
    use super::super::testing::*;
    use super::testing::*;
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn schedule_lifecycle_and_next_run_at() {
        let (store, state, admin) = setup();
        let cred = auth(&state, &admin);
        let app = router(state.clone());
        let request = json_request_with(
            "POST",
            "/api/schedules",
            json!({
                "name": "nightly",
                "target_kind": "all_active",
                "task_kind": "command",
                "command": "systemctl restart nginx",
                "cron_expression": "0 3 * * *"
            }),
            std::slice::from_ref(&cred),
        );
        let response = tower::ServiceExt::oneshot(app, request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let created = body_json(response).await;
        assert_eq!(created["enabled"], json!(true), "enabled defaults to true");
        assert_eq!(created["target_kind"], json!("all_active"));
        assert_eq!(created["params"], json!({}));
        assert!(created["next_run_at"].is_string());
        assert!(created["last_run_at"].is_null());
        let id = created["id"].as_str().unwrap().to_owned();

        // List.
        let app = router(state.clone());
        let request = json_request_with(
            "GET",
            "/api/schedules",
            serde_json::Value::Null,
            std::slice::from_ref(&cred),
        );
        let response = tower::ServiceExt::oneshot(app, request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_json(response).await.as_array().unwrap().len(), 1);

        // Partial update (only `enabled` sent): everything else preserved.
        let app = router(state.clone());
        let request = json_request_with(
            "PUT",
            &format!("/api/schedules/{id}"),
            json!({"enabled": false}),
            std::slice::from_ref(&cred),
        );
        let response = tower::ServiceExt::oneshot(app, request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let updated = body_json(response).await;
        assert_eq!(updated["enabled"], json!(false));
        assert_eq!(updated["name"], json!("nightly"));
        assert_eq!(updated["command"], json!("systemctl restart nginx"));

        // Delete → 204 then 404.
        let app = router(state.clone());
        let request = json_request_with(
            "DELETE",
            &format!("/api/schedules/{id}"),
            serde_json::Value::Null,
            std::slice::from_ref(&cred),
        );
        let response = tower::ServiceExt::oneshot(app, request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let app = router(state.clone());
        let request = json_request_with(
            "DELETE",
            &format!("/api/schedules/{id}"),
            serde_json::Value::Null,
            std::slice::from_ref(&cred),
        );
        let response = tower::ServiceExt::oneshot(app, request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            body_json(response).await,
            json!({"detail": "schedule not found"})
        );

        let db = store.db.lock().unwrap();
        let events: Vec<&str> = db.audit.iter().map(|e| e.event_type.as_str()).collect();
        assert_eq!(
            events,
            vec!["schedule_create", "schedule_update", "schedule_delete"]
        );
    }

    #[tokio::test]
    async fn schedule_schema_validations_are_422() {
        let (_store, state, admin) = setup();
        let cred = auth(&state, &admin);
        let base = json!({
            "name": "nightly",
            "target_kind": "all_active",
            "task_kind": "command",
            "command": "uptime",
            "cron_expression": "0 3 * * *"
        });

        for (patch, detail) in [
            (
                json!({"cron_expression": "not a cron"}),
                "invalid cron expression",
            ),
            (
                json!({"target_kind": "vm", "target_vm_id": null}),
                "target_vm_id required when target_kind=vm",
            ),
            (
                json!({"target_kind": "tag", "target_tag_id": null}),
                "target_tag_id required when target_kind=tag",
            ),
            (
                json!({"task_kind": "action", "action_name": null}),
                "action_name required when task_kind=action",
            ),
            (
                json!({"task_kind": "command", "command": null}),
                "command required when task_kind=command",
            ),
        ] {
            let mut body = base.clone();
            let obj = body.as_object_mut().unwrap();
            for (k, v) in patch.as_object().unwrap() {
                if v.is_null() {
                    obj.remove(k);
                } else {
                    obj.insert(k.clone(), v.clone());
                }
            }
            let app = router(state.clone());
            let request =
                json_request_with("POST", "/api/schedules", body, std::slice::from_ref(&cred));
            let response = tower::ServiceExt::oneshot(app, request).await.unwrap();
            assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
            assert_eq!(body_json(response).await, json!({"detail": detail}));
        }

        // Unknown action name is a service-layer error → 400.
        let mut body = base.clone();
        let obj = body.as_object_mut().unwrap();
        obj.insert("task_kind".into(), json!("action"));
        obj.insert("action_name".into(), json!("reboot"));
        obj.remove("command");
        let app = router(state.clone());
        let request =
            json_request_with("POST", "/api/schedules", body, std::slice::from_ref(&cred));
        let response = tower::ServiceExt::oneshot(app, request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            body_json(response).await,
            json!({"detail": "unknown action: 'reboot'"})
        );
    }

    #[tokio::test]
    async fn update_clears_nullable_columns_with_explicit_null() {
        let (store, state, admin) = setup();
        let cred = auth(&state, &admin);

        let app = router(state.clone());
        let request = json_request_with(
            "POST",
            "/api/schedules",
            json!({
                "name": "per-vm",
                "target_kind": "vm",
                "target_vm_id": Uuid::new_v4(),
                "task_kind": "command",
                "command": "uptime",
                "cron_expression": "0 3 * * *"
            }),
            std::slice::from_ref(&cred),
        );
        let response = tower::ServiceExt::oneshot(app, request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let id = body_json(response).await["id"].as_str().unwrap().to_owned();

        // Switching kind: `target_vm_id: null` must clear the column.
        let app = router(state.clone());
        let request = json_request_with(
            "PUT",
            &format!("/api/schedules/{id}"),
            json!({"target_kind": "all_active", "target_vm_id": null}),
            std::slice::from_ref(&cred),
        );
        let response = tower::ServiceExt::oneshot(app, request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let updated = body_json(response).await;
        assert_eq!(updated["target_kind"], json!("all_active"));
        assert!(updated["target_vm_id"].is_null());
        assert_eq!(updated["command"], json!("uptime"), "untouched field");
        let _ = store;
    }
}
