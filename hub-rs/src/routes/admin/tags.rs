//! `/api/tags` — port of `hub/app/api/routes/tags.py`.
//!
//! Reads are operator+; mutations are admin-only. Tag names are unique
//! (duplicate → 409 `a tag with that name already exists`), colors are
//! `#rrggbb` hex, and every mutation is audited (`tag_create`/`tag_update`/
//! `tag_delete`).

use axum::extract::{ConnectInfo, Extension, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use uuid::Uuid;

use super::{
    audit_record, authenticate, enforce_body_size, json_body, path_uuid, peer_addr, AdminState,
    RouteError,
};
use crate::models::tag::{Tag, TagPatch};

// ---------------------------------------------------------------------------
// Wire schemas (app/schemas/tag.py)
// ---------------------------------------------------------------------------

/// `TagCreate` — `name` 1..64 chars, `color` a `#rrggbb` hex literal.
#[derive(Debug, Clone, Deserialize)]
pub struct TagCreate {
    pub name: String,
    pub color: String,
}

/// `TagUpdate` — partial; `None`/absent leaves the column untouched.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct TagUpdate {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub color: Option<String>,
}

/// `TagOut`.
#[derive(Debug, Clone, Serialize)]
pub struct TagOut {
    pub id: Uuid,
    pub name: String,
    pub color: String,
    pub created_at: DateTime<Utc>,
}

impl From<&Tag> for TagOut {
    fn from(tag: &Tag) -> Self {
        Self {
            id: tag.id,
            name: tag.name.clone(),
            color: tag.color.clone(),
            created_at: tag.created_at,
        }
    }
}

/// `tag.py:schemas._HEX` — `^#[0-9a-fA-F]{6}$`.
fn check_color(color: &str) -> Result<(), RouteError> {
    let ok = color.len() == 7
        && color.starts_with('#')
        && color[1..].chars().all(|c| c.is_ascii_hexdigit());
    if ok {
        Ok(())
    } else {
        Err(RouteError::unprocessable_entity(
            "color must look like #rrggbb",
        ))
    }
}

fn check_name(name: &str) -> Result<(), RouteError> {
    if name.is_empty() {
        return Err(RouteError::unprocessable_entity(
            "name must be at least 1 character",
        ));
    }
    if name.chars().count() > 64 {
        return Err(RouteError::unprocessable_entity(
            "name must be at most 64 characters",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

/// The `/api/tags` router (prefix included).
pub fn routes() -> Router<AdminState> {
    Router::new()
        .route("/api/tags", get(list_tags))
        .route("/api/tags", post(create_tag))
        .route("/api/tags/{tag_id}", put(update_tag))
        .route("/api/tags/{tag_id}", delete(delete_tag))
}

/// `GET /api/tags` — operator+.
async fn list_tags(
    State(state): State<AdminState>,
    headers: HeaderMap,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
) -> Result<impl IntoResponse, RouteError> {
    enforce_body_size(&headers, state.global_body_cap())?;
    let caller = authenticate(&state, &headers, peer_addr(peer)).await?;
    caller.require_operator()?;
    let tags = state.store.list_tags().await?;
    Ok(Json(tags.iter().map(TagOut::from).collect::<Vec<_>>()))
}

/// `POST /api/tags` — admin only (201).
async fn create_tag(
    State(state): State<AdminState>,
    headers: HeaderMap,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    body: Result<Json<TagCreate>, axum::extract::rejection::JsonRejection>,
) -> Result<impl IntoResponse, RouteError> {
    enforce_body_size(&headers, state.global_body_cap())?;
    let caller = authenticate(&state, &headers, peer_addr(peer)).await?;
    caller.require_admin()?;
    let body = json_body(body)?;
    check_name(&body.name)?;
    check_color(&body.color)?;

    let tag = state.store.create_tag(&body.name, &body.color).await?;
    audit_record(
        &state,
        &caller,
        "tag_create",
        serde_json::json!({"name": tag.name, "color": tag.color}),
    )
    .await?;
    Ok((StatusCode::CREATED, Json(TagOut::from(&tag))))
}

/// `PUT /api/tags/{tag_id}` — admin only.
async fn update_tag(
    State(state): State<AdminState>,
    headers: HeaderMap,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    Path(tag_id): Path<String>,
    body: Result<Json<TagUpdate>, axum::extract::rejection::JsonRejection>,
) -> Result<impl IntoResponse, RouteError> {
    enforce_body_size(&headers, state.global_body_cap())?;
    let caller = authenticate(&state, &headers, peer_addr(peer)).await?;
    caller.require_admin()?;
    let tag_id = path_uuid(&tag_id, "tag id")?;
    let body = json_body(body)?;
    if let Some(name) = &body.name {
        check_name(name)?;
    }
    if let Some(color) = &body.color {
        check_color(color)?;
    }

    let tag = state.store.get_tag(tag_id).await?;
    if tag.is_none() {
        return Err(RouteError::not_found("tag not found"));
    }
    let tag = state
        .store
        .update_tag(
            tag_id,
            TagPatch {
                name: body.name.clone(),
                color: body.color.clone(),
            },
        )
        .await?;
    let Some(tag) = tag else {
        return Err(RouteError::not_found("tag not found"));
    };
    audit_record(
        &state,
        &caller,
        "tag_update",
        serde_json::json!({"tag_id": tag_id.to_string(), "name": tag.name}),
    )
    .await?;
    Ok(Json(TagOut::from(&tag)))
}

/// `DELETE /api/tags/{tag_id}` — admin only (204).
async fn delete_tag(
    State(state): State<AdminState>,
    headers: HeaderMap,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    Path(tag_id): Path<String>,
) -> Result<impl IntoResponse, RouteError> {
    enforce_body_size(&headers, state.global_body_cap())?;
    let caller = authenticate(&state, &headers, peer_addr(peer)).await?;
    caller.require_admin()?;
    let tag_id = path_uuid(&tag_id, "tag id")?;

    let tag = state.store.get_tag(tag_id).await?;
    let Some(tag) = tag else {
        return Err(RouteError::not_found("tag not found"));
    };
    state.store.delete_tag(tag_id).await?;
    audit_record(
        &state,
        &caller,
        "tag_delete",
        serde_json::json!({"tag_id": tag_id.to_string(), "name": tag.name}),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use serde_json::json;

    use super::super::router;
    use super::super::testing::*;
    use super::*;
    use crate::models::user::User;
    use crate::models::UserRole;

    fn setup() -> (Arc<MockStore>, AdminState, User) {
        let store = Arc::new(MockStore::default());
        let state = test_state(store.clone());
        let admin = seed_user(&store, make_user("admin", UserRole::Admin));
        (store, state, admin)
    }

    fn auth(state: &AdminState, user: &User) -> (&'static str, String) {
        ("authorization", format!("Bearer {}", bearer(state, user)))
    }

    #[tokio::test]
    async fn tag_lifecycle_create_list_update_delete() {
        let (store, state, admin) = setup();
        let cred = auth(&state, &admin);

        // Create → 201.
        let app = router(state.clone());
        let request = json_request_with(
            "POST",
            "/api/tags",
            json!({"name": "prod", "color": "#ff0000"}),
            std::slice::from_ref(&cred),
        );
        let response = tower::ServiceExt::oneshot(app, request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let created = body_json(response).await;
        assert_eq!(created["name"], json!("prod"));
        assert_eq!(created["color"], json!("#ff0000"));
        let tag_id = created["id"].as_str().unwrap().to_owned();

        // Duplicate name → 409 with the Python message.
        let app = router(state.clone());
        let request = json_request_with(
            "POST",
            "/api/tags",
            json!({"name": "prod", "color": "#00ff00"}),
            std::slice::from_ref(&cred),
        );
        let response = tower::ServiceExt::oneshot(app, request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert_eq!(
            body_json(response).await,
            json!({"detail": "a tag with that name already exists"})
        );

        // List (operator+) → the created tag.
        let app = router(state.clone());
        let request = json_request_with(
            "GET",
            "/api/tags",
            serde_json::Value::Null,
            std::slice::from_ref(&cred),
        );
        let response = tower::ServiceExt::oneshot(app, request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let listed = body_json(response).await;
        assert_eq!(listed.as_array().unwrap().len(), 1);
        assert_eq!(listed[0]["name"], json!("prod"));

        // Update.
        let app = router(state.clone());
        let request = json_request_with(
            "PUT",
            &format!("/api/tags/{tag_id}"),
            json!({"name": "prod-eu", "color": "#00ff00"}),
            std::slice::from_ref(&cred),
        );
        let response = tower::ServiceExt::oneshot(app, request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let updated = body_json(response).await;
        assert_eq!(updated["name"], json!("prod-eu"));
        assert_eq!(updated["color"], json!("#00ff00"));

        // Delete → 204, then 404.
        let app = router(state.clone());
        let request = json_request_with(
            "DELETE",
            &format!("/api/tags/{tag_id}"),
            serde_json::Value::Null,
            std::slice::from_ref(&cred),
        );
        let response = tower::ServiceExt::oneshot(app, request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let app = router(state.clone());
        let request = json_request_with(
            "DELETE",
            &format!("/api/tags/{tag_id}"),
            serde_json::Value::Null,
            std::slice::from_ref(&cred),
        );
        let response = tower::ServiceExt::oneshot(app, request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            body_json(response).await,
            json!({"detail": "tag not found"})
        );

        let db = store.db.lock().unwrap();
        let events: Vec<&str> = db.audit.iter().map(|e| e.event_type.as_str()).collect();
        assert_eq!(events, vec!["tag_create", "tag_update", "tag_delete"]);
    }

    #[tokio::test]
    async fn tag_validations_are_pydantic_style() {
        let (_store, state, admin) = setup();
        let cred = auth(&state, &admin);

        for (body, note) in [
            (json!({"name": "", "color": "#ff0000"}), "empty name"),
            (
                json!({"name": "x".repeat(65), "color": "#ff0000"}),
                "long name",
            ),
            (json!({"name": "ok", "color": "ff0000"}), "no hash"),
            (json!({"name": "ok", "color": "#ff000"}), "short hex"),
            (json!({"name": "ok", "color": "#gg0000"}), "non hex"),
        ] {
            let app = router(state.clone());
            let request = json_request_with("POST", "/api/tags", body, std::slice::from_ref(&cred));
            let response = tower::ServiceExt::oneshot(app, request).await.unwrap();
            assert_eq!(
                response.status(),
                StatusCode::UNPROCESSABLE_ENTITY,
                "{note}"
            );
        }
    }

    #[tokio::test]
    async fn tag_mutation_requires_admin_but_reads_are_operator_plus() {
        let (store, state, _admin) = setup();
        let operator = seed_user(&store, make_user("op", UserRole::Operator));
        let readonly = seed_user(&store, make_user("ro", UserRole::Readonly));

        // Read-only users cannot even list.
        let app = router(state.clone());
        let request = json_request_with(
            "GET",
            "/api/tags",
            serde_json::Value::Null,
            &[auth(&state, &readonly)],
        );
        let response = tower::ServiceExt::oneshot(app, request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            body_json(response).await,
            json!({"detail": "operator privileges required"})
        );

        // Operators may list…
        let app = router(state.clone());
        let request = json_request_with(
            "GET",
            "/api/tags",
            serde_json::Value::Null,
            &[auth(&state, &operator)],
        );
        let response = tower::ServiceExt::oneshot(app, request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // …but not create.
        let app = router(state.clone());
        let request = json_request_with(
            "POST",
            "/api/tags",
            json!({"name": "prod", "color": "#ff0000"}),
            &[auth(&state, &operator)],
        );
        let response = tower::ServiceExt::oneshot(app, request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            body_json(response).await,
            json!({"detail": "admin role required"})
        );
    }

    #[tokio::test]
    async fn unknown_tag_id_is_404() {
        let (_store, state, admin) = setup();
        let cred = auth(&state, &admin);
        for (method, body) in [
            ("PUT", json!({"name": "x", "color": "#ff0000"})),
            ("DELETE", serde_json::Value::Null),
        ] {
            let app = router(state.clone());
            let request = json_request_with(
                method,
                &format!("/api/tags/{}", Uuid::new_v4()),
                body,
                std::slice::from_ref(&cred),
            );
            let response = tower::ServiceExt::oneshot(app, request).await.unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{method}");
        }
    }

    #[tokio::test]
    async fn malformed_tag_id_is_422() {
        let (_store, state, admin) = setup();
        let app = router(state.clone());
        let request = json_request_with(
            "DELETE",
            "/api/tags/not-a-uuid",
            serde_json::Value::Null,
            &[auth(&state, &admin)],
        );
        let response = tower::ServiceExt::oneshot(app, request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }
}
