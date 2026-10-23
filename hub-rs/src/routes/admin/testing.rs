use super::schedules::SchedulePatch;
use super::store::{AdminStore, StoreFuture};
use super::*;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::response::Response;

use chrono::{DateTime, Utc};

use crate::security::SecurityConfig;

use crate::db::DbError;
use crate::models::audit::AuditNew;
use crate::models::custom_action::{CustomAction, CustomActionNew, CustomActionPatch};
use crate::models::enrollment::{EnrollmentToken, EnrollmentTokenNew};
use crate::models::mcp_token::{McpToken, McpTokenNew};
use crate::models::scheduled_command::{ScheduledCommand, ScheduledCommandNew};
use crate::models::setting::{Setting, SettingValues};
use crate::models::tag::{Tag, TagPatch};
use crate::models::user::User;
use crate::models::UserRole;

/// In-memory [`AdminStore`] for route tests.
#[derive(Default)]
pub struct MockStore {
    pub db: Mutex<MockDb>,
}

/// The rows a mock store keeps. Tests read/write these directly.
#[derive(Default)]
pub struct MockDb {
    pub users: HashMap<Uuid, User>,
    pub settings: Option<Setting>,
    pub mcp_tokens: HashMap<Uuid, McpToken>,
    pub tags: HashMap<Uuid, Tag>,
    pub schedules: HashMap<Uuid, ScheduledCommand>,
    pub actions: HashMap<Uuid, CustomAction>,
    pub action_tags: HashMap<Uuid, Vec<Uuid>>,
    pub enrollment_tokens: HashMap<Uuid, EnrollmentToken>,
    pub audit: Vec<AuditNew>,
}

impl MockDb {
    /// Tags sorted by name (parity with `services.tags.list_tags`).
    pub fn tags_by_name(&self) -> Vec<Tag> {
        let mut tags: Vec<Tag> = self.tags.values().cloned().collect();
        tags.sort_by(|a, b| a.name.cmp(&b.name));
        tags
    }

    /// MCP tokens of one user, oldest first (parity with `list_for_user`).
    pub fn mcp_tokens_of(&self, user_id: Uuid) -> Vec<McpToken> {
        let mut tokens: Vec<McpToken> = self
            .mcp_tokens
            .values()
            .filter(|t| t.user_id == user_id && t.revoked_at.is_none())
            .cloned()
            .collect();
        tokens.sort_by_key(|t| t.created_at);
        tokens
    }

    /// Schedules, newest first (parity with `list_schedules`).
    pub fn schedules_newest_first(&self) -> Vec<ScheduledCommand> {
        let mut rows: Vec<ScheduledCommand> = self.schedules.values().cloned().collect();
        rows.sort_by_key(|a| std::cmp::Reverse(a.created_at));
        rows
    }

    /// Custom actions sorted by name (parity with `list_all`).
    pub fn actions_by_name(&self) -> Vec<CustomAction> {
        let mut rows: Vec<CustomAction> = self.actions.values().cloned().collect();
        rows.sort_by(|a, b| a.name.cmp(&b.name));
        rows
    }

    /// Enrollment tokens, newest first (parity with `list_tokens`).
    pub fn enrollment_newest_first(&self) -> Vec<EnrollmentToken> {
        let mut rows: Vec<EnrollmentToken> = self.enrollment_tokens.values().cloned().collect();
        rows.sort_by_key(|a| std::cmp::Reverse(a.created_at));
        rows
    }
}

impl AdminStore for MockStore {
    fn get_user(&self, id: Uuid) -> StoreFuture<'_, Result<Option<User>, DbError>> {
        Box::pin(async move { Ok(self.db.lock().unwrap().users.get(&id).cloned()) })
    }

    fn get_settings(&self) -> StoreFuture<'_, Result<Option<Setting>, DbError>> {
        Box::pin(async move { Ok(self.db.lock().unwrap().settings.clone()) })
    }

    fn save_settings(&self, values: SettingValues) -> StoreFuture<'_, Result<Setting, DbError>> {
        Box::pin(async move {
            let mut db = self.db.lock().unwrap();
            let row = settings::setting_row(values, Utc::now());
            db.settings = Some(row.clone());
            Ok(row)
        })
    }

    fn list_mcp_tokens(&self, user_id: Uuid) -> StoreFuture<'_, Result<Vec<McpToken>, DbError>> {
        Box::pin(async move { Ok(self.db.lock().unwrap().mcp_tokens_of(user_id)) })
    }

    fn create_mcp_token(&self, new: McpTokenNew) -> StoreFuture<'_, Result<McpToken, DbError>> {
        Box::pin(async move {
            let mut db = self.db.lock().unwrap();
            let now = Utc::now();
            let token = McpToken {
                id: Uuid::new_v4(),
                user_id: new.user_id,
                token_hash: new.token_hash,
                name: new.name,
                allowed_ip: new.allowed_ip,
                last_used_at: None,
                revoked_at: None,
                created_at: now,
                updated_at: now,
            };
            db.mcp_tokens.insert(token.id, token.clone());
            Ok(token)
        })
    }

    fn set_mcp_allowed_ip(
        &self,
        token_id: Uuid,
        user_id: Uuid,
        allowed_ip: Option<String>,
    ) -> StoreFuture<'_, Result<Option<McpToken>, DbError>> {
        Box::pin(async move {
            let mut db = self.db.lock().unwrap();
            let now = Utc::now();
            let Some(token) = db.mcp_tokens.get_mut(&token_id) else {
                return Ok(None);
            };
            if token.user_id != user_id || token.revoked_at.is_some() {
                return Ok(None);
            }
            token.allowed_ip = allowed_ip;
            token.updated_at = now;
            Ok(Some(token.clone()))
        })
    }

    fn revoke_mcp_token(
        &self,
        token_id: Uuid,
        user_id: Uuid,
    ) -> StoreFuture<'_, Result<bool, DbError>> {
        Box::pin(async move {
            let mut db = self.db.lock().unwrap();
            let now = Utc::now();
            let Some(token) = db.mcp_tokens.get_mut(&token_id) else {
                return Ok(false);
            };
            if token.user_id != user_id || token.revoked_at.is_some() {
                return Ok(false);
            }
            token.revoked_at = Some(now);
            token.updated_at = now;
            Ok(true)
        })
    }

    fn active_mcp_token_by_hash(
        &self,
        token_hash: &str,
    ) -> StoreFuture<'_, Result<Option<McpToken>, DbError>> {
        // Owned copy so the future only borrows `self` (the trait's `'_`).
        let token_hash = token_hash.to_owned();
        Box::pin(async move {
            Ok(self
                .db
                .lock()
                .unwrap()
                .mcp_tokens
                .values()
                .find(|t| t.token_hash == token_hash && t.revoked_at.is_none())
                .cloned())
        })
    }

    fn touch_mcp_token(
        &self,
        token_id: Uuid,
        at: DateTime<Utc>,
    ) -> StoreFuture<'_, Result<(), DbError>> {
        Box::pin(async move {
            let mut db = self.db.lock().unwrap();
            if let Some(token) = db.mcp_tokens.get_mut(&token_id) {
                token.last_used_at = Some(at);
                token.updated_at = at;
            }
            Ok(())
        })
    }

    fn list_tags(&self) -> StoreFuture<'_, Result<Vec<Tag>, DbError>> {
        Box::pin(async move { Ok(self.db.lock().unwrap().tags_by_name()) })
    }

    fn get_tag(&self, tag_id: Uuid) -> StoreFuture<'_, Result<Option<Tag>, DbError>> {
        Box::pin(async move { Ok(self.db.lock().unwrap().tags.get(&tag_id).cloned()) })
    }

    fn create_tag(&self, name: &str, color: &str) -> StoreFuture<'_, Result<Tag, DbError>> {
        let (name, color) = (name.to_owned(), color.to_owned());
        Box::pin(async move {
            let mut db = self.db.lock().unwrap();
            if db.tags.values().any(|t| t.name == name) {
                return Err(DbError::Conflict(
                    "a tag with that name already exists".into(),
                ));
            }
            let now = Utc::now();
            let tag = Tag {
                id: Uuid::new_v4(),
                name,
                color,
                created_at: now,
                updated_at: now,
            };
            db.tags.insert(tag.id, tag.clone());
            Ok(tag)
        })
    }

    fn update_tag(
        &self,
        tag_id: Uuid,
        patch: TagPatch,
    ) -> StoreFuture<'_, Result<Option<Tag>, DbError>> {
        Box::pin(async move {
            let mut db = self.db.lock().unwrap();
            if !db.tags.contains_key(&tag_id) {
                return Ok(None);
            }
            if let Some(name) = &patch.name {
                if db.tags.values().any(|t| t.name == *name && t.id != tag_id) {
                    return Err(DbError::Conflict(
                        "a tag with that name already exists".into(),
                    ));
                }
            }
            let now = Utc::now();
            let tag = db.tags.get_mut(&tag_id).unwrap();
            if let Some(name) = patch.name {
                tag.name = name;
            }
            if let Some(color) = patch.color {
                tag.color = color;
            }
            tag.updated_at = now;
            Ok(Some(tag.clone()))
        })
    }

    fn delete_tag(&self, tag_id: Uuid) -> StoreFuture<'_, Result<bool, DbError>> {
        Box::pin(async move { Ok(self.db.lock().unwrap().tags.remove(&tag_id).is_some()) })
    }

    fn list_schedules(&self) -> StoreFuture<'_, Result<Vec<ScheduledCommand>, DbError>> {
        Box::pin(async move { Ok(self.db.lock().unwrap().schedules_newest_first()) })
    }

    fn get_schedule(
        &self,
        schedule_id: Uuid,
    ) -> StoreFuture<'_, Result<Option<ScheduledCommand>, DbError>> {
        Box::pin(async move { Ok(self.db.lock().unwrap().schedules.get(&schedule_id).cloned()) })
    }

    fn create_schedule(
        &self,
        new: ScheduledCommandNew,
    ) -> StoreFuture<'_, Result<ScheduledCommand, DbError>> {
        Box::pin(async move {
            let mut db = self.db.lock().unwrap();
            let now = Utc::now();
            let row = ScheduledCommand {
                id: Uuid::new_v4(),
                name: new.name,
                enabled: new.enabled,
                target_kind: new.target_kind,
                target_vm_id: new.target_vm_id,
                target_tag_id: new.target_tag_id,
                task_kind: new.task_kind,
                action_name: new.action_name,
                params: new.params,
                command: new.command,
                cron_expression: new.cron_expression,
                last_run_at: None,
                created_by: new.created_by,
                created_at: now,
                updated_at: now,
            };
            db.schedules.insert(row.id, row.clone());
            Ok(row)
        })
    }

    fn update_schedule(
        &self,
        schedule_id: Uuid,
        patch: SchedulePatch,
    ) -> StoreFuture<'_, Result<Option<ScheduledCommand>, DbError>> {
        Box::pin(async move {
            let mut db = self.db.lock().unwrap();
            let Some(row) = db.schedules.get_mut(&schedule_id) else {
                return Ok(None);
            };
            if let Some(v) = patch.name {
                row.name = v;
            }
            if let Some(v) = patch.enabled {
                row.enabled = v;
            }
            if let Some(v) = patch.target_kind {
                row.target_kind = v;
            }
            if let Some(v) = patch.target_vm_id {
                row.target_vm_id = v;
            }
            if let Some(v) = patch.target_tag_id {
                row.target_tag_id = v;
            }
            if let Some(v) = patch.task_kind {
                row.task_kind = v;
            }
            if let Some(v) = patch.action_name {
                row.action_name = v;
            }
            if let Some(v) = patch.params {
                row.params = v;
            }
            if let Some(v) = patch.command {
                row.command = v;
            }
            if let Some(v) = patch.cron_expression {
                row.cron_expression = v;
            }
            row.updated_at = Utc::now();
            Ok(Some(row.clone()))
        })
    }

    fn delete_schedule(&self, schedule_id: Uuid) -> StoreFuture<'_, Result<bool, DbError>> {
        Box::pin(async move {
            Ok(self
                .db
                .lock()
                .unwrap()
                .schedules
                .remove(&schedule_id)
                .is_some())
        })
    }

    fn list_actions(&self) -> StoreFuture<'_, Result<Vec<CustomAction>, DbError>> {
        Box::pin(async move { Ok(self.db.lock().unwrap().actions_by_name()) })
    }

    fn get_action(
        &self,
        action_id: Uuid,
    ) -> StoreFuture<'_, Result<Option<CustomAction>, DbError>> {
        Box::pin(async move { Ok(self.db.lock().unwrap().actions.get(&action_id).cloned()) })
    }

    fn create_action(
        &self,
        new: CustomActionNew,
    ) -> StoreFuture<'_, Result<CustomAction, DbError>> {
        Box::pin(async move {
            let mut db = self.db.lock().unwrap();
            let now = Utc::now();
            let commands = serde_json::Value::Array(
                new.commands
                    .iter()
                    .map(|argv| serde_json::json!(argv))
                    .collect(),
            );
            let row = CustomAction {
                id: Uuid::new_v4(),
                name: new.name,
                description: new.description,
                commands,
                enabled: true,
                created_by: new.created_by,
                created_at: now,
                updated_at: now,
            };
            db.actions.insert(row.id, row.clone());
            db.action_tags.insert(row.id, new.tag_ids);
            Ok(row)
        })
    }

    fn update_action(
        &self,
        action_id: Uuid,
        patch: CustomActionPatch,
    ) -> StoreFuture<'_, Result<Option<CustomAction>, DbError>> {
        Box::pin(async move {
            let mut db = self.db.lock().unwrap();
            if !db.actions.contains_key(&action_id) {
                return Ok(None);
            }
            if let Some(tag_ids) = patch.tag_ids {
                db.action_tags.insert(action_id, tag_ids);
            }
            let now = Utc::now();
            let row = db.actions.get_mut(&action_id).unwrap();
            if let Some(v) = patch.description {
                row.description = v;
            }
            if let Some(v) = patch.commands {
                row.commands = serde_json::Value::Array(
                    v.iter().map(|argv| serde_json::json!(argv)).collect(),
                );
            }
            if let Some(v) = patch.enabled {
                row.enabled = v;
            }
            row.updated_at = now;
            Ok(Some(row.clone()))
        })
    }

    fn remove_action(&self, action_id: Uuid) -> StoreFuture<'_, Result<bool, DbError>> {
        Box::pin(async move {
            let mut db = self.db.lock().unwrap();
            db.action_tags.remove(&action_id);
            Ok(db.actions.remove(&action_id).is_some())
        })
    }

    fn action_tag_ids(&self, action_id: Uuid) -> StoreFuture<'_, Result<Vec<Uuid>, DbError>> {
        Box::pin(async move {
            Ok(self
                .db
                .lock()
                .unwrap()
                .action_tags
                .get(&action_id)
                .cloned()
                .unwrap_or_default())
        })
    }

    fn create_enrollment_token(
        &self,
        new: EnrollmentTokenNew,
    ) -> StoreFuture<'_, Result<EnrollmentToken, DbError>> {
        Box::pin(async move {
            let mut db = self.db.lock().unwrap();
            let now = Utc::now();
            let expires_at = if new.ttl_seconds == 0 {
                // ttl_seconds == 0 → never expires (parity: year 9999).
                chrono::TimeZone::with_ymd_and_hms(&Utc, 9999, 12, 31, 23, 59, 59)
                    .single()
                    .unwrap()
            } else {
                now + chrono::Duration::seconds(new.ttl_seconds)
            };
            let row = EnrollmentToken {
                id: Uuid::new_v4(),
                token_hash: new.token_hash,
                label: new.label,
                created_by: new.created_by,
                max_uses: new.max_uses,
                uses_count: 0,
                expires_at,
                revoked_at: None,
                created_at: now,
                updated_at: now,
                auto_approve: new.auto_approve,
                install_browser: new.install_browser,
            };
            db.enrollment_tokens.insert(row.id, row.clone());
            Ok(row)
        })
    }

    fn list_enrollment_tokens(&self) -> StoreFuture<'_, Result<Vec<EnrollmentToken>, DbError>> {
        Box::pin(async move { Ok(self.db.lock().unwrap().enrollment_newest_first()) })
    }

    fn revoke_enrollment_token(
        &self,
        token_id: Uuid,
    ) -> StoreFuture<'_, Result<Option<EnrollmentToken>, DbError>> {
        Box::pin(async move {
            let mut db = self.db.lock().unwrap();
            let now = Utc::now();
            let Some(row) = db.enrollment_tokens.get_mut(&token_id) else {
                return Ok(None);
            };
            if row.revoked_at.is_none() {
                row.revoked_at = Some(now);
                row.updated_at = now;
            }
            Ok(Some(row.clone()))
        })
    }

    fn record_audit(&self, entry: AuditNew) -> StoreFuture<'_, Result<(), DbError>> {
        Box::pin(async move {
            self.db.lock().unwrap().audit.push(entry);
            Ok(())
        })
    }
}

// -- shared test fixtures ----------------------------------------------

/// Config with fixed keys and a known MCP service token.
pub fn test_config() -> Config {
    Config {
        mcp_service_token: "mcp-service-token".to_owned(),
        ..Config::default()
    }
}

/// State with a mock store; `store` lets a test seed rows.
pub fn test_state(store: Arc<MockStore>) -> AdminState {
    let config = test_config();
    let security = SecurityConfig::new(
        &config.mfa_encryption_key,
        &config.jwt_secret,
        &config.secret_hash_key,
    );
    AdminState {
        config,
        security,
        store,
    }
}

/// A user row for the mock store.
pub fn make_user(username: &str, role: UserRole) -> User {
    let now = Utc::now();
    User {
        id: Uuid::new_v4(),
        username: username.to_owned(),
        email: Some(format!("{username}@example.com")),
        password_hash: Some("hash".to_owned()),
        oidc_subject: None,
        ldap_dn: None,
        role,
        is_active: true,
        session_epoch: 0,
        last_login_at: None,
        created_at: now,
        updated_at: now,
        totp_secret_enc: None,
        totp_enabled: false,
        totp_confirmed_at: None,
        totp_last_step: None,
    }
}

/// Register `user` in the store and return it (with its id).
pub fn seed_user(store: &MockStore, user: User) -> User {
    store.db.lock().unwrap().users.insert(user.id, user.clone());
    user
}

/// A settings row seeded from the SQLAlchemy column defaults.
pub fn seed_settings(store: &MockStore) -> Setting {
    let row = settings::setting_row(SettingValues::default(), Utc::now());
    store.db.lock().unwrap().settings = Some(row.clone());
    row
}

/// A stored (hashed) MCP token for `user`; returns the plaintext secret.
pub async fn seed_mcp_token(
    state: &AdminState,
    store: &MockStore,
    user_id: Uuid,
    name: &str,
    allowed_ip: Option<&str>,
) -> (McpToken, String) {
    let plaintext = crate::security::generate_secret();
    let token = store
        .create_mcp_token(McpTokenNew {
            user_id,
            token_hash: state.security.hash_secret(&plaintext),
            name: name.to_owned(),
            allowed_ip: allowed_ip.map(str::to_owned),
        })
        .await
        .unwrap();
    (token, plaintext)
}

/// A bearer-JWT request for `user` against the test config's secret.
pub fn bearer(state: &AdminState, user: &User) -> String {
    state
        .security
        .jwt()
        .create_access_token(
            &user.id.to_string(),
            user.role.as_str(),
            15,
            user.session_epoch,
        )
        .unwrap()
}

/// JSON request helper.
pub fn json_request(
    method: &str,
    uri: &str,
    body: serde_json::Value,
) -> axum::http::Request<axum::body::Body> {
    let (payload, content_length) = if method == "GET" || method == "DELETE" {
        (String::new(), 0)
    } else {
        (body.to_string(), body.to_string().len())
    };
    axum::http::Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .header("content-length", content_length.to_string())
        .body(axum::body::Body::from(payload))
        .unwrap()
}

/// Request with a JSON body and headers.
pub fn json_request_with(
    method: &str,
    uri: &str,
    body: serde_json::Value,
    headers: &[(&'static str, String)],
) -> axum::http::Request<axum::body::Body> {
    let mut request = json_request(method, uri, body);
    for (name, value) in headers {
        request.headers_mut().insert(*name, value.parse().unwrap());
    }
    request
}

/// Collect a response body as JSON.
pub async fn body_json(response: Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}
