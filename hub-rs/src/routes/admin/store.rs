//! State and data access: [`AdminState`], the [`AdminStore`] trait the routes
//! are written against, and the sqlx-backed [`PgStore`] implementation.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::config::Config;
use crate::db::DbError;
use crate::models::audit::AuditNew;
use crate::models::custom_action::{CustomAction, CustomActionNew, CustomActionPatch};
use crate::models::enrollment::{EnrollmentToken, EnrollmentTokenNew};
use crate::models::mcp_token::{McpToken, McpTokenNew};
use crate::models::scheduled_command::{ScheduledCommand, ScheduledCommandNew};
use crate::models::setting::{Setting, SettingValues};
use crate::models::tag::{Tag, TagPatch};
use crate::models::user::User;
use crate::security::SecurityConfig;

use super::schedules::SchedulePatch;

/// Boxed future returned by [`AdminStore`] methods (dyn-compatible async trait).
pub type StoreFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Everything the admin routes need. Cheap to clone.
#[derive(Clone)]
pub struct AdminState {
    pub config: Config,
    pub security: SecurityConfig,
    pub store: Arc<dyn AdminStore>,
}

impl AdminState {
    /// Production state backed by the sqlx data layer.
    pub fn new(pool: sqlx::PgPool, config: Config) -> Self {
        let security = SecurityConfig::new(
            &config.mfa_encryption_key,
            &config.jwt_secret,
            &config.secret_hash_key,
        );
        Self {
            config,
            security,
            store: Arc::new(PgStore { pool }),
        }
    }

    /// The hard global request-body cap (`app/main.py` middleware): the largest
    /// legitimate body is a worker result carrying stdout+stderr each up to
    /// `max_output_bytes`.
    pub fn global_body_cap(&self) -> usize {
        self.config.max_output_bytes * 2 + 65_536
    }
}

impl std::fmt::Debug for AdminState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminState").finish_non_exhaustive()
    }
}

/// The data the admin routes touch. Mirrors `app/services/*` query semantics
/// one level down (the `crate::models` layer), so the routes stay pure
/// request/response + validation and tests can swap in an in-memory store.
pub trait AdminStore: Send + Sync {
    // users (principal resolution)
    fn get_user(&self, id: Uuid) -> StoreFuture<'_, Result<Option<User>, DbError>>;

    // settings (single row)
    fn get_settings(&self) -> StoreFuture<'_, Result<Option<Setting>, DbError>>;
    fn save_settings(&self, values: SettingValues) -> StoreFuture<'_, Result<Setting, DbError>>;

    // mcp tokens
    fn list_mcp_tokens(&self, user_id: Uuid) -> StoreFuture<'_, Result<Vec<McpToken>, DbError>>;
    fn create_mcp_token(&self, new: McpTokenNew) -> StoreFuture<'_, Result<McpToken, DbError>>;
    fn set_mcp_allowed_ip(
        &self,
        token_id: Uuid,
        user_id: Uuid,
        allowed_ip: Option<String>,
    ) -> StoreFuture<'_, Result<Option<McpToken>, DbError>>;
    fn revoke_mcp_token(
        &self,
        token_id: Uuid,
        user_id: Uuid,
    ) -> StoreFuture<'_, Result<bool, DbError>>;
    fn active_mcp_token_by_hash(
        &self,
        token_hash: &str,
    ) -> StoreFuture<'_, Result<Option<McpToken>, DbError>>;
    fn touch_mcp_token(
        &self,
        token_id: Uuid,
        at: DateTime<Utc>,
    ) -> StoreFuture<'_, Result<(), DbError>>;

    // tags
    fn list_tags(&self) -> StoreFuture<'_, Result<Vec<Tag>, DbError>>;
    fn get_tag(&self, tag_id: Uuid) -> StoreFuture<'_, Result<Option<Tag>, DbError>>;
    fn create_tag(&self, name: &str, color: &str) -> StoreFuture<'_, Result<Tag, DbError>>;
    fn update_tag(
        &self,
        tag_id: Uuid,
        patch: TagPatch,
    ) -> StoreFuture<'_, Result<Option<Tag>, DbError>>;
    fn delete_tag(&self, tag_id: Uuid) -> StoreFuture<'_, Result<bool, DbError>>;

    // scheduled commands
    fn list_schedules(&self) -> StoreFuture<'_, Result<Vec<ScheduledCommand>, DbError>>;
    fn get_schedule(
        &self,
        schedule_id: Uuid,
    ) -> StoreFuture<'_, Result<Option<ScheduledCommand>, DbError>>;
    fn create_schedule(
        &self,
        new: ScheduledCommandNew,
    ) -> StoreFuture<'_, Result<ScheduledCommand, DbError>>;
    fn update_schedule(
        &self,
        schedule_id: Uuid,
        patch: SchedulePatch,
    ) -> StoreFuture<'_, Result<Option<ScheduledCommand>, DbError>>;
    fn delete_schedule(&self, schedule_id: Uuid) -> StoreFuture<'_, Result<bool, DbError>>;

    // custom actions
    fn list_actions(&self) -> StoreFuture<'_, Result<Vec<CustomAction>, DbError>>;
    fn get_action(&self, action_id: Uuid)
        -> StoreFuture<'_, Result<Option<CustomAction>, DbError>>;
    fn create_action(&self, new: CustomActionNew)
        -> StoreFuture<'_, Result<CustomAction, DbError>>;
    fn update_action(
        &self,
        action_id: Uuid,
        patch: CustomActionPatch,
    ) -> StoreFuture<'_, Result<Option<CustomAction>, DbError>>;
    fn remove_action(&self, action_id: Uuid) -> StoreFuture<'_, Result<bool, DbError>>;
    fn action_tag_ids(&self, action_id: Uuid) -> StoreFuture<'_, Result<Vec<Uuid>, DbError>>;

    // enrollment tokens
    fn create_enrollment_token(
        &self,
        new: EnrollmentTokenNew,
    ) -> StoreFuture<'_, Result<EnrollmentToken, DbError>>;
    fn list_enrollment_tokens(&self) -> StoreFuture<'_, Result<Vec<EnrollmentToken>, DbError>>;
    fn revoke_enrollment_token(
        &self,
        token_id: Uuid,
    ) -> StoreFuture<'_, Result<Option<EnrollmentToken>, DbError>>;

    // audit chain
    fn record_audit(&self, entry: AuditNew) -> StoreFuture<'_, Result<(), DbError>>;
}

/// [`AdminStore`] over the sqlx data layer (production).
pub struct PgStore {
    pub pool: sqlx::PgPool,
}

impl AdminStore for PgStore {
    fn get_user(&self, id: Uuid) -> StoreFuture<'_, Result<Option<User>, DbError>> {
        Box::pin(async move { crate::models::user::get_by_id(&self.pool, id).await })
    }

    fn get_settings(&self) -> StoreFuture<'_, Result<Option<Setting>, DbError>> {
        Box::pin(async move { crate::models::setting::get_settings_row(&self.pool).await })
    }

    fn save_settings(&self, values: SettingValues) -> StoreFuture<'_, Result<Setting, DbError>> {
        Box::pin(async move { crate::models::setting::upsert(&self.pool, values).await })
    }

    fn list_mcp_tokens(&self, user_id: Uuid) -> StoreFuture<'_, Result<Vec<McpToken>, DbError>> {
        Box::pin(
            async move { crate::models::mcp_token::list_for_user(&self.pool, user_id, true).await },
        )
    }

    fn create_mcp_token(&self, new: McpTokenNew) -> StoreFuture<'_, Result<McpToken, DbError>> {
        Box::pin(async move { crate::models::mcp_token::create(&self.pool, new).await })
    }

    fn set_mcp_allowed_ip(
        &self,
        token_id: Uuid,
        user_id: Uuid,
        allowed_ip: Option<String>,
    ) -> StoreFuture<'_, Result<Option<McpToken>, DbError>> {
        Box::pin(async move {
            crate::models::mcp_token::set_allowed_ip(
                &self.pool,
                token_id,
                user_id,
                allowed_ip.as_deref(),
            )
            .await
        })
    }

    fn revoke_mcp_token(
        &self,
        token_id: Uuid,
        user_id: Uuid,
    ) -> StoreFuture<'_, Result<bool, DbError>> {
        Box::pin(
            async move { crate::models::mcp_token::revoke(&self.pool, token_id, user_id).await },
        )
    }

    fn active_mcp_token_by_hash(
        &self,
        token_hash: &str,
    ) -> StoreFuture<'_, Result<Option<McpToken>, DbError>> {
        // Owned copy so the future only borrows `self` (the trait's `'_`).
        let token_hash = token_hash.to_owned();
        Box::pin(async move {
            crate::models::mcp_token::get_active_by_token_hash(&self.pool, &token_hash).await
        })
    }

    fn touch_mcp_token(
        &self,
        token_id: Uuid,
        at: DateTime<Utc>,
    ) -> StoreFuture<'_, Result<(), DbError>> {
        Box::pin(async move {
            crate::models::mcp_token::touch_last_used(&self.pool, token_id, at)
                .await
                .map(|_| ())
        })
    }

    fn list_tags(&self) -> StoreFuture<'_, Result<Vec<Tag>, DbError>> {
        Box::pin(async move { crate::models::tag::list_tags(&self.pool).await })
    }

    fn get_tag(&self, tag_id: Uuid) -> StoreFuture<'_, Result<Option<Tag>, DbError>> {
        Box::pin(async move { crate::models::tag::get_tag(&self.pool, tag_id).await })
    }

    fn create_tag(&self, name: &str, color: &str) -> StoreFuture<'_, Result<Tag, DbError>> {
        let (name, color) = (name.to_owned(), color.to_owned());
        Box::pin(async move { crate::models::tag::create_tag(&self.pool, &name, &color).await })
    }

    fn update_tag(
        &self,
        tag_id: Uuid,
        patch: TagPatch,
    ) -> StoreFuture<'_, Result<Option<Tag>, DbError>> {
        Box::pin(async move { crate::models::tag::update_tag(&self.pool, tag_id, patch).await })
    }

    fn delete_tag(&self, tag_id: Uuid) -> StoreFuture<'_, Result<bool, DbError>> {
        Box::pin(async move { crate::models::tag::delete_tag(&self.pool, tag_id).await })
    }

    fn list_schedules(&self) -> StoreFuture<'_, Result<Vec<ScheduledCommand>, DbError>> {
        Box::pin(async move { crate::models::scheduled_command::list_schedules(&self.pool).await })
    }

    fn get_schedule(
        &self,
        schedule_id: Uuid,
    ) -> StoreFuture<'_, Result<Option<ScheduledCommand>, DbError>> {
        Box::pin(
            async move { crate::models::scheduled_command::get(&self.pool, schedule_id).await },
        )
    }

    fn create_schedule(
        &self,
        new: ScheduledCommandNew,
    ) -> StoreFuture<'_, Result<ScheduledCommand, DbError>> {
        Box::pin(async move { crate::models::scheduled_command::create(&self.pool, new).await })
    }

    fn update_schedule(
        &self,
        schedule_id: Uuid,
        patch: SchedulePatch,
    ) -> StoreFuture<'_, Result<Option<ScheduledCommand>, DbError>> {
        Box::pin(async move {
            // `COALESCE` covers "leave untouched"; the boolean flags cover
            // "explicitly sent as null" (`exclude_unset` + `setattr(None)` in
            // the Python service) — clearing a column is the one case the
            // models layer's COALESCE-only patch cannot express.
            let clear_vm = patch.target_vm_id.is_some_and(|v| v.is_none());
            let clear_tag = patch.target_tag_id.is_some_and(|v| v.is_none());
            let clear_action = patch.action_name.as_ref().is_some_and(|v| v.is_none());
            let clear_command = patch.command.as_ref().is_some_and(|v| v.is_none());
            let row = sqlx::query_as::<_, ScheduledCommand>(
                "UPDATE scheduled_commands SET \
                 name = COALESCE($2, name), \
                 enabled = COALESCE($3, enabled), \
                 target_kind = COALESCE($4, target_kind), \
                 target_vm_id = CASE WHEN $5 THEN NULL ELSE COALESCE($6, target_vm_id) END, \
                 target_tag_id = CASE WHEN $7 THEN NULL ELSE COALESCE($8, target_tag_id) END, \
                 task_kind = COALESCE($9, task_kind), \
                 action_name = CASE WHEN $10 THEN NULL ELSE COALESCE($11, action_name) END, \
                 params = COALESCE($12::json, params), \
                 command = CASE WHEN $13 THEN NULL ELSE COALESCE($14, command) END, \
                 cron_expression = COALESCE($15, cron_expression), \
                 updated_at = $16 \
                 WHERE id = $1 RETURNING *",
            )
            .bind(schedule_id)
            .bind(&patch.name)
            .bind(patch.enabled)
            .bind(&patch.target_kind)
            .bind(clear_vm)
            .bind(patch.target_vm_id.flatten())
            .bind(clear_tag)
            .bind(patch.target_tag_id.flatten())
            .bind(&patch.task_kind)
            .bind(clear_action)
            .bind(patch.action_name.as_ref().and_then(|v| v.as_deref()))
            .bind(patch.params.clone())
            .bind(clear_command)
            .bind(patch.command.as_ref().and_then(|v| v.as_deref()))
            .bind(&patch.cron_expression)
            .bind(Utc::now())
            .fetch_optional(&self.pool)
            .await?;
            Ok(row)
        })
    }

    fn delete_schedule(&self, schedule_id: Uuid) -> StoreFuture<'_, Result<bool, DbError>> {
        Box::pin(
            async move { crate::models::scheduled_command::delete(&self.pool, schedule_id).await },
        )
    }

    fn list_actions(&self) -> StoreFuture<'_, Result<Vec<CustomAction>, DbError>> {
        Box::pin(async move { crate::models::custom_action::list_all(&self.pool).await })
    }

    fn get_action(
        &self,
        action_id: Uuid,
    ) -> StoreFuture<'_, Result<Option<CustomAction>, DbError>> {
        Box::pin(async move { crate::models::custom_action::get(&self.pool, action_id).await })
    }

    fn create_action(
        &self,
        new: CustomActionNew,
    ) -> StoreFuture<'_, Result<CustomAction, DbError>> {
        Box::pin(async move { crate::models::custom_action::create(&self.pool, new).await })
    }

    fn update_action(
        &self,
        action_id: Uuid,
        patch: CustomActionPatch,
    ) -> StoreFuture<'_, Result<Option<CustomAction>, DbError>> {
        Box::pin(
            async move { crate::models::custom_action::update(&self.pool, action_id, patch).await },
        )
    }

    fn remove_action(&self, action_id: Uuid) -> StoreFuture<'_, Result<bool, DbError>> {
        Box::pin(async move { crate::models::custom_action::remove(&self.pool, action_id).await })
    }

    fn action_tag_ids(&self, action_id: Uuid) -> StoreFuture<'_, Result<Vec<Uuid>, DbError>> {
        Box::pin(
            async move { crate::models::custom_action::tag_ids_for(&self.pool, action_id).await },
        )
    }

    fn create_enrollment_token(
        &self,
        new: EnrollmentTokenNew,
    ) -> StoreFuture<'_, Result<EnrollmentToken, DbError>> {
        Box::pin(async move { crate::models::enrollment::create_token(&self.pool, new).await })
    }

    fn list_enrollment_tokens(&self) -> StoreFuture<'_, Result<Vec<EnrollmentToken>, DbError>> {
        Box::pin(async move { crate::models::enrollment::list_tokens(&self.pool).await })
    }

    fn revoke_enrollment_token(
        &self,
        token_id: Uuid,
    ) -> StoreFuture<'_, Result<Option<EnrollmentToken>, DbError>> {
        Box::pin(async move { crate::models::enrollment::revoke_token(&self.pool, token_id).await })
    }

    fn record_audit(&self, entry: AuditNew) -> StoreFuture<'_, Result<(), DbError>> {
        Box::pin(async move {
            // Hash-chain append: `row_hash = sha256(prev_hash + canonical(fields))`
            // while holding the advisory lock (models::audit).
            crate::models::audit::append_chained(&self.pool, entry, |entry, prev| {
                (
                    prev.to_owned(),
                    crate::security::compute_row_hash(prev, &entry.hash_fields()),
                )
            })
            .await
            .map(|_| ())
        })
    }
}
