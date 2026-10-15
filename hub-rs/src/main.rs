//! huginn-hub — the Huginn hub (Rust port of `hub/`).
//!
//! Application assembly, port of `hub/app/main.py`: config validation
//! (fail-closed in prod), database migrations, bootstrap admin, the background
//! sweeper (task timeouts, offline VMs, scheduled commands), and the merged
//! router (worker + auth/MFA/users + fleet/execution/audit/SSE + admin CRUD).

mod config;
mod db;
mod error;
mod models;
mod routes;
mod security;
mod services;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::{routing::get, Json, Router};
use chrono::Utc;
use serde_json::json;

use config::Config;
use models::audit::AuditNew;
use models::enums::{ActorType, UserRole, VMState};
use models::task::{ActionTaskNew, CommandTaskNew, SweepConfig};
use models::vm::VmListFilter;
use routes::admin::{schedules as admin_schedules, AdminState};
use routes::authapi::AuthState;
use routes::fleet::{events::EventBus, FleetState};
use routes::metrics::{MetricsLayer, MetricsState};
use routes::worker::WorkerState;
use services::metrics::Metrics;
use services::task_events::TaskEvents;

/// `GET /healthz` (meta endpoint of the Python hub).
async fn healthz() -> Json<serde_json::Value> {
    Json(json!({"status": "ok"}))
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let config = Config::from_env();
    if let Err(e) = config.validate_for_prod() {
        eprintln!("huginn-hub: {e}");
        std::process::exit(1);
    }

    let pool = match db::connect(&config.database_url, config.db_pool_size).await {
        Ok(p) => p,
        Err(e) => {
            eprintln!("huginn-hub: database connection failed: {e}");
            std::process::exit(1);
        }
    };
    if let Err(e) = db::run_migrations(&pool).await {
        eprintln!("huginn-hub: migrations failed: {e}");
        std::process::exit(1);
    }

    bootstrap_admin(&pool, &config).await;
    ensure_settings(&pool, &config).await;

    // One event bus shared by the worker long-poll and the fleet routes: a
    // task created on either side wakes the right worker instantly.
    // `TaskEvents::new()` already hands out a shared handle.
    let events = TaskEvents::new();
    // One SSE bus shared by worker results and the sweeper.
    let bus = Arc::new(EventBus::new_default());

    let worker_state =
        WorkerState::with_events(pool.clone(), config.clone(), events.clone(), bus.clone());
    let auth_state = AuthState::new(pool.clone(), config.clone());
    let fleet_state =
        FleetState::with_events(pool.clone(), config.clone(), events.clone(), bus.clone());
    let admin_state = AdminState::new(pool.clone(), config.clone());

    // Prometheus metrics: one registry, exposed at GET /metrics, fed by the
    // tower layer below plus live gauges (pool, long-polls, active workers).
    let metrics = Arc::new(Metrics::new());
    let metrics_state = MetricsState::new(metrics.clone())
        .with_pool(pool.clone())
        .with_events(events.clone())
        .workers_window(config.heartbeat_offline_seconds);

    tokio::spawn(sweeper(
        pool.clone(),
        config.clone(),
        events.clone(),
        bus.clone(),
    ));

    let app: Router = routes::worker::router(worker_state)
        .merge(routes::authapi::router(auth_state))
        .merge(routes::fleet::router(fleet_state))
        .merge(routes::admin::router(admin_state))
        .merge(routes::metrics::router(metrics_state))
        .route("/healthz", get(healthz))
        .layer(MetricsLayer::new(metrics.clone()));

    let port: u16 = std::env::var("HUGINN_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8000);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!("huginn-hub listening on {addr}");
    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind");
    // `into_make_service_with_connect_info` feeds `ConnectInfo<SocketAddr>` to
    // the extractors — without it every `client_ip` (audit source_ip) is None.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    // Graceful shutdown: on SIGTERM/SIGINT stop accepting, let in-flight
    // requests (worker long-polls included) finish, then exit — instead of
    // cutting every connection at deploy time.
    .with_graceful_shutdown(shutdown_signal())
    .await
    .expect("serve");
}

/// Resolves on SIGTERM or SIGINT (systemd stop / docker stop / Ctrl-C).
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = term.recv() => {},
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
    tracing::info!("shutdown signal received — draining connections");
}

/// Port of `users_service.ensure_bootstrap_admin` (called from `lifespan`):
/// create the first admin from the environment only on an empty user table.
async fn bootstrap_admin(pool: &sqlx::PgPool, config: &Config) {
    let admins = models::user::count_admins(pool).await.unwrap_or(0);
    if admins > 0 {
        return;
    }
    let Some(password) = config.bootstrap_admin_password.as_ref() else {
        return;
    };
    if password.is_empty() {
        return;
    }
    let password_hash = match security::password::hash_password(password) {
        Ok(h) => h,
        Err(e) => {
            tracing::error!("bootstrap admin: cannot hash password: {e}");
            return;
        }
    };
    let mut new = models::user::UserNew::new(config.bootstrap_admin_username.clone());
    new.password_hash = Some(password_hash);
    new.role = UserRole::Admin;
    new.is_active = true;
    match models::user::create(pool, new).await {
        Ok(admin) => tracing::info!("bootstrapped initial admin user {:?}", admin.username),
        Err(e) => tracing::error!("bootstrap admin failed: {e}"),
    }
}

/// Port of `settings_service.ensure_settings` (called from `lifespan`): seed
/// the single-row settings table from the environment on first boot.
async fn ensure_settings(pool: &sqlx::PgPool, config: &Config) {
    if models::setting::get_settings_row(pool)
        .await
        .ok()
        .flatten()
        .is_some()
    {
        return;
    }
    // Every field `settings_service.ensure_settings` seeds from app settings.
    let values = models::setting::SettingValues {
        target_worker_version: config.target_worker_version.clone(),
        target_release_repo: config.target_release_repo.clone(),
        allowed_release_domains: json!(config.allowed_release_domains()),
        require_admin_mfa: config.require_admin_mfa,
        allow_password_login: config.allow_password_login,
        webauthn_rp_id: config.webauthn_rp_id.clone(),
        webauthn_rp_name: config.webauthn_rp_name.clone(),
        webauthn_origin: config.webauthn_origin.clone(),
        oidc_enabled: config.oidc_enabled,
        oidc_provider_name: config.oidc_provider_name.clone(),
        oidc_issuer: config.oidc_issuer.clone(),
        oidc_client_id: config.oidc_client_id.clone(),
        // Python: `oidc_client_secret or None`
        oidc_client_secret: (!config.oidc_client_secret.is_empty())
            .then(|| config.oidc_client_secret.clone()),
        oidc_redirect_url: config.oidc_redirect_url.clone(),
        oidc_post_login_redirect: config.oidc_post_login_redirect.clone(),
        ..Default::default()
    };
    match models::setting::upsert(pool, values).await {
        Ok(_) => tracing::info!("seeded settings row"),
        Err(e) => tracing::error!("ensure_settings failed: {e}"),
    }
}

/// Background sweeper (port of `app/services/background.py`): task timeouts,
/// offline VMs, and due scheduled commands. Runs every 30 s.
async fn sweeper(pool: sqlx::PgPool, config: Config, events: Arc<TaskEvents>, bus: Arc<EventBus>) {
    let mut tick = tokio::time::interval(Duration::from_secs(30));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;

        // 1. Timed-out dispatched tasks → re-queue (retry budget left) or
        // dead-letter; re-queued tasks become claimable again → wake their VM.
        let sweep_cfg = SweepConfig {
            grace_seconds: config.default_task_timeout_seconds as i64 * 2 + 30,
            dead_letter_retries: config.task_dead_letter_retries,
        };
        match models::task::sweep_timeouts(&pool, sweep_cfg).await {
            Ok(res) => {
                for vm_id in &res.requeued_vm_ids {
                    events.notify_queue(&vm_id.to_string());
                }
                if !res.requeued_vm_ids.is_empty() || !res.dead_lettered.is_empty() {
                    bus.publish_hint("tasks");
                }
            }
            Err(e) => tracing::warn!("sweep_timeouts failed: {e}"),
        }

        // 2. Active VMs without a fresh heartbeat → offline (+ dashboard hint).
        match models::vm::sweep_offline_vms(&pool, config.heartbeat_offline_seconds as i64).await {
            Ok(vms) => {
                if !vms.is_empty() {
                    bus.publish_hint("vms");
                }
            }
            Err(e) => tracing::warn!("sweep_offline_vms failed: {e}"),
        }

        // 3. Due scheduled commands.
        run_due_schedules(&pool, &config, &events, &bus).await;

        // 4. Daily S3 backup + retention (best-effort: never breaks the loop).
        let report = crate::services::backup::sweep_backup(&pool).await;
        if let Some(reason) = report.skipped {
            tracing::debug!("backup sweep skipped: {reason}");
        }
    }
}

/// Port of `scheduled_commands.run_due`: create tasks for every enabled
/// schedule whose cron time has passed. Best-effort per VM/schedule.
async fn run_due_schedules(
    pool: &sqlx::PgPool,
    config: &Config,
    events: &TaskEvents,
    bus: &EventBus,
) {
    let now = Utc::now();
    let schedules = match models::scheduled_command::list_enabled(pool).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("list_enabled schedules failed: {e}");
            return;
        }
    };
    for sched in schedules {
        let Some(next) = admin_schedules::next_run_at(&sched, None) else {
            continue;
        };
        if next > now {
            continue;
        }
        let targets = resolve_schedule_targets(pool, &sched).await;
        for vm in targets {
            let created = if sched.task_kind == "action" {
                models::task::create_action_task(
                    pool,
                    ActionTaskNew {
                        vm_id: vm.id,
                        action_name: sched.action_name.clone().unwrap_or_default(),
                        params: sched.params.clone(),
                        timeout_seconds: config.default_task_timeout_seconds as i64,
                        created_by: format!("schedule:{}", sched.id),
                        idempotency_key: None,
                    },
                )
                .await
            } else {
                models::task::create_command_task(
                    pool,
                    CommandTaskNew {
                        vm_id: vm.id,
                        command: sched.command.clone().unwrap_or_default(),
                        timeout_seconds: config.default_task_timeout_seconds as i64,
                        created_by: format!("schedule:{}", sched.id),
                        idempotency_key: None,
                    },
                )
                .await
            };
            let task = match created {
                Ok(t) => t,
                Err(e) => {
                    tracing::warn!("schedule {} task creation failed: {e}", sched.name);
                    continue;
                }
            };
            // Record the trigger in the audit log (actor = schedule name, the
            // id lives in detail), exactly like the Python service.
            let audit = AuditNew {
                actor_type: ActorType::System,
                actor_id: sched.name.clone(),
                event_type: if sched.task_kind == "action" {
                    "scheduled_action".into()
                } else {
                    "scheduled_command".into()
                },
                vm_id: Some(vm.id),
                action_name: sched.action_name.clone(),
                command: sched.command.clone(),
                result_status: None,
                exit_code: None,
                detail: json!({"schedule_id": sched.id.to_string(), "task_id": task.id.to_string()}),
                source_ip: None,
            };
            let hash = |new: &AuditNew, head: &str| {
                (
                    head.to_string(),
                    security::audit::compute_row_hash(head, &new.hash_fields()),
                )
            };
            if let Err(e) = models::audit::append_chained(pool, audit, hash).await {
                tracing::warn!("schedule audit append failed: {e}");
            }
            // The task is committed → this VM's parked long-poll may claim it.
            events.notify_queue(&vm.id.to_string());
        }
        bus.publish_hint("tasks");
        if let Err(e) = models::scheduled_command::set_last_run_at(pool, sched.id, now).await {
            tracing::warn!("set_last_run_at failed: {e}");
        }
    }
}

/// Active VMs a schedule targets (port of `_resolve_targets`).
async fn resolve_schedule_targets(
    pool: &sqlx::PgPool,
    sched: &models::scheduled_command::ScheduledCommand,
) -> Vec<models::vm::VM> {
    match sched.target_kind.as_str() {
        "vm" => {
            let Some(vm_id) = sched.target_vm_id else {
                return Vec::new();
            };
            match models::vm::get_by_id(pool, vm_id).await {
                Ok(Some(vm)) if matches!(vm.state, VMState::Active | VMState::Offline) => {
                    vec![vm]
                }
                _ => Vec::new(),
            }
        }
        "tag" => {
            let Some(tag_id) = sched.target_tag_id else {
                return Vec::new();
            };
            let vm_ids = models::tag::vm_ids_for_tags(pool, &[tag_id])
                .await
                .unwrap_or_default();
            models::vm::list_vms(
                pool,
                VmListFilter {
                    state: None,
                    allowed_vm_ids: Some(vm_ids),
                    tag_ids: None,
                },
            )
            .await
            .unwrap_or_default()
        }
        "all_active" => models::vm::list_vms(
            pool,
            VmListFilter {
                state: Some(VMState::Active),
                allowed_vm_ids: None,
                tag_ids: None,
            },
        )
        .await
        .unwrap_or_default(),
        _ => Vec::new(),
    }
}
