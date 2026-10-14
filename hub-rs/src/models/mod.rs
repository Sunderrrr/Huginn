//! SQLx data layer: row models and queries for every table of the baseline
//! schema (17 tables), mirroring `app/models/*.py` and the query semantics of
//! `app/services/*.py`.
//!
//! This layer is deliberately business-logic-free: validation, authorization,
//! hashing and event fan-out belong to the service/route layers. What lives
//! here is row mapping, atomic SQL (claims, idempotent inserts, sweeps), and
//! the exact filtering/ordering semantics of the Python queries.
// Migration note: the data layer ships ahead of its consumers (WebAuthn
// ceremonies, OIDC/LDAP, route handlers still landing). Dead-code warnings
// for that surface are expected until everything is wired; the routes keep
// their own strict allow(dead_code) carve-out meanwhile.
#![allow(dead_code)]
#![allow(unused_imports)]

pub mod audit;
pub mod custom_action;
pub mod enrollment;
pub mod enums;
pub mod mcp_token;
pub mod scheduled_command;
pub mod setting;
pub mod tag;
pub mod task;
pub mod user;
pub mod vm;
pub mod webauthn;

pub use enums::{ActorType, ExecMode, TaskStatus, TaskType, UserRole, VMState, WorkerArch};

#[cfg(test)]
mod live_tests {
    //! End-to-end exercise of the data layer against a live PostgreSQL
    //! (skipped unless `HUGINN_TEST_DATABASE_URL` is set — `cargo test` stays
    //! green without a database).

    use chrono::{Duration, Utc};
    use sqlx::PgPool;
    use uuid::Uuid;

    use crate::db::{connect, run_migrations, LIVE_DB_GUARD};

    use super::enums::*;
    use super::{
        audit, custom_action, enrollment, mcp_token, scheduled_command, setting, tag, task, user,
        vm, webauthn,
    };

    async fn fresh_pool() -> Option<(PgPool, tokio::sync::MutexGuard<'static, ()>)> {
        let Ok(url) = std::env::var("HUGINN_TEST_DATABASE_URL") else {
            eprintln!("skipped: HUGINN_TEST_DATABASE_URL not set");
            return None;
        };
        let guard = LIVE_DB_GUARD.lock().await;
        let pool = connect(&url, 4).await.expect("connect");
        sqlx::query("DROP SCHEMA public CASCADE")
            .execute(&pool)
            .await
            .expect("drop schema");
        sqlx::query("CREATE SCHEMA public")
            .execute(&pool)
            .await
            .expect("create schema");
        run_migrations(&pool).await.expect("migrations");
        Some((pool, guard))
    }

    #[tokio::test]
    async fn data_layer_smoke() {
        let Some((pool, _guard)) = fresh_pool().await else {
            return;
        };
        let now = Utc::now();
        let k = Uuid::new_v4().simple().to_string()[..8].to_string();

        // --- settings ---------------------------------------------------
        let s = setting::upsert(
            &pool,
            setting::SettingValues {
                target_worker_version: "v1.4.0".into(),
                target_release_repo: "Sunderrrr/Huginn".into(),
                allowed_release_domains: serde_json::json!(["github.com"]),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(s.id, setting::SETTINGS_SINGLETON_ID);
        assert!(s.require_admin_mfa);
        let s = setting::upsert(
            &pool,
            setting::SettingValues {
                target_worker_version: "v1.5.0".into(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(s.target_worker_version, "v1.5.0"); // upsert replaced
        assert!(setting::get_settings_row(&pool).await.unwrap().is_some());

        // --- users + access ---------------------------------------------
        let admin = user::create(
            &pool,
            user::UserNew {
                username: format!("admin-{k}"),
                email: Some("a@b.c".into()),
                password_hash: Some("h1".into()),
                role: UserRole::Admin,
                is_active: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(user::count_admins(&pool).await.unwrap(), 1);
        assert!(user::get_by_username(&pool, &format!("admin-{k}"))
            .await
            .unwrap()
            .is_some());
        assert!(user::get_by_id(&pool, admin.id).await.unwrap().is_some());
        user::update_password(&pool, admin.id, Some("h2"))
            .await
            .unwrap()
            .unwrap();
        user::set_mfa(&pool, admin.id, "enc-secret", now)
            .await
            .unwrap()
            .unwrap();
        assert!(user::claim_totp_step(&pool, admin.id, 10).await.unwrap());
        assert!(!user::claim_totp_step(&pool, admin.id, 9).await.unwrap());
        user::touch_last_login(&pool, admin.id).await.unwrap();
        user::update(
            &pool,
            admin.id,
            user::UserPatch {
                role: Some(UserRole::Operator),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        user::disable_mfa(&pool, admin.id).await.unwrap();
        assert_eq!(user::list_users(&pool).await.unwrap().len(), 1);

        // --- VMs ---------------------------------------------------------
        let mut new = vm::VmNew::new(format!("vm-{k}"), WorkerArch::Amd64);
        new.hostname = Some(format!("host-{k}"));
        new.os_info = serde_json::json!({"os": "linux"});
        new.state = VMState::Pending;
        let v = vm::create(&pool, new).await.unwrap();
        assert!(vm::get_by_id(&pool, v.id).await.unwrap().is_some());
        assert!(vm::get_by_name(&pool, &format!("vm-{k}"))
            .await
            .unwrap()
            .is_some());
        assert!(vm::get_by_name_ci(&pool, &format!("VM-{k}"))
            .await
            .unwrap()
            .is_some());

        // set_exec_mode must fail before approval
        assert!(vm::set_exec_mode(&pool, v.id, ExecMode::Custom)
            .await
            .is_err());
        let v = vm::approve(&pool, v.id, Some(admin.id))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(v.state, VMState::Active);
        assert!(v.approved_at.is_some());
        vm::set_exec_mode(&pool, v.id, ExecMode::Custom)
            .await
            .unwrap()
            .unwrap();
        vm::update_heartbeat(&pool, v.id, now).await.unwrap();
        vm::update(
            &pool,
            v.id,
            vm::VmPatch {
                worker_version: Some("v1.4.0".into()),
                worker_secret_hash: Some("wh".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();

        user::replace_vm_access(&pool, admin.id, &[v.id])
            .await
            .unwrap();
        assert_eq!(
            user::vm_ids_for_user(&pool, admin.id).await.unwrap(),
            vec![v.id]
        );
        assert_eq!(
            user::user_ids_for_vm(&pool, v.id).await.unwrap(),
            vec![admin.id]
        );
        assert_eq!(
            vm::list_vms(
                &pool,
                vm::VmListFilter {
                    allowed_vm_ids: Some(vec![v.id]),
                    ..Default::default()
                }
            )
            .await
            .unwrap()
            .len(),
            1
        );
        assert!(vm::list_vms(
            &pool,
            vm::VmListFilter {
                allowed_vm_ids: Some(vec![]),
                ..Default::default()
            }
        )
        .await
        .unwrap()
        .is_empty());

        // --- tags --------------------------------------------------------
        let t1 = tag::create_tag(&pool, &format!("prod-{k}"), "#46d39a")
            .await
            .unwrap();
        let t2 = tag::create_tag(&pool, &format!("web-{k}"), "#123456")
            .await
            .unwrap();
        assert!(tag::create_tag(&pool, &format!("prod-{k}"), "#000000")
            .await
            .is_err());
        tag::set_vm_tags(&pool, v.id, &[t1.id, t2.id])
            .await
            .unwrap();
        assert_eq!(tag::tag_ids_for_vm(&pool, v.id).await.unwrap().len(), 2);
        assert_eq!(
            tag::vm_ids_for_tags(&pool, &[t1.id]).await.unwrap(),
            vec![v.id]
        );
        let by_vm = tag::load_tags_for_vms(&pool, &[v.id]).await.unwrap();
        assert_eq!(by_vm.get(&v.id).unwrap().len(), 2);
        tag::update_tag(
            &pool,
            t1.id,
            tag::TagPatch {
                color: Some("#654321".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(tag::list_tags(&pool).await.unwrap().len(), 2);

        // --- custom actions ----------------------------------------------
        let action = custom_action::create(
            &pool,
            custom_action::CustomActionNew {
                name: format!("restart-{k}"),
                description: "restart nginx".into(),
                commands: vec![vec!["systemctl".into(), "restart".into(), "nginx".into()]],
                created_by: Some("admin".into()),
                tag_ids: vec![t1.id],
            },
        )
        .await
        .unwrap();
        assert_eq!(
            action.command_argv()[0],
            vec!["systemctl", "restart", "nginx"]
        );
        assert_eq!(
            custom_action::tag_ids_for(&pool, action.id).await.unwrap(),
            vec![t1.id]
        );
        assert!(custom_action::vm_allowed(&pool, action.id, v.id)
            .await
            .unwrap());
        custom_action::update(
            &pool,
            action.id,
            custom_action::CustomActionPatch {
                enabled: Some(false),
                ..Default::default()
            },
        )
        .await
        .unwrap();

        // --- tasks -------------------------------------------------------
        let a1 = task::create_action_task(
            &pool,
            task::ActionTaskNew {
                vm_id: v.id,
                action_name: format!("restart-{k}"),
                params: serde_json::json!({"x": "1"}),
                timeout_seconds: 60,
                created_by: "user:admin".into(),
                idempotency_key: Some(format!("key-{k}")),
            },
        )
        .await
        .unwrap();
        // idempotent replay returns the same row
        let a2 = task::create_action_task(
            &pool,
            task::ActionTaskNew {
                vm_id: v.id,
                action_name: format!("restart-{k}"),
                params: serde_json::json!({}),
                timeout_seconds: 60,
                created_by: "user:admin".into(),
                idempotency_key: Some(format!("key-{k}")),
            },
        )
        .await
        .unwrap();
        assert_eq!(a1.id, a2.id);
        assert!(task::find_idempotent(&pool, v.id, &format!("key-{k}"))
            .await
            .unwrap()
            .is_some());

        task::create_command_task(
            &pool,
            task::CommandTaskNew {
                vm_id: v.id,
                command: "ls -la".into(),
                timeout_seconds: 30,
                created_by: "user:admin".into(),
                idempotency_key: None,
            },
        )
        .await
        .unwrap();
        task::create_update_task(
            &pool,
            task::UpdateTaskNew {
                vm_id: v.id,
                target_version: "v1.5.0".into(),
                urls: serde_json::json!({"download_url": "https://github.com/x"}),
                created_by: "system".into(),
            },
        )
        .await
        .unwrap();
        task::create_uninstall_task(&pool, v.id, "system")
            .await
            .unwrap();
        assert!(task::has_inflight_update(&pool, v.id).await.unwrap());

        // claim: oldest pending first, status → dispatched
        let c1 = task::claim_next_task(&pool, v.id).await.unwrap().unwrap();
        assert_eq!(c1.status, TaskStatus::Dispatched);
        assert_eq!(c1.id, a1.id);
        let c2 = task::claim_next_task(&pool, v.id).await.unwrap().unwrap();
        assert_ne!(c2.id, c1.id);

        // result: truncated outputs, idempotent on duplicates
        let done = task::submit_result(
            &pool,
            task::SubmitResult {
                task_id: c1.id,
                vm_id: v.id,
                status: TaskStatus::Succeeded,
                exit_code: Some(0),
                stdout: Some("x".repeat(5000)),
                stderr: None,
                error: None,
                output_cap_bytes: 1024,
            },
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(done.status, TaskStatus::Succeeded);
        assert!(done
            .stdout
            .as_ref()
            .unwrap()
            .ends_with("\n[...truncated...]"));
        assert!(done.started_at.is_some() && done.finished_at.is_some());
        let again = task::submit_result(
            &pool,
            task::SubmitResult {
                task_id: c1.id,
                vm_id: v.id,
                status: TaskStatus::Failed,
                exit_code: Some(1),
                stdout: None,
                stderr: None,
                error: None,
                output_cap_bytes: 1024,
            },
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            again.status,
            TaskStatus::Succeeded,
            "duplicate result ignored"
        );
        // wrong VM → None
        let other = task::submit_result(
            &pool,
            task::SubmitResult {
                task_id: c1.id,
                vm_id: Uuid::new_v4(),
                status: TaskStatus::Failed,
                exit_code: None,
                stdout: None,
                stderr: None,
                error: None,
                output_cap_bytes: 1024,
            },
        )
        .await
        .unwrap();
        assert!(other.is_none());
        assert!(
            task::wait_for_terminal(&pool, c1.id, Duration::seconds(0).to_std().unwrap())
                .await
                .unwrap()
                .is_some()
        );

        // sweep: dispatched + stale → re-queue, then dead-letter past budget
        sqlx::query("UPDATE tasks SET dispatched_at = now() - interval '1 day' WHERE id = $1")
            .bind(c2.id)
            .execute(&pool)
            .await
            .unwrap();
        let sweep = task::sweep_timeouts(
            &pool,
            task::SweepConfig {
                grace_seconds: 60,
                dead_letter_retries: 1,
            },
        )
        .await
        .unwrap();
        assert_eq!(sweep.swept, 1);
        assert_eq!(sweep.requeued_vm_ids, vec![v.id]);
        let requeued = task::get_by_id(&pool, c2.id).await.unwrap().unwrap();
        assert_eq!(requeued.status, TaskStatus::Pending);
        assert_eq!(requeued.retries, 1);
        assert!(requeued.dispatched_at.is_none());
        // force it stale again, now over the retry budget → dead-letter
        sqlx::query(
            "UPDATE tasks SET status = 'dispatched'::task_status, \
             dispatched_at = now() - interval '1 day' WHERE id = $1",
        )
        .bind(c2.id)
        .execute(&pool)
        .await
        .unwrap();
        let sweep = task::sweep_timeouts(
            &pool,
            task::SweepConfig {
                grace_seconds: 60,
                dead_letter_retries: 1,
            },
        )
        .await
        .unwrap();
        assert_eq!(sweep.dead_lettered, vec![c2.id]);

        // --- enrollment ---------------------------------------------------
        let tok = enrollment::create_token(
            &pool,
            enrollment::EnrollmentTokenNew {
                token_hash: format!("eth-{k}"),
                label: "fleet".into(),
                created_by: admin.id,
                ttl_seconds: 0,
                max_uses: 1,
                auto_approve: true,
            },
        )
        .await
        .unwrap();
        assert!(tok.is_usable(now));
        assert_eq!(enrollment::list_tokens(&pool).await.unwrap().len(), 1);
        let out = enrollment::create_vm_on_enroll(
            &pool,
            &format!("eth-{k}"),
            enrollment::EnrollVmParams {
                name: format!("vm2-{k}"),
                hostname: None,
                ip_address: Some("10.0.0.2".into()),
                arch: WorkerArch::Arm64,
                os_info: serde_json::json!({"os": "linux"}),
                worker_version: Some("v1.4.0".into()),
                worker_secret_hash: "sh".into(),
            },
        )
        .await
        .unwrap();
        assert_eq!(out.vm.state, VMState::Active, "auto_approve → ACTIVE");
        assert_eq!(out.token.uses_count, 1);
        // one-time token is spent
        assert!(enrollment::consume_token(&pool, &format!("eth-{k}"))
            .await
            .unwrap()
            .is_none());
        enrollment::revoke_token(&pool, tok.id).await.unwrap();
        assert!(enrollment::get_by_token_hash(&pool, &format!("eth-{k}"))
            .await
            .unwrap()
            .unwrap()
            .revoked_at
            .is_some());

        // --- mcp tokens ----------------------------------------------------
        let mt = mcp_token::create(
            &pool,
            mcp_token::McpTokenNew {
                user_id: admin.id,
                token_hash: format!("mth-{k}"),
                name: "ci".into(),
                allowed_ip: Some("10.0.0.0/8".into()),
            },
        )
        .await
        .unwrap();
        assert!(
            mcp_token::get_active_by_token_hash(&pool, &format!("mth-{k}"))
                .await
                .unwrap()
                .is_some()
        );
        assert_eq!(
            mcp_token::list_for_user(&pool, admin.id, true)
                .await
                .unwrap()
                .len(),
            1
        );
        mcp_token::touch_last_used(&pool, mt.id, now).await.unwrap();
        mcp_token::set_allowed_ip(&pool, mt.id, admin.id, None)
            .await
            .unwrap();
        assert!(mcp_token::revoke(&pool, mt.id, admin.id).await.unwrap());
        assert!(!mcp_token::revoke(&pool, mt.id, admin.id).await.unwrap());

        // --- webauthn + backup codes ---------------------------------------
        let ch = webauthn::create_challenge(
            &pool,
            &format!("chal-{k}"),
            Some(admin.id),
            "login",
            now + Duration::minutes(5),
        )
        .await
        .unwrap();
        assert!(
            webauthn::consume_challenge(&pool, &format!("chal-{k}"), "login")
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            webauthn::consume_challenge(&pool, &format!("chal-{k}"), "login")
                .await
                .unwrap()
                .is_none(),
            "challenge is single-use"
        );
        assert_eq!(ch.purpose, "login");

        let cred = webauthn::create_credential(
            &pool,
            webauthn::CredentialNew {
                user_id: admin.id,
                name: "Touch ID".into(),
                credential_id: format!("cid-{k}"),
                public_key: vec![1, 2, 3],
                sign_count: 0,
                transports: Some(serde_json::json!(["internal"])),
                aaguid: None,
            },
        )
        .await
        .unwrap();
        assert_eq!(
            webauthn::count_credentials(&pool, admin.id).await.unwrap(),
            1
        );
        assert!(
            webauthn::get_credential_by_credential_id(&pool, &format!("cid-{k}"))
                .await
                .unwrap()
                .is_some()
        );
        webauthn::update_credential_usage(&pool, cred.id, 5, now)
            .await
            .unwrap()
            .unwrap();
        webauthn::rename_credential(&pool, cred.id, "YubiKey")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            webauthn::list_credentials(&pool, admin.id)
                .await
                .unwrap()
                .len(),
            1
        );

        webauthn::replace_backup_codes(&pool, admin.id, &[format!("bh-{k}")])
            .await
            .unwrap();
        assert!(
            webauthn::consume_backup_code(&pool, admin.id, &format!("bh-{k}"))
                .await
                .unwrap()
        );
        assert!(
            !webauthn::consume_backup_code(&pool, admin.id, &format!("bh-{k}"))
                .await
                .unwrap()
        );
        webauthn::delete_backup_codes(&pool, admin.id)
            .await
            .unwrap();
        assert!(webauthn::delete_credential(&pool, cred.id, admin.id)
            .await
            .unwrap());
        assert_eq!(
            webauthn::delete_credentials_for_user(&pool, admin.id)
                .await
                .unwrap(),
            0
        );

        // --- audit chain ---------------------------------------------------
        let head0 = audit::chain_head(&pool).await.unwrap();
        assert_eq!(head0, audit::GENESIS_HASH);
        let mut entry = audit::AuditNew::new(ActorType::User, "admin", "vm.approve");
        entry.vm_id = Some(v.id);
        let row =
            audit::append_chained(&pool, entry, |_e, prev| (prev.to_string(), "d".repeat(64)))
                .await
                .unwrap();
        assert_eq!(row.prev_hash, audit::GENESIS_HASH);
        assert_eq!(audit::chain_head(&pool).await.unwrap(), "d".repeat(64));
        audit::append(
            &pool,
            audit::AuditNew::new(ActorType::System, "sweeper", "task.sweep"),
            "h0".into(),
            "h1".into(),
        )
        .await
        .unwrap();
        assert_eq!(audit::get_all_ordered(&pool).await.unwrap().len(), 2);
        assert_eq!(
            audit::list_filtered(&pool, Some(v.id), None, 10)
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            audit::list_filtered(&pool, None, Some("task.sweep"), 10)
                .await
                .unwrap()
                .len(),
            1
        );

        // --- scheduled commands ---------------------------------------------
        let sched = scheduled_command::create(
            &pool,
            scheduled_command::ScheduledCommandNew {
                name: format!("nightly-{k}"),
                enabled: true,
                target_kind: "all_active".into(),
                target_vm_id: None,
                target_tag_id: None,
                task_kind: "action".into(),
                action_name: Some("reboot".into()),
                params: serde_json::json!({}),
                command: None,
                cron_expression: "0 3 * * *".into(),
                created_by: Some(admin.id),
            },
        )
        .await
        .unwrap();
        assert_eq!(
            scheduled_command::list_enabled(&pool).await.unwrap().len(),
            1
        );
        scheduled_command::set_last_run_at(&pool, sched.id, now)
            .await
            .unwrap()
            .unwrap();
        scheduled_command::update(
            &pool,
            sched.id,
            scheduled_command::ScheduledCommandPatch {
                enabled: Some(false),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert!(scheduled_command::delete(&pool, sched.id).await.unwrap());

        // --- VM lifecycle: revoke + delete (dependents cleared) --------------
        let tasks_before = sqlx::query_as::<_, (i64,)>("SELECT count(*) FROM tasks")
            .fetch_one(&pool)
            .await
            .unwrap()
            .0;
        assert!(tasks_before > 0);
        let v = vm::revoke(&pool, v.id).await.unwrap().unwrap();
        assert_eq!(v.state, VMState::Revoked);
        assert!(v.worker_secret_hash.is_none());
        assert!(vm::set_exec_mode(&pool, v.id, ExecMode::Whitelist)
            .await
            .is_err());
        vm::delete(&pool, v.id).await.unwrap();
        assert!(vm::get_by_id(&pool, v.id).await.unwrap().is_none());
        let tasks_after = sqlx::query_as::<_, (i64,)>("SELECT count(*) FROM tasks")
            .fetch_one(&pool)
            .await
            .unwrap()
            .0;
        assert_eq!(tasks_after, 0, "tasks of a deleted VM are removed");
        // delete of a non-revoked VM is refused
        let vm3 = vm::create(&pool, vm::VmNew::new(format!("vm3-{k}"), WorkerArch::Amd64))
            .await
            .unwrap();
        assert!(vm::delete(&pool, vm3.id).await.is_err());

        // --- offline sweep ---------------------------------------------------
        let mut vm4 = vm::VmNew::new(format!("vm4-{k}"), WorkerArch::Amd64);
        vm4.state = VMState::Active;
        let vm4 = vm::create(&pool, vm4).await.unwrap();
        sqlx::query("UPDATE vms SET last_heartbeat_at = now() - interval '1 hour' WHERE id = $1")
            .bind(vm4.id)
            .execute(&pool)
            .await
            .unwrap();
        let gone = vm::sweep_offline_vms(&pool, 120).await.unwrap();
        assert_eq!(gone.len(), 1);
        assert_eq!(gone[0].state, VMState::Offline);

        // --- cleanup --------------------------------------------------------
        tag::delete_tag(&pool, t1.id).await.unwrap();
        custom_action::remove(&pool, action.id).await.unwrap();
    }
}
