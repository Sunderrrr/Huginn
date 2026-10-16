//! Database backups → S3-compatible object storage.
//!
//! One backup is a gzip-compressed SQL dump of the whole `public` schema
//! ([`dump`]), uploaded under a configurable key prefix with a SigV4-signed
//! PUT ([`s3`] / [`sigv4`]). Object names are `huginn-db-YYYYMMDDTHHMMSSZ.sql.gz`
//! and `backup_s3_retention_days` keeps the bucket tidy.
//!
//! Three entry points:
//!
//! * [`run_backup`] / [`list_backups`] / [`delete_backup`] — the admin API
//!   (`routes/admin/backups.rs`) drives these through the [`BackupBackend`]
//!   trait (production: [`PgBackup`]; tests swap in a mock);
//! * [`apply_retention`] — delete objects older than the retention window;
//! * [`sweep_backup`] — **the sweeper hook** (called from `main.rs`'s 30 s
//!   loop): one daily automatic backup at [`SCHEDULE_HOUR_UTC`] plus retention.
//!   It is strictly best-effort: it never returns an error and never panics,
//!   so a dead bucket or a dead database cannot take the sweeper down.

use std::future::Future;
use std::pin::Pin;

use chrono::{DateTime, NaiveDate, Utc};
use serde::Serialize;
use sqlx::PgPool;

use crate::db::DbError;
use crate::models::setting::Setting;

pub mod dump;
pub mod s3;
pub mod sigv4;

pub use s3::{BackupObject, ObjectHead, S3Client, S3Config};

/// Errors of the backup pipeline. `Display` strings are pre-sanitized: the
/// S3 secret key never appears in them ([`S3Config::sanitize`]).
#[derive(Debug, thiserror::Error)]
pub enum BackupError {
    /// No bucket/credentials configured at all.
    #[error("backup storage is not configured")]
    NotConfigured,
    /// The configuration is incomplete or unsafe (e.g. a non-loopback `http://`
    /// endpoint).
    #[error("invalid backup configuration: {0}")]
    Config(String),
    /// The SQL export failed.
    #[error("database export failed: {0}")]
    Export(String),
    /// The storage request failed before a response arrived.
    #[error("backup storage request failed: {0}")]
    Transport(String),
    /// The storage answered with a non-2xx status.
    #[error("backup storage returned HTTP {status}: {code}")]
    Http { status: u16, code: String },
    /// The database layer failed outside of the export itself.
    #[error("database error: {0}")]
    Db(#[from] DbError),
}

/// What one backup produced — the shape `POST /api/backups` returns.
#[derive(Debug, Clone, Serialize)]
pub struct BackupOutcome {
    pub name: String,
    pub size: u64,
    pub duration_ms: u64,
}

/// Boxed future returned by [`BackupBackend`] (dyn-compatible async trait).
pub type BackupFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The storage/database backend behind the backup routes.
///
/// The routes own the policy (settings → [`S3Config`], audit, rate limits);
/// the backend owns the mechanics (dump + S3). Tests inject an in-memory
/// implementation through an axum `Extension`.
pub trait BackupBackend: Send + Sync {
    fn list<'a>(
        &'a self,
        cfg: &'a S3Config,
    ) -> BackupFuture<'a, Result<Vec<BackupObject>, BackupError>>;

    fn create<'a>(
        &'a self,
        cfg: &'a S3Config,
    ) -> BackupFuture<'a, Result<BackupOutcome, BackupError>>;

    fn delete<'a>(
        &'a self,
        cfg: &'a S3Config,
        name: &'a str,
    ) -> BackupFuture<'a, Result<(), BackupError>>;
}

/// Production backend: SQL export from this hub's database, S3 storage.
pub struct PgBackup {
    pool: PgPool,
}

impl PgBackup {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Build the backend straight from a database URL (the admin routes only
    /// have [`crate::config::Config`]; the pool is lazy, so listing/deleting
    /// backups never touches the database).
    pub fn from_database_url(database_url: &str) -> Result<Self, BackupError> {
        let url = normalize_database_url(database_url);
        let pool = crate::db::pool_options(4)
            .connect_lazy(url.as_ref())
            .map_err(|_| BackupError::Config("invalid database URL".into()))?;
        Ok(Self::new(pool))
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

impl BackupBackend for PgBackup {
    fn list<'a>(
        &'a self,
        cfg: &'a S3Config,
    ) -> BackupFuture<'a, Result<Vec<BackupObject>, BackupError>> {
        Box::pin(async move { list_backups(cfg).await })
    }

    fn create<'a>(
        &'a self,
        cfg: &'a S3Config,
    ) -> BackupFuture<'a, Result<BackupOutcome, BackupError>> {
        Box::pin(async move { run_backup(&self.pool, cfg).await })
    }

    fn delete<'a>(
        &'a self,
        cfg: &'a S3Config,
        name: &'a str,
    ) -> BackupFuture<'a, Result<(), BackupError>> {
        Box::pin(async move { delete_backup(cfg, name).await })
    }
}

/// sqlx speaks `postgres://`/`postgresql://`; deployment URLs copied from the
/// Python hub may carry a driver suffix (`postgresql+asyncpg://…`). Strip it
/// rather than failing — the password never appears in any error.
fn normalize_database_url(url: &str) -> std::borrow::Cow<'_, str> {
    for scheme in [
        "postgresql+asyncpg://",
        "postgres+asyncpg://",
        "postgresql+psycopg2://",
    ] {
        if let Some(rest) = url.strip_prefix(scheme) {
            return std::borrow::Cow::Owned(format!("postgresql://{rest}"));
        }
    }
    std::borrow::Cow::Borrowed(url)
}

// ---------------------------------------------------------------------------
// Object naming / validation
// ---------------------------------------------------------------------------

/// Object name of one backup: `huginn-db-YYYYMMDDTHHMMSSZ.sql.gz` (UTC).
pub fn backup_object_name(now: DateTime<Utc>) -> String {
    format!("huginn-db-{}Z.sql.gz", now.format("%Y%m%dT%H%M%S"))
}

/// True for names [`backup_object_name`] produces — the only names the API
/// will delete (no path traversal, no arbitrary keys).
pub fn is_valid_object_name(name: &str) -> bool {
    name.starts_with("huginn-db-")
        && name.len() <= 255
        && name.ends_with(".sql.gz")
        && !name.contains("..")
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

/// Export the database and upload it as one gzip object.
pub async fn run_backup(pool: &PgPool, cfg: &S3Config) -> Result<BackupOutcome, BackupError> {
    cfg.validate()?;
    let started = std::time::Instant::now();
    let name = backup_object_name(Utc::now());
    let dump = dump::export_gzip(pool).await?;
    let size = dump.len() as u64;
    let client = S3Client::new(cfg.clone())?;
    client.put_object(&cfg.object_key(&name), dump).await?;
    Ok(BackupOutcome {
        name,
        size,
        duration_ms: started.elapsed().as_millis() as u64,
    })
}

/// List the backup objects under the configured prefix (newest first).
pub async fn list_backups(cfg: &S3Config) -> Result<Vec<BackupObject>, BackupError> {
    cfg.validate()?;
    let client = S3Client::new(cfg.clone())?;
    let mut objects = client.list_objects().await?;
    objects.sort_by(|a, b| b.name.cmp(&a.name));
    Ok(objects)
}

/// Delete one backup object by its [`BackupObject::name`].
pub async fn delete_backup(cfg: &S3Config, name: &str) -> Result<(), BackupError> {
    cfg.validate()?;
    if !is_valid_object_name(name) {
        return Err(BackupError::Config("invalid backup name".into()));
    }
    let client = S3Client::new(cfg.clone())?;
    client.delete_object(&cfg.object_key(name)).await
}

/// Delete every backup older than `retention_days` (0 = keep forever).
/// Returns how many objects were deleted.
pub async fn apply_retention(
    cfg: &S3Config,
    retention_days: i32,
    now: DateTime<Utc>,
) -> Result<usize, BackupError> {
    if retention_days <= 0 {
        return Ok(0);
    }
    cfg.validate()?;
    let client = S3Client::new(cfg.clone())?;
    let expired = select_expired(&client.list_objects().await?, retention_days, now);
    let mut deleted = 0;
    for object in &expired {
        client.delete_object(&cfg.object_key(&object.name)).await?;
        deleted += 1;
    }
    Ok(deleted)
}

/// The objects past the retention window (pure, so the policy is testable).
pub fn select_expired(
    objects: &[BackupObject],
    retention_days: i32,
    now: DateTime<Utc>,
) -> Vec<BackupObject> {
    if retention_days <= 0 {
        return Vec::new();
    }
    let cutoff = now - chrono::Duration::days(i64::from(retention_days));
    objects
        .iter()
        .filter(|object| object.last_modified < cutoff)
        .cloned()
        .collect()
}

// ---------------------------------------------------------------------------
// Sweeper hook
// ---------------------------------------------------------------------------

/// Hour (UTC) of the daily automatic backup.
pub const SCHEDULE_HOUR_UTC: u32 = 3;

/// One day-marker per process: the automatic slot is claimed once, successes
/// and failures alike (no retry storms every 30 s when S3 is down).
static LAST_ATTEMPT: std::sync::Mutex<Option<NaiveDate>> = std::sync::Mutex::new(None);

/// Outcome of one sweeper tick — purely informational, [`sweep_backup`]
/// itself never fails.
#[derive(Debug, Default)]
pub struct SweepReport {
    /// Why nothing ran: `disabled`, `not-due`, `already-attempted`,
    /// `not-configured`, `settings-unavailable`.
    pub skipped: Option<&'static str>,
    pub backup: Option<Result<BackupOutcome, BackupError>>,
    pub retention: Option<Result<usize, BackupError>>,
}

/// Sweeper entry point — **wire this into `main.rs`'s 30 s loop**:
///
/// ```ignore
/// crate::services::backup::sweep_backup(&pool).await;
/// ```
///
/// Best-effort by construction: every failure is logged and reported, never
/// propagated.
pub async fn sweep_backup(pool: &PgPool) -> SweepReport {
    sweep_backup_at(pool, Utc::now()).await
}

/// [`sweep_backup`] with a fixed clock (tests).
pub async fn sweep_backup_at(pool: &PgPool, now: DateTime<Utc>) -> SweepReport {
    let mut report = SweepReport::default();
    let row: Setting = match crate::models::setting::get_settings_row(pool).await {
        Ok(Some(row)) => row,
        Ok(None) => {
            report.skipped = Some("not-configured");
            return report;
        }
        Err(e) => {
            tracing::warn!("backup sweep: settings unavailable: {e}");
            report.skipped = Some("settings-unavailable");
            return report;
        }
    };
    if !row.backup_s3_enabled {
        report.skipped = Some("disabled");
        return report;
    }
    if !is_due(now) {
        report.skipped = Some("not-due");
        return report;
    }
    if !claim_attempt(now.date_naive()) {
        report.skipped = Some("already-attempted");
        return report;
    }
    let cfg = match S3Config::from_settings(&row) {
        Ok(cfg) => cfg,
        Err(e) => {
            tracing::warn!("backup sweep: invalid S3 configuration: {e}");
            report.skipped = Some("not-configured");
            return report;
        }
    };

    // Restart-safe de-duplication: if today's backup already exists (e.g. the
    // process restarted after a successful run, or an admin made one by hand),
    // don't create a second one. A failing LIST must not block the backup.
    let stamp = now.format("%Y%m%d").to_string();
    match list_backups(&cfg).await {
        Ok(objects)
            if objects
                .iter()
                .any(|o| o.name.starts_with(&format!("huginn-db-{stamp}"))) =>
        {
            tracing::info!("backup sweep: a backup for {stamp} already exists");
        }
        Ok(_) => {
            report.backup = Some(run_backup(pool, &cfg).await);
            if let Some(Err(e)) = &report.backup {
                tracing::warn!("backup sweep: automatic backup failed: {e}");
            }
        }
        Err(e) => {
            tracing::warn!("backup sweep: listing backups failed, backing up anyway: {e}");
            report.backup = Some(run_backup(pool, &cfg).await);
            if let Some(Err(e)) = &report.backup {
                tracing::warn!("backup sweep: automatic backup failed: {e}");
            }
        }
    }

    report.retention = Some(apply_retention(&cfg, row.backup_s3_retention_days, now).await);
    if let Some(Err(e)) = &report.retention {
        tracing::warn!("backup sweep: retention failed: {e}");
    }
    report
}

/// True once the daily slot (≥ [`SCHEDULE_HOUR_UTC`]:00 UTC) is reached.
pub fn is_due(now: DateTime<Utc>) -> bool {
    let Some(scheduled) = now.date_naive().and_hms_opt(SCHEDULE_HOUR_UTC, 0, 0) else {
        return false;
    };
    now.naive_utc() >= scheduled
}

/// Claim today's attempt slot: `true` only for the first caller of the day.
fn claim_attempt(date: NaiveDate) -> bool {
    let mut last = LAST_ATTEMPT.lock().unwrap_or_else(|e| e.into_inner());
    if *last == Some(date) {
        return false;
    }
    *last = Some(date);
    true
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use super::*;

    #[test]
    fn object_names_are_stamped_and_validated() {
        let now = chrono::TimeZone::with_ymd_and_hms(&Utc, 2026, 1, 2, 3, 4, 5)
            .single()
            .unwrap();
        assert_eq!(backup_object_name(now), "huginn-db-20260102T030405Z.sql.gz");
        assert!(is_valid_object_name("huginn-db-20260102T030405Z.sql.gz"));
        // No arbitrary keys through the delete endpoint.
        for bad in [
            "",
            "other.sql.gz",
            "x.sql",
            "../etc/passwd.sql.gz",
            "a/b.sql.gz",
            "/abs.sql.gz",
            "huginn-db.sql.gz;rm",
            "hünion.sql.gz",
        ] {
            assert!(!is_valid_object_name(bad), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn due_window_starts_at_the_fixed_hour_utc() {
        let day = |h, m, s| {
            chrono::TimeZone::with_ymd_and_hms(&Utc, 2026, 3, 1, h, m, s)
                .single()
                .unwrap()
        };
        assert!(!is_due(day(2, 59, 59)));
        assert!(is_due(day(3, 0, 0)));
        assert!(is_due(day(3, 0, 30)));
        assert!(is_due(day(12, 0, 0))); // catch-up after downtime
    }

    #[test]
    fn retention_selects_only_expired_objects() {
        let now = chrono::TimeZone::with_ymd_and_hms(&Utc, 2026, 3, 10, 0, 0, 0)
            .single()
            .unwrap();
        let object = |name: &str, days_ago: i64| BackupObject {
            name: name.to_owned(),
            size: 1,
            last_modified: now - chrono::Duration::days(days_ago),
        };
        let objects = vec![
            object("huginn-db-20260309T030000Z.sql.gz", 1),
            object("huginn-db-20260301T030000Z.sql.gz", 9),
            object("huginn-db-20260201T030000Z.sql.gz", 37),
        ];
        let expired = select_expired(&objects, 30, now);
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].name, "huginn-db-20260201T030000Z.sql.gz");
        // 0 = keep forever.
        assert!(select_expired(&objects, 0, now).is_empty());
    }

    #[test]
    fn database_url_normalization_strips_the_python_driver_suffix() {
        assert_eq!(
            normalize_database_url("postgresql+asyncpg://u:p@db/huginn"),
            "postgresql://u:p@db/huginn"
        );
        assert_eq!(
            normalize_database_url("postgres://u:p@db/huginn"),
            "postgres://u:p@db/huginn"
        );
    }

    /// A dead database must degrade into a report, never a failure.
    #[tokio::test]
    async fn sweep_is_best_effort_when_the_database_is_unreachable() {
        let pool = crate::db::pool_options(1)
            .connect_lazy("postgres://nobody@127.0.0.1:1/huginn")
            .unwrap();
        let report = sweep_backup(&pool).await;
        assert_eq!(report.skipped, Some("settings-unavailable"));
        assert!(report.backup.is_none());
        assert!(report.retention.is_none());
    }

    /// The whole pipeline against a live PostgreSQL (skipped unless
    /// HUGINN_TEST_DATABASE_URL is set): export → psql restore → identical
    /// schema, rows and sequence values.
    #[tokio::test]
    async fn sql_export_round_trips_through_psql() {
        let Ok(url) = std::env::var("HUGINN_TEST_DATABASE_URL") else {
            eprintln!("skipped: HUGINN_TEST_DATABASE_URL not set");
            return;
        };
        let _guard = crate::db::LIVE_DB_GUARD.lock().await;
        let pool = crate::db::connect(&url, 2).await.expect("connect");
        reset_schema(&pool).await;
        crate::db::run_migrations(&pool).await.expect("migrations");
        seed_tricky_rows(&pool).await;

        let gz = dump::export_gzip(&pool).await.expect("export");
        assert_eq!(&gz[..2], &[0x1f, 0x8b], "the artifact is gzip");
        let sql = {
            let mut decoded = Vec::new();
            flate2::read::GzDecoder::new(&gz[..])
                .read_to_end(&mut decoded)
                .expect("gunzip");
            String::from_utf8(decoded).expect("utf-8 dump")
        };
        // Structure of a psql-restorable script.
        assert!(sql.contains("CREATE TABLE settings"));
        assert!(sql.contains("CREATE TYPE task_type AS ENUM"));
        assert!(sql.contains("COPY settings (id,"));
        assert!(sql.contains("\\.\n"), "COPY blocks are terminated");
        assert!(sql.contains("ALTER TABLE ONLY settings ADD CONSTRAINT settings_pkey"));
        // The seeded rows used the audit sequence; its value must be restored.
        assert!(sql.contains("SELECT pg_catalog.setval('audit_log_id_seq'"));
        assert!(sql.trim_end().ends_with("COMMIT;"));

        // Restore into a throwaway database with the real psql.
        let restore_url = create_restore_database(&url).await;
        let dump_path = std::env::temp_dir().join("huginn-backup-roundtrip.sql");
        std::fs::write(&dump_path, &sql).expect("write dump");
        let output = std::process::Command::new("psql")
            .arg(&restore_url)
            .arg("-v")
            .arg("ON_ERROR_STOP=1")
            .arg("-q")
            .arg("-f")
            .arg(&dump_path)
            .output()
            .expect("psql runs");
        assert!(
            output.status.success(),
            "psql restore failed: {}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );

        // Same schema, same rows, same sequence values.
        let restore = crate::db::connect(&restore_url, 2)
            .await
            .expect("connect restore");
        assert_same_contents(&pool, &restore).await;

        drop(restore);
        let _ = std::fs::remove_file(&dump_path);
        drop_database(&url, restore_db_name()).await;
    }

    /// The migration coexistence path: a database initialized by the Python
    /// hub's Alembic (baseline stamped, no `_sqlx_migrations`) still gets
    /// `0002` — and the backup columns with it.
    #[tokio::test]
    async fn alembic_initialized_databases_get_the_backup_columns() {
        let Ok(url) = std::env::var("HUGINN_TEST_DATABASE_URL") else {
            eprintln!("skipped: HUGINN_TEST_DATABASE_URL not set");
            return;
        };
        let _guard = crate::db::LIVE_DB_GUARD.lock().await;
        let pool = crate::db::connect(&url, 2).await.expect("connect");
        reset_schema(&pool).await;
        crate::db::run_migrations(&pool).await.expect("migrations");
        // Back to "Alembic only": the schema is at the baseline revision and
        // sqlx has never recorded anything.
        sqlx::query("DROP TABLE _sqlx_migrations")
            .execute(&pool)
            .await
            .expect("drop sqlx migrator table");

        crate::db::run_migrations(&pool).await.expect("migrations");
        let (applied,): (i64,) = sqlx::query_as("SELECT count(*) FROM _sqlx_migrations")
            .fetch_one(&pool)
            .await
            .unwrap();
        // The baseline is recorded once and every post-baseline migration
        // (0002+) applies on top of it.
        assert_eq!(
            applied as usize,
            crate::db::MIGRATIONS.migrations.len(),
            "baseline recorded + post-baseline migrations applied"
        );
        let (columns,): (i64,) = sqlx::query_as(
            "SELECT count(*) FROM information_schema.columns \
             WHERE table_schema = 'public' AND table_name = 'settings' \
               AND column_name LIKE 'backup\\_s3\\_%'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(columns, 8, "the 0002 backup columns exist");
    }

    fn restore_db_name() -> String {
        "huginn_backup_restore_test".to_owned()
    }

    async fn reset_schema(pool: &PgPool) {
        sqlx::query("DROP SCHEMA public CASCADE")
            .execute(pool)
            .await
            .expect("drop schema");
        sqlx::query("CREATE SCHEMA public")
            .execute(pool)
            .await
            .expect("create schema");
    }

    /// Rows with every shape that breaks naive dumps: unicode, newlines,
    /// tabs, quotes, backslashes, NULLs, jsonb and enum values.
    async fn seed_tricky_rows(pool: &PgPool) {
        let values = crate::models::setting::SettingValues {
            target_worker_version: "v1.2.3\ttab\nnewline 'quote' \"dq\" \\backslash\\ éü 中".into(),
            allowed_release_domains: serde_json::json!([
                "github.com",
                "objects.githubusercontent.com"
            ]),
            backup_s3_enabled: true,
            backup_s3_bucket: "huginn-backups".into(),
            backup_s3_prefix: "db/backups".into(),
            backup_s3_access_key: "AKIDEXAMPLE".into(),
            backup_s3_secret_key: Some("write-only-secret".into()),
            backup_s3_retention_days: 7,
            ..Default::default()
        };
        crate::models::setting::upsert(pool, values)
            .await
            .expect("settings");

        crate::models::tag::create_tag(pool, "prød 'tag' \n", "#a1b2c3")
            .await
            .expect("tag");

        let mut user = crate::models::user::UserNew::new("ådmin üser");
        user.role = crate::models::enums::UserRole::Admin;
        user.is_active = true;
        crate::models::user::create(pool, user).await.expect("user");

        let mut audit = crate::models::audit::AuditNew::new(
            crate::models::enums::ActorType::System,
            "sweeper".to_owned(),
            "backup_created".to_owned(),
        );
        audit.detail = serde_json::json!({"note": "héllo\nworld\t!", "n": null});
        crate::models::audit::append_chained(pool, audit, |entry, prev| {
            (
                prev.to_owned(),
                crate::security::compute_row_hash(prev, &entry.hash_fields()),
            )
        })
        .await
        .expect("audit");
    }

    async fn create_restore_database(source_url: &str) -> String {
        drop_database(source_url, restore_db_name()).await;
        let admin_url = with_database(source_url, "postgres");
        sqlx::raw_sql(&format!("CREATE DATABASE {}", restore_db_name()))
            .execute(
                &crate::db::connect(&admin_url, 1)
                    .await
                    .expect("admin connect"),
            )
            .await
            .expect("create restore database");
        with_database(source_url, &restore_db_name())
    }

    async fn drop_database(source_url: &str, name: String) {
        let admin_url = with_database(source_url, "postgres");
        let Ok(admin) = crate::db::connect(&admin_url, 1).await else {
            return;
        };
        let _ = sqlx::raw_sql(&format!("DROP DATABASE IF EXISTS {name} WITH (FORCE)"))
            .execute(&admin)
            .await;
    }

    /// Swap the database name of a connection URL (`…:5432/db?opt` → `…:5432/other?opt`).
    fn with_database(url: &str, database: &str) -> String {
        let url = normalize_database_url(url);
        let (head, tail) = match url.split_once('?') {
            Some((head, tail)) => (head, Some(tail)),
            None => (url.as_ref(), None),
        };
        let (prefix, _) = head.rsplit_once('/').unwrap_or((head, ""));
        let mut out = format!("{prefix}/{database}");
        if let Some(tail) = tail {
            out.push('?');
            out.push_str(tail);
        }
        out
    }

    /// Generic content comparison over every table of `public`.
    async fn assert_same_contents(source: &PgPool, restored: &PgPool) {
        let tables: Vec<(String,)> = sqlx::query_as(
            "SELECT table_name FROM information_schema.tables \
             WHERE table_schema = 'public' ORDER BY table_name",
        )
        .fetch_all(source)
        .await
        .unwrap();
        assert!(!tables.is_empty());
        for (table,) in &tables {
            assert_eq!(
                table_fingerprint(source, table).await,
                table_fingerprint(restored, table).await,
                "table {table} differs"
            );
        }
        // Column types, index definitions, sequence values.
        assert_eq!(
            one_column(
                source,
                "SELECT string_agg(table_name || '.' || column_name || ':' || data_type, \
                 ',' ORDER BY table_name, column_name) \
                 FROM information_schema.columns WHERE table_schema = 'public'"
            )
            .await,
            one_column(
                restored,
                "SELECT string_agg(table_name || '.' || column_name || ':' || data_type, \
                 ',' ORDER BY table_name, column_name) \
                 FROM information_schema.columns WHERE table_schema = 'public'"
            )
            .await,
            "column types differ"
        );
        assert_eq!(
            one_column(
                source,
                "SELECT string_agg(indexdef, '|' ORDER BY indexdef) \
                 FROM pg_catalog.pg_indexes WHERE schemaname = 'public'"
            )
            .await,
            one_column(
                restored,
                "SELECT string_agg(indexdef, '|' ORDER BY indexdef) \
                 FROM pg_catalog.pg_indexes WHERE schemaname = 'public'"
            )
            .await,
            "indexes differ"
        );
        let sequences: Vec<(String,)> = sqlx::query_as(
            "SELECT c.relname FROM pg_catalog.pg_class c \
             JOIN pg_catalog.pg_sequence s ON s.seqrelid = c.oid \
             JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace \
             WHERE n.nspname = 'public' ORDER BY c.relname",
        )
        .fetch_all(source)
        .await
        .unwrap();
        for (name,) in sequences {
            assert_eq!(
                sequence_value(source, &name).await,
                sequence_value(restored, &name).await,
                "sequence {name} differs"
            );
        }
    }

    /// Last value of one sequence (`NULL` when it was never advanced).
    async fn sequence_value(pool: &PgPool, name: &str) -> Option<i64> {
        let (value,): (Option<i64>,) = sqlx::query_as(&format!(
            "SELECT pg_catalog.pg_sequence_last_value('{name}'::regclass)"
        ))
        .fetch_one(pool)
        .await
        .unwrap();
        value
    }

    /// `(row_count, md5 of every row's JSON rendering)` for one table.
    async fn table_fingerprint(pool: &PgPool, table: &str) -> (i64, Option<String>) {
        sqlx::query_as(&format!(
            "SELECT count(*), md5(COALESCE(string_agg(t, '|' ORDER BY t), '')) \
             FROM (SELECT row_to_json(q)::text AS t FROM {table} q) rows"
        ))
        .fetch_one(pool)
        .await
        .expect("table fingerprint")
    }

    /// One `SELECT <single text column>` as a string.
    async fn one_column(pool: &PgPool, sql: &str) -> Option<String> {
        let (value,): (Option<String>,) = sqlx::query_as(sql).fetch_one(pool).await.unwrap();
        value
    }
}
