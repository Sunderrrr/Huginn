//! PostgreSQL access: connection pool, migrations, and the shared DB error type.
//!
//! The schema is managed by `migrations/0001_baseline.sql`, generated from the
//! Python hub's Alembic head (`n4c5d6e7f8a9`) — so a database migrated by the
//! Rust hub and one migrated by the Python hub are interchangeable. The
//! migration also stamps `alembic_version` so the Python hub's Alembic sees the
//! database as fully migrated.

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

/// Embedded migration set (migrations/0001_baseline.sql).
pub const MIGRATIONS: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// Serializes live-database tests (they reset the `public` schema).
#[cfg(test)]
pub(crate) static LIVE_DB_GUARD: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Errors surfaced by the data layer.
#[derive(Debug, thiserror::Error)]
pub enum DbError {
    /// A database/query error (connection, constraint, decoding, ...).
    #[error("database error: {0}")]
    Sqlx(#[from] sqlx::Error),
    /// A migration failure.
    #[error("migration error: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
    /// The requested row does not exist.
    #[error("not found")]
    NotFound,
    /// A uniqueness/ownership conflict (e.g. duplicate name).
    #[error("conflict: {0}")]
    Conflict(String),
    /// The operation is invalid for the row's current state.
    #[error("invalid: {0}")]
    Invalid(String),
}

impl DbError {
    /// True when the error is a PostgreSQL unique_violation (23505) — e.g. a
    /// duplicate username or the (vm_id, idempotency_key) task index.
    pub fn is_unique_violation(&self) -> bool {
        matches!(self, DbError::Sqlx(sqlx::Error::Database(e)) if e.code().as_deref() == Some("23505"))
    }
}

/// Build a pool with the given maximum size (maps to the Python hub's
/// `pool_size + max_overflow`).
pub fn pool_options(max_connections: u32) -> PgPoolOptions {
    PgPoolOptions::new()
        .max_connections(max_connections.max(1))
        // Close idle sessions. A PostgreSQL "smart shutdown" (what SIGTERM asks
        // for) waits for every open client connection, and a pool that keeps
        // its connections forever leaves the database waiting on a session
        // that never goes away: the container stays up but answers nothing.
        .idle_timeout(Some(std::time::Duration::from_secs(60)))
        // And recycle the connections themselves, so a long-lived hub does
        // not pin one backend forever.
        .max_lifetime(Some(std::time::Duration::from_secs(1800)))
}

/// Connect to PostgreSQL with a bounded pool.
pub async fn connect(database_url: &str, max_connections: u32) -> Result<PgPool, DbError> {
    let pool = pool_options(max_connections).connect(database_url).await?;
    Ok(pool)
}

/// Alembic revision of the baseline schema (`hub-rs/migrations/0001_baseline.sql`
/// was dumped from it; stamped back into `alembic_version`).
const BASELINE_ALEMBIC_REV: &str = "n4c5d6e7f8a9";

/// Apply every pending migration (idempotent; checksum-verified).
///
/// Coexistence with the Python hub: a database already initialized by Alembic
/// at the baseline revision has the *identical* schema, so the baseline is
/// recorded as applied (with the exact checksum sqlx would store) instead of
/// replaying DDL against existing tables. Migrations *after* the baseline
/// (0002+, the hub-rs extensions Alembic does not know about) then run on top.
/// Fresh databases run normally.
pub async fn run_migrations(pool: &PgPool) -> Result<(), DbError> {
    if alembic_at_baseline(pool).await? {
        // Idempotent: CREATE IF NOT EXISTS + INSERT ON CONFLICT DO NOTHING.
        record_baseline_applied(pool).await?;
        return MIGRATIONS.run(pool).await.map_err(Into::into);
    }
    MIGRATIONS.run(pool).await?;
    Ok(())
}

async fn alembic_at_baseline(pool: &PgPool) -> Result<bool, DbError> {
    // A fresh database has no `alembic_version` table at all: undefined_table
    // (42P01) simply means "not initialized by Alembic" — run sqlx migrations.
    let row: Option<(String,)> =
        match sqlx::query_as("SELECT version_num FROM alembic_version WHERE version_num = $1")
            .bind(BASELINE_ALEMBIC_REV)
            .fetch_optional(pool)
            .await
        {
            Ok(row) => row,
            Err(sqlx::Error::Database(db)) if db.code().as_deref() == Some("42P01") => {
                return Ok(false)
            }
            Err(e) => return Err(e.into()),
        };
    Ok(row.is_some())
}

/// Create sqlx's migrator table and record the baseline row exactly like
/// `Migrator::run` would (same columns, same checksum source).
async fn record_baseline_applied(pool: &PgPool) -> Result<(), DbError> {
    let migration = MIGRATIONS
        .migrations
        .iter()
        .find(|m| m.version == 1)
        .ok_or_else(|| DbError::Invalid("baseline migration missing".into()))?;
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS _sqlx_migrations ( \
             version BIGINT PRIMARY KEY, \
             description TEXT NOT NULL, \
             installed_on TIMESTAMPTZ NOT NULL DEFAULT now(), \
             success BOOLEAN NOT NULL, \
             checksum BYTEA NOT NULL, \
             execution_time BIGINT NOT NULL)",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "INSERT INTO _sqlx_migrations \
             (version, description, installed_on, success, checksum, execution_time) \
             VALUES ($1, $2, now(), true, $3, 0) \
             ON CONFLICT (version) DO NOTHING",
    )
    .bind(migration.version)
    .bind(&*migration.description)
    .bind(&*migration.checksum)
    .execute(pool)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pool_size_is_clamped_to_at_least_one() {
        assert_eq!(pool_options(0).get_max_connections(), 1);
        assert_eq!(pool_options(20).get_max_connections(), 20);
    }

    #[test]
    fn unique_violation_detection_only_matches_23505() {
        let plain = DbError::NotFound;
        assert!(!plain.is_unique_violation());
        assert!(matches!(
            DbError::Conflict("x".into()),
            DbError::Conflict(_)
        ));
    }

    /// Applies the embedded baseline migration against a live PostgreSQL
    /// (skipped unless HUGINN_TEST_DATABASE_URL is set — `cargo test` stays
    /// green without a database).
    #[tokio::test]
    async fn baseline_migration_applies() {
        let Ok(url) = std::env::var("HUGINN_TEST_DATABASE_URL") else {
            eprintln!("skipped: HUGINN_TEST_DATABASE_URL not set");
            return;
        };
        let _guard = crate::db::LIVE_DB_GUARD.lock().await;
        let pool = connect(&url, 2).await.expect("connect");
        sqlx::query("DROP SCHEMA public CASCADE")
            .execute(&pool)
            .await
            .expect("drop schema");
        sqlx::query("CREATE SCHEMA public")
            .execute(&pool)
            .await
            .expect("create schema");
        run_migrations(&pool).await.expect("migrations");
        let (tables,): (i64,) = sqlx::query_as(
            "SELECT count(*) FROM information_schema.tables \
             WHERE table_schema = 'public' AND table_name != '_sqlx_migrations'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(tables, 17, "baseline schema has 17 tables");
        let (stamp,): (String,) = sqlx::query_as("SELECT version_num FROM public.alembic_version")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(stamp, "n4c5d6e7f8a9", "alembic head is stamped");
    }
}
