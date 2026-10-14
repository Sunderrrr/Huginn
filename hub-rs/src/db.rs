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
    PgPoolOptions::new().max_connections(max_connections.max(1))
}

/// Connect to PostgreSQL with a bounded pool.
pub async fn connect(database_url: &str, max_connections: u32) -> Result<PgPool, DbError> {
    let pool = pool_options(max_connections).connect(database_url).await?;
    Ok(pool)
}

/// Apply every pending migration (idempotent; checksum-verified).
pub async fn run_migrations(pool: &PgPool) -> Result<(), DbError> {
    MIGRATIONS.run(pool).await?;
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
