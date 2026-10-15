-- 0002 — backup-to-S3 settings columns (hub-rs feature extension).
--
-- Additive ALTERs only: the Python hub's Alembic head (`n4c5d6e7f8a9`, stamped
-- by 0001_baseline.sql) keeps working — Alembic never learns about these
-- columns, and a database migrated by either hub stays valid for the other.
-- See `db.rs:run_migrations`: a database at the Alembic baseline records
-- 0001 as applied and then applies this migration on top.
--
-- `backup_s3_secret_key` is **write-only**: the API accepts it on
-- `PUT /api/settings` but never serializes it back out (same policy as
-- `ldap_bind_password` / `oidc_client_secret`).

ALTER TABLE public.settings
    ADD COLUMN IF NOT EXISTS backup_s3_enabled boolean DEFAULT false NOT NULL,
    ADD COLUMN IF NOT EXISTS backup_s3_endpoint text DEFAULT '' NOT NULL,
    ADD COLUMN IF NOT EXISTS backup_s3_region text DEFAULT '' NOT NULL,
    ADD COLUMN IF NOT EXISTS backup_s3_bucket text DEFAULT '' NOT NULL,
    ADD COLUMN IF NOT EXISTS backup_s3_prefix text DEFAULT '' NOT NULL,
    ADD COLUMN IF NOT EXISTS backup_s3_access_key text DEFAULT '' NOT NULL,
    ADD COLUMN IF NOT EXISTS backup_s3_secret_key text,
    ADD COLUMN IF NOT EXISTS backup_s3_retention_days integer DEFAULT 30 NOT NULL;
