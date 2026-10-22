-- Browser engine auto-update (migrations/0006): opt-in daily check against
-- the Obscura GitHub releases, at a user-defined UTC time, re-pinning the
-- version + per-arch SHA-256 when a new release ships.
ALTER TABLE public.settings
    ADD COLUMN IF NOT EXISTS browser_engine_auto_update boolean NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS browser_engine_check_time text NOT NULL DEFAULT '03:00',
    ADD COLUMN IF NOT EXISTS browser_engine_last_check_at timestamptz,
    ADD COLUMN IF NOT EXISTS browser_engine_last_check_result text NOT NULL DEFAULT '';
