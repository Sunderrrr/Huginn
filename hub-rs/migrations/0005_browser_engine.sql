-- Browser automation via Obscura (hub-rs extension, see docs/browser.md):
--
-- 1. A dedicated install task type (admin-triggered): the worker downloads
--    the hub-pinned engine release (version + per-arch SHA-256 from the
--    settings row) into a Huginn-managed directory.
-- 2. A per-VM enablement gate: browser tasks are refused unless an admin
--    enables the capability on the VM (mirrors the exec-mode gate).
-- 3. The pinned engine release coordinates (defaults: Obscura v0.2.4).
ALTER TYPE task_type ADD VALUE IF NOT EXISTS 'browser_install';

ALTER TABLE public.vms
    ADD COLUMN IF NOT EXISTS browser_enabled boolean NOT NULL DEFAULT false;

ALTER TABLE public.settings
    ADD COLUMN IF NOT EXISTS browser_engine_version text NOT NULL DEFAULT 'v0.2.4',
    ADD COLUMN IF NOT EXISTS browser_engine_sha256_amd64 text NOT NULL
        DEFAULT '757e7b597ba5cdd53af9fc701e0a9b80f0a8d788f545d4f82ec9ad32db77f000',
    ADD COLUMN IF NOT EXISTS browser_engine_sha256_arm64 text NOT NULL
        DEFAULT 'd9ba3719c2442a227567d7664b5505b38ab68236f3f5388884eee2e27f55db28';
