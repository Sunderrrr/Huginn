-- The Obscura engine state of a node, as reported by its worker.
--
-- The engine lives on the WORKER's filesystem, so the hub cannot know
-- whether a node can run browser steps unless the worker says so. The
-- worker reports the installed engine version in its heartbeat (NULL when
-- no engine is installed); the dashboard shows it, so an operator sees
-- whether "Run" will work before clicking it.
--
-- browser_engine_version   the installed version ("v0.2.5"), NULL = not installed
-- browser_engine_reported_at when the worker last reported that state
ALTER TABLE vms
    ADD COLUMN IF NOT EXISTS browser_engine_version TEXT,
    ADD COLUMN IF NOT EXISTS browser_engine_reported_at TIMESTAMPTZ;

COMMENT ON COLUMN vms.browser_engine_version IS
    'Obscura engine version reported by the worker heartbeat (NULL = not installed)';
COMMENT ON COLUMN vms.browser_engine_reported_at IS
    'When the worker last reported its Obscura engine state';
