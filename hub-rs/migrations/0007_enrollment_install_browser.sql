-- Enrollment tokens carry an "install browser engine" flag: when set, the
-- hub auto-queues a `browser_install` task for the newly enrolled VM (only
-- effective for auto-approved tokens, since the worker must be able to poll).
ALTER TABLE public.enrollment_tokens
    ADD COLUMN IF NOT EXISTS install_browser boolean NOT NULL DEFAULT false;
