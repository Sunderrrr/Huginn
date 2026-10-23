-- Server-side session revocation (audit finding F-08): a `session_epoch`
-- counter per user. The access token carries the epoch it was issued with;
-- every request compares it with the stored value, so bumping the counter
-- (password change, MFA reset, logout) invalidates the tokens issued before
-- that moment — without a denylist to store or purge.
--
-- Existing rows start at 0; a token issued before this migration carries no
-- epoch and is therefore treated as epoch 0 — it stays valid until it
-- expires, exactly as before.
ALTER TABLE public.users
    ADD COLUMN IF NOT EXISTS session_epoch bigint NOT NULL DEFAULT 0;
