-- Add the enrollment base URL: the address shown in the "Add VM" install
-- command. Defaults to '' (= use the dashboard origin). Set it to a VPN/LAN
-- address (e.g. https://100.73.17.140) so workers enroll directly.
ALTER TABLE public.settings ADD COLUMN IF NOT EXISTS enrollment_base_url text NOT NULL DEFAULT '';
