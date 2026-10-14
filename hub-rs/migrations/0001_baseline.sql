-- Huginn baseline schema — generated from Alembic head n4c5d6e7f8a9.
-- Identical to the Python hub's schema; alembic_version is stamped so
-- the Python hub's alembic sees this database as fully migrated.

--
-- PostgreSQL database dump
--

\restrict gWcfKh8TQh1sg48n7sOF55fM5qgzLyUzyf6USbb9XMMqQziubzVX5W1iqSwqc6f

-- Dumped from database version 16.15
-- Dumped by pg_dump version 16.15

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: actor_type; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.actor_type AS ENUM (
    'user',
    'agent',
    'system'
);


--
-- Name: exec_mode; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.exec_mode AS ENUM (
    'whitelist',
    'unrestricted',
    'custom'
);


--
-- Name: task_status; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.task_status AS ENUM (
    'pending',
    'dispatched',
    'running',
    'succeeded',
    'failed',
    'timeout',
    'dead_letter',
    'cancelled'
);


--
-- Name: task_type; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.task_type AS ENUM (
    'action',
    'command',
    'update',
    'uninstall'
);


--
-- Name: user_role; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.user_role AS ENUM (
    'admin',
    'readonly',
    'operator'
);


--
-- Name: vm_state; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.vm_state AS ENUM (
    'pending',
    'active',
    'offline',
    'revoked'
);


--
-- Name: worker_arch; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.worker_arch AS ENUM (
    'amd64',
    'arm64'
);


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: alembic_version; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.alembic_version (
    version_num character varying(32) NOT NULL
);


--
-- Name: audit_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.audit_log (
    id bigint NOT NULL,
    ts timestamp with time zone NOT NULL,
    actor_type public.actor_type NOT NULL,
    actor_id character varying(255) NOT NULL,
    event_type character varying(64) NOT NULL,
    vm_id uuid,
    action_name character varying(64),
    command character varying(4096),
    result_status character varying(64),
    exit_code integer,
    detail jsonb NOT NULL,
    source_ip character varying(64),
    prev_hash character varying(64) NOT NULL,
    row_hash character varying(64) NOT NULL
);


--
-- Name: audit_log_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.audit_log_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: audit_log_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.audit_log_id_seq OWNED BY public.audit_log.id;


--
-- Name: custom_action_tags; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.custom_action_tags (
    action_id uuid NOT NULL,
    tag_id uuid NOT NULL
);


--
-- Name: custom_actions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.custom_actions (
    id uuid NOT NULL,
    name character varying(64) NOT NULL,
    description character varying(255) DEFAULT ''::character varying NOT NULL,
    commands json NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    created_by character varying(255),
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL
);


--
-- Name: enrollment_tokens; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.enrollment_tokens (
    id uuid NOT NULL,
    token_hash character varying(128) NOT NULL,
    label character varying(255) NOT NULL,
    created_by uuid NOT NULL,
    max_uses integer NOT NULL,
    uses_count integer NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    revoked_at timestamp with time zone,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    auto_approve boolean DEFAULT false NOT NULL
);


--
-- Name: mcp_tokens; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mcp_tokens (
    id uuid NOT NULL,
    user_id uuid NOT NULL,
    token_hash character varying(128) NOT NULL,
    name character varying(255) DEFAULT ''::character varying NOT NULL,
    last_used_at timestamp with time zone,
    revoked_at timestamp with time zone,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    allowed_ip character varying(64)
);


--
-- Name: mfa_backup_codes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mfa_backup_codes (
    id uuid NOT NULL,
    user_id uuid NOT NULL,
    code_hash character varying(128) NOT NULL,
    used_at timestamp with time zone,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL
);


--
-- Name: scheduled_commands; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.scheduled_commands (
    id uuid NOT NULL,
    name character varying(128) NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    target_kind character varying(16) NOT NULL,
    target_vm_id uuid,
    target_tag_id uuid,
    task_kind character varying(16) NOT NULL,
    action_name character varying(64),
    params jsonb NOT NULL,
    command text,
    cron_expression character varying(128) NOT NULL,
    last_run_at timestamp with time zone,
    created_by uuid,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL
);


--
-- Name: settings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.settings (
    id integer NOT NULL,
    target_worker_version character varying(64) NOT NULL,
    target_release_repo character varying(255) NOT NULL,
    allowed_release_domains jsonb NOT NULL,
    updated_by uuid,
    updated_at timestamp with time zone NOT NULL,
    oidc_enabled boolean DEFAULT false NOT NULL,
    oidc_issuer character varying(512) DEFAULT ''::character varying NOT NULL,
    oidc_client_id character varying(255) DEFAULT ''::character varying NOT NULL,
    oidc_client_secret character varying(512),
    oidc_redirect_url character varying(512) DEFAULT ''::character varying NOT NULL,
    oidc_post_login_redirect character varying(512) DEFAULT ''::character varying NOT NULL,
    ldap_enabled boolean DEFAULT false NOT NULL,
    ldap_server_url character varying(512) DEFAULT ''::character varying NOT NULL,
    ldap_bind_dn character varying(512) DEFAULT ''::character varying NOT NULL,
    ldap_bind_password character varying(512),
    ldap_user_search_base character varying(512) DEFAULT ''::character varying NOT NULL,
    ldap_user_search_filter character varying(512) DEFAULT ''::character varying NOT NULL,
    ldap_start_tls boolean DEFAULT false NOT NULL,
    ldap_use_ldaps boolean DEFAULT false NOT NULL,
    notifications_enabled boolean DEFAULT false NOT NULL,
    discord_webhook_url character varying(512),
    generic_webhook_url character varying(512),
    notify_vm_offline boolean DEFAULT true NOT NULL,
    notify_vm_recovered boolean DEFAULT false NOT NULL,
    notify_task_failure boolean DEFAULT false NOT NULL,
    auto_update_enabled boolean DEFAULT false NOT NULL,
    oidc_provider_name character varying(64) DEFAULT 'SSO'::character varying NOT NULL,
    require_admin_mfa boolean DEFAULT true NOT NULL,
    allow_password_login boolean DEFAULT false NOT NULL,
    webauthn_rp_id character varying(255) DEFAULT ''::character varying NOT NULL,
    webauthn_rp_name character varying(255) DEFAULT 'Huginn'::character varying NOT NULL,
    webauthn_origin character varying(512) DEFAULT ''::character varying NOT NULL
);


--
-- Name: settings_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.settings_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: settings_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.settings_id_seq OWNED BY public.settings.id;


--
-- Name: tags; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tags (
    id uuid NOT NULL,
    name character varying(64) NOT NULL,
    color character varying(7) NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL
);


--
-- Name: tasks; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tasks (
    id uuid NOT NULL,
    vm_id uuid NOT NULL,
    type public.task_type NOT NULL,
    action_name character varying(64),
    payload jsonb NOT NULL,
    status public.task_status NOT NULL,
    stdout text,
    stderr text,
    exit_code integer,
    error text,
    retries integer NOT NULL,
    created_by character varying(255) NOT NULL,
    idempotency_key character varying(128),
    dispatched_at timestamp with time zone,
    started_at timestamp with time zone,
    finished_at timestamp with time zone,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL
);


--
-- Name: user_vm_access; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_vm_access (
    user_id uuid NOT NULL,
    vm_id uuid NOT NULL
);


--
-- Name: users; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.users (
    id uuid NOT NULL,
    username character varying(255) NOT NULL,
    email character varying(320),
    password_hash character varying(255),
    oidc_subject character varying(255),
    role public.user_role NOT NULL,
    is_active boolean NOT NULL,
    last_login_at timestamp with time zone,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    ldap_dn character varying(512),
    totp_secret_enc character varying(512),
    totp_enabled boolean DEFAULT false NOT NULL,
    totp_confirmed_at timestamp with time zone,
    totp_last_step bigint
);


--
-- Name: vm_tags; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.vm_tags (
    vm_id uuid NOT NULL,
    tag_id uuid NOT NULL
);


--
-- Name: vms; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.vms (
    id uuid NOT NULL,
    name character varying(255) NOT NULL,
    hostname character varying(255),
    ip_address character varying(64),
    arch public.worker_arch NOT NULL,
    os_info jsonb NOT NULL,
    state public.vm_state NOT NULL,
    exec_mode public.exec_mode NOT NULL,
    worker_version character varying(64),
    worker_secret_hash character varying(128),
    enrollment_token_id uuid,
    approved_by uuid,
    last_heartbeat_at timestamp with time zone,
    enrolled_at timestamp with time zone,
    approved_at timestamp with time zone,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL
);


--
-- Name: webauthn_challenges; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.webauthn_challenges (
    id uuid NOT NULL,
    challenge character varying(255) NOT NULL,
    user_id uuid,
    purpose character varying(16) NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    consumed_at timestamp with time zone,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL
);


--
-- Name: webauthn_credentials; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.webauthn_credentials (
    id uuid NOT NULL,
    user_id uuid NOT NULL,
    name character varying(255) DEFAULT ''::character varying NOT NULL,
    credential_id character varying(512) NOT NULL,
    public_key bytea NOT NULL,
    sign_count bigint DEFAULT '0'::bigint NOT NULL,
    transports jsonb,
    aaguid character varying(64),
    last_used_at timestamp with time zone,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL
);


--
-- Name: audit_log id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_log ALTER COLUMN id SET DEFAULT nextval('public.audit_log_id_seq'::regclass);


--
-- Name: settings id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.settings ALTER COLUMN id SET DEFAULT nextval('public.settings_id_seq'::regclass);


--
-- Name: alembic_version alembic_version_pkc; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alembic_version
    ADD CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num);


--
-- Name: audit_log audit_log_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_log
    ADD CONSTRAINT audit_log_pkey PRIMARY KEY (id);


--
-- Name: audit_log audit_log_row_hash_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_log
    ADD CONSTRAINT audit_log_row_hash_key UNIQUE (row_hash);


--
-- Name: custom_action_tags custom_action_tags_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.custom_action_tags
    ADD CONSTRAINT custom_action_tags_pkey PRIMARY KEY (action_id, tag_id);


--
-- Name: custom_actions custom_actions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.custom_actions
    ADD CONSTRAINT custom_actions_pkey PRIMARY KEY (id);


--
-- Name: enrollment_tokens enrollment_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.enrollment_tokens
    ADD CONSTRAINT enrollment_tokens_pkey PRIMARY KEY (id);


--
-- Name: mcp_tokens mcp_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_tokens
    ADD CONSTRAINT mcp_tokens_pkey PRIMARY KEY (id);


--
-- Name: mfa_backup_codes mfa_backup_codes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mfa_backup_codes
    ADD CONSTRAINT mfa_backup_codes_pkey PRIMARY KEY (id);


--
-- Name: scheduled_commands scheduled_commands_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scheduled_commands
    ADD CONSTRAINT scheduled_commands_pkey PRIMARY KEY (id);


--
-- Name: settings settings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.settings
    ADD CONSTRAINT settings_pkey PRIMARY KEY (id);


--
-- Name: tags tags_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tags
    ADD CONSTRAINT tags_pkey PRIMARY KEY (id);


--
-- Name: tasks tasks_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tasks
    ADD CONSTRAINT tasks_pkey PRIMARY KEY (id);


--
-- Name: user_vm_access user_vm_access_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_vm_access
    ADD CONSTRAINT user_vm_access_pkey PRIMARY KEY (user_id, vm_id);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


--
-- Name: vm_tags vm_tags_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vm_tags
    ADD CONSTRAINT vm_tags_pkey PRIMARY KEY (vm_id, tag_id);


--
-- Name: vms vms_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vms
    ADD CONSTRAINT vms_pkey PRIMARY KEY (id);


--
-- Name: webauthn_challenges webauthn_challenges_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webauthn_challenges
    ADD CONSTRAINT webauthn_challenges_pkey PRIMARY KEY (id);


--
-- Name: webauthn_credentials webauthn_credentials_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webauthn_credentials
    ADD CONSTRAINT webauthn_credentials_pkey PRIMARY KEY (id);


--
-- Name: ix_audit_log_event_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_audit_log_event_type ON public.audit_log USING btree (event_type);


--
-- Name: ix_audit_log_ts; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_audit_log_ts ON public.audit_log USING btree (ts);


--
-- Name: ix_audit_log_vm_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_audit_log_vm_id ON public.audit_log USING btree (vm_id);


--
-- Name: ix_custom_actions_name; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX ix_custom_actions_name ON public.custom_actions USING btree (name);


--
-- Name: ix_enrollment_tokens_token_hash; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX ix_enrollment_tokens_token_hash ON public.enrollment_tokens USING btree (token_hash);


--
-- Name: ix_mcp_tokens_token_hash; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX ix_mcp_tokens_token_hash ON public.mcp_tokens USING btree (token_hash);


--
-- Name: ix_mcp_tokens_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_mcp_tokens_user_id ON public.mcp_tokens USING btree (user_id);


--
-- Name: ix_mfa_backup_codes_code_hash; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX ix_mfa_backup_codes_code_hash ON public.mfa_backup_codes USING btree (code_hash);


--
-- Name: ix_mfa_backup_codes_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_mfa_backup_codes_user_id ON public.mfa_backup_codes USING btree (user_id);


--
-- Name: ix_scheduled_commands_enabled; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_scheduled_commands_enabled ON public.scheduled_commands USING btree (enabled);


--
-- Name: ix_tags_name; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX ix_tags_name ON public.tags USING btree (name);


--
-- Name: ix_tasks_idempotency_key; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_tasks_idempotency_key ON public.tasks USING btree (idempotency_key);


--
-- Name: ix_tasks_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_tasks_status ON public.tasks USING btree (status);


--
-- Name: ix_tasks_vm_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_tasks_vm_id ON public.tasks USING btree (vm_id);


--
-- Name: ix_tasks_vm_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_tasks_vm_status ON public.tasks USING btree (vm_id, status);


--
-- Name: ix_users_ldap_dn; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX ix_users_ldap_dn ON public.users USING btree (ldap_dn);


--
-- Name: ix_users_oidc_subject; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX ix_users_oidc_subject ON public.users USING btree (oidc_subject);


--
-- Name: ix_users_username; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX ix_users_username ON public.users USING btree (username);


--
-- Name: ix_vms_state; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_vms_state ON public.vms USING btree (state);


--
-- Name: ix_webauthn_challenges_challenge; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX ix_webauthn_challenges_challenge ON public.webauthn_challenges USING btree (challenge);


--
-- Name: ix_webauthn_credentials_credential_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX ix_webauthn_credentials_credential_id ON public.webauthn_credentials USING btree (credential_id);


--
-- Name: ix_webauthn_credentials_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_webauthn_credentials_user_id ON public.webauthn_credentials USING btree (user_id);


--
-- Name: uq_tasks_vm_idempotency; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_tasks_vm_idempotency ON public.tasks USING btree (vm_id, idempotency_key) WHERE (idempotency_key IS NOT NULL);


--
-- Name: custom_action_tags custom_action_tags_action_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.custom_action_tags
    ADD CONSTRAINT custom_action_tags_action_id_fkey FOREIGN KEY (action_id) REFERENCES public.custom_actions(id) ON DELETE CASCADE;


--
-- Name: custom_action_tags custom_action_tags_tag_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.custom_action_tags
    ADD CONSTRAINT custom_action_tags_tag_id_fkey FOREIGN KEY (tag_id) REFERENCES public.tags(id) ON DELETE CASCADE;


--
-- Name: mcp_tokens mcp_tokens_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_tokens
    ADD CONSTRAINT mcp_tokens_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: mfa_backup_codes mfa_backup_codes_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mfa_backup_codes
    ADD CONSTRAINT mfa_backup_codes_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: user_vm_access user_vm_access_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_vm_access
    ADD CONSTRAINT user_vm_access_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: user_vm_access user_vm_access_vm_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_vm_access
    ADD CONSTRAINT user_vm_access_vm_id_fkey FOREIGN KEY (vm_id) REFERENCES public.vms(id) ON DELETE CASCADE;


--
-- Name: vm_tags vm_tags_tag_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vm_tags
    ADD CONSTRAINT vm_tags_tag_id_fkey FOREIGN KEY (tag_id) REFERENCES public.tags(id) ON DELETE CASCADE;


--
-- Name: vm_tags vm_tags_vm_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vm_tags
    ADD CONSTRAINT vm_tags_vm_id_fkey FOREIGN KEY (vm_id) REFERENCES public.vms(id) ON DELETE CASCADE;


--
-- Name: webauthn_credentials webauthn_credentials_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webauthn_credentials
    ADD CONSTRAINT webauthn_credentials_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- PostgreSQL database dump complete
--

\unrestrict gWcfKh8TQh1sg48n7sOF55fM5qgzLyUzyf6USbb9XMMqQziubzVX5W1iqSwqc6f


-- Stamp the alembic revision this schema corresponds to (Python/Rust coexistence).
DELETE FROM alembic_version;
INSERT INTO alembic_version (version_num) VALUES ('n4c5d6e7f8a9');
