export type VMState = "pending" | "active" | "offline" | "revoked";
export type ExecMode = "whitelist" | "custom" | "unrestricted";

export interface CustomAction {
  id: string;
  name: string;
  description: string;
  commands: string[]; // canonical command lines (one per command)
  argv: string[][]; // parsed argv vectors (what actually runs)
  enabled: boolean;
  tag_ids: string[];
  created_at: string;
}
export type UserRole = "admin" | "operator" | "readonly";
export type TaskStatus =
  | "pending"
  | "dispatched"
  | "running"
  | "succeeded"
  | "failed"
  | "timeout"
  | "dead_letter"
  | "cancelled";

export interface User {
  id: string;
  username: string;
  email: string | null;
  role: UserRole;
  is_active: boolean;
  vm_ids: string[];
  totp_enabled?: boolean;
  passkey_count?: number;
}

export interface UserCreate {
  username: string;
  password: string;
  email?: string;
  role: UserRole;
  vm_ids?: string[];
}

export interface UserUpdate {
  role?: UserRole;
  is_active?: boolean;
  email?: string;
}

export interface PasswordChange {
  old_password?: string;
  new_password: string;
}

export interface Tag {
  id: string;
  name: string;
  color: string;
  created_at: string;
}

export interface TagCreate {
  name: string;
  color: string;
}

export interface TagUpdate {
  name?: string;
  color?: string;
}

export type ScheduleTargetKind = "vm" | "tag" | "all_active";
export type ScheduleTaskKind = "action" | "command";

export interface Schedule {
  id: string;
  name: string;
  enabled: boolean;
  target_kind: ScheduleTargetKind;
  target_vm_id: string | null;
  target_tag_id: string | null;
  task_kind: ScheduleTaskKind;
  action_name: string | null;
  params: Record<string, string>;
  command: string | null;
  cron_expression: string;
  last_run_at: string | null;
  next_run_at: string | null;
  created_at: string;
}

export interface ScheduleCreate {
  name: string;
  enabled?: boolean;
  target_kind: ScheduleTargetKind;
  target_vm_id?: string | null;
  target_tag_id?: string | null;
  task_kind: ScheduleTaskKind;
  action_name?: string | null;
  params?: Record<string, string>;
  command?: string | null;
  cron_expression: string;
}

export interface VM {
  id: string;
  name: string;
  hostname: string | null;
  ip_address: string | null;
  arch: "amd64" | "arm64";
  state: VMState;
  exec_mode: ExecMode;
  worker_version: string | null;
  last_heartbeat_at: string | null;
  enrolled_at: string | null;
  approved_at: string | null;
  created_at: string;
  tags: Tag[];
  // Browser automation gate (off by default; an admin flips it per VM).
  browser_enabled: boolean;
}

export interface Task {
  id: string;
  vm_id: string;
  type: "action" | "command" | "update" | "uninstall" | "browser" | "browser_install";
  action_name: string | null;
  status: TaskStatus;
  exit_code: number | null;
  stdout: string | null;
  stderr: string | null;
  error: string | null;
  created_at: string;
  finished_at: string | null;
}

// Statuses a task never leaves — used to stop task polling.
export const TERMINAL_TASK_STATUS: ReadonlySet<TaskStatus> = new Set([
  "succeeded",
  "failed",
  "timeout",
  "dead_letter",
  "cancelled",
]);

export interface EnrollmentToken {
  id: string;
  label: string;
  max_uses: number; // 0 = unlimited (reusable join key)
  uses_count: number;
  auto_approve: boolean;
  expires_at: string;
  revoked_at: string | null;
  created_at: string;
}

export interface EnrollmentTokenCreated extends EnrollmentToken {
  token: string;
}

export interface AuditEntry {
  id: number;
  ts: string;
  actor_type: "user" | "agent" | "system";
  actor_id: string;
  actor_label: string | null;
  event_type: string;
  vm_id: string | null;
  action_name: string | null;
  command: string | null;
  result_status: string | null;
  exit_code: number | null;
  detail: Record<string, unknown>;
  source_ip: string | null;
}

// One backup archive object in the S3 bucket.
export interface BackupFile {
  name: string;
  size: number;
  last_modified: string;
}

export interface BackupList {
  backups: BackupFile[];
  configured: boolean;
}

// Result of POST /api/backups — a backup that just ran.
export interface BackupRunResult {
  name: string;
  size: number;
  duration_ms: number;
}

export interface Settings {
  target_worker_version: string;
  target_release_repo: string;
  allowed_release_domains: string[];
  auto_update_enabled: boolean;
  updated_at: string;
  // S3 backup target (admin-only). `backup_s3_secret_key` is write-only: the GET
  // never returns it — only `backup_s3_secret_key_configured` tells whether one is stored.
  backup_s3_enabled?: boolean;
  backup_s3_endpoint?: string | null;
  backup_s3_region?: string | null;
  backup_s3_bucket?: string | null;
  backup_s3_prefix?: string | null;
  backup_s3_access_key?: string | null;
  backup_s3_secret_key?: string | null;
  backup_s3_secret_key_configured?: boolean;
  backup_s3_retention_days?: number | null;
  enrollment_base_url?: string | null;
  // Browser automation: the pinned Obscura engine release `browser_install`
  // tasks download (admin-only read; workers get it via the task payload).
  browser_engine_version?: string;
  // SSO / OIDC / LDAP / notifications fields are admin-only and optional here.
  oidc_provider_name?: string;
  notifications_enabled?: boolean;
  discord_webhook_url?: string | null;
  generic_webhook_url?: string | null;
  notify_vm_offline?: boolean;
  notify_vm_recovered?: boolean;
  notify_task_failure?: boolean;
}

export interface AuthConfig {
  oidc_enabled: boolean;
  oidc_provider_name: string;
  password_login_enabled: boolean;
  webauthn_enabled: boolean;
}

export interface LoginChallenge {
  mfa_required?: boolean;
  mfa_setup_required?: boolean;
  challenge_token: string;
  methods: string[];
}

export interface TotpEnrollBegin {
  secret: string;
  otpauth_uri: string;
}

export interface WebAuthnCredentialOut {
  id: string;
  name: string;
  created_at: string;
  last_used_at: string | null;
  transports: string[] | null;
}

export interface McpToken {
  id: string;
  name: string;
  allowed_ip: string | null;
  created_at: string;
  last_used_at: string | null;
}

export interface McpTokenCreated {
  id: string;
  name: string;
  allowed_ip: string | null;
  token: string; // plaintext, shown once
}

export interface ActionSpec {
  name: string;
  label: string;
  description: string;
  param?: { name: string; placeholder: string };
}

// Client-side mirror of the hub whitelist catalog (UI affordance only; the hub
// validates authoritatively).
export const ACTION_CATALOG: ActionSpec[] = [
  { name: "status", label: "Status", description: "Host & worker status (uname)" },
  { name: "metrics", label: "Metrics", description: "Load average snapshot" },
  {
    name: "restart_service",
    label: "Restart service",
    description: "systemctl restart <service>",
    param: { name: "service", placeholder: "e.g. nginx" },
  },
  {
    name: "list_upgradable_packages",
    label: "List upgrades",
    description: "apt list --upgradable",
  },
  { name: "apt_upgrade", label: "Apt upgrade", description: "apt-get -y upgrade" },
];
