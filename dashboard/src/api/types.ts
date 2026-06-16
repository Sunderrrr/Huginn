export type VMState = "pending" | "active" | "offline" | "revoked";
export type ExecMode = "whitelist" | "unrestricted";
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
}

export interface Task {
  id: string;
  vm_id: string;
  type: "action" | "command" | "update" | "uninstall";
  action_name: string | null;
  status: TaskStatus;
  exit_code: number | null;
  stdout: string | null;
  stderr: string | null;
  error: string | null;
  created_at: string;
  finished_at: string | null;
}

export interface EnrollmentToken {
  id: string;
  label: string;
  max_uses: number;
  uses_count: number;
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
  event_type: string;
  vm_id: string | null;
  action_name: string | null;
  command: string | null;
  result_status: string | null;
  exit_code: number | null;
  detail: Record<string, unknown>;
  source_ip: string | null;
}

export interface Settings {
  target_worker_version: string;
  target_release_repo: string;
  allowed_release_domains: string[];
  auto_update_enabled: boolean;
  updated_at: string;
  // SSO / OIDC / LDAP / notifications fields are admin-only and optional here.
  notifications_enabled?: boolean;
  discord_webhook_url?: string | null;
  generic_webhook_url?: string | null;
  notify_vm_offline?: boolean;
  notify_vm_recovered?: boolean;
  notify_task_failure?: boolean;
}

export interface McpTokenResponse {
  token: string;
  masked: string;
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
