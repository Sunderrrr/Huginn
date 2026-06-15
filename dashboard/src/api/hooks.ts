import {
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import { api } from "./client";
import type {
  AuditEntry,
  EnrollmentToken,
  EnrollmentTokenCreated,
  ExecMode,
  McpTokenResponse,
  PasswordChange,
  Settings,
  Task,
  User,
  UserCreate,
  UserUpdate,
  VM,
} from "./types";

export function useMe() {
  return useQuery({
    queryKey: ["me"],
    queryFn: () => api.get<User>("/api/auth/me"),
    retry: false,
    staleTime: 60_000,
  });
}

export function useVms() {
  return useQuery({
    queryKey: ["vms"],
    queryFn: () => api.get<VM[]>("/api/vms"),
    refetchInterval: 5_000,
  });
}

export function useVm(id: string) {
  return useQuery({
    queryKey: ["vm", id],
    queryFn: () => api.get<VM>(`/api/vms/${id}`),
    refetchInterval: 5_000,
  });
}

export function useSettings() {
  return useQuery({
    queryKey: ["settings"],
    queryFn: () => api.get<Settings>("/api/settings"),
  });
}

export function useAudit(params?: { vm_id?: string; event_type?: string; limit?: number }) {
  const search = new URLSearchParams();
  if (params?.vm_id) search.set("vm_id", params.vm_id);
  if (params?.event_type) search.set("event_type", params.event_type);
  search.set("limit", String(params?.limit ?? 100));
  return useQuery({
    queryKey: ["audit", params],
    queryFn: () => api.get<AuditEntry[]>(`/api/audit?${search.toString()}`),
    refetchInterval: 8_000,
  });
}

export function useTokens() {
  return useQuery({
    queryKey: ["tokens"],
    queryFn: () => api.get<EnrollmentToken[]>("/api/enrollment-tokens"),
  });
}

export function useUsers() {
  return useQuery({
    queryKey: ["users"],
    queryFn: () => api.get<User[]>("/api/users"),
  });
}

export function useMcpToken() {
  return useQuery({
    queryKey: ["mcp-token"],
    queryFn: () => api.get<McpTokenResponse>("/api/settings/mcp-token"),
  });
}

// --- Mutations ---

function useInvalidate(keys: string[]) {
  const qc = useQueryClient();
  return () => keys.forEach((k) => qc.invalidateQueries({ queryKey: [k] }));
}

export function useApproveVm() {
  const invalidate = useInvalidate(["vms", "vm", "audit"]);
  return useMutation({
    mutationFn: (id: string) => api.post<VM>(`/api/vms/${id}/approve`),
    onSuccess: invalidate,
  });
}

export function useRevokeVm() {
  const invalidate = useInvalidate(["vms", "vm", "audit"]);
  return useMutation({
    mutationFn: (vars: { id: string; uninstall?: boolean }) =>
      api.post<VM>(`/api/vms/${vars.id}/revoke`, { uninstall: vars.uninstall ?? false }),
    onSuccess: invalidate,
  });
}

export function useSetExecMode() {
  const invalidate = useInvalidate(["vms", "vm", "audit"]);
  return useMutation({
    mutationFn: (vars: { id: string; mode: ExecMode }) =>
      api.put<VM>(`/api/vms/${vars.id}/exec-mode`, { exec_mode: vars.mode }),
    onSuccess: invalidate,
  });
}

export function useRunAction() {
  const invalidate = useInvalidate(["audit"]);
  return useMutation({
    mutationFn: (vars: { id: string; action: string; params?: Record<string, string> }) =>
      api.post<Task>(`/api/vms/${vars.id}/actions`, {
        action: vars.action,
        params: vars.params ?? {},
        wait: true,
      }),
    onSuccess: invalidate,
  });
}

export interface BulkActionResult {
  vm_id: string;
  task_id: string | null;
  status: string;
  error: string | null;
}

export function useBulkRunAction() {
  const invalidate = useInvalidate(["audit"]);
  return useMutation({
    mutationFn: (vars: { vm_ids: string[]; action: string; params?: Record<string, string> }) =>
      api.post<BulkActionResult[]>(`/api/vms/bulk/actions`, {
        vm_ids: vars.vm_ids,
        action: vars.action,
        params: vars.params ?? {},
      }),
    onSuccess: invalidate,
  });
}

export function useRunCommand() {
  const invalidate = useInvalidate(["audit"]);
  return useMutation({
    mutationFn: (vars: { id: string; command: string }) =>
      api.post<Task>(`/api/vms/${vars.id}/commands`, { command: vars.command, wait: true }),
    onSuccess: invalidate,
  });
}

export function useTriggerUpdate() {
  const invalidate = useInvalidate(["vms", "vm", "audit"]);
  return useMutation({
    mutationFn: (id: string) => api.post<Task>(`/api/vms/${id}/update`),
    onSuccess: invalidate,
  });
}

export function useCreateToken() {
  const invalidate = useInvalidate(["tokens"]);
  return useMutation({
    mutationFn: (vars: { label: string; ttl_seconds: number; max_uses: number }) =>
      api.post<EnrollmentTokenCreated>("/api/enrollment-tokens", vars),
    onSuccess: invalidate,
  });
}

export function useRevokeToken() {
  const invalidate = useInvalidate(["tokens"]);
  return useMutation({
    mutationFn: (id: string) => api.del<void>(`/api/enrollment-tokens/${id}`),
    onSuccess: invalidate,
  });
}

export function useUpdateSettings() {
  const invalidate = useInvalidate(["settings", "audit"]);
  return useMutation({
    mutationFn: (vars: Partial<Settings>) => api.put<Settings>("/api/settings", vars),
    onSuccess: invalidate,
  });
}

// --- User management ---

export function useCreateUser() {
  const invalidate = useInvalidate(["users"]);
  return useMutation({
    mutationFn: (vars: UserCreate) => api.post<User>("/api/users", vars),
    onSuccess: invalidate,
  });
}

export function useUpdateUser() {
  const invalidate = useInvalidate(["users"]);
  return useMutation({
    mutationFn: (vars: { id: string } & UserUpdate) =>
      api.put<User>(`/api/users/${vars.id}`, { role: vars.role, is_active: vars.is_active, email: vars.email }),
    onSuccess: invalidate,
  });
}

export function useDeactivateUser() {
  const invalidate = useInvalidate(["users"]);
  return useMutation({
    mutationFn: (id: string) => api.del<void>(`/api/users/${id}`),
    onSuccess: invalidate,
  });
}

export function useChangePassword() {
  return useMutation({
    mutationFn: (vars: { id: string } & PasswordChange) =>
      api.put<{ status: string }>(`/api/users/${vars.id}/password`, {
        old_password: vars.old_password,
        new_password: vars.new_password,
      }),
  });
}

export function useSetUserVms() {
  const invalidate = useInvalidate(["users"]);
  return useMutation({
    mutationFn: (vars: { id: string; vm_ids: string[] }) =>
      api.put<User>(`/api/users/${vars.id}/vms`, { vm_ids: vars.vm_ids }),
    onSuccess: invalidate,
  });
}

// --- MCP Token ---

export function useRegenerateMcpToken() {
  const invalidate = useInvalidate(["mcp-token"]);
  return useMutation({
    mutationFn: () => api.put<McpTokenResponse>("/api/settings/mcp-token"),
    onSuccess: invalidate,
  });
}
