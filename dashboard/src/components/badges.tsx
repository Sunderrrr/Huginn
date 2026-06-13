import type { ExecMode, TaskStatus, VMState } from "../api/types";

const STATE_CLASS: Record<VMState, string> = {
  active: "badge--active",
  pending: "badge--pending",
  offline: "badge--offline",
  revoked: "badge--revoked",
};

export function StateBadge({ state }: { state: VMState }) {
  return (
    <span className={`badge ${STATE_CLASS[state]}`}>
      <span className="dot" />
      {state}
    </span>
  );
}

export function ModeBadge({ mode }: { mode: ExecMode }) {
  if (mode === "unrestricted") {
    return <span className="badge badge--unrestricted">⚠ unrestricted</span>;
  }
  return <span className="badge badge--whitelist">whitelist</span>;
}

const TASK_COLOR: Record<TaskStatus, string> = {
  succeeded: "var(--signal)",
  failed: "var(--blood)",
  timeout: "var(--amber)",
  dead_letter: "var(--blood)",
  cancelled: "var(--dim)",
  pending: "var(--amber)",
  dispatched: "var(--steel)",
  running: "var(--steel)",
};

export function TaskStatusTag({ status }: { status: TaskStatus }) {
  return (
    <span style={{ color: TASK_COLOR[status], fontWeight: 600, letterSpacing: "0.08em" }}>
      {status.toUpperCase()}
    </span>
  );
}
