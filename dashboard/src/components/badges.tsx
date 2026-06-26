import type { ExecMode, Tag, TaskStatus, UserRole, VMState } from "../api/types";

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
  if (mode === "custom") {
    return <span className="badge badge--custom">custom</span>;
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

const ROLE_COLOR: Record<UserRole, string> = {
  admin: "var(--ember)",
  operator: "var(--amber)",
  readonly: "var(--dim)",
};

export function RoleBadge({ role }: { role: UserRole }) {
  return (
    <span className="badge" style={{ color: ROLE_COLOR[role], borderColor: ROLE_COLOR[role] }}>
      {role}
    </span>
  );
}

export function TagBadge({ tag, onRemove }: { tag: Tag; onRemove?: () => void }) {
  return (
    <span
      className="badge"
      style={{
        color: tag.color,
        borderColor: tag.color,
        backgroundColor: `${tag.color}1a`,
      }}
    >
      <span className="dot" style={{ background: tag.color }} />
      {tag.name}
      {onRemove && (
        <button
          onClick={(e) => {
            e.stopPropagation();
            onRemove();
          }}
          style={{
            marginLeft: 4,
            background: "none",
            border: "none",
            color: "inherit",
            cursor: "pointer",
            fontSize: 13,
            lineHeight: 1,
            padding: 0,
          }}
          aria-label={`remove ${tag.name}`}
        >
          ×
        </button>
      )}
    </span>
  );
}
