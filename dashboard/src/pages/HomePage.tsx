import { useState } from "react";
import { motion } from "framer-motion";
import { Link } from "react-router-dom";
import { useAudit, useSchedules, useSettings, useTriggerUpdate, useVms } from "../api/hooks";
import { useAuth } from "../auth/AuthContext";
import { useToast } from "../components/Toast";
import { timeAgo, fmtTime } from "../lib/format";
import type { VM, VMState } from "../api/types";

const ACTOR_COLOR: Record<string, string> = {
  user: "var(--steel)",
  agent: "var(--ember-soft)",
  system: "var(--dim)",
};

const STATES: { key: VMState; label: string; color: string }[] = [
  { key: "active", label: "active", color: "var(--signal)" },
  { key: "pending", label: "pending", color: "var(--amber)" },
  { key: "offline", label: "offline", color: "var(--dim)" },
  { key: "revoked", label: "revoked", color: "var(--blood)" },
];

function count(vms: VM[] | undefined, state: VMState): number {
  return vms?.filter((v) => v.state === state).length ?? 0;
}

function StatCard({
  label,
  value,
  color,
  to,
  delay,
}: {
  label: string;
  value: number;
  color: string;
  to?: string;
  delay: number;
}) {
  const body = (
    <motion.div
      className="panel"
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay }}
      style={{
        padding: "18px 20px",
        flex: "1 1 130px",
        minWidth: 130,
        borderLeft: `2px solid ${color}`,
        cursor: to ? "pointer" : "default",
      }}
    >
      <div style={{ fontFamily: "var(--font-display)", fontSize: 36, color, lineHeight: 1 }}>
        {String(value).padStart(2, "0")}
      </div>
      <div className="eyebrow" style={{ marginTop: 10 }}>{label}</div>
    </motion.div>
  );
  return to ? (
    <Link to={to} style={{ textDecoration: "none", flex: "1 1 130px", minWidth: 130, display: "flex" }}>
      {body}
    </Link>
  ) : (
    body
  );
}

/** Stacked proportional bar of the fleet by state. */
function FleetHealthBar({ vms }: { vms: VM[] }) {
  const total = vms.length || 1;
  const segments = STATES.map((s) => ({
    ...s,
    n: count(vms, s.key),
  })).filter((s) => s.n > 0);

  return (
    <div className="stack" style={{ gap: 10 }}>
      <div
        style={{
          display: "flex",
          height: 10,
          borderRadius: 2,
          overflow: "hidden",
          background: "var(--void-2)",
          border: "1px solid var(--line)",
        }}
      >
        {segments.map((s) => (
          <div
            key={s.key}
            title={`${s.n} ${s.label}`}
            style={{ width: `${(s.n / total) * 100}%`, background: s.color, opacity: 0.85 }}
          />
        ))}
      </div>
      <div className="row" style={{ gap: 16, flexWrap: "wrap" }}>
        {STATES.map((s) => (
          <span key={s.key} className="row" style={{ gap: 6 }}>
            <span style={{ width: 8, height: 8, borderRadius: "50%", background: s.color }} />
            <span className="tiny muted">
              {count(vms, s.key)} {s.label}
            </span>
          </span>
        ))}
      </div>
    </div>
  );
}

function resultColor(status: string | null): string {
  if (status === "error" || status === "failed") return "var(--blood)";
  if (status === "ok" || status === "success") return "var(--signal)";
  return "var(--dim)";
}

export function HomePage() {
  const { user } = useAuth();
  const toast = useToast();
  const { data: vms } = useVms();
  const { data: settings } = useSettings();
  const { data: audit } = useAudit({ limit: 14 });
  const isAdmin = user?.role === "admin";
  const { data: schedules } = useSchedules({ enabled: isAdmin });
  const triggerUpdate = useTriggerUpdate();
  const [updatingAll, setUpdatingAll] = useState(false);

  const fleet = vms ?? [];
  const target = settings?.target_worker_version;
  const stale = fleet.filter((v) => v.worker_version && target && v.worker_version !== target);
  const activeSchedules = (schedules ?? []).filter((s) => s.enabled);

  const updateAllStale = async () => {
    setUpdatingAll(true);
    let ok = 0;
    for (const v of stale) {
      try {
        await triggerUpdate.mutateAsync(v.id);
        ok += 1;
      } catch {
        /* best-effort per VM */
      }
    }
    setUpdatingAll(false);
    toast("ok", `update triggered on ${ok}/${stale.length} worker(s)`);
  };

  const allHealthy = fleet.length > 0 && count(vms, "offline") === 0 && count(vms, "pending") === 0;

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}>
      {/* Hero */}
      <div className="spread" style={{ marginBottom: 24, flexWrap: "wrap", gap: 12 }}>
        <div>
          <div className="eyebrow">overview</div>
          <h1 className="display" style={{ fontSize: 28, letterSpacing: "0.08em", margin: "8px 0 0" }}>
            Welcome{user ? `, ${user.username}` : ""}
          </h1>
        </div>
        <span
          className="badge"
          style={{
            color: allHealthy ? "var(--signal)" : "var(--amber)",
            background: allHealthy ? "rgba(70,211,154,0.08)" : "rgba(255,180,63,0.08)",
          }}
        >
          <span className="dot" />
          {fleet.length === 0 ? "no workers" : allHealthy ? "all systems nominal" : "attention needed"}
        </span>
      </div>

      {/* Stat cards */}
      <div className="row" style={{ gap: 14, flexWrap: "wrap", marginBottom: 18, alignItems: "stretch" }}>
        <StatCard label="active" value={count(vms, "active")} color="var(--signal)" to="/fleet" delay={0} />
        <StatCard label="pending" value={count(vms, "pending")} color="var(--amber)" to="/fleet" delay={0.03} />
        <StatCard label="offline" value={count(vms, "offline")} color="var(--dim)" to="/fleet" delay={0.06} />
        <StatCard label="total fleet" value={fleet.length} color="var(--bone)" to="/fleet" delay={0.09} />
        <StatCard
          label="stale workers"
          value={stale.length}
          color={stale.length ? "var(--amber)" : "var(--dim)"}
          to="/fleet"
          delay={0.12}
        />
      </div>

      {/* Fleet health bar */}
      {fleet.length > 0 && (
        <motion.div
          className="panel"
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.15 }}
          style={{ padding: 18, marginBottom: 24 }}
        >
          <div className="eyebrow" style={{ marginBottom: 14 }}>fleet health</div>
          <FleetHealthBar vms={fleet} />
        </motion.div>
      )}

      <div style={{ display: "grid", gridTemplateColumns: "1.4fr 1fr", gap: 20 }}>
        {/* Recent activity */}
        <motion.div
          className="panel panel--bracket"
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.18 }}
          style={{ padding: 20, alignSelf: "start" }}
        >
          <div className="spread" style={{ marginBottom: 14 }}>
            <div className="eyebrow">recent activity</div>
            <Link to="/audit" className="tiny" style={{ color: "var(--ember-soft)" }}>all logs ›</Link>
          </div>
          <div className="stack" style={{ gap: 0, maxHeight: 440, overflow: "auto" }}>
            {audit?.length === 0 && <div className="muted tiny">no events yet</div>}
            {audit?.map((e) => (
              <div
                key={e.id}
                style={{ display: "flex", gap: 10, padding: "10px 0", borderBottom: "1px solid rgba(35,40,48,0.5)" }}
              >
                <span
                  style={{
                    width: 3,
                    alignSelf: "stretch",
                    borderRadius: 2,
                    background: resultColor(e.result_status),
                    flexShrink: 0,
                  }}
                />
                <div className="grow" style={{ minWidth: 0 }}>
                  <div className="spread">
                    <span style={{ color: "var(--ember-soft)", fontSize: 12, letterSpacing: "0.04em" }}>
                      {e.event_type}
                    </span>
                    <span className="muted tiny" style={{ flexShrink: 0 }}>{timeAgo(e.ts)}</span>
                  </div>
                  <div className="muted tiny" style={{ marginTop: 2 }}>
                    <span style={{ color: ACTOR_COLOR[e.actor_type] ?? "var(--dim)" }}>{e.actor_type}</span>
                    {" · "}{e.actor_label ?? e.actor_id.slice(0, 12)}
                    {e.action_name ? ` · ${e.action_name}` : ""}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </motion.div>

        {/* Side column */}
        <div className="stack" style={{ gap: 20 }}>
          {/* Stale workers */}
          {stale.length > 0 && (
            <motion.div
              className="panel"
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.2 }}
              style={{ padding: 20, borderLeft: "3px solid var(--amber)" }}
            >
              <div className="spread" style={{ marginBottom: 12 }}>
                <div className="eyebrow">stale workers</div>
                {isAdmin && (
                  <button className="btn btn--sm" onClick={updateAllStale} disabled={updatingAll}>
                    {updatingAll ? <span className="spin" /> : "update all"}
                  </button>
                )}
              </div>
              <div className="stack" style={{ gap: 6 }}>
                {stale.slice(0, 6).map((v) => (
                  <Link
                    key={v.id}
                    to={`/vm/${v.id}`}
                    className="spread"
                    style={{ textDecoration: "none", color: "inherit" }}
                  >
                    <span style={{ fontSize: 13 }}>{v.name}</span>
                    <span className="muted tiny">{v.worker_version} → {target}</span>
                  </Link>
                ))}
                {stale.length > 6 && <div className="muted tiny">+{stale.length - 6} more</div>}
              </div>
            </motion.div>
          )}

          {/* Upcoming schedules (admin) */}
          {isAdmin && (
            <motion.div
              className="panel"
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.23 }}
              style={{ padding: 20 }}
            >
              <div className="spread" style={{ marginBottom: 12 }}>
                <div className="eyebrow">upcoming schedules</div>
                <Link to="/schedules" className="tiny" style={{ color: "var(--ember-soft)" }}>manage ›</Link>
              </div>
              {activeSchedules.length === 0 && <div className="muted tiny">no active schedules</div>}
              <div className="stack" style={{ gap: 10 }}>
                {activeSchedules
                  .slice()
                  .sort((a, b) => (a.next_run_at ?? "").localeCompare(b.next_run_at ?? ""))
                  .slice(0, 5)
                  .map((s) => (
                    <div key={s.id} className="spread">
                      <span style={{ fontSize: 13, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                        {s.name}
                      </span>
                      <span className="muted tiny" style={{ flexShrink: 0 }}>{fmtTime(s.next_run_at)}</span>
                    </div>
                  ))}
              </div>
            </motion.div>
          )}

          {/* Quick links */}
          <motion.div
            className="panel"
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.26 }}
            style={{ padding: 20 }}
          >
            <div className="eyebrow" style={{ marginBottom: 12 }}>quick links</div>
            <div className="row" style={{ gap: 8, flexWrap: "wrap" }}>
              <Link to="/fleet" className="btn btn--sm btn--ghost">Fleet</Link>
              {isAdmin && <Link to="/schedules" className="btn btn--sm btn--ghost">Schedules</Link>}
              {isAdmin && <Link to="/tags" className="btn btn--sm btn--ghost">Tags</Link>}
              <Link to="/access-tokens" className="btn btn--sm btn--ghost">MCP Token</Link>
              <Link to="/audit" className="btn btn--sm btn--ghost">Logs</Link>
            </div>
          </motion.div>
        </div>
      </div>
    </motion.div>
  );
}
