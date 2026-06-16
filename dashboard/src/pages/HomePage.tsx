import { motion } from "framer-motion";
import { Link } from "react-router-dom";
import { useAudit, useSchedules, useSettings, useVms } from "../api/hooks";
import { useAuth } from "../auth/AuthContext";
import { timeAgo, fmtTime } from "../lib/format";
import type { VM, VMState } from "../api/types";

const ACTOR_COLOR: Record<string, string> = {
  user: "var(--steel)",
  agent: "var(--ember-soft)",
  system: "var(--dim)",
};

function count(vms: VM[] | undefined, state: VMState): number {
  return vms?.filter((v) => v.state === state).length ?? 0;
}

function StatCard({ label, value, color, to }: { label: string; value: number; color: string; to?: string }) {
  const body = (
    <div className="panel" style={{ padding: "20px 22px", minWidth: 130 }}>
      <div style={{ fontFamily: "var(--font-display)", fontSize: 34, color, lineHeight: 1 }}>
        {String(value).padStart(2, "0")}
      </div>
      <div className="eyebrow" style={{ marginTop: 8 }}>{label}</div>
    </div>
  );
  return to ? <Link to={to} style={{ textDecoration: "none" }}>{body}</Link> : body;
}

export function HomePage() {
  const { user } = useAuth();
  const { data: vms } = useVms();
  const { data: settings } = useSettings();
  const { data: audit } = useAudit({ limit: 12 });
  const isAdmin = user?.role === "admin";
  const { data: schedules } = useSchedules({ enabled: isAdmin });

  const target = settings?.target_worker_version;
  const stale = (vms ?? []).filter((v) => v.worker_version && target && v.worker_version !== target);

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}>
      <div style={{ marginBottom: 24 }}>
        <div className="eyebrow">overview</div>
        <h1 className="display" style={{ fontSize: 28, letterSpacing: "0.08em", margin: "8px 0" }}>
          Welcome{user ? `, ${user.username}` : ""}
        </h1>
      </div>

      {/* Stat cards */}
      <div className="row" style={{ gap: 14, flexWrap: "wrap", marginBottom: 24 }}>
        <StatCard label="active" value={count(vms, "active")} color="var(--signal)" to="/fleet" />
        <StatCard label="pending" value={count(vms, "pending")} color="var(--amber)" to="/fleet" />
        <StatCard label="offline" value={count(vms, "offline")} color="var(--dim)" to="/fleet" />
        <StatCard label="total" value={vms?.length ?? 0} color="var(--bone)" to="/fleet" />
        <StatCard label="stale workers" value={stale.length} color={stale.length ? "var(--amber)" : "var(--dim)"} to="/fleet" />
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1.4fr 1fr", gap: 20 }}>
        {/* Recent activity */}
        <motion.div className="panel panel--bracket" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.05 }} style={{ padding: 20, alignSelf: "start" }}>
          <div className="spread" style={{ marginBottom: 14 }}>
            <div className="eyebrow">recent activity</div>
            <Link to="/audit" className="tiny" style={{ color: "var(--ember-soft)" }}>all logs ›</Link>
          </div>
          <div className="stack" style={{ gap: 0, maxHeight: 420, overflow: "auto" }}>
            {audit?.length === 0 && <div className="muted tiny">no events yet</div>}
            {audit?.map((e) => (
              <div key={e.id} style={{ padding: "9px 0", borderBottom: "1px solid rgba(35,40,48,0.5)" }}>
                <div className="spread">
                  <span style={{ color: "var(--ember-soft)", fontSize: 12, letterSpacing: "0.04em" }}>
                    {e.event_type}
                  </span>
                  <span className="muted tiny">{timeAgo(e.ts)}</span>
                </div>
                <div className="muted tiny" style={{ marginTop: 2 }}>
                  <span style={{ color: ACTOR_COLOR[e.actor_type] ?? "var(--dim)" }}>{e.actor_type}</span>
                  {" · "}{e.actor_label ?? e.actor_id.slice(0, 12)}
                </div>
              </div>
            ))}
          </div>
        </motion.div>

        {/* Side column */}
        <div className="stack" style={{ gap: 20 }}>
          {/* Active schedules (admin) */}
          {isAdmin && (
            <motion.div className="panel" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }} style={{ padding: 20 }}>
              <div className="spread" style={{ marginBottom: 12 }}>
                <div className="eyebrow">upcoming schedules</div>
                <Link to="/schedules" className="tiny" style={{ color: "var(--ember-soft)" }}>manage ›</Link>
              </div>
              {(!schedules || schedules.filter((s) => s.enabled).length === 0) && (
                <div className="muted tiny">no active schedules</div>
              )}
              <div className="stack" style={{ gap: 8 }}>
                {schedules?.filter((s) => s.enabled).slice(0, 5).map((s) => (
                  <div key={s.id} className="spread">
                    <span style={{ fontSize: 13 }}>{s.name}</span>
                    <span className="muted tiny">{fmtTime(s.next_run_at)}</span>
                  </div>
                ))}
              </div>
            </motion.div>
          )}

          {/* Stale workers */}
          {stale.length > 0 && (
            <motion.div className="panel" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.12 }} style={{ padding: 20, borderLeft: "3px solid var(--amber)" }}>
              <div className="eyebrow" style={{ marginBottom: 10 }}>stale workers</div>
              <div className="stack" style={{ gap: 6 }}>
                {stale.slice(0, 6).map((v) => (
                  <Link key={v.id} to={`/vm/${v.id}`} className="spread" style={{ textDecoration: "none", color: "inherit" }}>
                    <span style={{ fontSize: 13 }}>{v.name}</span>
                    <span className="muted tiny">{v.worker_version} → {target}</span>
                  </Link>
                ))}
              </div>
            </motion.div>
          )}
        </div>
      </div>
    </motion.div>
  );
}
