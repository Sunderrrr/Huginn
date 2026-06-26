import { motion } from "framer-motion";
import { useState } from "react";
import { api } from "../api/client";
import { useAudit } from "../api/hooks";
import { useAuth } from "../auth/AuthContext";
import { useToast } from "../components/Toast";
import { fmtTime } from "../lib/format";

const EVENT_TYPES = [
  "",
  "login",
  "login_failed",
  "enroll",
  "approve",
  "revoke",
  "execute_action",
  "execute_command",
  "scheduled_action",
  "scheduled_command",
  "toggle_unrestricted",
  "trigger_update",
  "token_create",
  "token_revoke",
  "settings_update",
];

const ACTOR_COLOR: Record<string, string> = {
  user: "var(--steel)",
  agent: "var(--ember-soft)",
  system: "var(--dim)",
};

export function AuditPage() {
  const { user } = useAuth();
  const [eventType, setEventType] = useState("");
  const { data: audit, isLoading } = useAudit({ event_type: eventType || undefined, limit: 200 });
  const toast = useToast();

  async function verify() {
    try {
      const res = await api.get<{ intact: boolean }>("/api/audit/verify");
      toast(res.intact ? "ok" : "err", res.intact ? "audit chain intact ✓" : "CHAIN TAMPER DETECTED");
    } catch {
      toast("err", "verification failed");
    }
  }

  return (
    <div>
      <div className="spread" style={{ marginBottom: 20, flexWrap: "wrap", gap: 12 }}>
        <div>
          <div className="eyebrow">immutable ledger</div>
          <h1 className="display" style={{ fontSize: 28, letterSpacing: "0.08em" }}>
            Audit Log
          </h1>
        </div>
        <div className="row" style={{ gap: 10 }}>
          <select className="field" style={{ width: 200 }} value={eventType} onChange={(e) => setEventType(e.target.value)}>
            {EVENT_TYPES.map((t) => (
              <option key={t} value={t}>
                {t || "all events"}
              </option>
            ))}
          </select>
          {user?.role === "admin" && (
            <button className="btn" onClick={verify}>
              ✓ Verify chain
            </button>
          )}
        </div>
      </div>

      <motion.div className="panel panel--bracket" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} style={{ overflow: "hidden" }}>
        <table className="tbl">
          <thead>
            <tr>
              <th style={{ width: 60 }}>#</th>
              <th>Time</th>
              <th>Actor</th>
              <th>Event</th>
              <th>Detail</th>
            </tr>
          </thead>
          <tbody>
            {audit?.map((e) => (
              <tr key={e.id} style={{ cursor: "default" }}>
                <td className="muted tiny">{e.id}</td>
                <td className="muted tiny">{fmtTime(e.ts)}</td>
                <td>
                  <span style={{ color: ACTOR_COLOR[e.actor_type] ?? "var(--dim)" }}>{e.actor_type}</span>
                  <span className="muted tiny"> · {e.actor_label ?? e.actor_id.slice(0, 14)}</span>
                </td>
                <td>
                  <span style={{ color: "var(--ember-soft)", letterSpacing: "0.04em" }}>{e.event_type}</span>
                </td>
                <td className="muted tiny">
                  {e.action_name && <span>{e.action_name} </span>}
                  {e.command && <span>· {e.command} </span>}
                  {e.result_status && <span>· {e.result_status}</span>}
                  {e.source_ip && <span className="muted"> · {e.source_ip}</span>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {isLoading && (
          <div style={{ padding: 36, textAlign: "center" }}>
            <span className="spin" />
          </div>
        )}
      </motion.div>
    </div>
  );
}
