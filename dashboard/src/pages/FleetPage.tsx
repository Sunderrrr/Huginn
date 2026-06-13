import { motion } from "framer-motion";
import { useNavigate } from "react-router-dom";
import { useApproveVm, useSettings, useVms } from "../api/hooks";
import { useAuth } from "../auth/AuthContext";
import { ModeBadge, StateBadge } from "../components/badges";
import { useToast } from "../components/Toast";
import { timeAgo, shortId } from "../lib/format";
import type { VM } from "../api/types";

function VersionCell({ vm, target }: { vm: VM; target?: string }) {
  if (!vm.worker_version) return <span className="muted">—</span>;
  const stale = target && vm.worker_version !== target;
  return (
    <span style={{ color: stale ? "var(--amber)" : "var(--dim)" }}>
      {vm.worker_version}
      {stale && <span className="muted" style={{ marginLeft: 6 }}>→ {target}</span>}
    </span>
  );
}

export function FleetPage() {
  const { data: vms, isLoading } = useVms();
  const { data: settings } = useSettings();
  const { user } = useAuth();
  const approve = useApproveVm();
  const toast = useToast();
  const navigate = useNavigate();
  const isAdmin = user?.role === "admin";

  async function onApprove(e: React.MouseEvent, id: string) {
    e.stopPropagation();
    try {
      await approve.mutateAsync(id);
      toast("ok", "VM approved · now active");
    } catch {
      toast("err", "approval failed");
    }
  }

  return (
    <div>
      <div className="spread" style={{ marginBottom: 20 }}>
        <div>
          <div className="eyebrow">inventory</div>
          <h1 className="display" style={{ fontSize: 28, letterSpacing: "0.08em" }}>
            Fleet
          </h1>
        </div>
        <div className="muted tiny">target worker · {settings?.target_worker_version ?? "…"}</div>
      </div>

      <motion.div
        className="panel panel--bracket"
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4 }}
        style={{ overflow: "hidden" }}
      >
        <table className="tbl">
          <thead>
            <tr>
              <th>Node</th>
              <th>State</th>
              <th>Mode</th>
              <th>Worker</th>
              <th>Heartbeat</th>
              <th style={{ textAlign: "right" }}>—</th>
            </tr>
          </thead>
          <tbody>
            {vms?.map((vm, i) => (
              <motion.tr
                key={vm.id}
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ delay: Math.min(i * 0.03, 0.4) }}
                onClick={() => navigate(`/vm/${vm.id}`)}
              >
                <td>
                  <div style={{ fontFamily: "var(--font-display)", letterSpacing: "0.04em" }}>
                    {vm.name}
                  </div>
                  <div className="muted tiny">
                    {vm.ip_address ?? "no ip"} · {vm.arch} · {shortId(vm.id)}
                  </div>
                </td>
                <td>
                  <StateBadge state={vm.state} />
                </td>
                <td>
                  <ModeBadge mode={vm.exec_mode} />
                </td>
                <td>
                  <VersionCell vm={vm} target={settings?.target_worker_version} />
                </td>
                <td className="muted">{timeAgo(vm.last_heartbeat_at)}</td>
                <td style={{ textAlign: "right" }}>
                  {vm.state === "pending" && isAdmin ? (
                    <button className="btn btn--primary btn--sm" onClick={(e) => onApprove(e, vm.id)}>
                      Approve
                    </button>
                  ) : (
                    <span className="muted">›</span>
                  )}
                </td>
              </motion.tr>
            ))}
          </tbody>
        </table>

        {isLoading && (
          <div style={{ padding: 40, textAlign: "center" }}>
            <span className="spin" />
          </div>
        )}
        {!isLoading && vms?.length === 0 && (
          <div style={{ padding: 48, textAlign: "center" }} className="muted">
            <div className="display" style={{ fontSize: 18, marginBottom: 6 }}>
              No nodes enrolled
            </div>
            <div className="tiny">
              Generate an enrollment token and run the installer on a VM.
            </div>
          </div>
        )}
      </motion.div>
    </div>
  );
}
