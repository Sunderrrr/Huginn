import { motion } from "framer-motion";
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useApproveVm, useBulkRunAction, useSettings, useTags, useVms } from "../api/hooks";
import { useAuth } from "../auth/AuthContext";
import { AddVmModal } from "../components/AddVmModal";
import { ModeBadge, StateBadge, TagBadge } from "../components/badges";
import { useToast } from "../components/Toast";
import { timeAgo, shortId } from "../lib/format";
import { ACTION_CATALOG, type VM } from "../api/types";

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
  const { data: allVms, isLoading } = useVms();
  const { data: settings } = useSettings();
  const { data: tags } = useTags();
  const { user } = useAuth();
  const approve = useApproveVm();
  const bulkRun = useBulkRunAction();
  const toast = useToast();
  const navigate = useNavigate();
  const isAdmin = user?.role === "admin";
  const isOperator = user?.role === "operator";
  const canExecute = isAdmin || isOperator;

  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [bulkAction, setBulkAction] = useState("status");
  const [bulkParam, setBulkParam] = useState("");
  const [filterTags, setFilterTags] = useState<Set<string>>(new Set());
  const [addOpen, setAddOpen] = useState(false);

  // Apply the tag filter client-side.
  const vms = (allVms ?? []).filter(
    (v) => filterTags.size === 0 || v.tags.some((t) => filterTags.has(t.id))
  );

  const spec = ACTION_CATALOG.find((a) => a.name === bulkAction);
  // Only VMs that can actually run actions are selectable.
  const selectableVms = vms.filter(
    (v) => v.state === "active" || v.state === "offline"
  );
  const allSelected = selectableVms.length > 0 && selectableVms.every((v) => selected.has(v.id));

  function toggle(id: string) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  function toggleAll() {
    if (allSelected) setSelected(new Set());
    else setSelected(new Set(selectableVms.map((v) => v.id)));
  }

  async function onApprove(e: React.MouseEvent, id: string) {
    e.stopPropagation();
    try {
      await approve.mutateAsync(id);
      toast("ok", "VM approved · now active");
    } catch {
      toast("err", "approval failed");
    }
  }

  async function runBulk() {
    const ids = [...selected];
    const params = spec?.param && bulkParam ? { [spec.param.name]: bulkParam } : {};
    try {
      const results = await bulkRun.mutateAsync({ vm_ids: ids, action: bulkAction, params });
      const queued = results.filter((r) => r.status === "queued").length;
      const failed = results.length - queued;
      toast(failed ? "info" : "ok", `Dispatched on ${queued} VM(s)${failed ? `, ${failed} skipped` : ""}`);
      setSelected(new Set());
    } catch (e: unknown) {
      toast("err", e instanceof Error ? e.message : "bulk action failed");
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
        <div className="row" style={{ gap: 14 }}>
          <div className="muted tiny">target worker · {settings?.target_worker_version ?? "…"}</div>
          {isAdmin && (
            <button className="btn btn--primary btn--sm" onClick={() => setAddOpen(true)}>
              + Add VM
            </button>
          )}
        </div>
      </div>

      {isAdmin && <AddVmModal open={addOpen} onClose={() => setAddOpen(false)} />}

      {/* Tag filter */}
      {tags && tags.length > 0 && (
        <div className="row" style={{ gap: 8, flexWrap: "wrap", marginBottom: 14, alignItems: "center" }}>
          <span className="eyebrow">filter</span>
          {tags.map((t) => {
            const on = filterTags.has(t.id);
            return (
              <button
                key={t.id}
                onClick={() =>
                  setFilterTags((prev) => {
                    const next = new Set(prev);
                    if (next.has(t.id)) next.delete(t.id);
                    else next.add(t.id);
                    return next;
                  })
                }
                style={{
                  background: "none", border: "none", padding: 0, cursor: "pointer",
                  opacity: filterTags.size === 0 || on ? 1 : 0.4,
                }}
              >
                <TagBadge tag={t} />
              </button>
            );
          })}
          {filterTags.size > 0 && (
            <button className="btn btn--ghost btn--sm" onClick={() => setFilterTags(new Set())}>
              Clear
            </button>
          )}
        </div>
      )}

      {/* Bulk action bar */}
      {canExecute && selected.size > 0 && (
        <motion.div
          className="panel"
          initial={{ opacity: 0, y: -6 }}
          animate={{ opacity: 1, y: 0 }}
          style={{ padding: "12px 16px", marginBottom: 14 }}
        >
          <div className="row" style={{ gap: 12, flexWrap: "wrap", alignItems: "center" }}>
            <span className="display" style={{ fontSize: 13, letterSpacing: "0.08em" }}>
              {selected.size} selected
            </span>
            <select className="field" style={{ maxWidth: 200 }} value={bulkAction} onChange={(e) => setBulkAction(e.target.value)}>
              {ACTION_CATALOG.map((a) => (
                <option key={a.name} value={a.name}>{a.label}</option>
              ))}
            </select>
            {spec?.param && (
              <input
                className="field"
                style={{ maxWidth: 180 }}
                placeholder={spec.param.placeholder}
                value={bulkParam}
                onChange={(e) => setBulkParam(e.target.value)}
              />
            )}
            <button className="btn btn--primary" onClick={runBulk} disabled={bulkRun.isPending}>
              {bulkRun.isPending ? <span className="spin" /> : `Run on ${selected.size} ›`}
            </button>
            <button className="btn btn--ghost btn--sm" onClick={() => setSelected(new Set())}>
              Clear
            </button>
          </div>
        </motion.div>
      )}

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
              {canExecute && (
                <th style={{ width: 36 }}>
                  <input
                    type="checkbox"
                    checked={allSelected}
                    onChange={toggleAll}
                    aria-label="select all"
                  />
                </th>
              )}
              <th>Node</th>
              <th>State</th>
              <th>Mode</th>
              <th>Tags</th>
              <th>Worker</th>
              <th>Heartbeat</th>
              <th style={{ textAlign: "right" }}>—</th>
            </tr>
          </thead>
          <tbody>
            {vms.map((vm, i) => {
              const selectable = vm.state === "active" || vm.state === "offline";
              return (
                <motion.tr
                  key={vm.id}
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  transition={{ delay: Math.min(i * 0.03, 0.4) }}
                  onClick={() => navigate(`/vm/${vm.id}`)}
                >
                  {canExecute && (
                    <td onClick={(e) => e.stopPropagation()}>
                      <input
                        type="checkbox"
                        checked={selected.has(vm.id)}
                        disabled={!selectable}
                        onChange={() => toggle(vm.id)}
                        aria-label={`select ${vm.name}`}
                      />
                    </td>
                  )}
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
                    {vm.tags.length > 0 ? (
                      <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
                        {vm.tags.map((t) => <TagBadge key={t.id} tag={t} />)}
                      </div>
                    ) : (
                      <span className="muted">—</span>
                    )}
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
              );
            })}
          </tbody>
        </table>

        {isLoading && (
          <div style={{ padding: 40, textAlign: "center" }}>
            <span className="spin" />
          </div>
        )}
        {!isLoading && vms.length === 0 && (
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
