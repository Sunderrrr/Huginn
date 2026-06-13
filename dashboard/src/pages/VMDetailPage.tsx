import { motion } from "framer-motion";
import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import {
  useAudit,
  useRevokeVm,
  useRunAction,
  useRunCommand,
  useSetExecMode,
  useSettings,
  useTriggerUpdate,
  useVm,
} from "../api/hooks";
import { ACTION_CATALOG, type Task } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { ModeBadge, StateBadge, TaskStatusTag } from "../components/badges";
import { Modal } from "../components/Dialog";
import { useToast } from "../components/Toast";
import { fmtTime, timeAgo } from "../lib/format";

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <div className="eyebrow" style={{ marginBottom: 4 }}>
        {label}
      </div>
      <div style={{ fontSize: 13 }}>{children}</div>
    </div>
  );
}

function ResultView({ task }: { task: Task }) {
  return (
    <div style={{ marginTop: 12 }}>
      <div className="row" style={{ gap: 12, marginBottom: 6 }}>
        <TaskStatusTag status={task.status} />
        {task.exit_code !== null && <span className="muted tiny">exit {task.exit_code}</span>}
      </div>
      {task.stdout && <pre className="codeblock">{task.stdout}</pre>}
      {task.stderr && (
        <pre className="codeblock" style={{ borderColor: "rgba(255,77,77,0.3)", marginTop: 8 }}>
          {task.stderr}
        </pre>
      )}
      {task.error && <div style={{ color: "var(--blood)", marginTop: 8 }}>{task.error}</div>}
    </div>
  );
}

export function VMDetailPage() {
  const { id = "" } = useParams();
  const { data: vm, isLoading } = useVm(id);
  const { data: settings } = useSettings();
  const { data: audit } = useAudit({ vm_id: id, limit: 40 });
  const { user } = useAuth();
  const toast = useToast();
  const isAdmin = user?.role === "admin";

  const runAction = useRunAction();
  const runCommand = useRunCommand();
  const setMode = useSetExecMode();
  const triggerUpdate = useTriggerUpdate();
  const revoke = useRevokeVm();

  const [action, setAction] = useState("status");
  const [serviceParam, setServiceParam] = useState("");
  const [command, setCommand] = useState("");
  const [result, setResult] = useState<Task | null>(null);
  const [confirmMode, setConfirmMode] = useState(false);
  const [confirmRevoke, setConfirmRevoke] = useState(false);

  if (isLoading || !vm) {
    return (
      <div style={{ display: "grid", placeItems: "center", padding: 80 }}>
        <span className="spin" />
      </div>
    );
  }

  const spec = ACTION_CATALOG.find((a) => a.name === action);
  const unrestricted = vm.exec_mode === "unrestricted";
  const stale = vm.worker_version && settings && vm.worker_version !== settings.target_worker_version;
  const canActOn = isAdmin && (vm.state === "active" || vm.state === "offline");

  async function doAction() {
    try {
      const params = spec?.param && serviceParam ? { [spec.param.name]: serviceParam } : {};
      const task = await runAction.mutateAsync({ id, action, params });
      setResult(task);
      toast(task.status === "succeeded" ? "ok" : "err", `action ${action} · ${task.status}`);
    } catch (e: any) {
      toast("err", e?.message ?? "action failed");
    }
  }

  async function doCommand() {
    try {
      const task = await runCommand.mutateAsync({ id, command });
      setResult(task);
      toast(task.status === "succeeded" ? "ok" : "err", `command · ${task.status}`);
    } catch (e: any) {
      toast("err", e?.message ?? "command failed");
    }
  }

  async function toggleMode() {
    setConfirmMode(false);
    try {
      await setMode.mutateAsync({ id, mode: unrestricted ? "whitelist" : "unrestricted" });
      toast("ok", unrestricted ? "restricted to whitelist" : "UNRESTRICTED mode enabled");
    } catch {
      toast("err", "mode change failed");
    }
  }

  async function doUpdate() {
    try {
      await triggerUpdate.mutateAsync(id);
      toast("ok", "update task dispatched");
    } catch (e: any) {
      toast("err", e?.message ?? "update failed");
    }
  }

  async function doRevoke() {
    setConfirmRevoke(false);
    try {
      await revoke.mutateAsync(id);
      toast("ok", "VM revoked");
    } catch {
      toast("err", "revoke failed");
    }
  }

  return (
    <div>
      <Link to="/fleet" className="eyebrow" style={{ display: "inline-block", marginBottom: 14 }}>
        ‹ back to fleet
      </Link>

      <div className="spread" style={{ marginBottom: 24, flexWrap: "wrap", gap: 16 }}>
        <div className="row" style={{ gap: 16 }}>
          <h1 className="display" style={{ fontSize: 30, letterSpacing: "0.06em" }}>
            {vm.name}
          </h1>
          <StateBadge state={vm.state} />
          <ModeBadge mode={vm.exec_mode} />
        </div>
        {isAdmin && vm.state !== "revoked" && (
          <button className="btn btn--danger btn--sm" onClick={() => setConfirmRevoke(true)}>
            Revoke node
          </button>
        )}
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1.4fr 1fr", gap: 20 }}>
        {/* LEFT COLUMN */}
        <div className="stack" style={{ gap: 20 }}>
          <motion.div
            className="panel"
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            style={{ padding: 20 }}
          >
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "1fr 1fr 1fr",
                gap: 18,
              }}
            >
              <Field label="hostname">{vm.hostname ?? "—"}</Field>
              <Field label="ip">{vm.ip_address ?? "—"}</Field>
              <Field label="arch">{vm.arch}</Field>
              <Field label="worker">
                <span style={{ color: stale ? "var(--amber)" : "var(--bone)" }}>
                  {vm.worker_version ?? "—"}
                </span>
              </Field>
              <Field label="target">{settings?.target_worker_version ?? "—"}</Field>
              <Field label="heartbeat">{timeAgo(vm.last_heartbeat_at)}</Field>
              <Field label="enrolled">{fmtTime(vm.enrolled_at)}</Field>
              <Field label="approved">{fmtTime(vm.approved_at)}</Field>
            </div>
            {canActOn && stale && (
              <div style={{ marginTop: 18 }}>
                <button className="btn btn--sm" onClick={doUpdate} disabled={triggerUpdate.isPending}>
                  ⟳ Update worker → {settings?.target_worker_version}
                </button>
              </div>
            )}
          </motion.div>

          {/* Actions */}
          <motion.div className="panel panel--bracket" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.05 }} style={{ padding: 20 }}>
            <div className="eyebrow" style={{ marginBottom: 14 }}>
              whitelisted actions
            </div>
            {!canActOn ? (
              <div className="muted tiny">
                {isAdmin ? "node must be active to run actions" : "read-only — execution disabled"}
              </div>
            ) : (
              <>
                <div className="row" style={{ gap: 10, flexWrap: "wrap" }}>
                  <select className="field" style={{ maxWidth: 220 }} value={action} onChange={(e) => setAction(e.target.value)}>
                    {ACTION_CATALOG.map((a) => (
                      <option key={a.name} value={a.name}>
                        {a.label}
                      </option>
                    ))}
                  </select>
                  {spec?.param && (
                    <input
                      className="field"
                      style={{ maxWidth: 200 }}
                      placeholder={spec.param.placeholder}
                      value={serviceParam}
                      onChange={(e) => setServiceParam(e.target.value)}
                    />
                  )}
                  <button className="btn btn--primary" onClick={doAction} disabled={runAction.isPending}>
                    {runAction.isPending ? <span className="spin" /> : "Run ›"}
                  </button>
                </div>
                <div className="muted tiny" style={{ marginTop: 8 }}>
                  {spec?.description}
                </div>
              </>
            )}

            {/* Unrestricted toggle + free command */}
            {isAdmin && (vm.state === "active" || vm.state === "offline") && (
              <div style={{ marginTop: 22, paddingTop: 18, borderTop: "1px solid var(--line)" }}>
                <div className="spread" style={{ marginBottom: unrestricted ? 14 : 0 }}>
                  <div>
                    <div style={{ fontFamily: "var(--font-display)", letterSpacing: "0.08em", fontSize: 13 }}>
                      UNRESTRICTED SHELL
                    </div>
                    <div className="muted tiny">arbitrary command execution · audited</div>
                  </div>
                  <button
                    className={unrestricted ? "btn btn--danger btn--sm" : "btn btn--sm"}
                    onClick={() => setConfirmMode(true)}
                    disabled={setMode.isPending}
                  >
                    {unrestricted ? "Disable" : "Enable"}
                  </button>
                </div>
                {unrestricted && (
                  <div className="row" style={{ gap: 10 }}>
                    <input
                      className="field"
                      style={{ fontFamily: "var(--font-mono)" }}
                      placeholder="$ command to run…"
                      value={command}
                      onChange={(e) => setCommand(e.target.value)}
                      onKeyDown={(e) => e.key === "Enter" && command && doCommand()}
                    />
                    <button className="btn btn--danger" onClick={doCommand} disabled={!command || runCommand.isPending}>
                      {runCommand.isPending ? <span className="spin" /> : "Exec"}
                    </button>
                  </div>
                )}
              </div>
            )}

            {result && <ResultView task={result} />}
          </motion.div>
        </div>

        {/* RIGHT COLUMN — audit */}
        <motion.div className="panel" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }} style={{ padding: 20, alignSelf: "start" }}>
          <div className="eyebrow" style={{ marginBottom: 14 }}>
            node activity
          </div>
          <div className="stack" style={{ gap: 0, maxHeight: 540, overflow: "auto" }}>
            {audit?.length === 0 && <div className="muted tiny">no events yet</div>}
            {audit?.map((e) => (
              <div key={e.id} style={{ padding: "10px 0", borderBottom: "1px solid rgba(35,40,48,0.5)" }}>
                <div className="spread">
                  <span style={{ color: "var(--ember-soft)", fontSize: 12, letterSpacing: "0.04em" }}>
                    {e.event_type}
                  </span>
                  <span className="muted tiny">{timeAgo(e.ts)}</span>
                </div>
                <div className="muted tiny" style={{ marginTop: 2 }}>
                  {e.actor_type}:{e.actor_id.slice(0, 12)}
                  {e.action_name ? ` · ${e.action_name}` : ""}
                  {e.command ? ` · ${e.command}` : ""}
                </div>
              </div>
            ))}
          </div>
        </motion.div>
      </div>

      {/* Confirm: toggle unrestricted */}
      <Modal open={confirmMode} onClose={() => setConfirmMode(false)} title={unrestricted ? "Restrict node" : "Enable unrestricted shell"}>
        {!unrestricted ? (
          <div>
            <p style={{ marginBottom: 16, color: "var(--bone)" }}>
              This allows <strong style={{ color: "var(--blood)" }}>arbitrary shell command execution</strong> on{" "}
              <strong>{vm.name}</strong>. Every command is audited. Enable only when necessary.
            </p>
            <div className="row" style={{ justifyContent: "flex-end" }}>
              <button className="btn btn--ghost" onClick={() => setConfirmMode(false)}>
                Cancel
              </button>
              <button className="btn btn--danger" onClick={toggleMode}>
                Enable unrestricted
              </button>
            </div>
          </div>
        ) : (
          <div>
            <p style={{ marginBottom: 16 }}>Return {vm.name} to whitelist-only execution?</p>
            <div className="row" style={{ justifyContent: "flex-end" }}>
              <button className="btn btn--ghost" onClick={() => setConfirmMode(false)}>
                Cancel
              </button>
              <button className="btn btn--primary" onClick={toggleMode}>
                Restrict
              </button>
            </div>
          </div>
        )}
      </Modal>

      {/* Confirm: revoke */}
      <Modal open={confirmRevoke} onClose={() => setConfirmRevoke(false)} title="Revoke node">
        <p style={{ marginBottom: 16 }}>
          Revoking <strong>{vm.name}</strong> invalidates its credential — the worker can no longer
          authenticate. This cannot be undone.
        </p>
        <div className="row" style={{ justifyContent: "flex-end" }}>
          <button className="btn btn--ghost" onClick={() => setConfirmRevoke(false)}>
            Cancel
          </button>
          <button className="btn btn--danger" onClick={doRevoke}>
            Revoke node
          </button>
        </div>
      </Modal>
    </div>
  );
}
