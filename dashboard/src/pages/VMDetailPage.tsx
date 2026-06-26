import { motion } from "framer-motion";
import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import {
  useAudit,
  useDeleteVm,
  useRevokeVm,
  useRunAction,
  useRunCommand,
  useCustomActions,
  useSetExecMode,
  useSetVmTags,
  useSettings,
  useTags,
  useTriggerUpdate,
  useVm,
} from "../api/hooks";
import { ACTION_CATALOG, type ExecMode, type Task } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { ModeBadge, StateBadge, TagBadge, TaskStatusTag } from "../components/badges";
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
  const del = useDeleteVm();
  const navigate = useNavigate();
  const { data: allTags } = useTags();
  const { data: customActions } = useCustomActions();
  const setVmTags = useSetVmTags();

  const [action, setAction] = useState("status");
  const [serviceParam, setServiceParam] = useState("");
  const [command, setCommand] = useState("");
  const [result, setResult] = useState<Task | null>(null);
  const [confirmMode, setConfirmMode] = useState(false);
  const [confirmRevoke, setConfirmRevoke] = useState(false);
  const [uninstallBeforeRevoke, setUninstallBeforeRevoke] = useState(true);
  const [confirmDelete, setConfirmDelete] = useState(false);

  if (isLoading || !vm) {
    return (
      <div style={{ display: "grid", placeItems: "center", padding: 80 }}>
        <span className="spin" />
      </div>
    );
  }

  const spec = ACTION_CATALOG.find((a) => a.name === action);
  const unrestricted = vm.exec_mode === "unrestricted";
  // Custom commands available on this VM: enabled, mode allows them, and the VM
  // carries one of the command's tags (the same gates the hub enforces).
  const vmTagIds = new Set((vm.tags ?? []).map((t) => t.id));
  const eligibleCustom =
    vm.exec_mode === "custom" || vm.exec_mode === "unrestricted"
      ? (customActions ?? []).filter(
          (a) => a.enabled && a.tag_ids.some((tid) => vmTagIds.has(tid)),
        )
      : [];

  async function setModeTo(mode: ExecMode) {
    if (mode === vm!.exec_mode) return;
    if (mode === "unrestricted") {
      setConfirmMode(true); // keep the explicit confirmation for the free shell
      return;
    }
    try {
      await setMode.mutateAsync({ id, mode });
      toast("ok", `exec mode: ${mode}`);
    } catch {
      toast("err", "mode change failed");
    }
  }
  const stale = vm.worker_version && settings && vm.worker_version !== settings.target_worker_version;
  const isOperator = user?.role === "operator";
  const canActOn = (isAdmin || isOperator) && (vm.state === "active" || vm.state === "offline");

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
      await revoke.mutateAsync({ id, uninstall: uninstallBeforeRevoke });
      toast("ok", "VM revoked");
    } catch {
      toast("err", "revoke failed");
    }
  }

  async function doDelete() {
    setConfirmDelete(false);
    try {
      await del.mutateAsync(id);
      toast("ok", "VM deleted");
      navigate("/fleet");
    } catch (e: any) {
      toast("err", e?.message ?? "delete failed");
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
        {isAdmin && vm.state === "revoked" && (
          <button className="btn btn--danger btn--sm" onClick={() => setConfirmDelete(true)}>
            Delete permanently
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
            {canActOn && (
              <div style={{ marginTop: 18 }}>
                <button
                  className={stale ? "btn btn--sm btn--primary" : "btn btn--sm"}
                  onClick={doUpdate}
                  disabled={triggerUpdate.isPending}
                >
                  {triggerUpdate.isPending ? (
                    <span className="spin" />
                  ) : (
                    <>⟳ Update worker{stale ? ` → ${settings?.target_worker_version}` : ""}</>
                  )}
                </button>
                {!stale && (
                  <span className="muted tiny" style={{ marginLeft: 10 }}>
                    re-pushes the target build
                  </span>
                )}
              </div>
            )}

            {/* Tags */}
            <div style={{ marginTop: 18, paddingTop: 18, borderTop: "1px solid var(--line)" }}>
              <div className="eyebrow" style={{ marginBottom: 8 }}>tags</div>
              <div className="row" style={{ gap: 6, flexWrap: "wrap" }}>
                {vm.tags.length === 0 && <span className="muted tiny">no tags</span>}
                {vm.tags.map((t) => (
                  <TagBadge
                    key={t.id}
                    tag={t}
                    onRemove={
                      isAdmin
                        ? () => {
                            const next = vm.tags.filter((x) => x.id !== t.id).map((x) => x.id);
                            setVmTags.mutate({ id: vm.id, tag_ids: next });
                          }
                        : undefined
                    }
                  />
                ))}
              </div>
              {isAdmin && allTags && allTags.some((t) => !vm.tags.find((x) => x.id === t.id)) && (
                <select
                  className="field"
                  style={{ maxWidth: 220, marginTop: 10 }}
                  value=""
                  onChange={(e) => {
                    if (!e.target.value) return;
                    setVmTags.mutate({
                      id: vm.id,
                      tag_ids: [...vm.tags.map((x) => x.id), e.target.value],
                    });
                  }}
                >
                  <option value="">+ add tag…</option>
                  {allTags
                    .filter((t) => !vm.tags.find((x) => x.id === t.id))
                    .map((t) => (
                      <option key={t.id} value={t.id}>{t.name}</option>
                    ))}
                </select>
              )}
            </div>
          </motion.div>

          {/* Actions */}
          <motion.div className="panel panel--bracket" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.05 }} style={{ padding: 20 }}>
            <div className="spread" style={{ marginBottom: 14 }}>
              <div className="eyebrow">actions</div>
              {isAdmin && (vm.state === "active" || vm.state === "offline") && (
                <div className="row" style={{ gap: 4 }} title="exec mode">
                  {(["whitelist", "custom", "unrestricted"] as ExecMode[]).map((m) => (
                    <button
                      key={m}
                      className={`btn btn--sm ${vm.exec_mode === m ? "btn--primary" : "btn--ghost"}`}
                      disabled={setMode.isPending}
                      onClick={() => setModeTo(m)}
                    >
                      {m}
                    </button>
                  ))}
                </div>
              )}
            </div>
            {!canActOn ? (
              <div className="muted tiny">
                {isAdmin || isOperator ? "node must be active to run actions" : "read-only — execution disabled"}
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
                    {eligibleCustom.length > 0 && (
                      <optgroup label="custom commands">
                        {eligibleCustom.map((a) => (
                          <option key={a.id} value={a.name}>
                            {a.name}
                          </option>
                        ))}
                      </optgroup>
                    )}
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

            {/* Free shell — only in unrestricted mode (set via the selector above). */}
            {isAdmin && unrestricted && (vm.state === "active" || vm.state === "offline") && (
              <div style={{ marginTop: 22, paddingTop: 18, borderTop: "1px solid var(--line)" }}>
                <div style={{ marginBottom: 14 }}>
                  <div style={{ fontFamily: "var(--font-display)", letterSpacing: "0.08em", fontSize: 13 }}>
                    UNRESTRICTED SHELL
                  </div>
                  <div className="muted tiny">arbitrary command execution · audited</div>
                </div>
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
                  {e.actor_type}:{e.actor_label ?? e.actor_id.slice(0, 12)}
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
        <div className="stack" style={{ gap: 16 }}>
          <p>
            Revoking <strong>{vm.name}</strong> invalidates its credential — the worker can no longer
            authenticate. This cannot be undone.
          </p>
          {(vm.state === "active" || vm.state === "offline") && (
            <label className="row" style={{ gap: 10, cursor: "pointer", padding: "10px 14px", background: "var(--void)", borderRadius: 6 }}>
              <input
                type="checkbox"
                checked={uninstallBeforeRevoke}
                onChange={(e) => setUninstallBeforeRevoke(e.target.checked)}
              />
              <div>
                <div style={{ fontSize: 13, fontWeight: 600 }}>Uninstall worker service first</div>
                <div className="muted tiny" style={{ marginTop: 2 }}>
                  Sends an uninstall task to the worker (removes binary + systemd service). Best-effort — revocation proceeds regardless.
                </div>
              </div>
            </label>
          )}
          <div className="row" style={{ justifyContent: "flex-end" }}>
            <button className="btn btn--ghost" onClick={() => setConfirmRevoke(false)}>
              Cancel
            </button>
            <button className="btn btn--danger" onClick={doRevoke} disabled={revoke.isPending}>
              {revoke.isPending ? <span className="spin" /> : "Revoke node"}
            </button>
          </div>
        </div>
      </Modal>

      {/* Confirm: permanent delete */}
      <Modal open={confirmDelete} onClose={() => setConfirmDelete(false)} title="Delete node permanently">
        <div className="stack" style={{ gap: 16 }}>
          <p>
            Permanently delete <strong>{vm.name}</strong> and all of its tasks, tags and access
            grants. The audit history is kept. This cannot be undone.
          </p>
          <div className="row" style={{ justifyContent: "flex-end" }}>
            <button className="btn btn--ghost" onClick={() => setConfirmDelete(false)}>
              Cancel
            </button>
            <button className="btn btn--danger" onClick={doDelete} disabled={del.isPending}>
              {del.isPending ? <span className="spin" /> : "Delete permanently"}
            </button>
          </div>
        </div>
      </Modal>
    </div>
  );
}
