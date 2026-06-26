import { motion } from "framer-motion";
import { useState } from "react";
import {
  useCreateSchedule,
  useDeleteSchedule,
  useSchedules,
  useTags,
  useUpdateSchedule,
  useVms,
} from "../api/hooks";
import { useAuth } from "../auth/AuthContext";
import { Modal } from "../components/Dialog";
import { useToast } from "../components/Toast";
import { ACTION_CATALOG, type Schedule, type ScheduleTargetKind } from "../api/types";
import { fmtTime } from "../lib/format";

const DOW = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

type Preset = "hourly" | "daily" | "weekly" | "monthly" | "advanced";

function buildCron(p: Preset, hour: number, minute: number, dow: number, dom: number): string {
  switch (p) {
    case "hourly": return `${minute} * * * *`;
    case "daily": return `${minute} ${hour} * * *`;
    case "weekly": return `${minute} ${hour} * * ${dow}`;
    case "monthly": return `${minute} ${hour} ${dom} * *`;
    default: return `${minute} ${hour} * * *`;
  }
}

export function SchedulesPage() {
  const { user } = useAuth();
  const { data: schedules } = useSchedules();
  const toast = useToast();
  const del = useDeleteSchedule();
  const update = useUpdateSchedule();
  const [editing, setEditing] = useState<Schedule | "new" | null>(null);

  if (user?.role !== "admin") {
    return <div className="muted">Scheduled commands require an admin account.</div>;
  }

  function targetLabel(s: Schedule): string {
    if (s.target_kind === "all_active") return "all active VMs";
    if (s.target_kind === "tag") return "tag";
    return "1 VM";
  }

  function whatLabel(s: Schedule): string {
    return s.task_kind === "action" ? (s.action_name ?? "action") : `cmd: ${s.command?.slice(0, 30)}`;
  }

  return (
    <div>
      <div className="spread" style={{ marginBottom: 24 }}>
        <div>
          <div className="eyebrow">automation</div>
          <h1 className="display" style={{ fontSize: 28, letterSpacing: "0.08em", margin: "8px 0" }}>
            Schedules
          </h1>
        </div>
        <button className="btn btn--primary" onClick={() => setEditing("new")}>
          + New schedule
        </button>
      </div>

      {schedules && schedules.length === 0 && (
        <div className="panel" style={{ padding: 32, textAlign: "center", color: "var(--dim)" }}>
          No schedules yet. Automate recurring actions across your fleet.
        </div>
      )}

      {schedules && schedules.length > 0 && (
        <motion.div className="panel" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} style={{ padding: 0, overflow: "hidden" }}>
          <table className="tbl">
            <thead>
              <tr>
                <th>Name</th>
                <th>Target</th>
                <th>Runs</th>
                <th>Cron</th>
                <th>Next</th>
                <th>On</th>
                <th style={{ textAlign: "right" }}>—</th>
              </tr>
            </thead>
            <tbody>
              {schedules.map((s) => (
                <tr key={s.id}>
                  <td style={{ fontWeight: 600 }}>{s.name}</td>
                  <td className="muted tiny">{targetLabel(s)}</td>
                  <td className="muted tiny">{whatLabel(s)}</td>
                  <td className="muted tiny" style={{ fontFamily: "var(--font-mono)" }}>{s.cron_expression}</td>
                  <td className="muted tiny">{s.enabled ? fmtTime(s.next_run_at) : "—"}</td>
                  <td>
                    <input
                      type="checkbox"
                      checked={s.enabled}
                      onChange={(e) =>
                        update.mutate(
                          { id: s.id, enabled: e.target.checked },
                          { onError: (err: Error) => toast("err", err.message) }
                        )
                      }
                    />
                  </td>
                  <td style={{ textAlign: "right" }}>
                    <div className="row" style={{ gap: 6, justifyContent: "flex-end" }}>
                      <button className="btn btn--ghost btn--sm" onClick={() => setEditing(s)}>
                        Edit
                      </button>
                      <button
                        className="btn btn--danger btn--sm"
                        onClick={() => {
                          if (!confirm(`Delete schedule "${s.name}"?`)) return;
                          del.mutate(s.id, {
                            onSuccess: () => toast("ok", "schedule deleted"),
                            onError: (err: Error) => toast("err", err.message),
                          });
                        }}
                      >
                        Delete
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </motion.div>
      )}

      {editing && (
        <ScheduleModal
          schedule={editing === "new" ? null : editing}
          onClose={() => setEditing(null)}
          onToast={toast}
        />
      )}
    </div>
  );
}

function ScheduleModal({
  schedule,
  onClose,
  onToast,
}: {
  schedule: Schedule | null;
  onClose: () => void;
  onToast: (k: "ok" | "err" | "info", m: string) => void;
}) {
  const { data: vms } = useVms();
  const { data: tags } = useTags();
  const create = useCreateSchedule();
  const update = useUpdateSchedule();
  const editing = schedule !== null;

  const [name, setName] = useState(schedule?.name ?? "");
  const [targetKind, setTargetKind] = useState<ScheduleTargetKind>(schedule?.target_kind ?? "all_active");
  const [targetVm, setTargetVm] = useState(schedule?.target_vm_id ?? "");
  const [targetTag, setTargetTag] = useState(schedule?.target_tag_id ?? "");
  const [taskKind, setTaskKind] = useState<"action" | "command">(schedule?.task_kind ?? "action");
  const [action, setAction] = useState(schedule?.action_name ?? "status");
  const [actionParam, setActionParam] = useState(Object.values(schedule?.params ?? {})[0] ?? "");
  const [command, setCommand] = useState(schedule?.command ?? "");

  // Editing defaults to the raw cron (reverse-parsing into presets is lossy).
  const [preset, setPreset] = useState<Preset>(editing ? "advanced" : "daily");
  const [hour, setHour] = useState(3);
  const [minute, setMinute] = useState(0);
  const [dow, setDow] = useState(0);
  const [dom, setDom] = useState(1);
  const [advancedCron, setAdvancedCron] = useState(schedule?.cron_expression ?? "0 3 * * *");

  const spec = ACTION_CATALOG.find((a) => a.name === action);
  const cron = preset === "advanced" ? advancedCron : buildCron(preset, hour, minute, dow, dom);

  function submit(e: React.FormEvent) {
    e.preventDefault();
    const params = spec?.param && actionParam ? { [spec.param.name]: actionParam } : {};
    const payload = {
      name,
      target_kind: targetKind,
      target_vm_id: targetKind === "vm" ? targetVm : null,
      target_tag_id: targetKind === "tag" ? targetTag : null,
      task_kind: taskKind,
      action_name: taskKind === "action" ? action : null,
      params: taskKind === "action" ? params : {},
      command: taskKind === "command" ? command : null,
      cron_expression: cron,
    };
    const verb = editing ? "updated" : "created";
    const opts = {
      onSuccess: () => { onToast("ok", `schedule "${name}" ${verb}`); onClose(); },
      onError: (err: Error) => onToast("err", err.message),
    };
    if (editing && schedule) {
      update.mutate({ id: schedule.id, ...payload }, opts);
    } else {
      create.mutate(payload, opts);
    }
  }

  const pending = editing ? update.isPending : create.isPending;

  return (
    <Modal open onClose={onClose} title={editing ? "Edit schedule" : "New schedule"} width={560}>
      <form onSubmit={submit} className="stack" style={{ gap: 16 }}>
        <div>
          <label className="lbl">Name</label>
          <input className="field" value={name} onChange={(e) => setName(e.target.value)} required autoFocus placeholder="e.g. nightly apt upgrade" />
        </div>

        {/* Target */}
        <div>
          <label className="lbl">Target</label>
          <div className="row" style={{ gap: 14, marginBottom: 8 }}>
            {(["all_active", "tag", "vm"] as ScheduleTargetKind[]).map((k) => (
              <label key={k} className="row" style={{ gap: 6, cursor: "pointer" }}>
                <input type="radio" checked={targetKind === k} onChange={() => setTargetKind(k)} />
                <span style={{ fontSize: 13 }}>{k === "all_active" ? "All active" : k === "tag" ? "Tag" : "One VM"}</span>
              </label>
            ))}
          </div>
          {targetKind === "vm" && (
            <select className="field" value={targetVm} onChange={(e) => setTargetVm(e.target.value)} required>
              <option value="">select a VM…</option>
              {vms?.map((v) => <option key={v.id} value={v.id}>{v.name}</option>)}
            </select>
          )}
          {targetKind === "tag" && (
            <select className="field" value={targetTag} onChange={(e) => setTargetTag(e.target.value)} required>
              <option value="">select a tag…</option>
              {tags?.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}
            </select>
          )}
        </div>

        {/* What */}
        <div>
          <label className="lbl">Run</label>
          <div className="row" style={{ gap: 14, marginBottom: 8 }}>
            <label className="row" style={{ gap: 6, cursor: "pointer" }}>
              <input type="radio" checked={taskKind === "action"} onChange={() => setTaskKind("action")} />
              <span style={{ fontSize: 13 }}>Action</span>
            </label>
            <label className="row" style={{ gap: 6, cursor: "pointer" }}>
              <input type="radio" checked={taskKind === "command"} onChange={() => setTaskKind("command")} />
              <span style={{ fontSize: 13 }}>Command (unrestricted VMs)</span>
            </label>
          </div>
          {taskKind === "action" ? (
            <div className="row" style={{ gap: 8 }}>
              <select className="field" style={{ maxWidth: 200 }} value={action} onChange={(e) => setAction(e.target.value)}>
                {ACTION_CATALOG.map((a) => <option key={a.name} value={a.name}>{a.label}</option>)}
              </select>
              {spec?.param && (
                <input className="field" style={{ maxWidth: 180 }} placeholder={spec.param.placeholder} value={actionParam} onChange={(e) => setActionParam(e.target.value)} />
              )}
            </div>
          ) : (
            <input className="field" style={{ fontFamily: "var(--font-mono)" }} placeholder="$ command…" value={command} onChange={(e) => setCommand(e.target.value)} required />
          )}
        </div>

        {/* When */}
        <div>
          <label className="lbl">Recurrence</label>
          <select className="field" value={preset} onChange={(e) => setPreset(e.target.value as Preset)} style={{ marginBottom: 8 }}>
            <option value="hourly">Every hour</option>
            <option value="daily">Every day</option>
            <option value="weekly">Every week</option>
            <option value="monthly">Every month</option>
            <option value="advanced">Advanced (cron)</option>
          </select>

          {preset === "advanced" ? (
            <input className="field" style={{ fontFamily: "var(--font-mono)" }} value={advancedCron} onChange={(e) => setAdvancedCron(e.target.value)} placeholder="min hour dom mon dow" />
          ) : (
            <div className="row" style={{ gap: 8, flexWrap: "wrap", alignItems: "center" }}>
              {preset !== "hourly" && (
                <>
                  <span className="tiny muted">at</span>
                  <input className="field" type="number" min={0} max={23} value={hour} onChange={(e) => setHour(Number(e.target.value))} style={{ maxWidth: 70 }} />
                  <span className="tiny muted">:</span>
                  <input className="field" type="number" min={0} max={59} value={minute} onChange={(e) => setMinute(Number(e.target.value))} style={{ maxWidth: 70 }} />
                </>
              )}
              {preset === "hourly" && (
                <>
                  <span className="tiny muted">at minute</span>
                  <input className="field" type="number" min={0} max={59} value={minute} onChange={(e) => setMinute(Number(e.target.value))} style={{ maxWidth: 70 }} />
                </>
              )}
              {preset === "weekly" && (
                <select className="field" value={dow} onChange={(e) => setDow(Number(e.target.value))} style={{ maxWidth: 110 }}>
                  {DOW.map((d, i) => <option key={d} value={i}>{d}</option>)}
                </select>
              )}
              {preset === "monthly" && (
                <>
                  <span className="tiny muted">on day</span>
                  <input className="field" type="number" min={1} max={28} value={dom} onChange={(e) => setDom(Number(e.target.value))} style={{ maxWidth: 70 }} />
                </>
              )}
            </div>
          )}
          <div className="muted tiny" style={{ marginTop: 6, fontFamily: "var(--font-mono)" }}>cron: {cron}</div>
        </div>

        <div className="spread" style={{ marginTop: 8 }}>
          <button type="button" className="btn btn--ghost" onClick={onClose}>Cancel</button>
          <button type="submit" className="btn btn--primary" disabled={pending}>
            {pending ? <span className="spin" /> : editing ? "Save changes" : "Create schedule"}
          </button>
        </div>
      </form>
    </Modal>
  );
}
