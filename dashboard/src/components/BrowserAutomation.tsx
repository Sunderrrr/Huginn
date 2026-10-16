// The "Browser automation" card of the VM detail page. Admins get the
// per-VM capability gate (toggle) and the pinned engine install; operators
// (and admins) get the step runner — presets, a JSON steps textarea and a
// timeout — with the queued task followed live (202 + pending, then
// polled) and screenshots rendered in the result.

import { motion } from "framer-motion";
import { useState } from "react";
import {
  useInstallBrowserEngine,
  useRunBrowserTask,
  useSetBrowserEnabled,
  useTask,
} from "../api/hooks";
import type { Task, VM } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { TaskResultView } from "./TaskOutput";
import { useToast } from "./Toast";

// Mirrors the hub/worker step catalog — a client-side affordance only; the
// hub re-validates every step authoritatively (URL scheme, caps, fields).
const KNOWN_ACTIONS = [
  "navigate",
  "click",
  "type",
  "eval",
  "screenshot",
  "get_text",
  "get_html",
  "wait_for",
];
const MAX_STEPS = 50;
const MIN_TIMEOUT = 1;
const MAX_TIMEOUT = 300;

const PRESET_STEPS = {
  shot: JSON.stringify(
    [
      { action: "navigate", url: "https://example.com" },
      { action: "screenshot", format: "jpeg", quality: 80 },
    ],
    null,
    2,
  ),
  text: JSON.stringify(
    [{ action: "navigate", url: "https://example.com" }, { action: "get_text" }],
    null,
    2,
  ),
} as const;

type Preset = "shot" | "text" | "custom";

const PRESET_BUTTONS: { id: Preset; label: string }[] = [
  { id: "shot", label: "Screenshot" },
  { id: "text", label: "Page text" },
  { id: "custom", label: "Custom" },
];

// Basic pre-flight validation with clear messages — the hub re-checks
// everything (unknown actions, URL scheme, payload caps).
function validateSteps(steps: unknown): string | null {
  if (!Array.isArray(steps)) return "steps must be a JSON array";
  if (steps.length === 0) return "steps must contain at least one step";
  if (steps.length > MAX_STEPS) return `steps must have at most ${MAX_STEPS} items`;
  for (let i = 0; i < steps.length; i++) {
    const n = i + 1;
    const step = steps[i];
    if (typeof step !== "object" || step === null || Array.isArray(step)) {
      return `step ${n} must be a JSON object`;
    }
    const action = (step as Record<string, unknown>).action;
    if (typeof action !== "string" || action === "") return `step ${n} has no action`;
    if (!KNOWN_ACTIONS.includes(action)) {
      return `step ${n}: unknown action "${action}"`;
    }
  }
  return null;
}

export function BrowserAutomation({ vm }: { vm: VM }) {
  const { user } = useAuth();
  const toast = useToast();
  const isAdmin = user?.role === "admin";
  const isOperator = user?.role === "operator";
  const isActive = vm.state === "active" || vm.state === "offline";
  const canRun = (isAdmin || isOperator) && isActive;

  const setEnabled = useSetBrowserEnabled();
  const install = useInstallBrowserEngine();
  const run = useRunBrowserTask();

  const [preset, setPreset] = useState<Preset>("text");
  const [stepsJson, setStepsJson] = useState<string>(PRESET_STEPS.text);
  const [timeoutSec, setTimeoutSec] = useState("120");
  const [stepsError, setStepsError] = useState<string | null>(null);
  const [runError, setRunError] = useState<string | null>(null);
  // The task objects as returned by the 202 responses; useTask keeps them
  // current until they reach a terminal state.
  const [task, setTask] = useState<Task | null>(null);
  const [installTask, setInstallTask] = useState<Task | null>(null);

  const { data: liveTask } = useTask(task?.id ?? null);
  const { data: liveInstall } = useTask(installTask?.id ?? null);
  const current = liveTask ?? task;
  const currentInstall = liveInstall ?? installTask;

  function applyPreset(p: Preset) {
    setPreset(p);
    if (p === "shot" || p === "text") {
      setStepsJson(PRESET_STEPS[p]);
      setStepsError(null);
    }
    // "custom" keeps the current steps for free editing
  }

  function editSteps(value: string) {
    setStepsJson(value);
    setPreset("custom");
    setStepsError(null);
  }

  async function toggleBrowser(enabled: boolean) {
    try {
      await setEnabled.mutateAsync({ id: vm.id, enabled });
      toast("ok", enabled ? "browser automation enabled" : "browser automation disabled");
    } catch (e: any) {
      toast("err", e?.message ?? "toggle failed");
    }
  }

  async function installEngine() {
    try {
      const t = await install.mutateAsync(vm.id);
      setInstallTask(t);
      toast("ok", "engine install task queued");
    } catch (e: any) {
      toast("err", e?.message ?? "install failed");
    }
  }

  async function doRun() {
    setRunError(null);
    let parsed: unknown;
    try {
      parsed = JSON.parse(stepsJson);
    } catch (e) {
      setStepsError(`invalid JSON — ${(e as Error).message}`);
      return;
    }
    const stepsErr = validateSteps(parsed);
    if (stepsErr) {
      setStepsError(stepsErr);
      return;
    }
    const seconds = Math.round(Number(timeoutSec));
    if (!Number.isFinite(seconds) || seconds < MIN_TIMEOUT || seconds > MAX_TIMEOUT) {
      setStepsError(`timeout must be between ${MIN_TIMEOUT} and ${MAX_TIMEOUT} seconds`);
      return;
    }
    setStepsError(null);
    try {
      const t = await run.mutateAsync({ id: vm.id, steps: parsed as unknown[], timeout: seconds });
      setTask(t);
      toast("ok", "browser task queued");
    } catch (e: any) {
      // The hub's refusal verbatim — e.g. the disabled-capability 403 names
      // the exact admin action needed.
      setRunError(e?.message ?? "browser task failed");
      toast("err", e?.message ?? "browser task failed");
    }
  }

  return (
    <motion.div
      className="panel panel--bracket"
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: 0.05 }}
      style={{ padding: 20 }}
    >
      <div className="spread" style={{ marginBottom: 14 }}>
        <div>
          <div className="eyebrow">browser automation</div>
          <div className="muted tiny" style={{ marginTop: 4 }}>
            headless web steps via the Obscura engine · Linux workers only
          </div>
        </div>
      </div>

      {/* Admin: capability gate + engine install */}
      {isAdmin && (
        <div className="stack" style={{ gap: 14 }}>
          <label className="row" style={{ gap: 10, cursor: "pointer" }}>
            <input
              type="checkbox"
              checked={vm.browser_enabled}
              disabled={setEnabled.isPending}
              onChange={(e) => toggleBrowser(e.target.checked)}
            />
            <span style={{ fontSize: 13 }}>Browser automation</span>
          </label>
          <div className="row" style={{ gap: 10, flexWrap: "wrap" }}>
            {/* title on the wrapper: disabled buttons don't show tooltips */}
            <span
              title={isActive ? undefined : "node must be active to queue the install"}
              style={{ display: "inline-block" }}
            >
              <button
                className="btn btn--sm"
                onClick={installEngine}
                disabled={!isActive || install.isPending}
              >
                {install.isPending ? <span className="spin" /> : "Install browser engine"}
              </button>
            </span>
            <span className="muted tiny">pinned engine · ~70 MB download · 1–2 min</span>
          </div>
          {currentInstall && <TaskResultView task={currentInstall} />}
        </div>
      )}

      {/* Operator+: step runner */}
      <div style={isAdmin ? { marginTop: 18, paddingTop: 18, borderTop: "1px solid var(--line)" } : undefined}>
        {!canRun ? (
          <div className="muted tiny">
            {isAdmin || isOperator
              ? "node must be active to run browser steps"
              : "read-only — execution disabled"}
          </div>
        ) : (
          <>
            {!isAdmin && (
              <div className="muted tiny" style={{ marginBottom: 12 }}>
                {vm.browser_enabled
                  ? "enabled on this node"
                  : "disabled on this node — an admin must enable it first"}
              </div>
            )}
            <div className="row" style={{ gap: 4, marginBottom: 10 }}>
              {PRESET_BUTTONS.map((p) => (
                <button
                  key={p.id}
                  className={`btn btn--sm ${preset === p.id ? "btn--primary" : "btn--ghost"}`}
                  onClick={() => applyPreset(p.id)}
                >
                  {p.label}
                </button>
              ))}
            </div>
            <textarea
              className="field"
              rows={7}
              spellCheck={false}
              style={{ fontFamily: "var(--font-mono)", fontSize: 12, resize: "vertical" }}
              value={stepsJson}
              onChange={(e) => editSteps(e.target.value)}
            />
            <div className="row" style={{ gap: 10, marginTop: 10, flexWrap: "wrap" }}>
              <label className="row" style={{ gap: 8 }}>
                <span className="muted tiny">timeout (s)</span>
                <input
                  type="number"
                  className="field"
                  style={{ maxWidth: 100 }}
                  min={MIN_TIMEOUT}
                  max={MAX_TIMEOUT}
                  value={timeoutSec}
                  onChange={(e) => {
                    setTimeoutSec(e.target.value);
                    setStepsError(null);
                  }}
                />
              </label>
              <button className="btn btn--primary" onClick={doRun} disabled={run.isPending}>
                {run.isPending ? <span className="spin" /> : "Run ›"}
              </button>
            </div>
            {stepsError && (
              <div className="tiny" style={{ color: "var(--amber)", marginTop: 8 }}>
                {stepsError}
              </div>
            )}
            {runError && (
              <div className="tiny" style={{ color: "var(--blood)", marginTop: 8 }}>
                {runError}
              </div>
            )}
            {current && <TaskResultView task={current} />}
          </>
        )}
      </div>
    </motion.div>
  );
}
