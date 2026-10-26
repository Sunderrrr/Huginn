import { useState } from "react";
import { useCreateToken, useRevokeToken, useSettings, useTokens } from "../api/hooks";
import type { EnrollmentTokenCreated } from "../api/types";
import { Modal } from "./Dialog";
import { useToast } from "./Toast";
import { fmtTime } from "../lib/format";
import { installCommand, type InstallOS } from "../lib/commands";

const TTL_OPTIONS = [
  { label: "1 hour", value: 3600 },
  { label: "12 hours", value: 43200 },
  { label: "7 days", value: 604800 },
  { label: "30 days", value: 2592000 },
  { label: "Never", value: 0 },
];

const mask = (t: string) => (t.length > 8 ? `****${t.slice(-8)}` : "****");

type OS = InstallOS;

/** Enroll a new VM: generate a single-use token and show the install one-liner. */
export function AddVmModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { data: tokens } = useTokens();
  const create = useCreateToken();
  const revoke = useRevokeToken();
  const toast = useToast();

  const [label, setLabel] = useState("");
  const [ttl, setTtl] = useState(3600);
  // Reusable = a join key (max_uses 0 = unlimited) for bulk/Ansible enrollment;
  // otherwise the token is single-use.
  const [reusable, setReusable] = useState(false);
  const [autoApprove, setAutoApprove] = useState(false);
  const [installBrowser, setInstallBrowser] = useState(false);
  const [created, setCreated] = useState<EnrollmentTokenCreated | null>(null);
  const [reveal, setReveal] = useState(false);
  const [revealCmd, setRevealCmd] = useState(false);
  const [os, setOs] = useState<OS>("linux");

  // Install base URL: configured server-side in Settings (enrollment_base_url),
  // falls back to the dashboard origin when empty.
  const { data: settings } = useSettings();
  const [installUrl, setInstallUrl] = useState("");
  const effectiveUrl = settings?.enrollment_base_url || window.location.origin;
  const onUrlChange = (v: string) => setInstallUrl(v);
  const base = (installUrl || effectiveUrl).replace(/\/$/, "");


  const copy = (text: string, what: string) => {
    navigator.clipboard?.writeText(text);
    toast("ok", what);
  };

  function reset() {
    setCreated(null);
    setReveal(false);
    setRevealCmd(false);
    setLabel("");
    setReusable(false);
    setAutoApprove(false);
    setInstallBrowser(false);
    setOs("linux");
  }

  async function onGenerate() {
    try {
      // Reusable token => unlimited uses (join key); otherwise single-use.
      const t = await create.mutateAsync({
        label,
        ttl_seconds: ttl,
        max_uses: reusable ? 0 : 1,
        auto_approve: autoApprove,
        install_browser: installBrowser,
      });
      setReveal(false);
      setRevealCmd(false);
      setCreated(t);
      toast("ok", "invitation created");
    } catch {
      toast("err", "could not create the invitation");
    }
  }

  // Outstanding invitations: tokens not yet used up, revoked, or expired
  // (max_uses 0 = unlimited, so it always has uses left).
  const pending = (tokens ?? []).filter(
    (t) =>
      !t.revoked_at &&
      (t.max_uses === 0 || t.uses_count < t.max_uses) &&
      new Date(t.expires_at).getTime() > Date.now(),
  );

  // The token is masked in the install command by default; the full token
  // is available in the Token field below (its own reveal toggle) and in the
  // copy action.
  const cmdToken = created ? (revealCmd ? created.token : mask(created.token)) : "";

  return (
    <Modal open={open} onClose={() => { reset(); onClose(); }} title="Add a VM" width={640}>
      {created ? (
        <div>
          <p className="muted tiny" style={{ marginBottom: 12 }}>
            {created.max_uses === 0
              ? "Run this on every machine you want to enroll — this token is reusable. The secret is shown only once."
              : "Run this on the new machine. The token is single-use and shown only once."}
          </p>

          {/* Install base URL */}
          <label className="lbl" style={{ marginBottom: 4 }}>Install URL</label>
          <input
            className="field"
            value={installUrl || effectiveUrl}
            onChange={(e) => onUrlChange(e.target.value)}
            placeholder={window.location.origin}
            spellCheck={false}
            style={{ marginBottom: 12, fontFamily: "var(--font-mono)", fontSize: 13 }}
          />
          <p className="muted tiny" style={{ marginBottom: 12, lineHeight: 1.5 }}>
            The address workers use to download the installer and enroll. Point it at your
            VPN/LAN IP (e.g. https://10.x.x.x) so workers connect directly instead of
            through a public domain.
          </p>

          {/* OS selector */}
          <div className="row" style={{ gap: 8, marginBottom: 12 }}>
            <button
              className={`btn btn--sm ${os === "linux" ? "btn--primary" : "btn--ghost"}`}
              onClick={() => setOs("linux")}
            >
              ▲ Linux
            </button>
            <button
              className={`btn btn--sm ${os === "windows" ? "btn--primary" : "btn--ghost"}`}
              onClick={() => setOs("windows")}
            >
              ⊞ Windows
            </button>
          </div>

          <label className="lbl">
            {os === "linux" ? "One-line install (bash)" : "One-line install (PowerShell, as Administrator)"}
          </label>
          <div className="row" style={{ gap: 8, alignItems: "stretch" }}>
            <div
              className="codeblock grow"
              style={{
                userSelect: "all",
                padding: "9px 12px",
                fontSize: os === "windows" ? 12 : 13,
                lineHeight: 1.5,
              }}
            >
              {installCommand(os, base, cmdToken)}
            </div>
            <button className="btn btn--sm" onClick={() => setRevealCmd((v) => !v)}>
              {revealCmd ? "hide" : "reveal"}
            </button>
            <button
              className="btn btn--sm"
              aria-label="copy install command"
              onClick={() =>
                copy(
                  installCommand(os, base, created.token),
                  `${os === "windows" ? "Windows" : "Linux"} command copied`,
                )
              }
            >
              copy
            </button>
          </div>

          {os === "windows" && (
            <p className="muted tiny" style={{ marginTop: 8, lineHeight: 1.5 }}>
              Run PowerShell <b>as Administrator</b> on the Windows VM. The installer downloads
              the worker .exe, verifies its SHA-256, installs the hub's CA if needed, creates the
              <b> HuginnWorker</b> service, and enrolls.
            </p>
          )}
          {os === "linux" && (
            <p className="muted tiny" style={{ marginTop: 8, lineHeight: 1.5 }}>
              Run on the Linux VM as root. The installer detects the architecture (amd64/arm64),
              downloads the matching static binary, verifies the checksum, and installs a systemd
              unit.
            </p>
          )}

          <label className="lbl" style={{ marginTop: 16 }}>Token</label>
          <div className="row" style={{ gap: 8, alignItems: "stretch" }}>
            <div
              className="codeblock grow"
              style={{ userSelect: "all", padding: "9px 12px", color: reveal ? "var(--ember-soft)" : "var(--dim)" }}
            >
              {reveal ? created.token : mask(created.token)}
            </div>
            <button className="btn btn--sm" onClick={() => setReveal((v) => !v)}>{reveal ? "hide" : "reveal"}</button>
            <button
              className="btn btn--sm"
              aria-label="copy enrollment token"
              onClick={() => copy(created.token, "token copied")}
            >
              copy
            </button>
          </div>

          <div className="muted tiny" style={{ marginTop: 10, lineHeight: 1.6 }}>
            {created.auto_approve ? (
              <>
                Enrolled VMs are <b style={{ color: "var(--signal)" }}>auto-approved</b> and become
                active immediately — no manual approval needed.
              </>
            ) : (
              <>
                The VM appears as <b>PENDING</b> after it enrolls — approve it from the fleet before
                it can receive any command.
              </>
            )}
          </div>

          <div className="row" style={{ justifyContent: "flex-end", marginTop: 18, gap: 8 }}>
            <button className="btn btn--ghost" onClick={reset}>Add another</button>
            <button className="btn btn--primary" onClick={() => { reset(); onClose(); }}>Done</button>
          </div>
        </div>
      ) : (
        <div>
          <div className="row" style={{ gap: 14, flexWrap: "wrap", alignItems: "flex-end" }}>
            <div style={{ flex: "2 1 220px" }}>
              <label className="lbl">Label (optional)</label>
              <input className="field" placeholder="e.g. web-prod-03" value={label} onChange={(e) => setLabel(e.target.value)} />
            </div>
            <div style={{ flex: "1 1 130px" }}>
              <label className="lbl">Expires</label>
              <select className="field" value={ttl} onChange={(e) => setTtl(Number(e.target.value))}>
                {TTL_OPTIONS.map((o) => (
                  <option key={o.value} value={o.value}>{o.label}</option>
                ))}
              </select>
            </div>
            <button className="btn btn--primary" onClick={onGenerate} disabled={create.isPending}>
              {create.isPending ? <span className="spin" /> : "Create invite ›"}
            </button>
          </div>

          <div className="stack" style={{ gap: 10, marginTop: 16 }}>
            <label className="row" style={{ gap: 10, cursor: "pointer", alignItems: "flex-start" }}>
              <input
                type="checkbox"
                checked={reusable}
                onChange={(e) => setReusable(e.target.checked)}
                style={{ marginTop: 2 }}
              />
              <span>
                <span style={{ fontSize: 13 }}>Reusable (join key)</span>
                <span className="muted tiny" style={{ display: "block" }}>
                  Unlimited uses — enroll as many VMs as you want with one token. Ideal for Ansible
                  or scripted provisioning.
                </span>
              </span>
            </label>
            <label className="row" style={{ gap: 10, cursor: "pointer", alignItems: "flex-start" }}>
              <input
                type="checkbox"
                checked={autoApprove}
                onChange={(e) => setAutoApprove(e.target.checked)}
                style={{ marginTop: 2 }}
              />
              <span>
                <span style={{ fontSize: 13 }}>Auto-approve enrolled VMs</span>
                <span className="muted tiny" style={{ display: "block" }}>
                  Enrolled VMs become active immediately, skipping manual approval. Anyone holding
                  this token can add a live worker — keep it secret and revoke when done.
                </span>
              </span>
            </label>
            <label className="row" style={{ gap: 10, cursor: "pointer", alignItems: "flex-start" }}>
              <input
                type="checkbox"
                checked={installBrowser}
                onChange={(e) => setInstallBrowser(e.target.checked)}
                disabled={!autoApprove}
                style={{ marginTop: 2 }}
              />
              <span>
                <span style={{ fontSize: 13 }}>Install Obscura engine on enrollment</span>
                <span className="muted tiny" style={{ display: "block" }}>
                  Auto-queues a browser_install task for the new VM (Linux only, needs an
                  auto-approved token). The engine is downloaded from the hub's pinned
                  release (~70 MB) after enrollment.
                </span>
              </span>
            </label>
          </div>

          {pending.length > 0 && (
            <div style={{ marginTop: 22 }}>
              <div className="eyebrow" style={{ marginBottom: 8 }}>pending invitations</div>
              <div className="stack" style={{ gap: 6 }}>
                {pending.map((t) => (
                  <div key={t.id} className="spread">
                    <div className="row" style={{ gap: 8 }}>
                      <span style={{ fontSize: 13 }}>{t.label || "unlabeled"}</span>
                      {t.max_uses === 0 && (
                        <span className="badge badge--whitelist">reusable</span>
                      )}
                      {t.auto_approve && (
                        <span className="badge badge--active">auto-approve</span>
                      )}
                      <span className="muted tiny">· expires {fmtTime(t.expires_at)}</span>
                    </div>
                    <button
                      className="btn btn--sm btn--danger"
                      disabled={revoke.isPending}
                      onClick={async () => {
                        await revoke.mutateAsync(t.id);
                        toast("ok", "invitation revoked");
                      }}
                    >
                      Revoke
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </Modal>
  );
}
