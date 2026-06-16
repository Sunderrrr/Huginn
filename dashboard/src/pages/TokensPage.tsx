import { motion } from "framer-motion";
import { useState } from "react";
import { useCreateToken, useRevokeToken, useTokens } from "../api/hooks";
import type { EnrollmentTokenCreated } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { Modal } from "../components/Dialog";
import { useToast } from "../components/Toast";
import { fmtTime } from "../lib/format";

const TTL_OPTIONS = [
  { label: "1 hour", value: 3600 },
  { label: "12 hours", value: 43200 },
  { label: "7 days", value: 604800 },
  { label: "30 days", value: 2592000 },
  { label: "Never", value: 0 },
];

export function TokensPage() {
  const { user } = useAuth();
  const { data: tokens } = useTokens();
  const create = useCreateToken();
  const revoke = useRevokeToken();
  const toast = useToast();

  const [label, setLabel] = useState("");
  const [ttl, setTtl] = useState(3600);
  const [maxUses, setMaxUses] = useState(1);
  const [created, setCreated] = useState<EnrollmentTokenCreated | null>(null);
  const [reveal, setReveal] = useState(false);
  const [revealCmd, setRevealCmd] = useState(false);

  if (user?.role !== "admin") {
    return <div className="muted">Token management requires an admin account.</div>;
  }

  async function onCreate() {
    try {
      const t = await create.mutateAsync({ label, ttl_seconds: ttl, max_uses: maxUses });
      setReveal(false);
      setRevealCmd(false);
      setCreated(t);
      setLabel("");
      toast("ok", "token generated");
    } catch {
      toast("err", "could not create token");
    }
  }

  // The dashboard is served from the same origin the hub is reachable on, so the
  // installer points workers back here. -k: the machines don't trust the hub's
  // (internal CA) cert yet — the script then installs the hub CA on first use.
  const base = window.location.origin;
  const installCmd = (token: string) =>
    `curl -fsSLk ${base}/install.sh | HUB_URL=${base} TOKEN=${token} bash`;
  const mask = (t: string) => (t.length > 8 ? `****${t.slice(-8)}` : "****");
  const copy = (text: string, what: string) => {
    navigator.clipboard?.writeText(text);
    toast("ok", what);
  };

  return (
    <div>
      <div className="eyebrow">provisioning</div>
      <h1 className="display" style={{ fontSize: 28, letterSpacing: "0.08em", marginBottom: 20 }}>
        Enrollment Tokens
      </h1>

      <motion.div className="panel panel--bracket" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} style={{ padding: 20, marginBottom: 22 }}>
        <div className="row" style={{ gap: 14, flexWrap: "wrap", alignItems: "flex-end" }}>
          <div style={{ flex: "2 1 200px" }}>
            <label className="lbl">Label</label>
            <input className="field" placeholder="e.g. batch-edge-nodes" value={label} onChange={(e) => setLabel(e.target.value)} />
          </div>
          <div style={{ flex: "1 1 120px" }}>
            <label className="lbl">Expires</label>
            <select className="field" value={ttl} onChange={(e) => setTtl(Number(e.target.value))}>
              {TTL_OPTIONS.map((o) => (
                <option key={o.value} value={o.value}>
                  {o.label}
                </option>
              ))}
            </select>
          </div>
          <div style={{ flex: "0 1 110px" }}>
            <label className="lbl">Max uses</label>
            <input className="field" type="number" min={1} max={1000} value={maxUses} onChange={(e) => setMaxUses(Number(e.target.value))} />
          </div>
          <button className="btn btn--primary" onClick={onCreate} disabled={create.isPending}>
            {create.isPending ? <span className="spin" /> : "Generate ›"}
          </button>
        </div>
      </motion.div>

      <motion.div className="panel" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.05 }} style={{ overflow: "hidden" }}>
        <table className="tbl">
          <thead>
            <tr>
              <th>Label</th>
              <th>Uses</th>
              <th>Expires</th>
              <th>Status</th>
              <th style={{ textAlign: "right" }}>—</th>
            </tr>
          </thead>
          <tbody>
            {tokens?.map((t) => {
              const isNever = new Date(t.expires_at).getFullYear() >= 9999;
              const expired = !isNever && new Date(t.expires_at).getTime() < Date.now();
              const exhausted = t.uses_count >= t.max_uses;
              const dead = !!t.revoked_at || expired || exhausted;
              return (
                <tr key={t.id} style={{ cursor: "default" }}>
                  <td>{t.label || <span className="muted">unlabeled</span>}</td>
                  <td className="muted">
                    {t.uses_count}/{t.max_uses}
                  </td>
                  <td className="muted">{isNever ? "Never" : fmtTime(t.expires_at)}</td>
                  <td>
                    {t.revoked_at ? (
                      <span style={{ color: "var(--blood)" }}>revoked</span>
                    ) : expired ? (
                      <span className="muted">expired</span>
                    ) : exhausted ? (
                      <span className="muted">exhausted</span>
                    ) : (
                      <span style={{ color: "var(--signal)" }}>live</span>
                    )}
                  </td>
                  <td style={{ textAlign: "right" }}>
                    {!dead && (
                      <button
                        className="btn btn--danger btn--sm"
                        onClick={async () => {
                          await revoke.mutateAsync(t.id);
                          toast("ok", "token revoked");
                        }}
                      >
                        Revoke
                      </button>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
        {tokens?.length === 0 && <div style={{ padding: 32 }} className="muted tiny">No tokens yet.</div>}
      </motion.div>

      <Modal open={!!created} onClose={() => setCreated(null)} title="Token generated" width={640}>
        {created && (
          <div>
            <p className="muted tiny" style={{ marginBottom: 12 }}>
              Copy this now — the plaintext token is shown only once.
            </p>

            <label className="lbl">Token</label>
            <div className="row" style={{ gap: 8, alignItems: "stretch", marginBottom: 18 }}>
              <div
                className="codeblock grow"
                style={{ userSelect: "all", padding: "9px 12px", color: reveal ? "var(--ember-soft)" : "var(--dim)" }}
              >
                {reveal ? created.token : mask(created.token)}
              </div>
              <button className="btn btn--sm" onClick={() => setReveal((v) => !v)}>
                {reveal ? "hide" : "reveal"}
              </button>
              <button className="btn btn--sm" onClick={() => copy(created.token, "token copied")}>
                copy
              </button>
            </div>

            <label className="lbl">One-line install</label>
            <div className="row" style={{ gap: 8, alignItems: "stretch" }}>
              <div className="codeblock grow" style={{ userSelect: "all", padding: "9px 12px" }}>
                {installCmd(revealCmd ? created.token : mask(created.token))}
              </div>
              <button className="btn btn--sm" onClick={() => setRevealCmd((v) => !v)}>
                {revealCmd ? "hide" : "reveal"}
              </button>
              <button className="btn btn--sm" onClick={() => copy(installCmd(created.token), "command copied")}>
                copy
              </button>
            </div>
            <div className="muted tiny" style={{ marginTop: 10, lineHeight: 1.6 }}>
              <code style={{ color: "var(--ember-soft)" }}>-k</code> skips the cert check to fetch
              the script; the installer then trust-on-first-use installs the hub CA, so the worker's
              own connection stays verified.
            </div>

            <div className="row" style={{ justifyContent: "flex-end", marginTop: 18 }}>
              <button className="btn btn--primary" onClick={() => setCreated(null)}>
                Done
              </button>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
}
