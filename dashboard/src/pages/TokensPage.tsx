import { motion } from "framer-motion";
import { useState } from "react";
import { api } from "../api/client";
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

  if (user?.role !== "admin") {
    return <div className="muted">Token management requires an admin account.</div>;
  }

  async function onCreate() {
    try {
      const t = await create.mutateAsync({ label, ttl_seconds: ttl, max_uses: maxUses });
      setCreated(t);
      setLabel("");
      toast("ok", "token generated");
    } catch {
      toast("err", "could not create token");
    }
  }

  const installCmd = (token: string) =>
    `curl -sSL ${api.hubUrl}/install.sh | HUB_URL=${api.hubUrl} TOKEN=${token} bash`;

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
              const expired = new Date(t.expires_at).getTime() < Date.now();
              const exhausted = t.uses_count >= t.max_uses;
              const dead = !!t.revoked_at || expired || exhausted;
              return (
                <tr key={t.id} style={{ cursor: "default" }}>
                  <td>{t.label || <span className="muted">unlabeled</span>}</td>
                  <td className="muted">
                    {t.uses_count}/{t.max_uses}
                  </td>
                  <td className="muted">{fmtTime(t.expires_at)}</td>
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

      <Modal open={!!created} onClose={() => setCreated(null)} title="Token generated" width={620}>
        {created && (
          <div>
            <p className="muted tiny" style={{ marginBottom: 12 }}>
              Copy this now — the plaintext token is shown only once.
            </p>
            <div className="codeblock" style={{ color: "var(--ember-soft)", userSelect: "all" }}>
              {created.token}
            </div>
            <div className="eyebrow" style={{ margin: "18px 0 6px" }}>
              one-line install
            </div>
            <div className="codeblock" style={{ userSelect: "all" }}>{installCmd(created.token)}</div>
            <div className="row" style={{ justifyContent: "flex-end", marginTop: 18 }}>
              <button
                className="btn"
                onClick={() => {
                  navigator.clipboard?.writeText(created.token);
                  toast("ok", "token copied");
                }}
              >
                Copy token
              </button>
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
