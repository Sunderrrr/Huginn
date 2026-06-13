import { motion } from "framer-motion";
import { useEffect, useState } from "react";
import { useSettings, useUpdateSettings } from "../api/hooks";
import { useAuth } from "../auth/AuthContext";
import { useToast } from "../components/Toast";
import { fmtTime } from "../lib/format";

export function SettingsPage() {
  const { user } = useAuth();
  const { data: settings } = useSettings();
  const update = useUpdateSettings();
  const toast = useToast();
  const isAdmin = user?.role === "admin";

  const [version, setVersion] = useState("");
  const [repo, setRepo] = useState("");
  const [domains, setDomains] = useState("");

  useEffect(() => {
    if (settings) {
      setVersion(settings.target_worker_version);
      setRepo(settings.target_release_repo);
      setDomains(settings.allowed_release_domains.join(", "));
    }
  }, [settings]);

  async function save() {
    try {
      await update.mutateAsync({
        target_worker_version: version,
        target_release_repo: repo,
        allowed_release_domains: domains
          .split(",")
          .map((d) => d.trim())
          .filter(Boolean),
      });
      toast("ok", "settings saved");
    } catch (e: any) {
      toast("err", e?.message ?? "save failed");
    }
  }

  return (
    <div style={{ maxWidth: 620 }}>
      <div className="eyebrow">control plane</div>
      <h1 className="display" style={{ fontSize: 28, letterSpacing: "0.08em", marginBottom: 20 }}>
        Settings
      </h1>

      <motion.div className="panel panel--bracket" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} style={{ padding: 24 }}>
        <div className="stack" style={{ gap: 18 }}>
          <div>
            <label className="lbl">Target worker version</label>
            <input className="field" value={version} onChange={(e) => setVersion(e.target.value)} disabled={!isAdmin} />
            <div className="muted tiny" style={{ marginTop: 5 }}>
              Workers below this version show as stale and can be updated.
            </div>
          </div>
          <div>
            <label className="lbl">Release repository</label>
            <input className="field" value={repo} onChange={(e) => setRepo(e.target.value)} disabled={!isAdmin} />
          </div>
          <div>
            <label className="lbl">Allowed release domains (SSRF allowlist)</label>
            <input className="field" value={domains} onChange={(e) => setDomains(e.target.value)} disabled={!isAdmin} />
            <div className="muted tiny" style={{ marginTop: 5 }}>
              Comma-separated hostnames. IP literals and internal names are rejected.
            </div>
          </div>

          {isAdmin ? (
            <div className="spread">
              <span className="muted tiny">updated {fmtTime(settings?.updated_at ?? null)}</span>
              <button className="btn btn--primary" onClick={save} disabled={update.isPending}>
                {update.isPending ? <span className="spin" /> : "Save settings"}
              </button>
            </div>
          ) : (
            <div className="muted tiny">Read-only — settings changes require an admin account.</div>
          )}
        </div>
      </motion.div>
    </div>
  );
}
