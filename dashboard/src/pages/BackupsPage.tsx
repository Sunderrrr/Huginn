import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import {
  useBackups,
  useCreateBackup,
  useDeleteBackup,
  useSettings,
  useUpdateSettings,
} from "../api/hooks";
import { useAuth } from "../auth/AuthContext";
import { useToast } from "../components/Toast";
import type { BackupRunResult, Settings } from "../api/types";
import { fmtBytes, fmtTime } from "../lib/format";

export function BackupsPage() {
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";
  const toast = useToast();

  const { data: settings } = useSettings();
  const update = useUpdateSettings();
  const { data: backups, isLoading: loadingBackups, error: backupsError } = useBackups();
  const create = useCreateBackup();
  const del = useDeleteBackup();

  // S3 target config
  const [enabled, setEnabled] = useState(false);
  const [endpoint, setEndpoint] = useState("");
  const [region, setRegion] = useState("");
  const [bucket, setBucket] = useState("");
  const [prefix, setPrefix] = useState("");
  const [accessKey, setAccessKey] = useState("");
  const [secretKey, setSecretKey] = useState("");
  const [retention, setRetention] = useState("");
  const [secretSet, setSecretSet] = useState(false);

  // Result of the last "Back up now" run.
  const [lastRun, setLastRun] = useState<BackupRunResult | null>(null);

  useEffect(() => {
    if (!settings) return;
    setEnabled(!!settings.backup_s3_enabled);
    setEndpoint(settings.backup_s3_endpoint ?? "");
    setRegion(settings.backup_s3_region ?? "");
    setBucket(settings.backup_s3_bucket ?? "");
    setPrefix(settings.backup_s3_prefix ?? "");
    setAccessKey(settings.backup_s3_access_key ?? "");
    setRetention(
      settings.backup_s3_retention_days === null || settings.backup_s3_retention_days === undefined
        ? ""
        : String(settings.backup_s3_retention_days),
    );
    // The secret is write-only: the API only tells us whether one is stored.
    setSecretSet(
      settings.backup_s3_secret_key_configured ?? !!settings.backup_s3_secret_key,
    );
  }, [settings]);

  async function save() {
    if (enabled && !bucket.trim()) {
      toast("err", "a bucket is required when S3 backups are enabled");
      return;
    }
    const days = retention.trim() === "" ? null : Number(retention.trim());
    if (days !== null && (!Number.isInteger(days) || days < 1)) {
      toast("err", "retention must be a whole number of days");
      return;
    }
    try {
      await update.mutateAsync({
        backup_s3_enabled: enabled,
        // An empty endpoint means the provider default (AWS S3).
        backup_s3_endpoint: endpoint.trim(),
        backup_s3_region: region.trim(),
        backup_s3_bucket: bucket.trim(),
        backup_s3_prefix: prefix.trim(),
        backup_s3_access_key: accessKey.trim(),
        // Write-only: omit when blank so the stored secret stays unchanged.
        backup_s3_secret_key: secretKey || undefined,
        backup_s3_retention_days: days,
      } as Partial<Settings>);
      setSecretKey("");
      if (secretKey) setSecretSet(true);
      toast("ok", "backup settings saved");
    } catch (e: unknown) {
      toast("err", e instanceof Error ? e.message : "save failed");
    }
  }

  async function runNow() {
    try {
      const result = await create.mutateAsync();
      setLastRun(result);
      toast("ok", `backup stored — ${result.name}`);
    } catch (e: unknown) {
      toast("err", e instanceof Error ? e.message : "backup failed");
    }
  }

  async function remove(name: string) {
    if (!confirm(`Delete backup "${name}"? This cannot be undone.`)) return;
    try {
      await del.mutateAsync(name);
      setLastRun((r) => (r && r.name === name ? null : r));
      toast("ok", "backup deleted");
    } catch (e: unknown) {
      toast("err", e instanceof Error ? e.message : "delete failed");
    }
  }

  const s3Configured = backups?.configured ?? false;

  return (
    <div>
      <div className="eyebrow">storage</div>
      <h1 className="display" style={{ fontSize: 28, letterSpacing: "0.08em", marginBottom: 6 }}>
        Backups
      </h1>
      <p className="muted tiny" style={{ marginBottom: 22, maxWidth: 680, lineHeight: 1.6 }}>
        Nightly database dumps stored in your own S3 bucket. Point the target at AWS
        S3 or any S3-compatible endpoint, set a retention window, and trigger a
        backup any time from here.
      </p>

      <div className="stack" style={{ gap: 24, maxWidth: 760 }}>
        {/* S3 target config */}
        <motion.div
          className="panel panel--bracket"
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          style={{ padding: 24 }}
        >
          <div className="spread" style={{ marginBottom: 16 }}>
            <SectionTitle>S3 target</SectionTitle>
            {isAdmin && (
              <label className="row" style={{ gap: 8, cursor: "pointer" }}>
                <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
                <span style={{ fontSize: 13 }}>Enabled</span>
              </label>
            )}
          </div>
          <div className="stack" style={{ gap: 18 }}>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14 }}>
              <Field label="Endpoint">
                <input
                  className="field"
                  value={endpoint}
                  onChange={(e) => setEndpoint(e.target.value)}
                  disabled={!isAdmin}
                  placeholder="empty = AWS"
                />
                <Hint>S3-compatible server URL, e.g. https://minio.example.com — leave empty for AWS.</Hint>
              </Field>
              <Field label="Region">
                <input
                  className="field"
                  value={region}
                  onChange={(e) => setRegion(e.target.value)}
                  disabled={!isAdmin}
                  placeholder="eu-west-1"
                />
              </Field>
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14 }}>
              <Field label="Bucket">
                <input
                  className="field"
                  value={bucket}
                  onChange={(e) => setBucket(e.target.value)}
                  disabled={!isAdmin}
                  placeholder="huginn-backups"
                />
              </Field>
              <Field label="Prefix">
                <input
                  className="field"
                  value={prefix}
                  onChange={(e) => setPrefix(e.target.value)}
                  disabled={!isAdmin}
                  placeholder="db/ — optional key prefix"
                />
              </Field>
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14 }}>
              <Field label="Access key">
                <input
                  className="field"
                  value={accessKey}
                  onChange={(e) => setAccessKey(e.target.value)}
                  disabled={!isAdmin}
                  placeholder="AKIA…"
                />
              </Field>
              <Field label="Secret key">
                <input
                  className="field"
                  type="password"
                  autoComplete="new-password"
                  name="backup-s3-secret-key"
                  value={secretKey}
                  onChange={(e) => setSecretKey(e.target.value)}
                  disabled={!isAdmin}
                  placeholder={secretSet ? "•••••••• (set — leave empty to keep)" : "••••••••"}
                />
                <Hint>
                  {secretSet
                    ? "A secret key is stored — leave blank to keep it."
                    : "Write-only: once saved it is never shown again."}
                </Hint>
              </Field>
            </div>
            <Field label="Retention (days)">
              <input
                className="field"
                style={{ maxWidth: 160 }}
                value={retention}
                onChange={(e) => setRetention(e.target.value)}
                disabled={!isAdmin}
                placeholder="empty = keep forever"
                inputMode="numeric"
              />
              <Hint>Backups older than this are pruned on every run.</Hint>
            </Field>
          </div>

          {isAdmin ? (
            <div className="spread" style={{ marginTop: 20 }}>
              <span className="muted tiny">updated {fmtTime(settings?.updated_at ?? null)}</span>
              <button className="btn btn--primary" onClick={save} disabled={update.isPending}>
                {update.isPending ? <span className="spin" /> : "Save target"}
              </button>
            </div>
          ) : (
            <div className="muted tiny" style={{ marginTop: 16 }}>
              Read-only — backup settings require an admin account.
            </div>
          )}
        </motion.div>

        {/* Backup archive */}
        <motion.div
          className="panel"
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.05 }}
          style={{ overflow: "hidden" }}
        >
          <div
            className="spread"
            style={{ padding: "16px 18px", borderBottom: s3Configured ? "1px solid var(--line)" : "none" }}
          >
            <div>
              <div className="display" style={{ fontSize: 15, letterSpacing: "0.1em" }}>
                Archive
              </div>
              <div className="muted tiny" style={{ marginTop: 2 }}>
                {s3Configured
                  ? `${backups?.backups.length ?? 0} backup${backups?.backups.length === 1 ? "" : "s"} in ${bucket || "the bucket"}`
                  : "database dumps in S3"}
              </div>
            </div>
            {isAdmin && (
              <button
                className="btn btn--primary"
                onClick={runNow}
                disabled={create.isPending || !s3Configured}
                title={s3Configured ? "Run a backup now" : "Configure the S3 target first"}
              >
                {create.isPending ? <span className="spin" /> : "Back up now"}
              </button>
            )}
          </div>

          {lastRun && (
            <div
              className="row"
              style={{
                gap: 10,
                padding: "10px 18px",
                borderBottom: "1px solid var(--line)",
                borderLeft: "2px solid var(--signal)",
                background: "rgba(70, 211, 154, 0.06)",
              }}
            >
              <span style={{ color: "var(--signal)", fontFamily: "var(--font-display)" }}>✓</span>
              <span className="tiny">
                <b>{lastRun.name}</b>
              </span>
              <span className="muted tiny">{fmtBytes(lastRun.size)}</span>
              <span className="muted tiny">
                {lastRun.duration_ms >= 1000
                  ? `${(lastRun.duration_ms / 1000).toFixed(1)} s`
                  : `${lastRun.duration_ms} ms`}
              </span>
              <span className="muted tiny" style={{ marginLeft: "auto" }}>
                backup complete
              </span>
            </div>
          )}

          {backupsError ? (
            <div style={{ padding: 28 }} className="muted tiny">
              <span style={{ color: "var(--blood)" }}>✕</span> could not load backups —{" "}
              {backupsError instanceof Error ? backupsError.message : "request failed"}
            </div>
          ) : loadingBackups && !backups ? (
            <div style={{ padding: 28 }}>
              <span className="spin" />
            </div>
          ) : !s3Configured ? (
            <div style={{ padding: "36px 28px", textAlign: "center" }}>
              <div className="eyebrow" style={{ marginBottom: 10 }}>
                no s3 target
              </div>
              <div className="display" style={{ fontSize: 15, letterSpacing: "0.08em", marginBottom: 8 }}>
                S3 backups are not configured
              </div>
              <div className="muted tiny" style={{ maxWidth: 420, margin: "0 auto", lineHeight: 1.7 }}>
                Enable the S3 target above, fill in bucket and credentials, then save —
                backups will be listed here.
              </div>
            </div>
          ) : (
            <>
              <table className="tbl">
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Size</th>
                    <th>Modified</th>
                    <th style={{ textAlign: "right" }}>—</th>
                  </tr>
                </thead>
                <tbody>
                  {backups?.backups.map((b) => (
                    <tr key={b.name} style={{ cursor: "default" }}>
                      <td style={{ fontWeight: 600 }}>{b.name}</td>
                      <td className="muted tiny">{fmtBytes(b.size)}</td>
                      <td className="muted tiny">{fmtTime(b.last_modified)}</td>
                      <td style={{ textAlign: "right" }}>
                        {isAdmin && (
                          <button
                            className="btn btn--danger btn--sm"
                            disabled={del.isPending}
                            onClick={() => remove(b.name)}
                          >
                            {del.isPending && del.variables === b.name ? <span className="spin" /> : "Delete"}
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {backups?.backups.length === 0 && (
                <div style={{ padding: 32 }} className="muted tiny">
                  No backups stored yet — use <b>Back up now</b> to create the first one.
                </div>
              )}
            </>
          )}
        </motion.div>
      </div>
    </div>
  );
}

function SectionTitle({ children }: { children: React.ReactNode }) {
  return (
    <div className="display" style={{ fontSize: 15, letterSpacing: "0.1em", marginBottom: 4 }}>
      {children}
    </div>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <label className="lbl">{label}</label>
      {children}
    </div>
  );
}

function Hint({ children }: { children: React.ReactNode }) {
  return <div className="muted tiny" style={{ marginTop: 5 }}>{children}</div>;
}
