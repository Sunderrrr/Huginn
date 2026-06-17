import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import QRCode from "qrcode";
import {
  useChangePassword,
  useDeletePasskey,
  useMe,
  usePasskeys,
  useRegenerateBackupCodes,
  useRegisterPasskey,
  useRenamePasskey,
  useTotpDisable,
  useTotpEnrollBegin,
  useTotpEnrollFinish,
  useUpdateProfile,
} from "../api/hooks";
import { Modal } from "../components/Dialog";
import { useToast } from "../components/Toast";
import { fmtTime } from "../lib/format";

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <motion.div
      className="panel panel--bracket"
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      style={{ padding: 24 }}
    >
      <div className="display" style={{ fontSize: 15, letterSpacing: "0.1em", marginBottom: 14 }}>
        {title}
      </div>
      {children}
    </motion.div>
  );
}

export function AccountPage() {
  const { data: me } = useMe();
  const toast = useToast();

  // --- profile / password ---
  const updateProfile = useUpdateProfile();
  const changePw = useChangePassword();
  const [email, setEmail] = useState("");
  const [oldPw, setOldPw] = useState("");
  const [newPw, setNewPw] = useState("");

  // --- TOTP ---
  const enrollBegin = useTotpEnrollBegin();
  const enrollFinish = useTotpEnrollFinish();
  const disableTotp = useTotpDisable();
  const regen = useRegenerateBackupCodes();
  const [secret, setSecret] = useState<{ secret: string; otpauth_uri: string } | null>(null);
  const [qr, setQr] = useState("");
  const [totpCode, setTotpCode] = useState("");
  const [backupCodes, setBackupCodes] = useState<string[] | null>(null);
  const [disableCode, setDisableCode] = useState("");
  const [showDisable, setShowDisable] = useState(false);

  // --- passkeys ---
  const { data: passkeys } = usePasskeys();
  const registerPasskey = useRegisterPasskey();
  const renamePasskey = useRenamePasskey();
  const deletePasskey = useDeletePasskey();
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editName, setEditName] = useState("");

  useEffect(() => {
    if (secret) QRCode.toDataURL(secret.otpauth_uri, { margin: 1, width: 180 }).then(setQr);
  }, [secret]);

  useEffect(() => {
    if (me) setEmail(me.email ?? "");
  }, [me]);

  async function saveEmail(e: React.FormEvent) {
    e.preventDefault();
    try {
      await updateProfile.mutateAsync({ email: email.trim() || null });
      toast("ok", "email updated");
    } catch (err) {
      toast("err", err instanceof Error ? err.message : "failed");
    }
  }

  async function doChangePw(e: React.FormEvent) {
    e.preventDefault();
    if (!me) return;
    try {
      await changePw.mutateAsync({ id: me.id, old_password: oldPw, new_password: newPw });
      toast("ok", "password changed");
      setOldPw("");
      setNewPw("");
    } catch (err) {
      toast("err", err instanceof Error ? err.message : "failed");
    }
  }

  async function startTotp() {
    try {
      setSecret(await enrollBegin.mutateAsync());
    } catch (err) {
      toast("err", err instanceof Error ? err.message : "failed");
    }
  }

  async function confirmTotp(e: React.FormEvent) {
    e.preventDefault();
    try {
      const res = await enrollFinish.mutateAsync({ code: totpCode });
      setBackupCodes(res.backup_codes);
      setSecret(null);
      setTotpCode("");
      toast("ok", "2FA enabled");
    } catch (err) {
      toast("err", err instanceof Error ? err.message : "invalid code");
    }
  }

  async function doDisable(e: React.FormEvent) {
    e.preventDefault();
    try {
      await disableTotp.mutateAsync({ code: disableCode });
      setShowDisable(false);
      setDisableCode("");
      toast("ok", "2FA disabled");
    } catch (err) {
      toast("err", err instanceof Error ? err.message : "re-authentication failed");
    }
  }

  async function addPasskey() {
    try {
      // Runs the OS passkey ceremony straight away — no custom prompt. It gets a
      // default name you can rename inline below.
      await registerPasskey.mutateAsync(undefined);
      toast("ok", "passkey added — rename it below if you like");
    } catch (err) {
      toast("err", err instanceof Error ? err.message : "could not add passkey");
    }
  }

  async function saveName(id: string) {
    const name = editName.trim();
    if (!name) return setEditingId(null);
    try {
      await renamePasskey.mutateAsync({ id, name });
      setEditingId(null);
    } catch (err) {
      toast("err", err instanceof Error ? err.message : "rename failed");
    }
  }

  const totpEnabled = me?.totp_enabled;

  return (
    <div style={{ maxWidth: 680 }}>
      <div className="eyebrow">account</div>
      <h1 className="display" style={{ fontSize: 28, letterSpacing: "0.08em", marginBottom: 20 }}>
        Security
      </h1>

      <div className="stack" style={{ gap: 24 }}>
        {/* Profile */}
        <Section title="Profile">
          <form onSubmit={saveEmail} className="stack" style={{ gap: 14 }}>
            <div>
              <label className="lbl">Username</label>
              <input className="field" value={me?.username ?? ""} disabled />
            </div>
            <div>
              <label className="lbl">Email</label>
              <input
                className="field"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="you@example.com"
              />
            </div>
            <button
              className="btn btn--primary"
              style={{ alignSelf: "flex-start" }}
              disabled={updateProfile.isPending || email === (me?.email ?? "")}
            >
              {updateProfile.isPending ? <span className="spin" /> : "Save email"}
            </button>
          </form>
        </Section>

        {/* Password */}
        <Section title="Password">
          <form onSubmit={doChangePw} className="stack" style={{ gap: 14 }}>
            <div>
              <label className="lbl">Current password</label>
              <input className="field" type="password" value={oldPw} onChange={(e) => setOldPw(e.target.value)} />
            </div>
            <div>
              <label className="lbl">New password</label>
              <input className="field" type="password" value={newPw} onChange={(e) => setNewPw(e.target.value)} />
            </div>
            <button className="btn btn--primary" style={{ alignSelf: "flex-start" }} disabled={changePw.isPending || newPw.length < 12}>
              {changePw.isPending ? <span className="spin" /> : "Change password"}
            </button>
          </form>
        </Section>

        {/* TOTP */}
        <Section title="Authenticator app (TOTP)">
          {totpEnabled ? (
            <div className="row" style={{ justifyContent: "space-between" }}>
              <span className="badge badge--active"><span className="dot" /> enabled</span>
              <div className="row" style={{ gap: 8 }}>
                <button className="btn btn--sm btn--ghost" onClick={() => setShowDisable(true)}>Disable</button>
              </div>
            </div>
          ) : secret ? (
            <form onSubmit={confirmTotp} className="stack" style={{ gap: 14 }}>
              {qr && <img src={qr} alt="TOTP QR" style={{ alignSelf: "center", borderRadius: 4, background: "#fff", padding: 6 }} />}
              <div className="muted tiny">Scan with your authenticator, or enter the key manually:</div>
              <div className="codeblock" style={{ userSelect: "all", fontSize: 12 }}>{secret.secret}</div>
              <div>
                <label className="lbl">6-digit code</label>
                <input className="field" value={totpCode} onChange={(e) => setTotpCode(e.target.value)} placeholder="123456" inputMode="numeric" />
              </div>
              <div className="row" style={{ gap: 8 }}>
                <button className="btn btn--primary" disabled={enrollFinish.isPending || !totpCode}>
                  {enrollFinish.isPending ? <span className="spin" /> : "Enable"}
                </button>
                <button type="button" className="btn btn--ghost" onClick={() => setSecret(null)}>Cancel</button>
              </div>
            </form>
          ) : (
            <div className="row" style={{ justifyContent: "space-between" }}>
              <span className="muted tiny">Not configured.</span>
              <button className="btn btn--sm btn--primary" onClick={startTotp} disabled={enrollBegin.isPending}>
                {enrollBegin.isPending ? <span className="spin" /> : "Enable"}
              </button>
            </div>
          )}
        </Section>

        {/* Passkeys */}
        <Section title="Passkeys">
          <div className="stack" style={{ gap: 10 }}>
            {(passkeys?.length ?? 0) === 0 && <div className="muted tiny">No passkeys registered.</div>}
            {passkeys?.map((p) => (
              <div key={p.id} className="spread">
                <div className="grow" style={{ minWidth: 0 }}>
                  {editingId === p.id ? (
                    <form
                      onSubmit={(e) => { e.preventDefault(); saveName(p.id); }}
                      className="row"
                      style={{ gap: 6 }}
                    >
                      <input
                        className="field"
                        style={{ height: 30, padding: "4px 8px" }}
                        autoFocus
                        value={editName}
                        onChange={(e) => setEditName(e.target.value)}
                      />
                      <button className="btn btn--sm btn--primary" type="submit">Save</button>
                      <button className="btn btn--sm btn--ghost" type="button" onClick={() => setEditingId(null)}>Cancel</button>
                    </form>
                  ) : (
                    <>
                      <div className="row" style={{ gap: 8 }}>
                        <span style={{ fontSize: 13 }}>{p.name}</span>
                        <button
                          className="btn btn--sm btn--ghost"
                          style={{ padding: "2px 8px" }}
                          onClick={() => { setEditingId(p.id); setEditName(p.name); }}
                        >
                          Rename
                        </button>
                      </div>
                      <div className="muted tiny">added {fmtTime(p.created_at)} · last used {fmtTime(p.last_used_at)}</div>
                    </>
                  )}
                </div>
                <button
                  className="btn btn--sm btn--danger"
                  onClick={async () => {
                    try {
                      await deletePasskey.mutateAsync(p.id);
                      toast("ok", "passkey removed");
                    } catch (err) {
                      toast("err", err instanceof Error ? err.message : "failed");
                    }
                  }}
                >
                  Remove
                </button>
              </div>
            ))}
            <button className="btn btn--sm" style={{ alignSelf: "flex-start", marginTop: 4 }} onClick={addPasskey} disabled={registerPasskey.isPending}>
              {registerPasskey.isPending ? <span className="spin" /> : "Add passkey"}
            </button>
            <div className="muted tiny" style={{ lineHeight: 1.6 }}>
              Passkeys require reaching the dashboard over its configured domain (not a bare IP).
            </div>
          </div>
        </Section>
      </div>

      {/* Backup codes shown once */}
      <Modal open={!!backupCodes} onClose={() => setBackupCodes(null)} title="Backup codes" width={420}>
        {backupCodes && (
          <div>
            <p className="muted tiny" style={{ marginBottom: 12 }}>
              Save these now — each works once if you lose your authenticator. They won't be shown again.
            </p>
            <div className="codeblock" style={{ userSelect: "all", lineHeight: 1.8 }}>
              {backupCodes.join("\n")}
            </div>
            <div className="row" style={{ justifyContent: "flex-end", marginTop: 16, gap: 8 }}>
              <button className="btn btn--sm" onClick={() => { navigator.clipboard?.writeText(backupCodes.join("\n")); toast("ok", "copied"); }}>Copy</button>
              <button className="btn btn--sm btn--primary" onClick={() => setBackupCodes(null)}>Done</button>
            </div>
          </div>
        )}
      </Modal>

      {/* Disable TOTP (re-auth) */}
      <Modal open={showDisable} onClose={() => setShowDisable(false)} title="Disable 2FA" width={420}>
        <form onSubmit={doDisable} className="stack" style={{ gap: 14 }}>
          <p className="muted tiny">Enter a current authenticator code to confirm.</p>
          <input className="field" value={disableCode} onChange={(e) => setDisableCode(e.target.value)} placeholder="123456" inputMode="numeric" autoFocus />
          <div className="row" style={{ justifyContent: "flex-end", gap: 8 }}>
            <button type="button" className="btn btn--ghost" onClick={() => setShowDisable(false)}>Cancel</button>
            <button className="btn btn--danger" disabled={disableTotp.isPending || !disableCode}>
              {disableTotp.isPending ? <span className="spin" /> : "Disable 2FA"}
            </button>
          </div>
          <button
            type="button"
            className="btn btn--ghost btn--sm"
            onClick={async () => {
              try {
                const res = await regen.mutateAsync({ code: disableCode });
                setBackupCodes(res.backup_codes);
                setShowDisable(false);
                setDisableCode("");
              } catch (err) {
                toast("err", err instanceof Error ? err.message : "invalid code");
              }
            }}
          >
            …or regenerate backup codes instead
          </button>
        </form>
      </Modal>
    </div>
  );
}
