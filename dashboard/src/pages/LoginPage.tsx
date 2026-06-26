import { motion } from "framer-motion";
import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import QRCode from "qrcode";
import { api, ApiError } from "../api/client";
import { useAuthConfig } from "../api/hooks";
import { useAuth } from "../auth/AuthContext";
import { useToast } from "../components/Toast";
import type { TotpEnrollBegin } from "../api/types";

type Step = "credentials" | "mfa" | "setup";

export function LoginPage() {
  const { login, verifyMfa, passkeyLogin, oidcLogin, setupToken, finishSetup, user } = useAuth();
  const navigate = useNavigate();
  const toast = useToast();
  const { data: cfg } = useAuthConfig();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [step, setStep] = useState<Step>("credentials");

  // Second-factor input.
  const [code, setCode] = useState("");
  const [useBackup, setUseBackup] = useState(false);

  // Forced TOTP setup (admin without a factor).
  const [enroll, setEnroll] = useState<TotpEnrollBegin | null>(null);
  const [qr, setQr] = useState<string>("");
  const [setupCode, setSetupCode] = useState("");

  useEffect(() => {
    if (user) navigate("/", { replace: true });
  }, [user, navigate]);

  useEffect(() => {
    if (enroll) QRCode.toDataURL(enroll.otpauth_uri, { margin: 1, width: 180 }).then(setQr);
  }, [enroll]);

  const passwordEnabled = cfg?.password_login_enabled ?? true;

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      const res = await login(username, password);
      if (res.kind === "ok") return navigate("/");
      if (res.kind === "mfa") return setStep("mfa");
      if (res.kind === "mfa_setup") return setStep("setup");
    } catch (err) {
      toast("err", err instanceof ApiError ? err.message : "login failed");
    } finally {
      setBusy(false);
    }
  }

  async function submitMfa(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      await verifyMfa(useBackup ? { backup_code: code } : { code });
      navigate("/");
    } catch (err) {
      toast("err", err instanceof ApiError ? err.message : "verification failed");
    } finally {
      setBusy(false);
    }
  }

  async function beginSetup() {
    if (!setupToken) return;
    setBusy(true);
    try {
      const data = await api.postWithToken<TotpEnrollBegin>(
        "/api/auth/mfa/totp/enroll/begin",
        {},
        setupToken,
      );
      setEnroll(data);
    } catch (err) {
      toast("err", err instanceof ApiError ? err.message : "could not start setup");
    } finally {
      setBusy(false);
    }
  }

  async function finishSetupSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!setupToken) return;
    setBusy(true);
    try {
      const res = await api.postWithToken<{ backup_codes: string[]; access_token?: string }>(
        "/api/auth/mfa/totp/enroll/finish",
        { code: setupCode },
        setupToken,
      );
      toast("ok", "2FA enabled — save your backup codes from the Account page");
      if (res.access_token) await finishSetup(res.access_token);
      navigate("/");
    } catch (err) {
      toast("err", err instanceof ApiError ? err.message : "invalid code");
    } finally {
      setBusy(false);
    }
  }

  async function setupPasskey() {
    if (!setupToken) return;
    setBusy(true);
    try {
      const { startRegistration } = await import("@simplewebauthn/browser");
      const options = await api.postWithToken<Record<string, unknown>>(
        "/api/auth/mfa/webauthn/register/begin",
        {},
        setupToken,
      );
      const attestation = await startRegistration({ optionsJSON: options as never });
      const res = await api.postWithToken<{ access_token?: string }>(
        "/api/auth/mfa/webauthn/register/finish",
        { name: "passkey", credential: attestation },
        setupToken,
      );
      toast("ok", "passkey registered");
      if (res.access_token) await finishSetup(res.access_token);
      navigate("/");
    } catch (err) {
      toast("err", err instanceof ApiError ? err.message : "passkey setup failed");
    } finally {
      setBusy(false);
    }
  }

  async function passkey() {
    setBusy(true);
    try {
      await passkeyLogin(username || undefined);
      navigate("/");
    } catch (err) {
      toast("err", err instanceof ApiError ? err.message : "passkey sign-in failed");
    } finally {
      setBusy(false);
    }
  }

  const stagger = (i: number) => ({
    initial: { opacity: 0, y: 14 },
    animate: { opacity: 1, y: 0 },
    transition: { delay: 0.08 * i, duration: 0.5, ease: [0.2, 0.7, 0.2, 1] as const },
  });

  return (
    <div style={{ minHeight: "100vh", display: "grid", placeItems: "center", padding: 24 }}>
      <div
        aria-hidden
        className="display"
        style={{
          position: "fixed",
          right: "-4vw",
          bottom: "-6vh",
          fontSize: "26vw",
          color: "rgba(255,255,255,0.018)",
          letterSpacing: "0.04em",
          pointerEvents: "none",
          userSelect: "none",
        }}
      >
        HUGINN
      </div>

      <motion.div
        className="panel panel--bracket"
        initial={{ opacity: 0, scale: 0.97 }}
        animate={{ opacity: 1, scale: 1 }}
        transition={{ duration: 0.5, ease: [0.2, 0.7, 0.2, 1] }}
        style={{ width: 420, maxWidth: "100%", padding: 36, boxShadow: "var(--shadow)" }}
      >
        <motion.div {...stagger(0)} className="row" style={{ gap: 12, marginBottom: 4 }}>
          <svg width="30" height="30" viewBox="0 0 32 32" fill="none" aria-hidden>
            <path d="M2 16 L16 6 L30 16 L16 26 Z" stroke="var(--ember)" strokeWidth="1.5" />
            <circle cx="16" cy="16" r="4.5" fill="var(--ember)" />
          </svg>
          <div className="display" style={{ fontSize: 26, letterSpacing: "0.24em" }}>
            HUGINN
          </div>
        </motion.div>
        <motion.div {...stagger(1)} className="eyebrow" style={{ marginBottom: 28 }}>
          {step === "credentials" && "fleet control · authenticate to proceed"}
          {step === "mfa" && "second factor required"}
          {step === "setup" && "two-factor setup required"}
        </motion.div>

        {/* Step 1 — credentials */}
        {step === "credentials" && (
          <>
            {passwordEnabled && (
              <form onSubmit={submit}>
                <motion.div {...stagger(2)} style={{ marginBottom: 16 }}>
                  <label className="lbl">Operator</label>
                  <input
                    className="field"
                    autoFocus
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    placeholder="admin"
                  />
                </motion.div>
                <motion.div {...stagger(3)} style={{ marginBottom: 24 }}>
                  <label className="lbl">Passphrase</label>
                  <input
                    className="field"
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="••••••••••••"
                  />
                </motion.div>
                <motion.button
                  {...stagger(4)}
                  className="btn btn--primary"
                  style={{ width: "100%", justifyContent: "center" }}
                  disabled={busy || !username || !password}
                >
                  {busy ? <span className="spin" /> : "Authenticate ›"}
                </motion.button>
              </form>
            )}

            {(cfg?.oidc_enabled || cfg?.webauthn_enabled) && (
              <>
                {passwordEnabled && (
                  <motion.div {...stagger(5)} className="row" style={{ margin: "22px 0 18px" }}>
                    <div style={{ flex: 1, height: 1, background: "var(--line)" }} />
                    <span className="eyebrow">or</span>
                    <div style={{ flex: 1, height: 1, background: "var(--line)" }} />
                  </motion.div>
                )}
                <div className="stack" style={{ gap: 10, marginTop: passwordEnabled ? 0 : 8 }}>
                  {cfg?.oidc_enabled && (
                    <button
                      type="button"
                      className="btn"
                      style={{ width: "100%", justifyContent: "center" }}
                      onClick={() =>
                        oidcLogin().catch(() => toast("err", "OIDC error"))
                      }
                    >
                      Continue with {cfg.oidc_provider_name || "SSO"}
                    </button>
                  )}
                  {cfg?.webauthn_enabled && (
                    <button
                      type="button"
                      className="btn"
                      style={{ width: "100%", justifyContent: "center" }}
                      onClick={passkey}
                      disabled={busy}
                    >
                      Sign in with a passkey
                    </button>
                  )}
                </div>
              </>
            )}
          </>
        )}

        {/* Step 2 — TOTP / backup code */}
        {step === "mfa" && (
          <form onSubmit={submitMfa}>
            <div style={{ marginBottom: 16 }}>
              <label className="lbl">{useBackup ? "Backup code" : "Authenticator code"}</label>
              <input
                className="field"
                autoFocus
                value={code}
                onChange={(e) => setCode(e.target.value)}
                placeholder={useBackup ? "xxxxx-xxxxx" : "123456"}
                inputMode={useBackup ? "text" : "numeric"}
              />
            </div>
            <button
              className="btn btn--primary"
              style={{ width: "100%", justifyContent: "center" }}
              disabled={busy || !code}
            >
              {busy ? <span className="spin" /> : "Verify ›"}
            </button>
            <button
              type="button"
              className="btn btn--ghost btn--sm"
              style={{ width: "100%", justifyContent: "center", marginTop: 12 }}
              onClick={() => {
                setUseBackup((v) => !v);
                setCode("");
              }}
            >
              {useBackup ? "Use authenticator app" : "Use a backup code"}
            </button>
          </form>
        )}

        {/* Step 3 — forced 2FA enrollment (choose TOTP or passkey) */}
        {step === "setup" && (
          <div className="stack" style={{ gap: 16 }}>
            <p className="muted tiny" style={{ lineHeight: 1.6 }}>
              This admin account must enable a second factor before continuing.
              Choose one:
            </p>
            {!enroll ? (
              <div className="stack" style={{ gap: 10 }}>
                <button className="btn btn--primary" style={{ justifyContent: "center" }} onClick={beginSetup} disabled={busy}>
                  {busy ? <span className="spin" /> : "Authenticator app (TOTP)"}
                </button>
                {cfg?.webauthn_enabled && (
                  <button className="btn" style={{ justifyContent: "center" }} onClick={setupPasskey} disabled={busy}>
                    {busy ? <span className="spin" /> : "Passkey / security key"}
                  </button>
                )}
              </div>
            ) : (
              <form onSubmit={finishSetupSubmit} className="stack" style={{ gap: 14 }}>
                {qr && (
                  <img
                    src={qr}
                    alt="TOTP QR"
                    style={{ alignSelf: "center", borderRadius: 4, background: "#fff", padding: 6 }}
                  />
                )}
                <div className="codeblock" style={{ userSelect: "all", fontSize: 12 }}>
                  {enroll.secret}
                </div>
                <div>
                  <label className="lbl">Enter the 6-digit code</label>
                  <input
                    className="field"
                    autoFocus
                    value={setupCode}
                    onChange={(e) => setSetupCode(e.target.value)}
                    placeholder="123456"
                    inputMode="numeric"
                  />
                </div>
                <button
                  className="btn btn--primary"
                  style={{ justifyContent: "center" }}
                  disabled={busy || !setupCode}
                >
                  {busy ? <span className="spin" /> : "Enable & continue ›"}
                </button>
              </form>
            )}
          </div>
        )}
      </motion.div>
    </div>
  );
}
