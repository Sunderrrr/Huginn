import { motion } from "framer-motion";
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { ApiError } from "../api/client";
import { useAuthConfig } from "../api/hooks";
import { useAuth } from "../auth/AuthContext";
import { useToast } from "../components/Toast";

export function LoginPage() {
  const { login, oidcLogin } = useAuth();
  const navigate = useNavigate();
  const toast = useToast();
  const { data: authConfig } = useAuthConfig();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      await login(username, password);
      navigate("/fleet");
    } catch (err) {
      toast("err", err instanceof ApiError ? err.message : "login failed");
    } finally {
      setBusy(false);
    }
  }

  async function oidc() {
    try {
      await oidcLogin();
    } catch (err) {
      toast("err", err instanceof ApiError && err.status === 404 ? "OIDC is not enabled" : "OIDC error");
    }
  }

  const stagger = (i: number) => ({
    initial: { opacity: 0, y: 14 },
    animate: { opacity: 1, y: 0 },
    transition: { delay: 0.08 * i, duration: 0.5, ease: [0.2, 0.7, 0.2, 1] as const },
  });

  return (
    <div style={{ minHeight: "100vh", display: "grid", gridTemplateColumns: "1fr", placeItems: "center", padding: 24 }}>
      {/* Oversized backdrop wordmark */}
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
          fleet control · authenticate to proceed
        </motion.div>

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

        {authConfig?.oidc_enabled && (
          <>
            <motion.div {...stagger(5)} className="row" style={{ margin: "22px 0 18px" }}>
              <div style={{ flex: 1, height: 1, background: "var(--line)" }} />
              <span className="eyebrow">or</span>
              <div style={{ flex: 1, height: 1, background: "var(--line)" }} />
            </motion.div>

            <motion.button
              {...stagger(6)}
              type="button"
              className="btn"
              style={{ width: "100%", justifyContent: "center" }}
              onClick={oidc}
            >
              Continue with {authConfig.oidc_provider_name || "SSO"}
            </motion.button>
          </>
        )}
      </motion.div>
    </div>
  );
}
