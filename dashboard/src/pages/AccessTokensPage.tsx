import { useState } from "react";
import { motion } from "framer-motion";
import { useMcpToken, useRegenerateMcpToken } from "../api/hooks";
import { Modal } from "../components/Dialog";
import { useToast } from "../components/Toast";

export function AccessTokensPage() {
  const { data: tokenData, isLoading } = useMcpToken();
  const regenerate = useRegenerateMcpToken();
  const toast = useToast();
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [newToken, setNewToken] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const handleRegenerate = () => {
    regenerate.mutate(undefined, {
      onSuccess: (data) => {
        setNewToken(data.token);
        setConfirmOpen(false);
        toast("ok", "MCP client token regenerated");
      },
      onError: (err: Error) => toast("err", err.message),
    });
  };

  const handleCopy = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      toast("err", "Failed to copy");
    }
  };

  if (isLoading) return <span className="spin" />;

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}>
      <div style={{ marginBottom: 24 }}>
        <div className="eyebrow">security</div>
        <h1 className="display" style={{ fontSize: 28, letterSpacing: "0.08em", margin: "8px 0" }}>
          Access Tokens
        </h1>
      </div>

      <div className="panel panel--bracket" style={{ marginBottom: 24 }}>
        <h2 className="display" style={{ fontSize: 16, letterSpacing: "0.1em", marginBottom: 16 }}>
          MCP Client Token
        </h2>
        <p style={{ color: "var(--dim)", fontSize: 13, marginBottom: 16, lineHeight: 1.6 }}>
          Agents must send <code style={{ color: "var(--ember)" }}>Authorization: Bearer &lt;token&gt;</code>{" "}
          to reach the MCP HTTP endpoint. Without this token, the endpoint is open to anyone who can reach it.
        </p>

        <div className="row" style={{ gap: 12, marginBottom: 16 }}>
          <div
            className="codeblock"
            style={{
              flex: 1,
              padding: "12px 16px",
              background: "var(--void)",
              borderRadius: 6,
              fontFamily: "var(--font-mono)",
              fontSize: 14,
              letterSpacing: "0.04em",
              color: tokenData?.masked ? "var(--bone)" : "var(--dim)",
            }}
          >
            {tokenData?.masked || "(not set)"}
          </div>
          {tokenData?.token && (
            <button
              className="btn btn--ghost btn--sm"
              onClick={() => handleCopy(tokenData.token)}
            >
              {copied ? "✓ Copied" : "Copy full token"}
            </button>
          )}
        </div>

        <div className="row" style={{ gap: 12 }}>
          <button
            className="btn btn--danger"
            onClick={() => setConfirmOpen(true)}
            disabled={regenerate.isPending}
          >
            {regenerate.isPending ? <span className="spin" /> : "Regenerate token"}
          </button>
        </div>

        <div
          className="muted tiny"
          style={{ marginTop: 12, padding: "10px 14px", borderLeft: "3px solid var(--amber)", background: "rgba(255,180,0,0.05)", borderRadius: 4 }}
        >
          After regeneration, update all agent configs with the new token. The old token will stop working immediately.
        </div>
      </div>

      {/* Confirm regeneration */}
      {confirmOpen && (
        <Modal open onClose={() => setConfirmOpen(false)} title="Regenerate MCP Token" width={480}>
          <div className="stack" style={{ gap: 16 }}>
            <p style={{ color: "var(--dim)", lineHeight: 1.6 }}>
              This will immediately invalidate the current token. All agents using it will be disconnected.
            </p>
            <p style={{ fontWeight: 600 }}>Continue?</p>
            <div className="spread">
              <button className="btn btn--ghost" onClick={() => setConfirmOpen(false)}>
                Cancel
              </button>
              <button className="btn btn--danger" onClick={handleRegenerate}>
                Regenerate
              </button>
            </div>
          </div>
        </Modal>
      )}

      {/* Show new token after regeneration */}
      {newToken && (
        <Modal open onClose={() => setNewToken(null)} title="New MCP Token" width={520}>
          <div className="stack" style={{ gap: 16 }}>
            <p style={{ color: "var(--dim)", lineHeight: 1.6 }}>
              Copy this token now — it will not be shown again.
            </p>
            <div
              className="codeblock"
              style={{
                padding: "14px 16px",
                background: "var(--void)",
                borderRadius: 6,
                fontFamily: "var(--font-mono)",
                fontSize: 13,
                wordBreak: "break-all",
                color: "var(--signal)",
                border: "1px solid var(--signal)",
              }}
            >
              {newToken}
            </div>
            <div className="spread">
              <button className="btn btn--ghost" onClick={() => setNewToken(null)}>
                Close
              </button>
              <button className="btn btn--primary" onClick={() => handleCopy(newToken)}>
                {copied ? "✓ Copied" : "Copy to clipboard"}
              </button>
            </div>
          </div>
        </Modal>
      )}
    </motion.div>
  );
}
