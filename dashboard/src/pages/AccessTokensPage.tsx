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

  const handleRegenerate = () => {
    regenerate.mutate(undefined, {
      onSuccess: (data) => {
        setNewToken(data.token);
        setConfirmOpen(false);
        toast("ok", "MCP token regenerated");
      },
      onError: (err: Error) => toast("err", err.message),
    });
  };

  const copy = (text: string) => {
    navigator.clipboard?.writeText(text);
    toast("ok", "token copied");
  };

  if (isLoading) return <span className="spin" />;

  return (
    <div>
      <div className="eyebrow">security</div>
      <h1 className="display" style={{ fontSize: 28, letterSpacing: "0.08em", marginBottom: 20 }}>
        MCP Token
      </h1>

      <motion.div
        className="panel panel--bracket"
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        style={{ padding: 20, maxWidth: 620 }}
      >
        <div className="stack" style={{ gap: 18 }}>
          <p className="muted tiny" style={{ lineHeight: 1.6 }}>
            Agents must send <code style={{ color: "var(--ember-soft)" }}>Authorization: Bearer &lt;token&gt;</code>{" "}
            to reach the MCP HTTP endpoint. Without it, the endpoint is open to anyone who can reach it.
          </p>

          <div>
            <label className="lbl">Current token</label>
            <div className="codeblock" style={{ userSelect: "all" }}>
              {tokenData?.masked || "(not set)"}
            </div>
          </div>

          <div className="row" style={{ gap: 10 }}>
            {tokenData?.token && (
              <button className="btn" onClick={() => copy(tokenData.token)}>
                Copy token
              </button>
            )}
            <button
              className="btn btn--danger"
              onClick={() => setConfirmOpen(true)}
              disabled={regenerate.isPending}
            >
              {regenerate.isPending ? <span className="spin" /> : "Regenerate"}
            </button>
          </div>

          <div className="muted tiny" style={{ lineHeight: 1.6 }}>
            After regeneration, update all agent configs with the new token. The old token stops working immediately.
          </div>
        </div>
      </motion.div>

      {/* Confirm regeneration */}
      <Modal open={confirmOpen} onClose={() => setConfirmOpen(false)} title="Regenerate MCP token" width={480}>
        <p style={{ marginBottom: 16 }}>
          This immediately invalidates the current token. All agents using it will be disconnected.
        </p>
        <div className="row" style={{ justifyContent: "flex-end" }}>
          <button className="btn btn--ghost" onClick={() => setConfirmOpen(false)}>
            Cancel
          </button>
          <button className="btn btn--danger" onClick={handleRegenerate}>
            Regenerate
          </button>
        </div>
      </Modal>

      {/* Show new token after regeneration */}
      <Modal open={!!newToken} onClose={() => setNewToken(null)} title="New MCP token" width={620}>
        {newToken && (
          <div>
            <p className="muted tiny" style={{ marginBottom: 12 }}>
              Copy this now — the token is shown only once.
            </p>
            <div className="codeblock" style={{ color: "var(--ember-soft)", userSelect: "all" }}>
              {newToken}
            </div>
            <div className="row" style={{ justifyContent: "flex-end", marginTop: 18 }}>
              <button className="btn" onClick={() => copy(newToken)}>
                Copy token
              </button>
              <button className="btn btn--primary" onClick={() => setNewToken(null)}>
                Done
              </button>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
}
