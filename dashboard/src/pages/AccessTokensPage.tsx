import { useMemo, useState } from "react";
import { motion } from "framer-motion";
import { useMcpToken, useRegenerateMcpToken } from "../api/hooks";
import { Modal } from "../components/Dialog";
import { useToast } from "../components/Toast";

const DOCS_URL = "https://github.com/Sunderrrr/Huginn/blob/main/docs/mcp-agents.md";

type ClientId = "claude-code" | "claude-desktop" | "cursor" | "continue" | "raw";

const CLIENTS: { id: ClientId; label: string; hint: string }[] = [
  { id: "claude-code", label: "Claude Code", hint: "CLI — run this command" },
  { id: "claude-desktop", label: "Claude Desktop", hint: "claude_desktop_config.json" },
  { id: "cursor", label: "Cursor", hint: ".cursor/mcp.json" },
  { id: "continue", label: "Continue", hint: "~/.continue/config.json" },
  { id: "raw", label: "Hermes / generic", hint: "any MCP-compatible agent" },
];

function buildConfig(client: ClientId, url: string, token: string): string {
  const auth = `Bearer ${token}`;
  switch (client) {
    case "claude-code":
      return [
        "claude mcp add huginn \\",
        "  --transport http \\",
        `  --url ${url} \\`,
        `  --header "Authorization: ${auth}"`,
      ].join("\n");
    case "continue":
      return JSON.stringify(
        {
          mcpServers: [
            {
              name: "huginn",
              transport: {
                type: "streamable-http",
                url,
                headers: { Authorization: auth },
              },
            },
          ],
        },
        null,
        2,
      );
    default:
      // claude-desktop, cursor, raw — all use the standard mcpServers map.
      return JSON.stringify(
        {
          mcpServers: {
            huginn: {
              url,
              headers: { Authorization: auth },
            },
          },
        },
        null,
        2,
      );
  }
}

export function AccessTokensPage() {
  const { data: tokenData, isLoading } = useMcpToken();
  const regenerate = useRegenerateMcpToken();
  const toast = useToast();
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [newToken, setNewToken] = useState<string | null>(null);
  const [client, setClient] = useState<ClientId>("claude-code");
  const [reveal, setReveal] = useState(false);

  const endpoint = `${window.location.origin}/mcp`;
  const realToken = tokenData?.token ?? "";
  const shownToken = reveal ? realToken : tokenData?.masked || "<token>";

  // The config shown on screen respects the reveal toggle; copying always uses
  // the real token so the pasted snippet works immediately.
  const shownConfig = useMemo(
    () => buildConfig(client, endpoint, shownToken),
    [client, endpoint, shownToken],
  );
  const realConfig = useMemo(
    () => buildConfig(client, endpoint, realToken),
    [client, endpoint, realToken],
  );

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

  const copy = (text: string, what = "copied") => {
    navigator.clipboard?.writeText(text);
    toast("ok", what);
  };

  if (isLoading) return <span className="spin" />;

  return (
    <div>
      <div className="eyebrow">security</div>
      <h1 className="display" style={{ fontSize: 28, letterSpacing: "0.08em", marginBottom: 6 }}>
        MCP Token
      </h1>
      <p className="muted tiny" style={{ marginBottom: 22, maxWidth: 620, lineHeight: 1.6 }}>
        Connect any MCP-compatible agent (Claude, Hermes, Cursor…) to drive your fleet.
        Paste one of the configs below — the endpoint and token are filled in for you.{" "}
        <a href={DOCS_URL} target="_blank" rel="noreferrer" style={{ color: "var(--ember-soft)" }}>
          full docs ›
        </a>
      </p>

      <div style={{ display: "grid", gridTemplateColumns: "minmax(0,1fr)", gap: 20, maxWidth: 760 }}>
        {/* Connection details */}
        <motion.div
          className="panel panel--bracket"
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          style={{ padding: 20 }}
        >
          <div className="eyebrow" style={{ marginBottom: 16 }}>connection</div>
          <div className="stack" style={{ gap: 16 }}>
            <div>
              <label className="lbl">Endpoint URL</label>
              <div className="row" style={{ gap: 8, alignItems: "stretch" }}>
                <div className="codeblock grow" style={{ userSelect: "all", padding: "9px 12px", color: "var(--bone)" }}>
                  {endpoint}
                </div>
                <button className="btn btn--sm" onClick={() => copy(endpoint, "URL copied")}>copy</button>
              </div>
            </div>
            <div>
              <label className="lbl">Bearer token</label>
              <div className="row" style={{ gap: 8, alignItems: "stretch" }}>
                <div className="codeblock grow" style={{ userSelect: "all", padding: "9px 12px", color: reveal ? "var(--ember-soft)" : "var(--dim)" }}>
                  {realToken ? shownToken : "(not set)"}
                </div>
                <button className="btn btn--sm" onClick={() => setReveal((v) => !v)} disabled={!realToken}>
                  {reveal ? "hide" : "reveal"}
                </button>
                {realToken && (
                  <button className="btn btn--sm" onClick={() => copy(realToken, "token copied")}>copy</button>
                )}
              </div>
            </div>
          </div>
        </motion.div>

        {/* Setup snippets */}
        <motion.div
          className="panel"
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.05 }}
          style={{ padding: 20 }}
        >
          <div className="eyebrow" style={{ marginBottom: 14 }}>setup</div>

          {/* Client tabs */}
          <div className="row" style={{ gap: 8, flexWrap: "wrap", marginBottom: 14 }}>
            {CLIENTS.map((c) => (
              <button
                key={c.id}
                className={`btn btn--sm ${client === c.id ? "btn--primary" : "btn--ghost"}`}
                onClick={() => setClient(c.id)}
              >
                {c.label}
              </button>
            ))}
          </div>

          <div className="muted tiny" style={{ marginBottom: 8 }}>
            {CLIENTS.find((c) => c.id === client)?.hint}
          </div>

          <div style={{ position: "relative" }}>
            <pre className="codeblock" style={{ margin: 0, maxHeight: 360 }}>
              {shownConfig}
            </pre>
            <button
              className="btn btn--sm"
              style={{ position: "absolute", top: 8, right: 8 }}
              onClick={() => copy(realConfig, "config copied")}
              disabled={!realToken}
            >
              copy config
            </button>
          </div>

          {!reveal && realToken && (
            <div className="muted tiny" style={{ marginTop: 10 }}>
              Token is masked above — <b>copy config</b> pastes the real one. Or hit <b>reveal</b> to show it.
            </div>
          )}

          <div className="muted tiny" style={{ marginTop: 12, lineHeight: 1.6 }}>
            After pasting, restart the agent. The Huginn tools (<code style={{ color: "var(--ember-soft)" }}>list_vms</code>,{" "}
            <code style={{ color: "var(--ember-soft)" }}>execute_action</code>…) will appear in its tool list.
          </div>
        </motion.div>

        {/* Danger zone */}
        <motion.div
          className="panel"
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          style={{ padding: 20, borderLeft: "3px solid var(--blood)" }}
        >
          <div className="spread">
            <div>
              <div className="eyebrow" style={{ marginBottom: 6 }}>rotate token</div>
              <div className="muted tiny" style={{ lineHeight: 1.6, maxWidth: 440 }}>
                Regenerating invalidates the current token immediately — every agent must be
                reconfigured with the new one.
              </div>
            </div>
            <button
              className="btn btn--danger"
              onClick={() => setConfirmOpen(true)}
              disabled={regenerate.isPending}
            >
              {regenerate.isPending ? <span className="spin" /> : "Regenerate"}
            </button>
          </div>
        </motion.div>
      </div>

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
              Copy this now — then update your agent configs. The old token no longer works.
            </p>
            <div className="codeblock" style={{ color: "var(--ember-soft)", userSelect: "all" }}>
              {newToken}
            </div>
            <div className="row" style={{ justifyContent: "flex-end", marginTop: 18 }}>
              <button className="btn" onClick={() => copy(newToken, "token copied")}>
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
