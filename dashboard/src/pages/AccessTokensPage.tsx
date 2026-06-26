import { useMemo, useState } from "react";
import { motion } from "framer-motion";
import {
  useCreateMcpToken,
  useMcpTokens,
  useRevokeMcpToken,
  useUpdateMcpToken,
} from "../api/hooks";
import type { McpTokenCreated } from "../api/types";
import { Modal } from "../components/Dialog";
import { useToast } from "../components/Toast";
import { fmtTime } from "../lib/format";

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
      // The name and URL are positional args (there is no --url flag); options
      // come first, then `<name> <url>`.
      return [
        "claude mcp add --transport http \\",
        `  huginn ${url} \\`,
        `  --header "Authorization: ${auth}"`,
      ].join("\n");
    case "continue":
      return JSON.stringify(
        { mcpServers: [{ name: "huginn", transport: { type: "streamable-http", url, headers: { Authorization: auth } } }] },
        null,
        2,
      );
    default:
      return JSON.stringify({ mcpServers: { huginn: { url, headers: { Authorization: auth } } } }, null, 2);
  }
}

export function AccessTokensPage() {
  const { data: tokens, isLoading } = useMcpTokens();
  const create = useCreateMcpToken();
  const revoke = useRevokeMcpToken();
  const update = useUpdateMcpToken();
  const toast = useToast();

  const [name, setName] = useState("");
  const [allowedIp, setAllowedIp] = useState("");
  const [created, setCreated] = useState<McpTokenCreated | null>(null);
  const [client, setClient] = useState<ClientId>("claude-code");
  const [reveal, setReveal] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editIp, setEditIp] = useState("");

  const endpoint = `${window.location.origin}/mcp`;
  const config = useMemo(
    () => (created ? buildConfig(client, endpoint, created.token) : ""),
    [client, endpoint, created],
  );
  // What's shown on screen: the token is masked (like the field above) unless
  // revealed. The copy button always copies the real, full config.
  const shownConfig = useMemo(
    () =>
      !created || reveal
        ? config
        : config.replaceAll(created.token, `****${created.token.slice(-8)}`),
    [config, created, reveal],
  );

  const copy = (text: string, what = "copied") => {
    navigator.clipboard?.writeText(text);
    toast("ok", what);
  };

  async function onCreate() {
    if (!name.trim()) return;
    try {
      const t = await create.mutateAsync({
        name: name.trim(),
        allowed_ip: allowedIp.trim() || null,
      });
      setCreated(t);
      setReveal(false);
      setName("");
      setAllowedIp("");
    } catch (err) {
      toast("err", err instanceof Error ? err.message : "could not create token");
    }
  }

  async function saveIp(id: string) {
    try {
      await update.mutateAsync({ id, allowed_ip: editIp.trim() || null });
      setEditingId(null);
      toast("ok", "IP restriction updated");
    } catch (err) {
      toast("err", err instanceof Error ? err.message : "invalid IP / CIDR");
    }
  }

  if (isLoading) return <span className="spin" />;

  return (
    <div>
      <div className="eyebrow">security</div>
      <h1 className="display" style={{ fontSize: 28, letterSpacing: "0.08em", marginBottom: 6 }}>
        MCP Tokens
      </h1>
      <p className="muted tiny" style={{ marginBottom: 22, maxWidth: 640, lineHeight: 1.6 }}>
        Create a token to connect an MCP agent (Claude, Hermes, Cursor…). Each token is
        yours: actions run as <b>you</b> and appear under your name in the audit log.
        Make one per agent/machine and revoke any you no longer use.{" "}
        <a href={DOCS_URL} target="_blank" rel="noreferrer" style={{ color: "var(--ember-soft)" }}>
          full docs ›
        </a>
      </p>

      <div style={{ display: "grid", gridTemplateColumns: "minmax(0,1fr)", gap: 20, maxWidth: 760 }}>
        {/* Create */}
        <motion.div className="panel panel--bracket" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} style={{ padding: 20 }}>
          <div className="eyebrow" style={{ marginBottom: 14 }}>new token</div>
          <div className="row" style={{ gap: 10, alignItems: "flex-end" }}>
            <div className="grow">
              <label className="lbl">Name</label>
              <input
                className="field"
                placeholder="e.g. my-laptop, hermes-prod"
                value={name}
                onChange={(e) => setName(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && onCreate()}
              />
            </div>
            <div style={{ width: 200 }}>
              <label className="lbl">Allowed IP / CIDR (optional)</label>
              <input
                className="field"
                placeholder="any — e.g. 203.0.113.7"
                value={allowedIp}
                onChange={(e) => setAllowedIp(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && onCreate()}
              />
            </div>
            <button className="btn btn--primary" onClick={onCreate} disabled={create.isPending || !name.trim()}>
              {create.isPending ? <span className="spin" /> : "Create ›"}
            </button>
          </div>
          <div className="muted tiny" style={{ marginTop: 10 }}>
            Bind a token to one machine: if set, it only works from that IP (or CIDR
            range). Leave blank to allow any source. Editable later.
          </div>
        </motion.div>

        {/* Existing tokens */}
        <motion.div className="panel" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.05 }} style={{ overflow: "hidden" }}>
          <table className="tbl">
            <thead>
              <tr>
                <th>Name</th>
                <th>Allowed IP</th>
                <th>Created</th>
                <th>Last used</th>
                <th style={{ textAlign: "right" }}>—</th>
              </tr>
            </thead>
            <tbody>
              {tokens?.map((t) => (
                <tr key={t.id} style={{ cursor: "default" }}>
                  <td style={{ fontWeight: 600 }}>{t.name}</td>
                  <td className="tiny">
                    {editingId === t.id ? (
                      <div className="row" style={{ gap: 6 }}>
                        <input
                          className="field"
                          style={{ height: 28, width: 150, padding: "2px 8px" }}
                          placeholder="any"
                          autoFocus
                          value={editIp}
                          onChange={(e) => setEditIp(e.target.value)}
                          onKeyDown={(e) => {
                            if (e.key === "Enter") saveIp(t.id);
                            if (e.key === "Escape") setEditingId(null);
                          }}
                        />
                        <button className="btn btn--sm btn--primary" onClick={() => saveIp(t.id)}>save</button>
                        <button className="btn btn--sm btn--ghost" onClick={() => setEditingId(null)}>×</button>
                      </div>
                    ) : (
                      <button
                        className="btn btn--ghost btn--sm"
                        title="Edit IP restriction"
                        onClick={() => {
                          setEditingId(t.id);
                          setEditIp(t.allowed_ip ?? "");
                        }}
                        style={{ color: t.allowed_ip ? "var(--signal)" : "var(--dim)" }}
                      >
                        {t.allowed_ip ?? "any"} ✎
                      </button>
                    )}
                  </td>
                  <td className="muted tiny">{fmtTime(t.created_at)}</td>
                  <td className="muted tiny">{t.last_used_at ? fmtTime(t.last_used_at) : "never"}</td>
                  <td style={{ textAlign: "right" }}>
                    <button
                      className="btn btn--danger btn--sm"
                      onClick={async () => {
                        if (!confirm(`Revoke token "${t.name}"? Agents using it stop working.`)) return;
                        try {
                          await revoke.mutateAsync(t.id);
                          toast("ok", "token revoked");
                        } catch (err) {
                          toast("err", err instanceof Error ? err.message : "failed");
                        }
                      }}
                    >
                      Revoke
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {tokens?.length === 0 && <div style={{ padding: 32 }} className="muted tiny">No MCP tokens yet.</div>}
        </motion.div>
      </div>

      {/* Show the new token + ready-to-paste config (once) */}
      <Modal open={!!created} onClose={() => setCreated(null)} title="MCP token created" width={680}>
        {created && (
          <div>
            <p className="muted tiny" style={{ marginBottom: 12 }}>
              Copy this now — the token is shown only once.
              {created.allowed_ip
                ? ` It only works from ${created.allowed_ip}.`
                : " It works from any IP (set a restriction in the list to pin it)."}
            </p>

            <label className="lbl">Token</label>
            <div className="row" style={{ gap: 8, alignItems: "stretch", marginBottom: 18 }}>
              <div className="codeblock grow" style={{ userSelect: "all", padding: "9px 12px", color: reveal ? "var(--ember-soft)" : "var(--dim)" }}>
                {reveal ? created.token : `****${created.token.slice(-8)}`}
              </div>
              <button className="btn btn--sm" onClick={() => setReveal((v) => !v)}>{reveal ? "hide" : "reveal"}</button>
              <button className="btn btn--sm" onClick={() => copy(created.token, "token copied")}>copy</button>
            </div>

            <div className="eyebrow" style={{ marginBottom: 8 }}>setup</div>
            <div className="row" style={{ gap: 8, flexWrap: "wrap", marginBottom: 10 }}>
              {CLIENTS.map((c) => (
                <button key={c.id} className={`btn btn--sm ${client === c.id ? "btn--primary" : "btn--ghost"}`} onClick={() => setClient(c.id)}>
                  {c.label}
                </button>
              ))}
            </div>
            <div className="muted tiny" style={{ marginBottom: 8 }}>{CLIENTS.find((c) => c.id === client)?.hint}</div>
            <div style={{ position: "relative" }}>
              <pre className="codeblock" style={{ margin: 0, maxHeight: 320 }}>{shownConfig}</pre>
              <button className="btn btn--sm" style={{ position: "absolute", top: 8, right: 8 }} onClick={() => copy(config, "config copied")}>
                copy config
              </button>
            </div>

            <div className="row" style={{ justifyContent: "flex-end", marginTop: 18 }}>
              <button className="btn btn--primary" onClick={() => setCreated(null)}>Done</button>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
}
