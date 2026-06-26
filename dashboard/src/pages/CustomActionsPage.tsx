import { useState } from "react";
import { motion } from "framer-motion";
import {
  useCreateCustomAction,
  useCustomActions,
  useDeleteCustomAction,
  useTags,
  useUpdateCustomAction,
} from "../api/hooks";
import { useToast } from "../components/Toast";

export function CustomActionsPage() {
  const { data: actions, isLoading } = useCustomActions();
  const { data: tags } = useTags();
  const create = useCreateCustomAction();
  const update = useUpdateCustomAction();
  const del = useDeleteCustomAction();
  const toast = useToast();

  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [commandsText, setCommandsText] = useState("");
  const [tagIds, setTagIds] = useState<string[]>([]);

  const tagName = (id: string) => tags?.find((t) => t.id === id)?.name ?? id;

  function toggleTag(id: string) {
    setTagIds((cur) => (cur.includes(id) ? cur.filter((x) => x !== id) : [...cur, id]));
  }

  async function onCreate() {
    const commands = commandsText.split("\n").map((l) => l.trim()).filter(Boolean);
    if (!name.trim() || commands.length === 0 || tagIds.length === 0) {
      toast("err", "name, at least one command, and one tag are required");
      return;
    }
    try {
      await create.mutateAsync({ name: name.trim(), description: description.trim(), commands, tag_ids: tagIds });
      setName("");
      setDescription("");
      setCommandsText("");
      setTagIds([]);
      toast("ok", "command created");
    } catch (err) {
      toast("err", err instanceof Error ? err.message : "could not create command");
    }
  }

  if (isLoading) return <span className="spin" />;

  return (
    <div>
      <div className="eyebrow">execution</div>
      <h1 className="display" style={{ fontSize: 28, letterSpacing: "0.08em", marginBottom: 6 }}>
        Custom Commands
      </h1>
      <p className="muted tiny" style={{ marginBottom: 22, maxWidth: 680, lineHeight: 1.6 }}>
        Define commands (no shell) that VMs in <b>custom</b> exec mode can run. One command per
        line — they run in order and stop at the first failure. A command runs on a VM only if the
        VM is in custom mode <b>and</b> carries one of the command's tags. Quoting is honoured
        (<code>echo "a b"</code> → two tokens); nothing is passed through a shell.
      </p>

      <div style={{ display: "grid", gap: 20, maxWidth: 820 }}>
        {/* Create */}
        <motion.div className="panel panel--bracket" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} style={{ padding: 20 }}>
          <div className="eyebrow" style={{ marginBottom: 14 }}>new command</div>
          <div className="row" style={{ gap: 10, marginBottom: 10 }}>
            <div style={{ width: 220 }}>
              <label className="lbl">Name</label>
              <input className="field" placeholder="restart-nginx" value={name} onChange={(e) => setName(e.target.value)} />
            </div>
            <div className="grow">
              <label className="lbl">Description</label>
              <input className="field" placeholder="what it does" value={description} onChange={(e) => setDescription(e.target.value)} />
            </div>
          </div>
          <label className="lbl">Commands — one full command per line (run in order, stop on failure)</label>
          <textarea
            className="field"
            style={{ fontFamily: "var(--font-mono)", minHeight: 96, resize: "vertical" }}
            placeholder={"systemctl restart nginx\ndocker compose -f /srv/app.yml pull"}
            value={commandsText}
            onChange={(e) => setCommandsText(e.target.value)}
          />
          <label className="lbl" style={{ marginTop: 12 }}>Allowed tags (VMs must carry one)</label>
          <div className="row" style={{ gap: 6, flexWrap: "wrap", marginBottom: 14 }}>
            {tags?.length ? (
              tags.map((t) => (
                <button
                  key={t.id}
                  className={`btn btn--sm ${tagIds.includes(t.id) ? "btn--primary" : "btn--ghost"}`}
                  onClick={() => toggleTag(t.id)}
                >
                  {t.name}
                </button>
              ))
            ) : (
              <span className="muted tiny">No tags yet — create some on the Tags page first.</span>
            )}
          </div>
          <button className="btn btn--primary" onClick={onCreate} disabled={create.isPending}>
            {create.isPending ? <span className="spin" /> : "Create ›"}
          </button>
        </motion.div>

        {/* List */}
        <motion.div className="panel" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.05 }} style={{ overflow: "hidden" }}>
          <table className="tbl">
            <thead>
              <tr>
                <th>Name</th>
                <th>Command</th>
                <th>Tags</th>
                <th>Enabled</th>
                <th style={{ textAlign: "right" }}>—</th>
              </tr>
            </thead>
            <tbody>
              {actions?.map((a) => (
                <tr key={a.id}>
                  <td style={{ fontWeight: 600 }}>
                    {a.name}
                    {a.description && <div className="muted tiny">{a.description}</div>}
                  </td>
                  <td>
                    {a.commands.map((line, i) => (
                      <div key={i}>
                        <code className="tiny" style={{ color: "var(--ember-soft)" }}>{line}</code>
                      </div>
                    ))}
                  </td>
                  <td>
                    <div className="row" style={{ gap: 4, flexWrap: "wrap" }}>
                      {a.tag_ids.map((id) => (
                        <span key={id} className="badge" style={{ fontSize: 11 }}>{tagName(id)}</span>
                      ))}
                    </div>
                  </td>
                  <td>
                    <button
                      className={`btn btn--sm ${a.enabled ? "btn--ghost" : ""}`}
                      onClick={() => update.mutateAsync({ id: a.id, enabled: !a.enabled }).then(
                        () => toast("ok", a.enabled ? "disabled" : "enabled"),
                        (e) => toast("err", e?.message ?? "failed"),
                      )}
                    >
                      {a.enabled ? "on" : "off"}
                    </button>
                  </td>
                  <td style={{ textAlign: "right" }}>
                    <button
                      className="btn btn--danger btn--sm"
                      onClick={() => {
                        if (!confirm(`Delete command "${a.name}"?`)) return;
                        del.mutateAsync(a.id).then(
                          () => toast("ok", "deleted"),
                          (e) => toast("err", e?.message ?? "failed"),
                        );
                      }}
                    >
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {actions?.length === 0 && <div style={{ padding: 32 }} className="muted tiny">No custom commands yet.</div>}
        </motion.div>
      </div>
    </div>
  );
}
