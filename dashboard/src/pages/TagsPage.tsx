import { motion } from "framer-motion";
import { useState } from "react";
import { useCreateTag, useDeleteTag, useTags, useUpdateTag, useVms } from "../api/hooks";
import { useAuth } from "../auth/AuthContext";
import { TagBadge } from "../components/badges";
import { Modal } from "../components/Dialog";
import { useToast } from "../components/Toast";
import type { Tag } from "../api/types";

const PRESET_COLORS = [
  "#46d39a", "#ff6a1a", "#ffb43f", "#6db3f2",
  "#ff4d4d", "#b07cf2", "#3fd0d6", "#e7e3d6",
];

export function TagsPage() {
  const { user } = useAuth();
  const { data: tags } = useTags();
  const { data: vms } = useVms();
  const toast = useToast();
  const [editing, setEditing] = useState<Tag | "new" | null>(null);

  if (user?.role !== "admin") {
    return <div className="muted">Tag management requires an admin account.</div>;
  }

  function countVms(tagId: string): number {
    return vms?.filter((v) => v.tags.some((t) => t.id === tagId)).length ?? 0;
  }

  return (
    <div>
      <div className="spread" style={{ marginBottom: 24 }}>
        <div>
          <div className="eyebrow">organization</div>
          <h1 className="display" style={{ fontSize: 28, letterSpacing: "0.08em", margin: "8px 0" }}>
            Tags
          </h1>
        </div>
        <button className="btn btn--primary" onClick={() => setEditing("new")}>
          + Create tag
        </button>
      </div>

      {tags && tags.length === 0 && (
        <div className="panel" style={{ padding: 32, textAlign: "center", color: "var(--dim)" }}>
          No tags yet. Create one to group your VMs.
        </div>
      )}

      {tags && tags.length > 0 && (
        <motion.div className="panel" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} style={{ padding: 0, overflow: "hidden" }}>
          <table className="tbl">
            <thead>
              <tr>
                <th>Tag</th>
                <th>Color</th>
                <th>VMs</th>
                <th style={{ textAlign: "right" }}>—</th>
              </tr>
            </thead>
            <tbody>
              {tags.map((t) => (
                <tr key={t.id}>
                  <td><TagBadge tag={t} /></td>
                  <td className="muted tiny" style={{ fontFamily: "var(--font-mono)" }}>{t.color}</td>
                  <td className="muted">{countVms(t.id)}</td>
                  <td style={{ textAlign: "right" }}>
                    <button className="btn btn--ghost btn--sm" onClick={() => setEditing(t)}>
                      Edit
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </motion.div>
      )}

      {editing && (
        <TagModal
          tag={editing === "new" ? null : editing}
          onClose={() => setEditing(null)}
          onToast={toast}
        />
      )}
    </div>
  );
}

function TagModal({
  tag,
  onClose,
  onToast,
}: {
  tag: Tag | null;
  onClose: () => void;
  onToast: (k: "ok" | "err" | "info", m: string) => void;
}) {
  const create = useCreateTag();
  const update = useUpdateTag();
  const del = useDeleteTag();
  const [name, setName] = useState(tag?.name ?? "");
  const [color, setColor] = useState(tag?.color ?? PRESET_COLORS[0]);

  function submit(e: React.FormEvent) {
    e.preventDefault();
    const onErr = (err: Error) => onToast("err", err.message);
    if (tag) {
      update.mutate({ id: tag.id, name, color }, {
        onSuccess: () => { onToast("ok", "tag updated"); onClose(); },
        onError: onErr,
      });
    } else {
      create.mutate({ name, color }, {
        onSuccess: () => { onToast("ok", `tag "${name}" created`); onClose(); },
        onError: onErr,
      });
    }
  }

  function remove() {
    if (!tag) return;
    if (!confirm(`Delete tag "${tag.name}"? It will be removed from all VMs.`)) return;
    del.mutate(tag.id, {
      onSuccess: () => { onToast("ok", "tag deleted"); onClose(); },
      onError: (err: Error) => onToast("err", err.message),
    });
  }

  const pending = create.isPending || update.isPending;

  return (
    <Modal open onClose={onClose} title={tag ? "Edit tag" : "Create tag"} width={460}>
      <form onSubmit={submit} className="stack" style={{ gap: 16 }}>
        <div>
          <label className="lbl">Name</label>
          <input className="field" value={name} onChange={(e) => setName(e.target.value)} required autoFocus maxLength={64} />
        </div>
        <div>
          <label className="lbl">Color</label>
          <div className="row" style={{ gap: 8, flexWrap: "wrap", alignItems: "center" }}>
            <input
              type="color"
              value={color}
              onChange={(e) => setColor(e.target.value)}
              style={{ width: 40, height: 32, padding: 0, border: "1px solid var(--line)", borderRadius: 6, background: "none", cursor: "pointer" }}
            />
            {PRESET_COLORS.map((c) => (
              <button
                key={c}
                type="button"
                onClick={() => setColor(c)}
                style={{
                  width: 24, height: 24, borderRadius: "50%", background: c, cursor: "pointer",
                  border: color.toLowerCase() === c.toLowerCase() ? "2px solid var(--bone)" : "1px solid var(--line)",
                }}
                aria-label={c}
              />
            ))}
          </div>
          <div style={{ marginTop: 10 }}>
            <TagBadge tag={{ id: "preview", name: name || "preview", color, created_at: "" }} />
          </div>
        </div>
        <div className="spread" style={{ marginTop: 8 }}>
          {tag ? (
            <button type="button" className="btn btn--danger btn--sm" onClick={remove}>
              Delete
            </button>
          ) : <span />}
          <div className="row" style={{ gap: 8 }}>
            <button type="button" className="btn btn--ghost" onClick={onClose}>Cancel</button>
            <button type="submit" className="btn btn--primary" disabled={pending}>
              {pending ? <span className="spin" /> : tag ? "Save" : "Create"}
            </button>
          </div>
        </div>
      </form>
    </Modal>
  );
}
