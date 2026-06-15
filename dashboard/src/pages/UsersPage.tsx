import { useState } from "react";
import { motion } from "framer-motion";
import {
  useUsers,
  useVms,
  useCreateUser,
  useUpdateUser,
  useDeactivateUser,
  useChangePassword,
  useSetUserVms,
} from "../api/hooks";
import { RoleBadge } from "../components/badges";
import { Modal } from "../components/Dialog";
import { useToast } from "../components/Toast";
import type { UserRole, User } from "../api/types";

export function UsersPage() {
  const { data: users, isLoading } = useUsers();
  const { data: vms } = useVms();
  const [createOpen, setCreateOpen] = useState(false);
  const [editUser, setEditUser] = useState<User | null>(null);

  if (isLoading) return <span className="spin" />;

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}>
      <div className="spread" style={{ marginBottom: 24 }}>
        <div>
          <div className="eyebrow">administration</div>
          <h1 className="display" style={{ fontSize: 28, letterSpacing: "0.08em", margin: "8px 0" }}>
            Users
          </h1>
        </div>
        <button className="btn btn--primary" onClick={() => setCreateOpen(true)}>
          + Create user
        </button>
      </div>

      {users && users.length === 0 && (
        <div className="panel" style={{ padding: 32, textAlign: "center", color: "var(--dim)" }}>
          No users yet.
        </div>
      )}

      {users && users.length > 0 && (
        <div className="panel" style={{ padding: 0, overflow: "hidden" }}>
          <table className="tbl">
            <thead>
              <tr>
                <th>Username</th>
                <th>Email</th>
                <th>Role</th>
                <th>Active</th>
                <th>VMs</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {users.map((u) => (
                <tr key={u.id}>
                  <td style={{ fontWeight: 600 }}>{u.username}</td>
                  <td className="muted">{u.email ?? "—"}</td>
                  <td>
                    <RoleBadge role={u.role} />
                  </td>
                  <td>
                    <span className="badge" style={{ color: u.is_active ? "var(--signal)" : "var(--blood)" }}>
                      {u.is_active ? "active" : "disabled"}
                    </span>
                  </td>
                  <td className="muted">{u.vm_ids.length}</td>
                  <td>
                    <button
                      className="btn btn--ghost btn--sm"
                      onClick={() => setEditUser(u)}
                    >
                      Edit
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {createOpen && (
        <CreateUserModal
          vms={vms ?? []}
          onClose={() => setCreateOpen(false)}
        />
      )}

      {editUser && (
        <EditUserModal
          user={editUser}
          vms={vms ?? []}
          onClose={() => setEditUser(null)}
        />
      )}
    </motion.div>
  );
}

function CreateUserModal({
  vms,
  onClose,
}: {
  vms: { id: string; name: string; hostname: string | null }[];
  onClose: () => void;
}) {
  const toast = useToast();
  const create = useCreateUser();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [email, setEmail] = useState("");
  const [role, setRole] = useState<UserRole>("readonly");
  const [vmIds, setVmIds] = useState<string[]>([]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    create.mutate(
      { username, password, email: email || undefined, role, vm_ids: vmIds },
      {
        onSuccess: () => {
          toast("ok", `User "${username}" created`);
          onClose();
        },
        onError: (err: Error) => toast("err", err.message),
      }
    );
  };

  const toggleVm = (id: string) => {
    setVmIds((prev) => (prev.includes(id) ? prev.filter((v) => v !== id) : [...prev, id]));
  };

  return (
    <Modal open onClose={onClose} title="Create User" width={560}>
      <form onSubmit={handleSubmit} className="stack" style={{ gap: 16 }}>
        <div>
          <label className="lbl">Username</label>
          <input
            className="field"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            required
            autoFocus
          />
        </div>
        <div>
          <label className="lbl">Password</label>
          <input
            className="field"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            minLength={8}
          />
        </div>
        <div>
          <label className="lbl">Email (optional)</label>
          <input
            className="field"
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
          />
        </div>
        <div>
          <label className="lbl">Role</label>
          <select className="field" value={role} onChange={(e) => setRole(e.target.value as UserRole)}>
            <option value="readonly">Read-only</option>
            <option value="operator">Operator</option>
            <option value="admin">Admin</option>
          </select>
        </div>
        {role !== "admin" && vms.length > 0 && (
          <div>
            <label className="lbl">VM Access</label>
            <div className="stack" style={{ gap: 6, maxHeight: 160, overflow: "auto", padding: "8px 0" }}>
              {vms.map((vm) => (
                <label key={vm.id} className="row" style={{ gap: 8, cursor: "pointer" }}>
                  <input
                    type="checkbox"
                    checked={vmIds.includes(vm.id)}
                    onChange={() => toggleVm(vm.id)}
                  />
                  <span style={{ fontSize: 13 }}>{vm.hostname ?? vm.name}</span>
                </label>
              ))}
            </div>
            <div className="tiny muted" style={{ marginTop: 4 }}>
              Leave empty = no access to any VM
            </div>
          </div>
        )}
        <div className="spread" style={{ marginTop: 8 }}>
          <button type="button" className="btn btn--ghost" onClick={onClose}>
            Cancel
          </button>
          <button type="submit" className="btn btn--primary" disabled={create.isPending}>
            {create.isPending ? <span className="spin" /> : "Create"}
          </button>
        </div>
      </form>
    </Modal>
  );
}

function EditUserModal({
  user,
  vms,
  onClose,
}: {
  user: User;
  vms: { id: string; name: string; hostname: string | null }[];
  onClose: () => void;
}) {
  const toast = useToast();
  const update = useUpdateUser();
  const deactivate = useDeactivateUser();
  const changePw = useChangePassword();
  const setVms = useSetUserVms();

  const [role, setRole] = useState<UserRole>(user.role);
  const [vmIds, setVmIds] = useState<string[]>(user.vm_ids);
  const [newPw, setNewPw] = useState("");
  const [confirmPw, setConfirmPw] = useState("");
  const [showPwForm, setShowPwForm] = useState(false);

  const handleSaveRole = () => {
    update.mutate(
      { id: user.id, role },
      {
        onSuccess: () => toast("ok", "Role updated"),
        onError: (err: Error) => toast("err", err.message),
      }
    );
  };

  const handleSaveVms = () => {
    setVms.mutate(
      { id: user.id, vm_ids: vmIds },
      {
        onSuccess: () => toast("ok", "VM access updated"),
        onError: (err: Error) => toast("err", err.message),
      }
    );
  };

  const handleChangePw = (e: React.FormEvent) => {
    e.preventDefault();
    if (newPw !== confirmPw) {
      toast("err", "Passwords don't match");
      return;
    }
    changePw.mutate(
      { id: user.id, new_password: newPw },
      {
        onSuccess: () => {
          toast("ok", "Password changed");
          setNewPw("");
          setConfirmPw("");
          setShowPwForm(false);
        },
        onError: (err: Error) => toast("err", err.message),
      }
    );
  };

  const handleDeactivate = () => {
    if (!confirm(`Deactivate user "${user.username}"?`)) return;
    deactivate.mutate(user.id, {
      onSuccess: () => {
        toast("ok", `User "${user.username}" deactivated`);
        onClose();
      },
      onError: (err: Error) => toast("err", err.message),
    });
  };

  const toggleVm = (id: string) => {
    setVmIds((prev) => (prev.includes(id) ? prev.filter((v) => v !== id) : [...prev, id]));
  };

  return (
    <Modal open onClose={onClose} title={`Edit: ${user.username}`} width={560}>
      <div className="stack" style={{ gap: 20 }}>
        {/* Role */}
        <div>
          <label className="lbl">Role</label>
          <div className="row" style={{ gap: 8 }}>
            <select className="field" value={role} onChange={(e) => setRole(e.target.value as UserRole)} style={{ flex: 1 }}>
              <option value="readonly">Read-only</option>
              <option value="operator">Operator</option>
              <option value="admin">Admin</option>
            </select>
            <button className="btn btn--sm btn--primary" onClick={handleSaveRole} disabled={role === user.role}>
              Save
            </button>
          </div>
        </div>

        {/* VM Access */}
        {user.role !== "admin" && vms.length > 0 && (
          <div>
            <label className="lbl">VM Access</label>
            <div className="stack" style={{ gap: 6, maxHeight: 160, overflow: "auto", padding: "8px 0" }}>
              {vms.map((vm) => (
                <label key={vm.id} className="row" style={{ gap: 8, cursor: "pointer" }}>
                  <input
                    type="checkbox"
                    checked={vmIds.includes(vm.id)}
                    onChange={() => toggleVm(vm.id)}
                  />
                  <span style={{ fontSize: 13 }}>{vm.hostname ?? vm.name}</span>
                </label>
              ))}
            </div>
            <button
              className="btn btn--sm btn--primary"
              style={{ marginTop: 8 }}
              onClick={handleSaveVms}
            >
              Save VM access
            </button>
          </div>
        )}

        {/* Password */}
        <div>
          <label className="lbl">Password</label>
          {!showPwForm ? (
            <button className="btn btn--sm btn--ghost" onClick={() => setShowPwForm(true)}>
              Reset password
            </button>
          ) : (
            <form onSubmit={handleChangePw} className="stack" style={{ gap: 8 }}>
              <input
                className="field"
                type="password"
                placeholder="New password"
                value={newPw}
                onChange={(e) => setNewPw(e.target.value)}
                required
                minLength={8}
                autoFocus
              />
              <input
                className="field"
                type="password"
                placeholder="Confirm password"
                value={confirmPw}
                onChange={(e) => setConfirmPw(e.target.value)}
                required
                minLength={8}
              />
              <div className="row" style={{ gap: 8 }}>
                <button type="button" className="btn btn--ghost btn--sm" onClick={() => setShowPwForm(false)}>
                  Cancel
                </button>
                <button type="submit" className="btn btn--sm btn--primary" disabled={changePw.isPending}>
                  {changePw.isPending ? <span className="spin" /> : "Change password"}
                </button>
              </div>
            </form>
          )}
        </div>

        {/* Deactivate */}
        {user.is_active && (
          <div style={{ borderTop: "1px solid var(--line)", paddingTop: 16 }}>
            <button className="btn btn--danger" onClick={handleDeactivate}>
              Deactivate user
            </button>
          </div>
        )}

        <div style={{ textAlign: "right" }}>
          <button className="btn btn--ghost" onClick={onClose}>
            Close
          </button>
        </div>
      </div>
    </Modal>
  );
}
