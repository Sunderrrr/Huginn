import { useEffect, useRef, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { NavLink, Outlet, useNavigate } from "react-router-dom";
import { useVms } from "../api/hooks";
import { useLiveEvents } from "../api/useLiveEvents";
import { useAuth } from "../auth/AuthContext";
import type { User, VM, VMState } from "../api/types";

function Sigil() {
  // A minimal geometric raven-eye mark.
  return (
    <svg width="26" height="26" viewBox="0 0 32 32" fill="none" aria-hidden>
      <path d="M2 16 L16 6 L30 16 L16 26 Z" stroke="var(--ember)" strokeWidth="1.5" />
      <circle cx="16" cy="16" r="4.5" fill="var(--ember)" />
      <circle cx="16" cy="16" r="9" stroke="var(--ember)" strokeWidth="1" opacity="0.4" />
    </svg>
  );
}

function count(vms: VM[] | undefined, state: VMState): number {
  return vms?.filter((v) => v.state === state).length ?? 0;
}

function Telemetry() {
  const { data: vms } = useVms();
  const cells: { label: string; n: number; color: string }[] = [
    { label: "active", n: count(vms, "active"), color: "var(--signal)" },
    { label: "pending", n: count(vms, "pending"), color: "var(--amber)" },
    { label: "offline", n: count(vms, "offline"), color: "var(--dim)" },
    { label: "total", n: vms?.length ?? 0, color: "var(--bone)" },
  ];
  return (
    <div className="row" style={{ gap: 0 }}>
      {cells.map((c) => (
        <div
          key={c.label}
          style={{
            padding: "0 18px",
            borderLeft: "1px solid var(--line)",
            textAlign: "right",
          }}
        >
          <div style={{ fontFamily: "var(--font-display)", fontSize: 22, color: c.color, lineHeight: 1 }}>
            {String(c.n).padStart(2, "0")}
          </div>
          <div className="eyebrow" style={{ marginTop: 3 }}>
            {c.label}
          </div>
        </div>
      ))}
    </div>
  );
}

const NAV = [
  { to: "/", label: "Home" },
  { to: "/fleet", label: "Fleet" },
  { to: "/access-tokens", label: "MCP Tokens" },
  { to: "/schedules", label: "Schedules", admin: true },
  { to: "/tags", label: "Tags", admin: true },
  { to: "/commands", label: "Commands", admin: true },
  { to: "/audit", label: "Logs" },
  { to: "/users", label: "Users", admin: true },
  { to: "/account", label: "Account" },
  { to: "/settings", label: "Settings" },
];

function roleColor(role: string | undefined): string {
  switch (role) {
    case "admin":
      return "var(--ember)";
    case "operator":
      return "var(--amber)";
    default:
      return "var(--dim)";
  }
}

function ProfileMenu({ user, onLogout }: { user: User | null; onLogout: () => void }) {
  const [open, setOpen] = useState(false);
  const navigate = useNavigate();
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", onDoc);
    return () => document.removeEventListener("mousedown", onDoc);
  }, [open]);

  const initial = (user?.username ?? "?").slice(0, 1).toUpperCase();
  const go = (to: string) => {
    setOpen(false);
    navigate(to);
  };

  return (
    <div ref={ref} style={{ position: "relative" }}>
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-haspopup="menu"
        aria-expanded={open}
        title="Account menu"
        className="row"
        style={{
          gap: 10,
          background: "transparent",
          border: "1px solid var(--line-bright)",
          borderRadius: 999,
          padding: "5px 10px 5px 6px",
          cursor: "pointer",
          color: "inherit",
        }}
      >
        <span
          aria-hidden
          style={{
            width: 26,
            height: 26,
            borderRadius: "50%",
            border: `1px solid ${roleColor(user?.role)}`,
            display: "grid",
            placeItems: "center",
            fontSize: 12,
            fontFamily: "var(--font-display)",
            color: roleColor(user?.role),
          }}
        >
          {initial}
        </span>
        <div style={{ textAlign: "left" }}>
          <div style={{ fontSize: 13, lineHeight: 1.1 }}>{user?.username ?? "—"}</div>
          <div className="eyebrow" style={{ color: roleColor(user?.role) }}>{user?.role ?? ""}</div>
        </div>
        <span aria-hidden style={{ color: "var(--dim)", fontSize: 10, marginLeft: 2 }}>▾</span>
      </button>

      <AnimatePresence>
        {open && (
          <motion.div
            role="menu"
            initial={{ opacity: 0, y: -6 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -6 }}
            transition={{ duration: 0.14 }}
            className="panel"
            style={{
              position: "absolute",
              right: 0,
              top: "calc(100% + 8px)",
              width: 240,
              padding: 8,
              boxShadow: "var(--shadow)",
              zIndex: 100,
            }}
          >
            <div style={{ padding: "8px 10px 10px" }}>
              <div style={{ fontSize: 13 }}>{user?.username}</div>
              <div className="muted tiny" style={{ marginTop: 2, wordBreak: "break-all" }}>
                {user?.email || "no email set"}
              </div>
            </div>
            <div style={{ height: 1, background: "var(--line)", margin: "0 -8px 6px" }} />
            <button type="button" role="menuitem" className="menu-item" onClick={() => go("/account")}>
              Account &amp; security
              <span className="muted tiny" style={{ display: "block", marginTop: 2 }}>
                email · password · 2FA · passkeys
              </span>
            </button>
            <button type="button" role="menuitem" className="menu-item" onClick={onLogout} style={{ color: "var(--blood)" }}>
              Sign out
            </button>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

function ThemeToggle() {
  const [theme, setTheme] = useState<string>(
    () => document.documentElement.dataset.theme || "dark",
  );
  const toggle = () => {
    const next = theme === "light" ? "dark" : "light";
    document.documentElement.dataset.theme = next;
    try {
      localStorage.setItem("huginn.theme", next);
    } catch {
      /* ignore */
    }
    setTheme(next);
  };
  return (
    <button
      type="button"
      onClick={toggle}
      title={theme === "light" ? "Switch to dark theme" : "Switch to light theme"}
      aria-label="Toggle light/dark theme"
      className="row"
      style={{
        width: 34,
        height: 34,
        justifyContent: "center",
        background: "transparent",
        border: "1px solid var(--line-bright)",
        borderRadius: 999,
        cursor: "pointer",
        color: "var(--dim)",
        fontSize: 15,
      }}
    >
      {theme === "light" ? "☾" : "☀"}
    </button>
  );
}

export function Layout() {
  const { user, logout } = useAuth();
  const isAdmin = user?.role === "admin";
  useLiveEvents(); // refresh caches live from the hub's SSE stream

  return (
    <div style={{ minHeight: "100%", display: "flex", flexDirection: "column" }}>
      <header
        style={{
          borderBottom: "1px solid var(--line)",
          background: "linear-gradient(180deg, rgba(255,106,26,0.04), transparent)",
          backdropFilter: "blur(6px)",
          position: "sticky",
          top: 0,
          zIndex: 50,
        }}
      >
        <div
          className="spread"
          style={{ maxWidth: 1280, margin: "0 auto", padding: "14px 24px" }}
        >
          <div className="row" style={{ gap: 14 }}>
            <Sigil />
            <div>
              <div className="display" style={{ fontSize: 20, letterSpacing: "0.22em" }}>
                HUGINN
              </div>
              <div className="eyebrow">fleet control plane</div>
            </div>
          </div>

          <Telemetry />

          <div className="row" style={{ gap: 10 }}>
            <ThemeToggle />
            <ProfileMenu user={user} onLogout={logout} />
          </div>
        </div>

        <nav style={{ maxWidth: 1280, margin: "0 auto", padding: "0 24px" }}>
          <div className="row" style={{ gap: 4 }}>
            {NAV.filter((n) => !n.admin || isAdmin).map((n) => (
              <NavLink
                key={n.to}
                to={n.to}
                end={n.to === "/"}
                className="display"
                style={({ isActive }) => ({
                  fontSize: 13,
                  letterSpacing: "0.12em",
                  padding: "11px 16px",
                  color: isActive ? "var(--bone)" : "var(--faint)",
                  borderBottom: `2px solid ${isActive ? "var(--ember)" : "transparent"}`,
                  transition: "color 0.15s, border-color 0.15s",
                })}
              >
                {n.label}
              </NavLink>
            ))}
          </div>
        </nav>
      </header>

      <main style={{ maxWidth: 1280, margin: "0 auto", padding: "28px 24px 80px", width: "100%", flex: 1 }}>
        <Outlet />
      </main>
    </div>
  );
}
