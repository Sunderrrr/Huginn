import { NavLink, Outlet } from "react-router-dom";
import { useVms } from "../api/hooks";
import { useAuth } from "../auth/AuthContext";
import type { VM, VMState } from "../api/types";

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
  { to: "/fleet", label: "Fleet" },
  { to: "/tokens", label: "Tokens" },
  { to: "/audit", label: "Audit" },
  { to: "/settings", label: "Settings" },
];

export function Layout() {
  const { user, logout } = useAuth();

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

          <div className="row" style={{ gap: 16 }}>
            <div style={{ textAlign: "right" }}>
              <div style={{ fontSize: 13 }}>{user?.username ?? "—"}</div>
              <div
                className="eyebrow"
                style={{ color: user?.role === "admin" ? "var(--ember)" : "var(--dim)" }}
              >
                {user?.role ?? ""}
              </div>
            </div>
            <button className="btn btn--ghost btn--sm" onClick={logout}>
              Sign out
            </button>
          </div>
        </div>

        <nav style={{ maxWidth: 1280, margin: "0 auto", padding: "0 24px" }}>
          <div className="row" style={{ gap: 4 }}>
            {NAV.map((n) => (
              <NavLink
                key={n.to}
                to={n.to}
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
