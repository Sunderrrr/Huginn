import { Navigate, Route, Routes } from "react-router-dom";
import { getToken } from "./api/client";
import { useAuth } from "./auth/AuthContext";
import { Layout } from "./components/Layout";
import { LoginPage } from "./pages/LoginPage";
import { FleetPage } from "./pages/FleetPage";
import { VMDetailPage } from "./pages/VMDetailPage";
import { AuditPage } from "./pages/AuditPage";
import { SettingsPage } from "./pages/SettingsPage";
import { UsersPage } from "./pages/UsersPage";
import { AccessTokensPage } from "./pages/AccessTokensPage";
import { TagsPage } from "./pages/TagsPage";
import { CustomActionsPage } from "./pages/CustomActionsPage";
import { SchedulesPage } from "./pages/SchedulesPage";
import { BackupsPage } from "./pages/BackupsPage";
import { HomePage } from "./pages/HomePage";
import { AccountPage } from "./pages/AccountPage";

// Role ranking, mirroring the hub's UserRole (admin > operator > readonly).
const ROLE_RANK: Record<string, number> = { readonly: 0, operator: 1, admin: 2 };

export type MinRole = "operator" | "admin";

function Protected({ children }: { children: React.ReactNode }) {
  const { user, loading } = useAuth();
  if (!getToken()) return <Navigate to="/login" replace />;
  if (loading) {
    return (
      <div style={{ display: "grid", placeItems: "center", height: "100vh" }}>
        <span className="spin" />
      </div>
    );
  }
  if (!user) return <Navigate to="/login" replace />;
  return <>{children}</>;
}

/**
 * Client-side role gate for the admin/operator pages.
 *
 * This is *not* a security boundary — the hub authorizes every request
 * server-side (a non-admin calling an admin route gets a 403). The gate only
 * keeps the UI honest: an admin-only page is not rendered (and does not fire
 * admin API calls that would only bounce) for a user who cannot use it.
 */
function RequireRole({ min, children }: { min: MinRole; children: React.ReactNode }) {
  const { user } = useAuth();
  const rank = ROLE_RANK[user?.role ?? "readonly"] ?? 0;
  if (rank < ROLE_RANK[min]) {
    return (
      <div className="panel" style={{ padding: 32, textAlign: "center", color: "var(--dim)" }}>
        This page requires the {min} role. You are signed in as {user?.role ?? "unknown"}.
      </div>
    );
  }
  return <>{children}</>;
}

export function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route
        element={
          <Protected>
            <Layout />
          </Protected>
        }
      >
        <Route path="/" element={<HomePage />} />
        <Route path="/fleet" element={<FleetPage />} />
        <Route path="/vm/:id" element={<VMDetailPage />} />
        {/* Operator+ (the hub requires an operator to read the audit log). */}
        <Route
          path="/audit"
          element={
            <RequireRole min="operator">
              <AuditPage />
            </RequireRole>
          }
        />
        <Route path="/settings" element={<SettingsPage />} />
        <Route
          path="/users"
          element={
            <RequireRole min="admin">
              <UsersPage />
            </RequireRole>
          }
        />
        <Route
          path="/tags"
          element={
            <RequireRole min="admin">
              <TagsPage />
            </RequireRole>
          }
        />
        <Route
          path="/commands"
          element={
            <RequireRole min="admin">
              <CustomActionsPage />
            </RequireRole>
          }
        />
        <Route
          path="/schedules"
          element={
            <RequireRole min="admin">
              <SchedulesPage />
            </RequireRole>
          }
        />
        <Route
          path="/backups"
          element={
            <RequireRole min="admin">
              <BackupsPage />
            </RequireRole>
          }
        />
        <Route path="/access-tokens" element={<AccessTokensPage />} />
        <Route path="/account" element={<AccountPage />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
