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
import { HomePage } from "./pages/HomePage";
import { AccountPage } from "./pages/AccountPage";

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
        <Route path="/audit" element={<AuditPage />} />
        <Route path="/settings" element={<SettingsPage />} />
        <Route path="/users" element={<UsersPage />} />
        <Route path="/tags" element={<TagsPage />} />
        <Route path="/commands" element={<CustomActionsPage />} />
        <Route path="/schedules" element={<SchedulesPage />} />
        <Route path="/access-tokens" element={<AccessTokensPage />} />
        <Route path="/account" element={<AccountPage />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
