import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { App } from "./App";
import { AuthProvider } from "./auth/AuthContext";
import { ToastProvider } from "./components/Toast";
import { setToken } from "./api/client";

function renderAt(path: string) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[path]}>
        <AuthProvider>
          <ToastProvider>
            <App />
          </ToastProvider>
        </AuthProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("App routing", () => {
  beforeEach(() => {
    setToken(null);
    // Any /api/auth/me probe returns 401 (unauthenticated).
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("", { status: 401 })));
  });
  afterEach(() => vi.unstubAllGlobals());

  it("redirects unauthenticated users to the login screen", async () => {
    renderAt("/fleet");
    expect(await screen.findByRole("button", { name: /authenticate/i })).toBeInTheDocument();
    expect(screen.getByText(/fleet control/i)).toBeInTheDocument();
  });

  it("shows the OIDC option on the login screen", async () => {
    renderAt("/login");
    expect(await screen.findByText(/continue with authentik/i)).toBeInTheDocument();
  });
});
