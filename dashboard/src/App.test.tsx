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
    // /api/auth/config drives the (conditional) SSO button; everything else
    // (e.g. /api/auth/me) returns 401 so the user is treated as unauthenticated.
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input);
        if (url.includes("/api/auth/config")) {
          return Promise.resolve(
            new Response(
              JSON.stringify({ oidc_enabled: true, oidc_provider_name: "Authentik" }),
              { status: 200, headers: { "Content-Type": "application/json" } },
            ),
          );
        }
        return Promise.resolve(new Response("", { status: 401 }));
      }),
    );
  });
  afterEach(() => vi.unstubAllGlobals());

  it("redirects unauthenticated users to the login screen", async () => {
    renderAt("/fleet");
    expect(await screen.findByRole("button", { name: /authenticate/i })).toBeInTheDocument();
    expect(screen.getByText(/fleet control/i)).toBeInTheDocument();
  });

  it("shows the OIDC option on the login screen when enabled", async () => {
    renderAt("/login");
    expect(await screen.findByText(/continue with authentik/i)).toBeInTheDocument();
  });

  it("hides the OIDC option when SSO is disabled", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input);
        if (url.includes("/api/auth/config")) {
          return Promise.resolve(
            new Response(JSON.stringify({ oidc_enabled: false, oidc_provider_name: "SSO" }), {
              status: 200,
              headers: { "Content-Type": "application/json" },
            }),
          );
        }
        return Promise.resolve(new Response("", { status: 401 }));
      }),
    );
    renderAt("/login");
    expect(await screen.findByRole("button", { name: /authenticate/i })).toBeInTheDocument();
    expect(screen.queryByText(/continue with/i)).not.toBeInTheDocument();
  });
});
