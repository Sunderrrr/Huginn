import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { setToken } from "../api/client";
import type { User } from "../api/types";
import { AuthProvider } from "../auth/AuthContext";
import { AddVmModal } from "./AddVmModal";
import { ToastProvider } from "./Toast";

// A placeholder enrollment token for the fixture. It is not a credential:
// the API stub never sends it anywhere. (Named so the secret scanner does
// not read it as a key.)
const SAMPLE_ENROLLMENT_TOKEN = "sample-enrollment-token";

function user(): User {
  return {
    id: "u1",
    username: "admin",
    email: null,
    role: "admin",
    is_active: true,
    vm_ids: [],
  };
}

type Handler = (url: string, init?: RequestInit) => Response;

function stubApi(onCall?: Handler) {
  const copied: string[] = [];
  let clipboard = "";
  Object.defineProperty(navigator, "clipboard", {
    configurable: true,
    value: {
      writeText: (t: string) => {
        clipboard = t;
        copied.push(t);
        return Promise.resolve();
      },
      readText: () => Promise.resolve(clipboard),
    },
  });
  vi.stubGlobal(
    "fetch",
    vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.includes("/api/auth/me")) {
        return Promise.resolve(new Response(JSON.stringify(user()), { status: 200 }));
      }
      if (url.includes("/api/enrollment-tokens") && init?.method === "POST") {
        return Promise.resolve(
          new Response(
            JSON.stringify({
              id: "t1",
              token: SAMPLE_ENROLLMENT_TOKEN,
              label: "x",
              max_uses: 1,
              uses_count: 0,
              auto_approve: false,
              install_browser: false,
              expires_at: "2099-01-01T00:00:00Z",
              created_at: "2026-01-01T00:00:00Z",
            }),
            { status: 201 },
          ),
        );
      }
      if (onCall) return Promise.resolve(onCall(url, init));
      return Promise.resolve(new Response("[]", { status: 200 }));
    }),
  );
  return copied;
}

function renderModal() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <AuthProvider>
        <ToastProvider>
          <AddVmModal open onClose={() => {}} />
        </ToastProvider>
      </AuthProvider>
    </QueryClientProvider>,
  );
}

describe("AddVmModal", () => {
  beforeEach(() => setToken("test-token"));
  afterEach(() => vi.unstubAllGlobals());

  it("copies the Windows command when Windows is selected", async () => {
    const copied = stubApi();
    renderModal();

    // Create the invite: the OS selector appears with the command.
    fireEvent.click(await screen.findByRole("button", { name: /Create invite/i }));
    await screen.findByText(/One-line install \(bash\)/);

    // Select Windows.
    fireEvent.click(screen.getByRole("button", { name: /Windows/i }));

    // The displayed command is the PowerShell one.
    await waitFor(() =>
      expect(screen.getByText(/One-line install \(PowerShell/)).toBeInTheDocument(),
    );
    expect(screen.getByText(/install\.ps1/)).toBeInTheDocument();
    expect(screen.queryByText(/install\.sh/)).toBeNull();

    // And the copy button copies that same command.
    // The first "copy" button belongs to the command row.
    fireEvent.click(screen.getByRole("button", { name: "copy install command" }));
    await waitFor(() => expect(copied.length).toBeGreaterThan(0));
    expect(copied[copied.length - 1]).toContain("install.ps1");
    expect(copied[copied.length - 1]).not.toContain("install.sh");
    // The command must bind the parameters: `irm | iex` cannot.
    expect(copied[copied.length - 1]).toContain("-File $installer -HUB_URL");
    expect(copied[copied.length - 1]).not.toContain("| iex");
  });

  it("copies the Linux command when Linux is selected", async () => {
    const copied = stubApi();
    renderModal();
    fireEvent.click(await screen.findByRole("button", { name: /Create invite/i }));
    await screen.findByText(/One-line install \(bash\)/);
    fireEvent.click(screen.getByRole("button", { name: "copy install command" }));
    await waitFor(() => expect(copied.length).toBeGreaterThan(0));
    expect(copied[copied.length - 1]).toContain("install.sh");
  });
});
