import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { setToken } from "../api/client";
import type { Task, User, VM } from "../api/types";
import { AuthProvider } from "../auth/AuthContext";
import { BrowserAutomation } from "./BrowserAutomation";
import { ToastProvider } from "./Toast";

const VM_ID = "11111111-1111-1111-1111-111111111111";

function vm(overrides: Partial<VM> = {}): VM {
  return {
    id: VM_ID,
    name: "vm-1",
    hostname: "h",
    ip_address: "1.2.3.4",
    arch: "amd64",
    state: "active",
    exec_mode: "whitelist",
    worker_version: "1.0.0",
    last_heartbeat_at: null,
    enrolled_at: null,
    approved_at: null,
    created_at: "2026-01-01T00:00:00Z",
    tags: [],
    browser_enabled: false,
    browser_engine_version: null,
    browser_engine_reported_at: null,
    ...overrides,
  };
}

function user(role: User["role"]): User {
  return {
    id: "u1",
    username: "u",
    email: null,
    role,
    is_active: true,
    vm_ids: [VM_ID],
  };
}

const PENDING_TASK: Task = {
  id: "22222222-2222-2222-2222-222222222222",
  vm_id: VM_ID,
  type: "browser",
  action_name: null,
  status: "pending",
  exit_code: null,
  stdout: null,
  stderr: null,
  error: null,
  created_at: "2026-01-01T00:00:00Z",
  finished_at: null,
};

type Handler = (url: string, init?: RequestInit) => Response;

// Stub fetch: /api/auth/me answers with `me`; every other request goes to
// `onCall` (undefined → 404-ish empty 401).
function stubApi(me: User, onCall?: Handler) {
  const calls: { url: string; init?: RequestInit }[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      calls.push({ url, init });
      if (url.includes("/api/auth/me")) {
        return Promise.resolve(new Response(JSON.stringify(me), { status: 200 }));
      }
      if (onCall) return Promise.resolve(onCall(url, init));
      return Promise.resolve(new Response("", { status: 401 }));
    }),
  );
  return calls;
}

function renderCard(v: VM) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <AuthProvider>
        <ToastProvider>
          <BrowserAutomation vm={v} />
        </ToastProvider>
      </AuthProvider>
    </QueryClientProvider>,
  );
}

describe("BrowserAutomation", () => {
  beforeEach(() => setToken("test-token"));
  afterEach(() => vi.unstubAllGlobals());

  it("shows the engine state reported by the worker", async () => {
    stubApi(user("operator"));
    renderCard(vm({ browser_engine_version: "v0.2.5" }));
    expect(await screen.findByText(/engine installed · v0\.2\.5/)).toBeInTheDocument();
  });

  it("flags a missing engine and blocks the run", async () => {
    stubApi(user("operator"));
    renderCard(vm({ browser_engine_reported_at: "2026-01-01T00:00:00Z" }));
    expect(await screen.findByText(/engine not installed/)).toBeInTheDocument();
    expect(
      await screen.findByText(/the Obscura engine is not installed on this node/),
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Run ›" })).toBeDisabled();
  });

  it("does not block the run when the engine state is unknown", async () => {
    stubApi(user("operator"));
    renderCard(vm());
    expect(await screen.findByText(/engine state unknown/)).toBeInTheDocument();
    // findByRole waits for the auth context to resolve (the runner only
    // renders once the user's role is known).
    expect(await screen.findByRole("button", { name: "Run ›" })).not.toBeDisabled();
  });

  it("offers a reinstall once the engine is installed", async () => {
    stubApi(user("admin"));
    renderCard(vm({ browser_engine_version: "v0.2.5" }));
    expect(
      await screen.findByRole("button", { name: "Reinstall browser engine" }),
    ).toBeInTheDocument();
  });

  it("shows the admin gate, engine install and step runner", async () => {
    stubApi(user("admin"));
    renderCard(vm({ browser_enabled: true }));
    expect(await screen.findByRole("checkbox")).toBeChecked();
    expect(screen.getByRole("button", { name: "Install browser engine" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Run ›" })).toBeInTheDocument();
    expect(screen.getByText(/Linux workers only/)).toBeInTheDocument(); // note
  });

  it("shows the operator the runner but not the admin controls", async () => {
    stubApi(user("operator"));
    renderCard(vm());
    expect(await screen.findByRole("button", { name: "Run ›" })).toBeInTheDocument();
    expect(screen.queryByRole("checkbox")).toBeNull();
    expect(screen.queryByRole("button", { name: "Install browser engine" })).toBeNull();
    expect(
      screen.getByText("disabled on this node — an admin must enable it first"),
    ).toBeInTheDocument();
  });

  it("tells readonly users execution is disabled", async () => {
    stubApi(user("readonly"));
    renderCard(vm());
    expect(await screen.findByText("read-only — execution disabled")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Run ›" })).toBeNull();
  });

  it("disables the install button when the VM is not active", async () => {
    stubApi(user("admin"));
    renderCard(vm({ state: "pending" }));
    expect(await screen.findByRole("button", { name: "Install browser engine" })).toBeDisabled();
  });

  it("rejects unparseable steps with a clear message, without calling the hub", async () => {
    const calls = stubApi(user("operator"));
    renderCard(vm({ browser_enabled: true }));
    fireEvent.change(await screen.findByRole("textbox"), { target: { value: "{not json" } });
    fireEvent.click(screen.getByRole("button", { name: "Run ›" }));
    expect(await screen.findByText(/invalid JSON/i)).toBeInTheDocument();
    expect(calls.filter((c) => c.url.includes("/browser"))).toHaveLength(0);
  });

  it("shows the hub's disabled-capability 403 verbatim", async () => {
    const detail =
      "browser automation is disabled on this VM; an admin must enable it (PUT /api/vms/{vm_id}/browser-enabled)";
    stubApi(user("operator"), (url) => {
      expect(url.includes("/browser")).toBe(true);
      return new Response(JSON.stringify({ detail }), { status: 403 });
    });
    renderCard(vm());
    fireEvent.click(await screen.findByRole("button", { name: "Run ›" }));
    // shown verbatim inline in the card (and as a toast)
    expect((await screen.findAllByText(detail)).length).toBeGreaterThan(0);
  });

  it("queues the run and follows the task", async () => {
    const calls = stubApi(user("operator"), (url, init) => {
      if (url.includes(`/api/vms/${VM_ID}/browser`)) {
        expect(init?.method).toBe("POST");
        const body = JSON.parse(String(init?.body));
        expect(body.steps).toHaveLength(2); // preloaded navigate + get_text
        expect(body.timeout).toBe(120);
        return new Response(JSON.stringify(PENDING_TASK), { status: 202 });
      }
      if (url.includes(`/api/tasks/${PENDING_TASK.id}`)) {
        return new Response(JSON.stringify({ ...PENDING_TASK, status: "running" }), {
          status: 200,
        });
      }
      return new Response("", { status: 404 });
    });
    renderCard(vm({ browser_enabled: true }));
    fireEvent.click(await screen.findByRole("button", { name: "Run ›" }));
    await waitFor(() =>
      expect(calls.some((c) => c.url.includes(`/api/tasks/${PENDING_TASK.id}`))).toBe(true),
    );
    expect(await screen.findByText("RUNNING")).toBeInTheDocument();
  });
});
