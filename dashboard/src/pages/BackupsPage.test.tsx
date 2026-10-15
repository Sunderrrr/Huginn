import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AuthProvider } from "../auth/AuthContext";
import { ToastProvider } from "../components/Toast";
import { setToken } from "../api/client";
import { BackupsPage } from "./BackupsPage";

const ADMIN = {
  id: "u1",
  username: "admin",
  email: null,
  role: "admin",
  is_active: true,
  vm_ids: [],
};

const SETTINGS = {
  target_worker_version: "1.0.0",
  target_release_repo: "org/huginn",
  allowed_release_domains: ["github.com"],
  auto_update_enabled: true,
  updated_at: "2026-10-15T03:00:00Z",
  backup_s3_enabled: true,
  backup_s3_endpoint: "",
  backup_s3_region: "eu-west-1",
  backup_s3_bucket: "huginn-backups",
  backup_s3_prefix: "db/",
  backup_s3_access_key: "AKIAEXAMPLE",
  backup_s3_secret_key: "",
  backup_s3_secret_key_set: true,
  backup_s3_retention_days: 30,
};

const LIST = {
  s3_configured: true,
  items: [
    { name: "huginn-20261015-030000.sql.gz", size: 12345, modified_at: "2026-10-15T03:00:32Z" },
    { name: "huginn-20261014-030000.sql.gz", size: 2 * 1024 * 1024, modified_at: "2026-10-14T03:00:30Z" },
  ],
};

interface RecordedCall {
  method: string;
  url: string;
  body?: unknown;
}

function stubApi(list: unknown = LIST): RecordedCall[] {
  const calls: RecordedCall[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const method = init?.method ?? "GET";
      calls.push({ method, url, body: init?.body ? JSON.parse(String(init.body)) : undefined });
      const json = (data: unknown, status = 200) =>
        Promise.resolve(
          new Response(JSON.stringify(data), {
            status,
            headers: { "Content-Type": "application/json" },
          }),
        );
      if (url.includes("/api/auth/me")) return json(ADMIN);
      if (url.includes("/api/settings")) return json(SETTINGS);
      if (url.includes("/api/backups")) {
        if (method === "POST") {
          return json({ name: "huginn-20261015-040000.sql.gz", size: 2048, duration_ms: 1500 }, 201);
        }
        if (method === "DELETE") return Promise.resolve(new Response("", { status: 204 }));
        return json(list);
      }
      return Promise.resolve(new Response("", { status: 404 }));
    }),
  );
  return calls;
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <AuthProvider>
        <ToastProvider>
          <BackupsPage />
        </ToastProvider>
      </AuthProvider>
    </QueryClientProvider>,
  );
}

describe("BackupsPage", () => {
  beforeEach(() => setToken("test-token"));
  afterEach(() => vi.unstubAllGlobals());

  it("lists stored backups with formatted size and date", async () => {
    stubApi();
    renderPage();
    expect(await screen.findByText("huginn-20261015-030000.sql.gz")).toBeInTheDocument();
    expect(screen.getByText("huginn-20261014-030000.sql.gz")).toBeInTheDocument();
    expect(screen.getByText("12.1 KB")).toBeInTheDocument();
    expect(screen.getByText("2.0 MB")).toBeInTheDocument();
  });

  it("pre-fills the S3 target form from settings", async () => {
    stubApi();
    renderPage();
    await screen.findByText("huginn-20261015-030000.sql.gz");
    expect(screen.getByDisplayValue("huginn-backups")).toBeInTheDocument();
    expect(screen.getByDisplayValue("eu-west-1")).toBeInTheDocument();
    expect(screen.getByDisplayValue("db/")).toBeInTheDocument();
    expect(screen.getByDisplayValue("AKIAEXAMPLE")).toBeInTheDocument();
    expect(screen.getByDisplayValue("30")).toBeInTheDocument();
    // The secret is write-only: never echoed back, only its "set" state.
    expect(screen.getByPlaceholderText(/set — leave empty to keep/i)).toBeInTheDocument();
  });

  it("runs a backup on demand and shows the result", async () => {
    const calls = stubApi();
    const user = userEvent.setup();
    renderPage();
    await screen.findByText("huginn-20261015-030000.sql.gz");
    await user.click(screen.getByRole("button", { name: /back up now/i }));
    expect(await screen.findByText("backup complete")).toBeInTheDocument();
    expect(screen.getByText("huginn-20261015-040000.sql.gz")).toBeInTheDocument();
    expect(screen.getByText("2.0 KB")).toBeInTheDocument();
    expect(screen.getByText("1.5 s")).toBeInTheDocument();
    expect(calls.some((c) => c.method === "POST" && c.url.includes("/api/backups"))).toBe(true);
  });

  it("asks for confirmation before deleting a backup", async () => {
    const calls = stubApi();
    const confirmSpy = vi.spyOn(window, "confirm").mockReturnValue(false);
    const user = userEvent.setup();
    renderPage();
    await screen.findByText("huginn-20261015-030000.sql.gz");
    await user.click(screen.getAllByRole("button", { name: /delete/i })[0]);
    expect(confirmSpy).toHaveBeenCalled();
    expect(calls.some((c) => c.method === "DELETE")).toBe(false);
    confirmSpy.mockRestore();
  });

  it("deletes a backup when confirmed", async () => {
    const calls = stubApi();
    const confirmSpy = vi.spyOn(window, "confirm").mockReturnValue(true);
    const user = userEvent.setup();
    renderPage();
    await screen.findByText("huginn-20261015-030000.sql.gz");
    await user.click(screen.getAllByRole("button", { name: /delete/i })[0]);
    await waitFor(() =>
      expect(
        calls.some(
          (c) =>
            c.method === "DELETE" &&
            c.url.includes(`/api/backups/${encodeURIComponent("huginn-20261015-030000.sql.gz")}`),
        ),
      ).toBe(true),
    );
    confirmSpy.mockRestore();
  });

  it("shows a clear empty state when S3 is not configured", async () => {
    stubApi({ s3_configured: false, items: [] });
    renderPage();
    expect(await screen.findByText(/s3 backups are not configured/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /back up now/i })).toBeDisabled();
  });
});
