// Minimal typed fetch wrapper around the hub REST API. The bearer token is held
// in module state and injected on every request.

// In production the SPA is served behind the same reverse proxy that routes
// /api and /mcp, so default to same-origin (relative) requests — that works no
// matter which hostname or upstream proxy (e.g. an SSO forward-auth) the
// dashboard is reached through, and stays within the CSP `connect-src 'self'`.
// Only fall back to the local hub in dev, where vite serves on another port.
const RAW = (import.meta.env.VITE_HUB_URL as string | undefined)?.replace(/\/$/, "");
const HUB_URL: string =
  RAW !== undefined && RAW !== "" ? RAW : import.meta.env.DEV ? "http://localhost:8000" : "";

const TOKEN_KEY = "huginn.token";

let token: string | null = localStorage.getItem(TOKEN_KEY);

// Complete an OIDC login: the hub redirects back with #access_token=… in the
// fragment. Capture it, persist it, and strip it from the URL.
(function captureOidcToken() {
  if (typeof window === "undefined" || !window.location.hash) return;
  const params = new URLSearchParams(window.location.hash.slice(1));
  const fromHash = params.get("access_token");
  if (fromHash) {
    token = fromHash;
    localStorage.setItem(TOKEN_KEY, fromHash);
    history.replaceState(null, "", window.location.pathname + window.location.search);
  }
})();

export function setToken(value: string | null): void {
  token = value;
  if (value) localStorage.setItem(TOKEN_KEY, value);
  else localStorage.removeItem(TOKEN_KEY);
}

export function getToken(): string | null {
  return token;
}

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (token) headers["Authorization"] = `Bearer ${token}`;

  const resp = await fetch(`${HUB_URL}${path}`, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });

  if (resp.status === 401) {
    setToken(null);
  }
  if (!resp.ok) {
    let detail = `${resp.status} ${resp.statusText}`;
    try {
      const data = await resp.json();
      if (data?.detail) detail = typeof data.detail === "string" ? data.detail : JSON.stringify(data.detail);
    } catch {
      /* ignore */
    }
    throw new ApiError(resp.status, detail);
  }
  if (resp.status === 204) return undefined as T;
  return (await resp.json()) as T;
}

// Like post(), but authenticates with a one-off token (e.g. an MFA challenge
// token) instead of the stored session token, and never clears the stored
// token on a 401 — used for the two-step login exchange.
async function postWithToken<T>(path: string, body: unknown, oneOffToken: string): Promise<T> {
  const resp = await fetch(`${HUB_URL}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${oneOffToken}` },
    body: JSON.stringify(body ?? {}),
  });
  if (!resp.ok) {
    let detail = `${resp.status} ${resp.statusText}`;
    try {
      const data = await resp.json();
      if (data?.detail) detail = typeof data.detail === "string" ? data.detail : JSON.stringify(data.detail);
    } catch {
      /* ignore */
    }
    throw new ApiError(resp.status, detail);
  }
  if (resp.status === 204) return undefined as T;
  return (await resp.json()) as T;
}

export const api = {
  hubUrl: HUB_URL,
  get: <T>(path: string) => request<T>("GET", path),
  post: <T>(path: string, body?: unknown) => request<T>("POST", path, body),
  put: <T>(path: string, body?: unknown) => request<T>("PUT", path, body),
  patch: <T>(path: string, body?: unknown) => request<T>("PATCH", path, body),
  del: <T>(path: string) => request<T>("DELETE", path),
  postWithToken,
};
