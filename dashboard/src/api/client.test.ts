import { beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError, api, getToken, setToken } from "./client";

describe("token storage", () => {
  beforeEach(() => {
    setToken(null);
  });

  it("persists and clears the token", () => {
    setToken("abc.def.ghi");
    expect(getToken()).toBe("abc.def.ghi");
    expect(localStorage.getItem("huginn.token")).toBe("abc.def.ghi");
    setToken(null);
    expect(getToken()).toBeNull();
    expect(localStorage.getItem("huginn.token")).toBeNull();
  });
});

describe("request error handling", () => {
  beforeEach(() => setToken(null));

  it("throws ApiError with the hub detail on non-2xx", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify({ detail: "operator privileges required" }), {
          status: 403,
        }),
      ),
    );
    await expect(api.get("/api/vms")).rejects.toMatchObject({
      status: 403,
      message: "operator privileges required",
    });
    vi.unstubAllGlobals();
  });

  it("clears the token on 401", async () => {
    setToken("stale");
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("", { status: 401 })));
    await expect(api.get("/api/auth/me")).rejects.toBeInstanceOf(ApiError);
    expect(getToken()).toBeNull();
    vi.unstubAllGlobals();
  });

  it("attaches the bearer token when set", async () => {
    setToken("tok123");
    const fetchMock = vi.fn().mockResolvedValue(new Response("[]", { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    await api.get("/api/vms");
    const headers = fetchMock.mock.calls[0][1].headers as Record<string, string>;
    expect(headers["Authorization"]).toBe("Bearer tok123");
    vi.unstubAllGlobals();
  });
});
