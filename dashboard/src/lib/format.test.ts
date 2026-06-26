import { describe, expect, it } from "vitest";
import { fmtTime, shortId, timeAgo } from "./format";

describe("timeAgo", () => {
  it("returns em dash for null", () => {
    expect(timeAgo(null)).toBe("—");
  });

  it("formats recent times", () => {
    const now = new Date().toISOString();
    expect(timeAgo(now)).toBe("just now");
  });

  it("formats minutes and hours", () => {
    const tenMinAgo = new Date(Date.now() - 10 * 60_000).toISOString();
    expect(timeAgo(tenMinAgo)).toBe("10m ago");
    const twoHoursAgo = new Date(Date.now() - 2 * 3_600_000).toISOString();
    expect(timeAgo(twoHoursAgo)).toBe("2h ago");
  });

  it("formats days", () => {
    const threeDaysAgo = new Date(Date.now() - 3 * 86_400_000).toISOString();
    expect(timeAgo(threeDaysAgo)).toBe("3d ago");
  });
});

describe("fmtTime", () => {
  it("returns em dash for null/invalid", () => {
    expect(fmtTime(null)).toBe("—");
    expect(fmtTime("not-a-date")).toBe("—");
  });

  it("renders a real date", () => {
    expect(fmtTime("2026-06-13T22:00:00Z")).not.toBe("—");
  });
});

describe("shortId", () => {
  it("truncates to 8 chars", () => {
    expect(shortId("0123456789abcdef")).toBe("01234567");
  });
});
