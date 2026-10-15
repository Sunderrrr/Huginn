import { describe, expect, it } from "vitest";
import { fmtBytes, fmtTime, shortId, timeAgo } from "./format";

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

describe("fmtBytes", () => {
  it("returns em dash for null/undefined/NaN", () => {
    expect(fmtBytes(null)).toBe("—");
    expect(fmtBytes(undefined)).toBe("—");
    expect(fmtBytes(Number.NaN)).toBe("—");
  });

  it("keeps bytes as-is below 1 KB", () => {
    expect(fmtBytes(0)).toBe("0 B");
    expect(fmtBytes(512)).toBe("512 B");
    expect(fmtBytes(1023)).toBe("1023 B");
  });

  it("scales through KB/MB/GB", () => {
    expect(fmtBytes(1024)).toBe("1.0 KB");
    expect(fmtBytes(12345)).toBe("12.1 KB");
    expect(fmtBytes(5 * 1024 * 1024)).toBe("5.0 MB");
    expect(fmtBytes(3 * 1024 ** 3)).toBe("3.0 GB");
    expect(fmtBytes(1024 ** 4)).toBe("1.0 TB");
  });

  it("rounds whole hundreds without a decimal", () => {
    expect(fmtBytes(150 * 1024)).toBe("150 KB");
  });
});
