import { describe, expect, it } from "vitest";
import { formatSystemLabel } from "./system";

describe("formatSystemLabel", () => {
  it("uses the detailed label reported by the worker", () => {
    expect(formatSystemLabel("windows", "Windows 11 Pro · 24H2 (build 26100)"))
      .toBe("Windows 11 Pro · 24H2 (build 26100)");
    expect(formatSystemLabel("linux", "Ubuntu 24.04.2 LTS"))
      .toBe("Ubuntu 24.04.2 LTS");
  });

  it("labels older workers without inventing a distribution or version", () => {
    expect(formatSystemLabel("windows", null)).toBe("Windows · details unavailable");
    expect(formatSystemLabel("linux", null)).toBe("Linux · details unavailable");
  });

  it("handles absent and unknown operating systems", () => {
    expect(formatSystemLabel(null, null)).toBe("Unknown");
    expect(formatSystemLabel("freebsd", null)).toBe("freebsd · details unavailable");
  });

  it("ignores blank detailed labels", () => {
    expect(formatSystemLabel("linux", "   ")).toBe("Linux · details unavailable");
  });
});
