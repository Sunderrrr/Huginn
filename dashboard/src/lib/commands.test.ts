import { describe, expect, it } from "vitest";
import { installCommand, uninstallCommand } from "./commands";

describe("installCommand", () => {
  it("gives the PowerShell installer for a Windows node", () => {
    const cmd = installCommand("windows", "https://hub.example", "tok");
    expect(cmd).toContain("https://hub.example/install.ps1");
    expect(cmd).toContain("-HUB_URL \"https://hub.example\"");
    // `irm | iex` cannot bind the parameters: the script is run as a file.
    expect(cmd).not.toContain("| iex");
    expect(cmd).not.toContain("Invoke-Expression");
  });

  it("gives the bash installer for a Linux node", () => {
    const cmd = installCommand("linux", "https://hub.example", "tok");
    expect(cmd).toContain("https://hub.example/install.sh");
    expect(cmd).toContain("TOKEN=tok");
  });
});

describe("uninstallCommand", () => {
  it("gives the PowerShell uninstaller for a Windows node", () => {
    const cmd = uninstallCommand("windows", "https://hub.example");
    expect(cmd).toContain("https://hub.example/uninstall.ps1");
    expect(cmd).not.toContain("uninstall.sh");
    // Same rule as the installer: run the script as a file, not piped.
    expect(cmd).not.toContain("| iex");
    expect(cmd).not.toContain("Invoke-Expression");
  });

  it("gives the bash uninstaller for a Linux node", () => {
    const cmd = uninstallCommand("linux", "https://hub.example");
    expect(cmd).toContain("https://hub.example/uninstall.sh");
    expect(cmd).not.toContain("uninstall.ps1");
  });

  it("falls back to the bash uninstaller when the OS is unknown", () => {
    // A node enrolled before the OS was reported: the Linux command is the
    // safe default (it is also the only one that works everywhere).
    expect(uninstallCommand(null, "https://hub.example")).toContain("uninstall.sh");
    expect(uninstallCommand(undefined, "https://hub.example")).toContain("uninstall.sh");
  });

  it("is not confused by the case of the reported OS", () => {
    expect(uninstallCommand("Windows", "https://hub.example")).toContain(
      "uninstall.ps1",
    );
  });
});
