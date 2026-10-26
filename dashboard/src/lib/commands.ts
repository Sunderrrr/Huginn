// The commands an operator pastes to install or remove a worker on a
// machine. They live here (not in a component) because both the "add a VM"
// dialog and the VM page show them, and both must show the same thing.

// The per-OS install command, shown after an enrollment token is generated.
export type InstallOS = "linux" | "windows";

export function installCommand(os: InstallOS, base: string, token: string): string {
  if (os === "windows") {
    // Run the installer AS A FILE: `irm | iex` cannot bind HUB_URL and Token
    // to the script's param() block, and a failure in a piped script closes
    // the session. The commands are separated by semicolons so the whole
    // line stays copy-pasteable in PowerShell 7.
    return (
      `$installer = "$env:TEMP\\huginn-install.ps1"; ` +
      `Invoke-WebRequest -Uri "${base}/install.ps1" -OutFile $installer; ` +
      `pwsh -NoProfile -ExecutionPolicy Bypass -File $installer -HUB_URL "${base}" -Token "${token}"`
    );
  }
  return `curl -fsSLk ${base}/install.sh | HUB_URL=${base} TOKEN=${token} bash`;
}

// The per-OS uninstall command, shown on the VM page.
//
// `os` is the OS the worker reported at enrollment; a null/unknown OS is
// treated as Linux, which is what the node most likely is.
export function uninstallCommand(os: string | null | undefined, base: string): string {
  if (os && os.toLowerCase() === "windows") {
    // Same rule as the installer: the script is run AS A FILE. `irm | iex`
    // cannot bind its parameters, and a failure in a piped script closes the
    // session before it can report anything.
    return (
      `$uninstaller = "$env:TEMP\\huginn-uninstall.ps1"; ` +
      `Invoke-WebRequest -Uri "${base}/uninstall.ps1" -OutFile $uninstaller; ` +
      `pwsh -NoProfile -ExecutionPolicy Bypass -File $uninstaller`
    );
  }
  return `curl -fsSL ${base}/uninstall.sh | bash`;
}
