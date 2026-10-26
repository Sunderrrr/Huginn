# Huginn worker uninstaller for Windows.
#
# Removes everything Huginn added to this machine: the "HuginnWorker" Windows
# Service, the worker binary and its install directory, the worker state
# (identity and secret) and the hub CA root from the LocalMachine Root trust
# store. Safe to re-run: a missing piece is skipped, not an error.
#
#   $uninstaller = "$env:TEMP\huginn-uninstall.ps1"
#   Invoke-WebRequest -Uri "https://<hub>/uninstall.ps1" -OutFile $uninstaller
#   pwsh -NoProfile -ExecutionPolicy Bypass -File $uninstaller
#
# Run it from a PowerShell 7 console opened as administrator: it stops a
# service, deletes it from the SCM, and removes files under Program Files and
# ProgramData.
#
# Do NOT use "irm ... | iex" here: a failure inside a piped script would
# terminate the caller's session before it could report anything. Run it as a
# file, as above.
#
# The node stays in the dashboard's fleet until it is revoked there (Fleet ->
# the node -> Revoke node). Revoking it also stops the hub from queuing
# tasks for a machine that no longer has a worker.
#
# Parameters:
#   ServiceName  (optional) name of the Windows Service (default: HuginnWorker)
#   BinDir       (optional) install directory (default: C:\Program Files\Huginn)
#   StateDir     (optional) state directory (default: C:\ProgramData\Huginn)

param(
    [string]$ServiceName = "HuginnWorker",
    [string]$BinDir = "C:\Program Files\Huginn",
    [string]$StateDir = "C:\ProgramData\Huginn"
)

$ErrorActionPreference = "Stop"
$BinaryName = "huginn-worker.exe"
$CaFileName = "hub-ca.crt"

function Log([string]$msg) {
    Write-Host "==> $msg" -ForegroundColor Cyan
}

function Warn([string]$msg) {
    Write-Host "   warning: $msg" -ForegroundColor Yellow
}

# Fail throws instead of calling exit: a script run with `exit` would close an
# interactive PowerShell session, and the caller could not read the error.
function Fail([string]$msg) {
    throw "huginn-uninstall: $msg"
}

# --- Must run as Administrator ---
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Fail "please run as Administrator (it stops a service and removes files under Program Files and ProgramData)"
}

# --- 1. stop the service ---
# The service holds the binary open: it must be stopped before the file can
# be deleted, and before the SCM entry can go away.
$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if (-not $service) {
    Log "service '$ServiceName' is not installed"
}
else {
    if ($service.Status -ne "Stopped") {
        Log "stopping $ServiceName"
        try {
            Stop-Service -Name $ServiceName -Force -ErrorAction Stop
        }
        catch {
            Warn "could not stop ${ServiceName}: $($_.Exception.Message)"
        }
        # The SCM takes a moment to release the process handle; the file
        # deletion below retries anyway.
        try {
            $service.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(30))
        }
        catch {
            Warn "${ServiceName} did not report 'Stopped' in time: $($_.Exception.Message)"
        }
    }
    else {
        Log "service '$ServiceName' is already stopped"
    }

    # --- 2. delete the service ---
    # sc.exe delete marks the entry for deletion: it disappears once the
    # service is stopped and the last handle is closed.
    Log "deleting the service '$ServiceName' from the SCM"
    # sc.exe writes its errors on stderr. Under PowerShell 7.0-7.2 a native
    # command writing there raises a terminating error when
    # $ErrorActionPreference is "Stop", so the preference is relaxed for the
    # call: the exit code is what tells success from failure.
    $previousPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $scOutput = & sc.exe delete $ServiceName 2>&1
        $scExit = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousPreference
    }
    foreach ($line in $scOutput) {
        if ($line -and "$line".Trim()) { Write-Host "   $line" }
    }
    # 0 = deleted, 1060 = already absent, 1072 = already marked for deletion.
    if ($scExit -notin @(0, 1060, 1072)) {
        Warn "sc.exe delete failed (exit code $scExit)"
    }
}

# --- 3. remove the hub CA from the LocalMachine Root store ---
# Only the certificate this machine was given is removed: its thumbprint is
# read from the CA file the installer kept. A CA that was already trusted
# before the install (a public one) is left alone.
$caFile = Join-Path $StateDir $CaFileName
if (-not (Test-Path $caFile)) {
    # A public CA needs no local file: the trust store was never touched.
    Log "no CA file at $caFile — the trust store is left untouched"
}
else {
    try {
        # The CA file is PEM; the bytes are decoded here rather than left to
        # the certificate constructor, whose PEM support depends on the
        # runtime version.
        $pemContent = Get-Content $caFile -Raw
        $match = [regex]::Match($pemContent, "-----BEGIN CERTIFICATE-----(?<body>[^-]+)-----END CERTIFICATE-----", "Singleline")
        if (-not $match.Success) {
            throw "$caFile does not look like a PEM certificate"
        }
        $der = [Convert]::FromBase64String(($match.Groups["body"].Value -replace "\s", ""))
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @(,$der)
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
        try {
            $store.Open("ReadWrite")
            # Remove() throws when the certificate is not in the store, so its
            # presence is checked first: the store may have been cleaned by
            # hand since the install.
            $present = @($store.Certificates | Where-Object { $_.Thumbprint -eq $cert.Thumbprint })
            if ($present.Count -eq 0) {
                Log "the hub CA is not in the LocalMachine Root trust store"
            }
            else {
                $store.Remove($cert)
                Log "hub CA (thumbprint $($cert.Thumbprint)) removed from the LocalMachine Root trust store"
            }
        }
        finally {
            $store.Close()
        }
    }
    catch {
        # A CA that cannot be identified is left in the store: removing the
        # wrong certificate would be worse. The operator is told how to find
        # it by hand.
        Warn "could not remove the hub CA from the trust store: $($_.Exception.Message)"
        Warn "remove it by hand if needed: certmgr.msc -> Trusted Root Certification Authorities"
    }
}

# --- 4. remove the worker binary ---
# The service may have taken a moment to release the file: retry.
$binaryPath = Join-Path $BinDir $BinaryName
if (-not (Test-Path $binaryPath)) {
    Log "no binary at $binaryPath"
}
else {
    Log "removing $binaryPath"
    $removed = $false
    for ($attempt = 1; $attempt -le 5 -and -not $removed; $attempt++) {
        try {
            Remove-Item $binaryPath -Force -ErrorAction Stop
            $removed = $true
        }
        catch {
            if ($attempt -eq 5) {
                Warn "could not remove ${binaryPath}: $($_.Exception.Message)"
            }
            else {
                Start-Sleep -Seconds 1
            }
        }
    }
}

# --- 5. remove the state directory (identity, secret, CA file) ---
if (-not (Test-Path $StateDir)) {
    Log "no state directory at $StateDir"
}
else {
    Log "removing $StateDir"
    $removed = $false
    for ($attempt = 1; $attempt -le 5 -and -not $removed; $attempt++) {
        try {
            Remove-Item $StateDir -Recurse -Force -ErrorAction Stop
            $removed = $true
        }
        catch {
            if ($attempt -eq 5) {
                Warn "could not remove ${StateDir}: $($_.Exception.Message)"
            }
            else {
                Start-Sleep -Seconds 1
            }
        }
    }
}

# --- 6. remove the install directory if it is empty ---
if (Test-Path $BinDir) {
    $leftover = @(Get-ChildItem $BinDir -Force -ErrorAction SilentlyContinue)
    if ($leftover.Count -eq 0) {
        Log "removing the empty install directory $BinDir"
        Remove-Item $BinDir -Force -ErrorAction SilentlyContinue
    }
    else {
        Log "keeping ${BinDir}: it still holds $($leftover.Count) file(s) that were not installed by Huginn"
    }
}

Log "done. The Huginn worker, its service, its state and the hub CA are gone from this machine."
Log "The node stays in the dashboard's fleet until you revoke it there (Fleet -> the node -> Revoke node)."
