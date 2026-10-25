# Huginn worker installer for Windows.
#
# Run the commands separately, from an elevated "Run as administrator"
# PowerShell 7 console:
#
#   pwsh -NoProfile
#   $PSVersionTable.PSVersion        # expect 7.6.8
#   $installer = "$env:TEMP\huginn-install.ps1"
#   Invoke-WebRequest -Uri "https://<hub>/install.ps1" -OutFile $installer
#   pwsh -NoProfile -ExecutionPolicy Bypass -File $installer -HUB_URL "https://<hub>" -Token "<token>"
#
# Do NOT use "irm ... | iex" here: Invoke-Expression cannot bind HUB_URL and
# Token to this script's param() block, and a failure inside the piped script
# would terminate the caller's shell. Run it as a file, as above.
#
# The script detects the architecture, downloads the matching worker binary
# from the hub, verifies its SHA-256 against the hub's own manifest, installs
# it as a Windows Service, and enrolls with the hub. The VM stays PENDING
# until an admin approves it.
#
# If the hub uses a private CA, the installer fetches the hub's CA root
# (trust-on-first-use) and installs it into the Windows trust store. Pass
# -CaSha256 <fingerprint> to pin that root instead of trusting it blindly.
#
# Parameters:
#   HUB_URL   (required) base URL of the hub, e.g. https://172.16.2.5
#   Token     (required) enrollment token from the dashboard
#   Name      (optional) friendly VM name (defaults to the hostname)
#   BinDir    (optional) install directory (default C:\Program Files\Huginn)
#   CaSha256  (optional) expected SHA-256 of the hub's CA root, as published
#             by the hub. When given, the fetched CA must match it.

param(
    [Parameter(Mandatory = $true)]
    [string]$HUB_URL,

    [Parameter(Mandatory = $true)]
    [string]$Token,

    [string]$Name = "",
    [string]$BinDir = "C:\Program Files\Huginn",
    [string]$CaSha256 = ""
)

$ErrorActionPreference = "Stop"
$BinaryName = "huginn-worker.exe"
$StateDir = "C:\ProgramData\Huginn"
# The hub's CA root is kept there (not in a temporary file): the worker runs as
# a service and needs it after the installation. The enrollment passes the
# path, the worker stores it in its state, and the service inherits it.
$HubCaFile = Join-Path $StateDir "hub-ca.crt"
$DownloadTimeoutSec = 120

function Log([string]$msg) {
    Write-Host "==> $msg" -ForegroundColor Cyan
}

# Fail throws instead of calling exit: a script run with `exit` would close an
# interactive PowerShell session, and the caller could not read the error or
# try a fallback. The message is prefixed so it stands out in a transcript.
function Fail([string]$msg) {
    throw "huginn-install: $msg"
}

function Invoke-WebRequestAllowUntrustedCertificate {
    # PowerShell 6+ web cmdlets go through HttpClient, and
    # ServicePointManager.ServerCertificateValidationCallback does not affect
    # them: the supported per-request switch is -SkipCertificateCheck. The
    # callback is kept for Windows PowerShell 5.1, which still uses
    # ServicePointManager.
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$RequestParameters
    )

    if ($PSVersionTable.PSVersion.Major -ge 6) {
        $RequestParameters["SkipCertificateCheck"] = $true
        return Invoke-WebRequest @RequestParameters
    }

    $previousCallback = [Net.ServicePointManager]::ServerCertificateValidationCallback
    try {
        [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
        return Invoke-WebRequest @RequestParameters
    }
    finally {
        [Net.ServicePointManager]::ServerCertificateValidationCallback = $previousCallback
    }
}

# Downloads to a sibling .part file and returns its path. The caller removes
# it on any failure, so a truncated download is never mistaken for a complete
# one and never replaces a working binary. The timeout is a parameter (not a
# script-level variable) so the function stands on its own.
function Save-Download([string]$Uri, [string]$OutFile, [int]$TimeoutSec = 120) {
    $part = "$OutFile.part"
    try {
        if (Test-Path $part) { Remove-Item $part -Force -ErrorAction SilentlyContinue }
        Invoke-WebRequest -Uri $Uri -OutFile $part -UseBasicParsing -TimeoutSec $TimeoutSec
        if (-not (Test-Path $part)) {
            Fail "the download produced no file: $Uri"
        }
        $length = (Get-Item $part).Length
        if ($length -le 0) {
            Fail "the downloaded file is empty: $Uri"
        }
        return $part
    }
    catch {
        if (Test-Path $part) { Remove-Item $part -Force -ErrorAction SilentlyContinue }
        throw
    }
}

# Parses a `sha256sum`-style manifest. The line endings may be CRLF or LF,
# the separator may be spaces or a tab, and the asset name must match
# exactly (no globbing, no prefix match).
function Get-ManifestHash([string]$Content, [string]$Asset) {
    foreach ($line in ($Content -split "`r?`n")) {
        $trimmed = $line.Trim()
        if (-not $trimmed) { continue }

        $parts = $trimmed -split '\s+', 2
        if ($parts.Count -ne 2) { continue }

        $hash = $parts[0]
        $name = $parts[1].TrimStart('*').Trim()
        if ($name -cne $Asset) { continue }

        if ($hash -notmatch '^[0-9A-Fa-f]{64}$') {
            Fail "the manifest entry for $Asset is not a SHA-256: '$hash'"
        }
        return $hash.ToLowerInvariant()
    }
    return $null
}

# --- Must run as Administrator ---
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Fail "please run as Administrator (it installs a Windows Service)"
}

# --- Detect architecture ---
$arch = switch ($env:PROCESSOR_ARCHITECTURE) {
    "AMD64" { "amd64" }
    "ARM64" { "arm64" }
    default { Fail "unsupported architecture: $($env:PROCESSOR_ARCHITECTURE)" }
}
Log "architecture: $arch"

# --- Validate the parameters ---
if (-not $HUB_URL) { Fail "HUB_URL is required" }
if (-not $Token) { Fail "Token is required" }
$HUB_URL = $HUB_URL.TrimEnd('/')
if ($CaSha256 -and $CaSha256 -notmatch '^[0-9A-Fa-f]{64}$') {
    Fail "CaSha256 must be a SHA-256 fingerprint (64 hex characters)"
}

# --- TLS trust (trust-on-first-use for a hub behind a private CA) ---
function Ensure-HubTrust {
    if ($HUB_URL -match '^http://') { return }

    try {
        Invoke-WebRequest -Uri "$HUB_URL/healthz" -UseBasicParsing -TimeoutSec 10 | Out-Null
        return
    }
    catch {
        $healthCheckError = $_.Exception.Message
    }

    Log "the hub certificate is not trusted ($healthCheckError); fetching its CA root"
    $caUrl = "$HUB_URL/caddy-root.crt"
    $caFile = $HubCaFile

    try {
        # The validation is bypassed for this one request: the CA is the thing
        # we are trying to establish trust in. It is checked against
        # -CaSha256 when the caller pinned it.
        Invoke-WebRequestAllowUntrustedCertificate -RequestParameters @{
            Uri             = $caUrl
            OutFile         = $caFile
            UseBasicParsing = $true
            TimeoutSec      = 10
        }
    }
    catch {
        Remove-Item $caFile -Force -ErrorAction SilentlyContinue
        Fail "could not fetch the hub CA from ${caUrl}: $($_.Exception.Message)"
    }

    try {
        $caContent = Get-Content $caFile -Raw
        if ($caContent -notmatch 'BEGIN CERTIFICATE') {
            Fail "the fetched CA does not look like a PEM certificate"
        }

        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($caFile)
        if ($CaSha256) {
            $actual = ([System.Security.Cryptography.SHA256]::Create().ComputeHash($cert.RawData) |
                ForEach-Object { $_.ToString("x2") }) -join ""
            if ($actual -ne $CaSha256.ToLowerInvariant()) {
                Fail "the hub CA fingerprint does not match the expected one (got $actual)"
            }
            Log "hub CA fingerprint matches the pinned value"
        }

        # Same lock-down as the worker applies to its state directory: SYSTEM
        # and Administrators only.
        & icacls $caFile /inheritance:r /grant:r "SYSTEM:(R)" /grant:r "Administrators:(R)" | Out-Null

        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
        try {
            $store.Open("ReadWrite")
            $store.Add($cert)
        }
        finally {
            $store.Close()
        }
        Log "hub CA installed into the LocalMachine Root trust store"
        Log "hub CA kept at $caFile (the worker is given that path)"
    }
    catch {
        Remove-Item $caFile -Force -ErrorAction SilentlyContinue
        throw
    }

    # The hub must now answer with a normal certificate validation.
    try {
        Invoke-WebRequest -Uri "$HUB_URL/healthz" -UseBasicParsing -TimeoutSec 10 | Out-Null
    }
    catch {
        Fail "the hub is still not trusted after installing its CA: $($_.Exception.Message)"
    }
}

# --- Prepare the directories (the CA lands in the state dir) ---
if (-not (Test-Path $BinDir)) {
    New-Item -ItemType Directory -Path $BinDir -Force | Out-Null
}
if (-not (Test-Path $StateDir)) {
    New-Item -ItemType Directory -Path $StateDir -Force | Out-Null
}

Ensure-HubTrust

$base = "$HUB_URL/dist"
$asset = "huginn-worker-windows-$arch.exe"
$binaryUrl = "$base/$asset"
$checksumUrl = "$base/checksums.txt"
$binaryPath = Join-Path $BinDir $BinaryName

# --- Fetch the manifest first: it tells us what the hub actually publishes ---
Log "fetching the manifest from $checksumUrl"
try {
    $checksumsContent = (Invoke-WebRequest -Uri $checksumUrl -UseBasicParsing -TimeoutSec 30).Content
}
catch {
    Fail "could not fetch $checksumUrl : $($_.Exception.Message)"
}

$expectedHash = Get-ManifestHash -Content $checksumsContent -Asset $asset
if (-not $expectedHash) {
    $published = @()
    foreach ($line in ($checksumsContent -split "`r?`n")) {
        $parts = $line.Trim() -split '\s+', 2
        if ($parts.Count -eq 2) { $published += $parts[1].TrimStart('*') }
    }
    Fail ("no checksum entry for $asset in $checksumUrl. The hub publishes: " +
          (($published -join ", ")))
}

# --- Download the binary ---
Log "downloading $asset from $base"
$newPath = Save-Download -Uri $binaryUrl -OutFile "$binaryPath.new" -TimeoutSec $DownloadTimeoutSec

try {
    # --- Verify the checksum before the file goes anywhere near the install ---
    Log "verifying the SHA-256"
    $actualHash = (Get-FileHash -Path $newPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualHash -ne $expectedHash) {
        Fail "checksum mismatch for ${asset}: got $actualHash, the manifest says $expectedHash"
    }
    Log "checksum OK ($actualHash)"
}
catch {
    Remove-Item $newPath -Force -ErrorAction SilentlyContinue
    throw
}

# --- Replace the binary atomically, keeping the old one until the new one is in place ---
$backupPath = "$binaryPath.old"
if (Test-Path $backupPath) { Remove-Item $backupPath -Force -ErrorAction SilentlyContinue }
if (Test-Path $binaryPath) { Move-Item $binaryPath $backupPath -Force }
try {
    Move-Item $newPath $binaryPath -Force
}
catch {
    if (Test-Path $backupPath) { Move-Item $backupPath $binaryPath -Force }
    throw
}
Remove-Item $backupPath -Force -ErrorAction SilentlyContinue
Log "installed $binaryPath"

# --- Enroll with the hub ---
if (-not $Name) { $Name = $env:COMPUTERNAME }

Log "enrolling with $HUB_URL"
$env:HUB_URL = $HUB_URL
$env:TOKEN = $Token
$env:NAME = $Name
$env:HUGINN_ALLOW_INSECURE = if ($HUB_URL -match '^http://') { "1" } else { "" }
# The worker keeps this path in its state, so the service (LocalSystem) trusts
# the same CA after the installation.
if (Test-Path $HubCaFile) {
    $env:HUGINN_CA_CERT = $HubCaFile
}

try {
    & $binaryPath enroll --state-dir $StateDir
    if ($LASTEXITCODE -ne 0) {
        Fail "enrollment failed (exit code $LASTEXITCODE)"
    }
}
finally {
    # The token must not linger in the environment of this session. The CA path
    # stays: the service needs it.
    Remove-Item Env:TOKEN -ErrorAction SilentlyContinue
}

# --- Install the Windows Service ---
Log "installing the Windows Service 'HuginnWorker'"
& $binaryPath install-service --state-dir $StateDir $binaryPath
if ($LASTEXITCODE -ne 0) {
    Fail "service installation failed (exit code $LASTEXITCODE)"
}

Log "done. Approve this VM in the dashboard to activate it."
