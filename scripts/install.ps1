# Huginn worker installer for Windows.
#
#   irm https://<hub>/install.ps1 | iex   # or download and run manually
#   .\install.ps1 -HUB_URL "https://<hub>" -Token "<token>"
#
# Detects the architecture, downloads the matching worker binary FROM THE HUB,
# verifies its SHA-256, installs it as a Windows Service, and enrolls with the
# hub. The VM is PENDING until approved.
#
# If the hub uses a self-signed certificate, the installer fetches the hub's
# CA root (trust-on-first-use) and installs it into the Windows trust store.
#
# Parameters:
#   HUB_URL   (required) base URL of the hub, e.g. https://192.0.2.13
#   Token     (required) enrollment token from the dashboard
#   Name      (optional) friendly VM name (defaults to hostname)
#   BinDir    (optional) install directory (default C:\Program Files\Huginn)

param(
    [Parameter(Mandatory = $true)]
    [string]$HUB_URL,

    [Parameter(Mandatory = $true)]
    [string]$Token,

    [string]$Name = "",
    [string]$BinDir = "C:\Program Files\Huginn"
)

$ErrorActionPreference = "Stop"
$BinaryName = "huginn-worker.exe"
$StateDir = "C:\ProgramData\Huginn"

function Log([string]$msg) {
    Write-Host "==> $msg" -ForegroundColor Cyan
}

function Fail([string]$msg) {
    Write-Host "error: $msg" -ForegroundColor Red
    exit 1
}

# --- Must run as Administrator ---
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Fail "please run as Administrator (installs a Windows Service)"
}

# --- Detect architecture ---
$arch = switch ($env:PROCESSOR_ARCHITECTURE) {
    "AMD64" { "amd64" }
    "ARM64" { "arm64" }
    default { Fail "unsupported architecture: $($env:PROCESSOR_ARCHITECTURE)" }
}
Log "architecture: $arch"

# --- Validate HUB_URL ---
if (-not $HUB_URL) { Fail "HUB_URL is required" }
if (-not $Token) { Fail "Token is required" }
$HUB_URL = $HUB_URL.TrimEnd('/')

# --- TLS trust (trust-on-first-use for self-signed hubs) ---
function Ensure-HubTrust {
    # No-op for HTTP or an already-trusted cert
    if ($HUB_URL -match '^http://') { return }
    try {
        Invoke-WebRequest -Uri "$HUB_URL/healthz" -UseBasicParsing -TimeoutSec 10 | Out-Null
        return
    } catch { }

    Log "hub certificate not trusted; installing the hub CA (trust-on-first-use)"
    $caUrl = "$HUB_URL/caddy-root.crt"
    $caFile = [System.IO.Path]::GetTempFileName() + ".crt"

    try {
        # Bypass TLS validation for the CA fetch itself
        [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
        Invoke-WebRequest -Uri $caUrl -OutFile $caFile -UseBasicParsing -TimeoutSec 10
    } catch {
        Fail "could not fetch the hub CA from $caUrl"
    } finally {
        [Net.ServicePointManager]::ServerCertificateValidationCallback = $null
    }

    # Install into the Windows Root CA store
    $caContent = Get-Content $caFile -Raw
    if ($caContent -notmatch 'BEGIN CERTIFICATE') {
        Fail "fetched CA does not look like a certificate"
    }
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
    $store.Open("ReadWrite")
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($caFile)
    $store.Add($cert)
    $store.Close()
    Remove-Item $caFile -Force
    Log "hub CA installed into the Root trust store"

    # Re-check
    try {
        Invoke-WebRequest -Uri "$HUB_URL/healthz" -UseBasicParsing -TimeoutSec 10 | Out-Null
    } catch {
        Fail "hub still not trusted after installing its CA"
    }
}

Ensure-HubTrust

# --- Download the worker binary ---
$base = "$HUB_URL/dist"
$asset = "huginn-worker-windows-$arch.exe"
$checksumUrl = "$base/checksums.txt"

if (-not (Test-Path $BinDir)) {
    New-Item -ItemType Directory -Path $BinDir -Force | Out-Null
}
if (-not (Test-Path $StateDir)) {
    New-Item -ItemType Directory -Path $StateDir -Force | Out-Null
}

$binaryPath = Join-Path $BinDir $BinaryName

Log "downloading $asset from $base"
$binaryUrl = "$base/$asset"
Invoke-WebRequest -Uri $binaryUrl -OutFile "$binaryPath.new" -UseBasicParsing

# --- Verify checksum ---
Log "verifying checksum"
$checksumsContent = Invoke-WebRequest -Uri $checksumUrl -UseBasicParsing | Select-Object -ExpandProperty Content
$expectedHash = ($checksumsContent -split "`n" | Where-Object { $_ -match $asset } | ForEach-Object { ($_ -split '\s+')[0] })
if (-not $expectedHash) {
    Fail "no checksum entry for $asset"
}

$actualHash = (Get-FileHash -Path "$binaryPath.new" -Algorithm SHA256).Hash.ToLower()
if ($actualHash -ne $expectedHash.ToLower()) {
    Remove-Item "$binaryPath.new" -Force
    Fail "checksum mismatch: got $actualHash want $expectedHash"
}
Log "checksum OK"

# --- Install the binary ---
Move-Item "$binaryPath.new" $binaryPath -Force
Log "installed $binaryPath"

# --- Enroll with the hub ---
if (-not $Name) { $Name = $env:COMPUTERNAME }

Log "enrolling with $HUB_URL"
$env:HUB_URL = $HUB_URL
$env:TOKEN = $Token
$env:NAME = $Name
$env:HUGINN_ALLOW_INSECURE = if ($HUB_URL -match '^http://') { "1" } else { "" }

& $binaryPath enroll --state-dir $StateDir
if ($LASTEXITCODE -ne 0) {
    Fail "enrollment failed (exit code $LASTEXITCODE)"
}

# --- Install the Windows Service ---
Log "installing Windows Service 'HuginnWorker'"
& $binaryPath install-service --state-dir $StateDir $binaryPath
if ($LASTEXITCODE -ne 0) {
    Fail "service installation failed (exit code $LASTEXITCODE)"
}

Log "done. Approve this VM in the dashboard to activate it."
