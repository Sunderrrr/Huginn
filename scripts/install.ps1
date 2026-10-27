# Huginn worker installer for Windows.
#
# Run the commands separately, from a PowerShell 7 console opened as
# administrator:
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
# The script detects the OS architecture, downloads the matching worker binary
# from the hub, verifies its SHA-256 against the hub's own manifest, installs
# it as a Windows Service, and enrolls with the hub.
#
# Re-running it is safe: when the node already has an identity
# (C:\ProgramData\Huginn\worker.json), the enrollment is NOT redone — the
# script only repairs the service. The identity is preserved.
#
# If the hub uses a private CA, the installer fetches the hub's CA root
# (trust-on-first-use) and installs it into the Windows trust store. That
# first fetch is done with the TLS validation DISABLED, so the certificate
# it returns is not proof of the hub's identity on its own. Pass
# -CaSha256 <fingerprint> to pin the root: the fetched certificate must then
# match the fingerprint you obtained through a trusted channel.
#
# Parameters:
#   HUB_URL   (required) base URL of the hub, e.g. https://172.16.2.5
#   Token     (required) enrollment token from the dashboard (only used when
#             the node has no identity yet)
#   Name      (optional) friendly VM name (defaults to the hostname)
#   BinDir    (optional) install directory (default C:\Program Files\Huginn)
#   CaSha256  (optional) expected SHA-256 of the hub's CA root, as published
#             by the hub. When given, the fetched CA must match it.

param(
    [Parameter(Mandatory = $true)]
    [string]$HUB_URL,

    [string]$Token = "",

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
$StateFile = Join-Path $StateDir "worker.json"
$DownloadTimeoutSec = 120
$PowerShellReleaseApi = "https://api.github.com/repos/PowerShell/PowerShell/releases/latest"

# The state directory holds the worker secret: only SYSTEM and the
# Administrators group may read it. The group is granted by SID, never by its
# English name (a localized Windows has no such name to resolve).
$AclGrants = @("/inheritance:r", "/grant:r", "SYSTEM:(OI)(CI)F", "/grant:r", "*S-1-5-32-544:(OI)(CI)F")
$ForbiddenPrincipals = @("BUILTIN\Users", "BUILTIN\Authenticated Users", "NT AUTHORITY\Everyone", "Everyone", "Users", "Authenticated Users")

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

# Install PowerShell 7 for the whole machine. The service runs as LocalSystem,
# so a per-user winget/App Execution Alias install is not sufficient. The MSI
# is obtained from the official PowerShell release and must have a valid
# Microsoft Authenticode signature before msiexec is allowed to run it.
function Ensure-PowerShell7 {
    param([string]$InstallRoot = $env:ProgramFiles)

    $pwsh = Join-Path $InstallRoot "PowerShell\7\pwsh.exe"
    if (Test-Path -LiteralPath $pwsh -PathType Leaf) {
        Log "PowerShell 7 is already installed machine-wide at $pwsh"
        return $pwsh
    }

    Log "PowerShell 7 is missing; downloading the official machine-wide MSI"
    try {
        $release = Invoke-RestMethod -Uri $PowerShellReleaseApi -Headers @{ "User-Agent" = "Huginn-Worker-Installer" } -TimeoutSec 30
    }
    catch {
        Fail "could not query the official PowerShell release: $($_.Exception.Message)"
    }

    $version = [string]$release.tag_name
    if ($version -notmatch '^v\d+\.\d+\.\d+$') {
        Fail "the official PowerShell release returned an invalid version tag: '$version'"
    }
    $assetName = "PowerShell-$($version.TrimStart('v'))-win-x64.msi"
    $asset = @($release.assets | Where-Object { $_.name -ceq $assetName } | Select-Object -First 1)
    if (-not $asset -or $asset.browser_download_url -notmatch '^https://github\.com/PowerShell/PowerShell/releases/download/') {
        Fail "the official PowerShell release does not contain the expected MSI asset '$assetName'"
    }

    $msi = Join-Path $env:TEMP $assetName
    $download = Save-Download -Uri $asset.browser_download_url -OutFile $msi -TimeoutSec $DownloadTimeoutSec
    try {
        $signature = Get-AuthenticodeSignature -FilePath $download
        if ($signature.Status -ne "Valid" -or $signature.SignerCertificate.Subject -notmatch '(^|,\s*)CN=Microsoft Corporation(,|$)') {
            Fail "PowerShell MSI signature is not valid and signed by Microsoft (status: $($signature.Status); signer: $($signature.SignerCertificate.Subject))"
        }
        Log "verified Microsoft signature for $assetName"

        $msiexec = Join-Path $env:SystemRoot "System32\msiexec.exe"
        $arguments = "/i `"$download`" /qn /norestart ADD_PATH=1"
        $process = Start-Process -FilePath $msiexec -ArgumentList $arguments -Wait -PassThru
        if ($process.ExitCode -notin @(0, 3010)) {
            Fail "PowerShell MSI installation failed (msiexec exit code $($process.ExitCode))"
        }
    }
    finally {
        Remove-Item -LiteralPath $download -Force -ErrorAction SilentlyContinue
    }

    if (-not (Test-Path -LiteralPath $pwsh -PathType Leaf)) {
        Fail "PowerShell 7 MSI completed but the machine-wide executable was not found at $pwsh"
    }
    $versionOutput = & $pwsh -NoProfile -NonInteractive -Command '$PSVersionTable.PSVersion.ToString()'
    if ($LASTEXITCODE -ne 0 -or [string]$versionOutput -notmatch '^7\.') {
        Fail "PowerShell executable validation failed at $pwsh (reported version: '$versionOutput')"
    }
    Log "PowerShell $versionOutput is installed machine-wide"
    return $pwsh
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

# Locks a path down to SYSTEM and Administrators, then reads the ACL back and
# refuses to continue if a forbidden principal can still read it. The state
# directory holds the worker secret, so a silent failure here would leave it
# readable by every local account.
function Protect-Path([string]$Path, [string]$What) {
    $icacls = Get-Command icacls -ErrorAction SilentlyContinue
    if (-not $icacls) {
        Fail "icacls is not available: cannot secure $What"
    }
    # The return code is checked: a warning (a localized name that does not
    # resolve, a missing privilege) must not pass as success.
    & icacls $Path @AclGrants | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Fail "icacls failed to lock down ${What} (exit code $LASTEXITCODE)"
    }
    $listing = & icacls $Path
    if ($LASTEXITCODE -ne 0) {
        Fail "icacls could not read the ACL of ${What} (exit code $LASTEXITCODE)"
    }
    foreach ($line in $listing) {
        $ace = $line.Trim()
        if (-not $ace -or $ace.StartsWith("Successfully processed")) { continue }
        $principal = ($ace -split '\s+')[0]
        foreach ($forbidden in $ForbiddenPrincipals) {
            if ($principal -ieq $forbidden) {
                Fail "${What} is still readable by $principal — the worker secret would be exposed"
            }
        }
    }
}

# --- Must run as Administrator ---
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Fail "please run as Administrator (it installs a Windows Service)"
}

# --- Detect the OS architecture, not the PowerShell process's ---
# A 32-bit PowerShell on a 64-bit Windows reports PROCESSOR_ARCHITECTURE=x86
# (WOW64), which would download the wrong worker.
$osArch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
switch ($osArch) {
    "X64" { $arch = "amd64" }
    "Arm64" { $arch = "arm64" }
    default { Fail "unsupported OS architecture: $osArch (this worker is published for windows/amd64 only)" }
}
Log "OS architecture: $osArch ($arch)"

# Only windows/amd64 is published (release.yml and build-artifacts.sh build
# x86_64-pc-windows-gnu only), so refuse anything else BEFORE downloading.
if ($arch -ne "amd64") {
    Fail "no windows/$arch worker is published: the release builds windows/amd64 only (x86_64-pc-windows-gnu). Use an amd64 node, or publish a windows/$arch build first."
}

# Do this before enrolling or installing the worker service. The official MSI
# installs under Program Files and adds PowerShell 7 to the machine PATH, making
# it available to LocalSystem and every user account.
$null = Ensure-PowerShell7

# --- Validate the parameters ---
if (-not $HUB_URL) { Fail "HUB_URL is required" }
$HUB_URL = $HUB_URL.TrimEnd('/')
if ($CaSha256 -and $CaSha256 -notmatch '^[0-9A-Fa-f]{64}$') {
    Fail "CaSha256 must be a SHA-256 fingerprint (64 hex characters)"
}

# --- Prepare the directories, and lock them down BEFORE anything secret lands in them ---
if (-not (Test-Path $BinDir)) {
    New-Item -ItemType Directory -Path $BinDir -Force | Out-Null
}
if (-not (Test-Path $StateDir)) {
    New-Item -ItemType Directory -Path $StateDir -Force | Out-Null
}
Protect-Path -Path $StateDir -What "the state directory $StateDir"

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
    if (-not $CaSha256) {
        Log "WARNING: this CA is fetched over a connection whose certificate was NOT verified."
        Log "         It is therefore not proof of the hub's identity: a man-in-the-middle could"
        Log "         substitute its own root. Pass -CaSha256 <fingerprint> (obtained over a"
        Log "         trusted channel) to pin the hub's real CA."
    }
    $caUrl = "$HUB_URL/caddy-root.crt"

    try {
        # The validation is bypassed for this one request: the CA is the thing
        # we are trying to establish trust in. It is checked against
        # -CaSha256 when the caller pinned it.
        Invoke-WebRequestAllowUntrustedCertificate -RequestParameters @{
            Uri             = $caUrl
            OutFile         = $HubCaFile
            UseBasicParsing = $true
            TimeoutSec      = 10
        }
    }
    catch {
        Remove-Item $HubCaFile -Force -ErrorAction SilentlyContinue
        Fail "could not fetch the hub CA from ${caUrl}: $($_.Exception.Message)"
    }

    try {
        $caContent = Get-Content $HubCaFile -Raw
        if ($caContent -notmatch 'BEGIN CERTIFICATE') {
            Fail "the fetched CA does not look like a PEM certificate"
        }

        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($HubCaFile)
        if ($CaSha256) {
            $actual = ([System.Security.Cryptography.SHA256]::Create().ComputeHash($cert.RawData) |
                ForEach-Object { $_.ToString("x2") }) -join ""
            if ($actual -ne $CaSha256.ToLowerInvariant()) {
                Fail "the hub CA fingerprint does not match the expected one (got $actual)"
            }
            Log "hub CA fingerprint matches the pinned value"
        }
        else {
            Log "hub CA accepted on trust (no fingerprint pinned)"
        }

        # Same lock-down as the state directory: the CA file is read by the
        # service (LocalSystem), by SYSTEM and the administrators only.
        Protect-Path -Path $HubCaFile -What "the hub CA file $HubCaFile"

        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
        try {
            $store.Open("ReadWrite")
            $store.Add($cert)
        }
        finally {
            $store.Close()
        }
        Log "hub CA installed into the LocalMachine Root trust store"
        Log "hub CA kept at $HubCaFile (the worker is given that path)"
    }
    catch {
        Remove-Item $HubCaFile -Force -ErrorAction SilentlyContinue
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

# --- Identity: reuse it when the node already has one ---
$existing = $null
if (Test-Path $StateFile) {
    try {
        $existing = Get-Content $StateFile -Raw | ConvertFrom-Json
    }
    catch {
        Fail ("$StateFile exists but could not be read ($($_.Exception.Message)). " +
              "Move it aside to enroll a new identity, or repair the service with " +
              "'huginn-worker.exe install-service --state-dir $StateDir $binaryPath'.")
    }
    if (-not $existing.worker_id -or -not $existing.worker_secret) {
        Fail ("$StateFile exists but has no worker identity. Move it aside to enroll " +
              "a new identity, or repair the service with 'huginn-worker.exe " +
              "install-service --state-dir $StateDir $binaryPath'.")
    }
}

if ($existing) {
    # The node is already enrolled: do NOT enroll again (that would create a
    # second worker, or fail on an already-consumed token).
    Log "reusing the existing identity $($existing.worker_id) — no enrollment"
    Log "if the hub has revoked or removed that worker, this identity is dead:"
    Log "move $StateFile aside and run the installer again with a fresh token"
}
else {
    if (-not $Token) {
        Fail ("this node has no identity yet: an enrollment token is required " +
              "(HUB_URL and Token), and the enrollment writes " +
              "$StateFile")
    }
    if (-not $Name) { $Name = $env:COMPUTERNAME }

    Log "enrolling with $HUB_URL"
    $env:HUB_URL = $HUB_URL
    $env:TOKEN = $Token
    $env:NAME = $Name
    $env:HUGINN_ALLOW_INSECURE = if ($HUB_URL -match '^http://') { "1" } else { "" }
    # The worker keeps this path in its state, so the service (LocalSystem)
    # trusts the same CA after the installation.
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
        # The token must not linger in the environment of this session. The CA
        # path stays: the service needs it.
        Remove-Item Env:TOKEN -ErrorAction SilentlyContinue
    }
}

# --- Install (or repair) the Windows Service ---
# The service is never *started* here: it is created and configured, and the
# operator starts it (or the SCM does, at boot).
Log "installing (or repairing) the Windows Service 'HuginnWorker'"
& $binaryPath install-service --state-dir $StateDir $binaryPath
if ($LASTEXITCODE -ne 0) {
    Fail "service installation failed (exit code $LASTEXITCODE)"
}

# A service that was already running still holds the OLD identity in memory:
# after a re-enrollment it would keep polling with it and the hub would
# refuse every request (the tasks then stay pending forever). Restart it if
# it was running.
$service = Get-Service -Name "HuginnWorker" -ErrorAction SilentlyContinue
if ($service -and $service.Status -eq "Running") {
    Log "restarting the running service so it picks up the current identity"
    Restart-Service -Name "HuginnWorker" -ErrorAction SilentlyContinue
}

Log "done. Start the service with 'Start-Service HuginnWorker' and approve the VM in the dashboard."
