# Functional test for scripts/uninstall.ps1.
#
# The uninstaller runs on the operator's own machine: a mistake in it (a
# directory left behind, a CA still trusted, a service still registered) is
# only discovered there, and never again. This test runs the real script
# against a throwaway installation and checks what it leaves behind.
#
# It is meant to run on a Windows runner, as Administrator (the script
# refuses otherwise, and so does the service removal).
#
#   pwsh -NoProfile -File scripts/tests/uninstall.test.ps1
#
# It touches nothing outside its own temporary directory and a certificate it
# adds to the machine's own Root store (removed again by the script under
# test).

$ErrorActionPreference = "Stop"

$Uninstaller = Join-Path (Split-Path $PSScriptRoot -Parent) "uninstall.ps1"
$ServiceName = "HuginnWorkerUninstallTest"

$failures = 0

function Assert-True([bool]$condition, [string]$what) {
    if ($condition) {
        Write-Host "ok   $what"
    } else {
        Write-Host "FAIL $what" -ForegroundColor Red
        $script:failures++
    }
}

# Runs a native command and returns its exit code, whatever it writes on
# stderr. Under $ErrorActionPreference = "Stop", the stderr of a native
# command becomes a terminating error — the exit code is what tells success
# from failure, so the preference is relaxed for the call.
function Invoke-Native([string]$name, [string[]]$arguments) {
    $previous = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        & $name @arguments | Out-Null
        return $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previous
    }
}

# A throwaway installation: a binary in its own directory, a state
# directory with the CA file the installer would have kept.
$root = Join-Path $env:TEMP ("huginn-uninstall-test-" + [Guid]::NewGuid().ToString("N"))
$binDir = Join-Path $root "bin"
$stateDir = Join-Path $root "state"
New-Item -ItemType Directory -Path $binDir -Force | Out-Null
New-Item -ItemType Directory -Path $stateDir -Force | Out-Null
$binaryPath = Join-Path $binDir "huginn-worker.exe"
Set-Content -Path $binaryPath -Value "not a real worker"
Set-Content -Path (Join-Path $stateDir "worker.json") -Value '{"worker_id":"test"}'

# A real self-signed certificate, so the trust store removal is exercised
# against the real API instead of a mock.
$rsa = [System.Security.Cryptography.RSA]::Create(2048)
$request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
    "CN=Huginn Uninstall Test", $rsa,
    [System.Security.Cryptography.HashAlgorithmName]::SHA256,
    [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
$cert = $request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddDays(-1), [DateTimeOffset]::UtcNow.AddDays(1))
$caFile = Join-Path $stateDir "hub-ca.crt"
$pem = [Convert]::ToBase64String($cert.Export("Cert"), [Base64FormattingOptions]::InsertLineBreaks)
Set-Content -Path $caFile -Value "-----BEGIN CERTIFICATE-----`n$pem`n-----END CERTIFICATE-----`n"

$store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
$store.Open("ReadWrite")
$store.Add($cert)
$store.Close()

# A service to delete, so the SCM path is exercised too. It is never
# started: only its registration matters here.
$createExit = Invoke-Native "sc.exe" @("create", $ServiceName, "binPath=", "$env:SystemRoot\System32\cmd.exe")
Assert-True ($createExit -eq 0) "the test service was created"

try {
    # --- the uninstaller runs ---
    # The script reports a failure by throwing (never by `exit`, which would
    # close the caller's session), so the check is "it did not throw".
    try {
        & $Uninstaller -ServiceName $ServiceName -BinDir $binDir -StateDir $stateDir
        Assert-True $true "the uninstaller ran without failing"
    }
    catch {
        Write-Host "FAIL the uninstaller threw: $($_.Exception.Message)" -ForegroundColor Red
        $script:failures++
    }

    # --- what it leaves behind ---
    Assert-True (-not (Test-Path $binaryPath)) "the worker binary is gone"
    Assert-True (-not (Test-Path $stateDir)) "the state directory is gone"
    Assert-True (-not (Test-Path $binDir)) "the empty install directory is gone"

    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    # The SCM keeps the entry until its last handle is closed, so the
    # assertion waits a moment instead of racing the deletion.
    $deadline = (Get-Date).AddSeconds(20)
    while ($null -ne $service -and (Get-Date) -lt $deadline) {
        Start-Sleep -Milliseconds 500
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    }
    Assert-True ($null -eq $service) "the service is no longer registered"

    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
    $store.Open("ReadOnly")
    $stillTrusted = @($store.Certificates | Where-Object { $_.Thumbprint -eq $cert.Thumbprint })
    $store.Close()
    Assert-True ($stillTrusted.Count -eq 0) "the hub CA is no longer trusted"

    # --- running it again changes nothing and still succeeds ---
    try {
        & $Uninstaller -ServiceName $ServiceName -BinDir $binDir -StateDir $stateDir
        Assert-True $true "the uninstaller is safe to re-run"
    }
    catch {
        Write-Host "FAIL the uninstaller threw on the second run: $($_.Exception.Message)" -ForegroundColor Red
        $script:failures++
    }
}
finally {
    # The cleanup must not depend on the test passing.
    Invoke-Native "sc.exe" @("delete", $ServiceName) | Out-Null
    Remove-Item $root -Recurse -Force -ErrorAction SilentlyContinue
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
    try {
        $store.Open("ReadWrite")
        $store.Remove($cert)
        $store.Close()
    }
    catch {
        # Already gone, or the store is locked: nothing to clean up.
    }
}

if ($failures -gt 0) {
    Write-Host "==> uninstaller test: $failures failure(s)" -ForegroundColor Red
    exit 1
}
Write-Host "==> uninstaller test: OK"
exit 0
