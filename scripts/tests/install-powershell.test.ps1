# Unit tests for the PowerShell 7 machine-wide bootstrap in install.ps1.
$ErrorActionPreference = "Stop"

$installerPath = Join-Path (Split-Path $PSScriptRoot -Parent) "install.ps1"
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($installerPath, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors) { throw "install.ps1 did not parse: $($parseErrors[0].Message)" }

function Get-InstallerFunction([string]$Name) {
    $functionAst = $ast.Find({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $Name
    }, $true)
    if (-not $functionAst) { throw "Could not find installer function $Name" }
    $functionScript = [scriptblock]::Create($functionAst.Extent.Text)
    Set-Item -Path "Function:script:$Name" -Value $functionScript
}

Get-InstallerFunction "Log"
Get-InstallerFunction "Fail"
Get-InstallerFunction "Save-Download"
Get-InstallerFunction "Ensure-PowerShell7"

$script:PowerShellReleaseApi = "https://api.github.com/repos/PowerShell/PowerShell/releases/latest"
$script:DownloadTimeoutSec = 120
$script:StartProcessCalls = [System.Collections.Generic.List[object]]::new()
$script:SignatureStatus = "Valid"
$script:SignerSubject = "CN=Microsoft Corporation, O=Microsoft Corporation"
$script:InstallerExitCode = 0

function Invoke-RestMethod {
    param($Uri, $Headers, $TimeoutSec)
    [pscustomobject]@{
        tag_name = "v7.6.9"
        assets = @([pscustomobject]@{
            name = "PowerShell-7.6.9-win-x64.msi"
            browser_download_url = "https://github.com/PowerShell/PowerShell/releases/download/v7.6.9/PowerShell-7.6.9-win-x64.msi"
        })
    }
}

function Invoke-WebRequest {
    param($Uri, $OutFile, $UseBasicParsing, $TimeoutSec)
    [System.IO.File]::WriteAllText($OutFile, "test MSI")
}

function Get-AuthenticodeSignature {
    param($FilePath)
    [pscustomobject]@{
        Status = $script:SignatureStatus
        SignerCertificate = [pscustomobject]@{ Subject = $script:SignerSubject }
    }
}

function Start-Process {
    param($FilePath, $ArgumentList, $Wait, $PassThru)
    $script:StartProcessCalls.Add([pscustomobject]@{ FilePath = $FilePath; ArgumentList = $ArgumentList })
    [pscustomobject]@{ ExitCode = $script:InstallerExitCode }
}

function Assert($Condition, [string]$Message) {
    if (-not $Condition) { throw "ASSERTION FAILED: $Message" }
}

$testRoot = Join-Path $env:TEMP ("huginn-install-pwsh-test-" + [guid]::NewGuid().ToString("N"))
$installRoot = Join-Path $testRoot "Program Files"
$env:TEMP = $testRoot
New-Item -ItemType Directory -Path $testRoot -Force | Out-Null

try {
    # Existing machine install is reused without downloading or invoking MSI.
    $existingPwsh = Join-Path $installRoot "PowerShell\7\pwsh.exe"
    New-Item -ItemType Directory -Path (Split-Path $existingPwsh) -Force | Out-Null
    Set-Content -LiteralPath $existingPwsh -Value "present"
    $result = Ensure-PowerShell7 -InstallRoot $installRoot
    Assert ($result -eq $existingPwsh) "should return the existing standard machine install"
    Assert ($script:StartProcessCalls.Count -eq 0) "should not rerun MSI when PowerShell 7 exists"

    Remove-Item -LiteralPath $existingPwsh -Force
    $script:SignatureStatus = "NotSigned"
    $failed = $false
    try { Ensure-PowerShell7 -InstallRoot $installRoot | Out-Null }
    catch { $failed = $_.Exception.Message -like "*signature is not valid*" }
    Assert $failed "must reject an MSI without a valid Microsoft signature"
    Assert ($script:StartProcessCalls.Count -eq 0) "must not launch msiexec after signature failure"

    $script:SignatureStatus = "Valid"
    $script:SignerSubject = "CN=Untrusted Publisher"
    $failed = $false
    try { Ensure-PowerShell7 -InstallRoot $installRoot | Out-Null }
    catch { $failed = $_.Exception.Message -like "*signature is not valid*" }
    Assert $failed "must reject a valid signature from a non-Microsoft publisher"

    $script:SignerSubject = "CN=Microsoft Corporation, O=Microsoft Corporation"
    $script:InstallerExitCode = 1603
    $failed = $false
    try { Ensure-PowerShell7 -InstallRoot $installRoot | Out-Null }
    catch { $failed = $_.Exception.Message -like "*exit code 1603*" }
    Assert $failed "must fail when msiexec reports an installation error"

    $script:InstallerExitCode = 0
    $failed = $false
    try { Ensure-PowerShell7 -InstallRoot $installRoot | Out-Null }
    catch { $failed = $_.Exception.Message -like "*executable was not found*" }
    Assert $failed "must fail if MSI succeeds without the machine-wide pwsh executable"
    Assert ($script:StartProcessCalls.Count -eq 2) "valid Microsoft MSI should be passed to msiexec"
    Assert ($script:StartProcessCalls[0].ArgumentList -like "*ADD_PATH=1*") "MSI must add PowerShell to machine PATH"

    Write-Host "PASS: PowerShell 7 machine-wide bootstrap tests"
}
finally {
    Remove-Item -LiteralPath $testRoot -Recurse -Force -ErrorAction SilentlyContinue
}
