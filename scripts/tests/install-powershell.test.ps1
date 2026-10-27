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
    if ($functionAst.Body.ParamBlock) {
        $functionScript = $functionAst.Body.GetScriptBlock()
    }
    else {
        $parameters = @($functionAst.Parameters | ForEach-Object { $_.Extent.Text })
        $parameterBlock = "param($($parameters -join ', '))"
        $body = $functionAst.Body.Extent.Text
        $bodyContent = $body.Substring(1, $body.Length - 2)
        $functionScript = [scriptblock]::Create("$parameterBlock`n$bodyContent")
    }
    Set-Item -Path "Function:script:$Name" -Value $functionScript
}

Get-InstallerFunction "Log"
Get-InstallerFunction "Fail"
Get-InstallerFunction "Save-Download"
Get-InstallerFunction "Ensure-PowerShell7"

$global:PowerShellReleaseApi = "https://api.github.com/repos/PowerShell/PowerShell/releases/latest"
$global:DownloadTimeoutSec = 120
$global:StartProcessCalls = [System.Collections.Generic.List[object]]::new()
$global:SignatureStatus = "Valid"
$global:SignerSubject = "CN=Microsoft Corporation, O=Microsoft Corporation"
$global:InstallerExitCode = 0

 $global:ReleaseLookup = {
    param($Uri)
    return [pscustomobject]@{
        tag_name = "v7.6.9"
        assets = @([pscustomobject]@{
            name = "PowerShell-7.6.9-win-x64.msi"
            browser_download_url = "https://github.com/PowerShell/PowerShell/releases/download/v7.6.9/PowerShell-7.6.9-win-x64.msi"
        })
    }
}

 $global:DownloadFile = {
    param($Uri, $OutFile, $TimeoutSec)
    $download = "$OutFile.part"
    [System.IO.File]::WriteAllText($download, "test MSI")
    return $download
}

 $global:SignatureReader = {
    param($FilePath)
    return [pscustomobject]@{
        Status = $global:SignatureStatus
        SignerCertificate = [pscustomobject]@{ Subject = $global:SignerSubject }
    }
}

 $global:MsiInstaller = {
    param($FilePath, $ArgumentList)
    $global:StartProcessCalls.Add([pscustomobject]@{ FilePath = $FilePath; ArgumentList = $ArgumentList })
    return [pscustomobject]@{ ExitCode = $global:InstallerExitCode }
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
    Assert ($global:StartProcessCalls.Count -eq 0) "should not rerun MSI when PowerShell 7 exists"

    Remove-Item -LiteralPath $existingPwsh -Force
    $global:SignatureStatus = "NotSigned"
    $failure = $null
    try { Ensure-PowerShell7 -InstallRoot $installRoot -ReleaseLookup $global:ReleaseLookup -DownloadFile $global:DownloadFile -SignatureReader $global:SignatureReader -MsiInstaller $global:MsiInstaller | Out-Null }
    catch { $failure = $_.Exception.Message }
    Assert ([bool]$failure) "must reject an MSI without a valid Microsoft signature ($failure)"
    Assert ($global:StartProcessCalls.Count -eq 0) "must not launch msiexec after signature failure"

    $global:SignatureStatus = "Valid"
    $global:SignerSubject = "CN=Untrusted Publisher"
    $failure = $null
    try { Ensure-PowerShell7 -InstallRoot $installRoot -ReleaseLookup $global:ReleaseLookup -DownloadFile $global:DownloadFile -SignatureReader $global:SignatureReader -MsiInstaller $global:MsiInstaller | Out-Null }
    catch { $failure = $_.Exception.Message }
    Assert ([bool]$failure) "must reject a valid signature from a non-Microsoft publisher ($failure)"

    $global:SignerSubject = "CN=Microsoft Corporation, O=Microsoft Corporation"
    $global:InstallerExitCode = 1603
    $failure = $null
    try { Ensure-PowerShell7 -InstallRoot $installRoot -ReleaseLookup $global:ReleaseLookup -DownloadFile $global:DownloadFile -SignatureReader $global:SignatureReader -MsiInstaller $global:MsiInstaller | Out-Null }
    catch { $failure = $_.Exception.Message }
    Assert ([bool]$failure) "must fail when msiexec reports an installation error ($failure)"

    $global:InstallerExitCode = 0
    $failure = $null
    try { Ensure-PowerShell7 -InstallRoot $installRoot -ReleaseLookup $global:ReleaseLookup -DownloadFile $global:DownloadFile -SignatureReader $global:SignatureReader -MsiInstaller $global:MsiInstaller | Out-Null }
    catch { $failure = $_.Exception.Message }
    Assert ([bool]$failure) "must fail if MSI succeeds without the machine-wide pwsh executable ($failure)"
    Assert ($global:StartProcessCalls.Count -eq 2) "valid Microsoft MSI should be passed to msiexec (calls: $($global:StartProcessCalls.Count))"
    Assert ($global:StartProcessCalls[0].ArgumentList -like "*ADD_PATH=1*") "MSI must add PowerShell to machine PATH"

    Write-Host "PASS: PowerShell 7 machine-wide bootstrap tests"
}
finally {
    Remove-Item -LiteralPath $testRoot -Recurse -Force -ErrorAction SilentlyContinue
}
