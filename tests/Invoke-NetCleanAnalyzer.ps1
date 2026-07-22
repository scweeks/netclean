[CmdletBinding()]
param(
    [version]$AnalyzerVersion = [version]'1.25.0'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-NetCleanNullReferenceException {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [System.Exception]$Exception
    )

    $currentException = $Exception
    while ($null -ne $currentException) {
        if ($currentException -is [System.NullReferenceException]) {
            return $true
        }

        $currentException = $currentException.InnerException
    }

    return $false
}

function Invoke-NetCleanTargetAnalysis {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TargetPath,

        [Parameter(Mandatory = $true)]
        [string]$SettingsPath
    )

    $maximumAttemptCount = 2
    for ($attemptNumber = 1; $attemptNumber -le $maximumAttemptCount; $attemptNumber++) {
        try {
            return @(
                Invoke-ScriptAnalyzer `
                    -Path $TargetPath `
                    -Settings $SettingsPath `
                    -ErrorAction Stop
            )
        }
        catch {
            $isRetryable = Test-NetCleanNullReferenceException -Exception $_.Exception
            if (-not $isRetryable -or $attemptNumber -ge $maximumAttemptCount) {
                throw
            }

            Write-Warning ("PSScriptAnalyzer returned a transient NullReferenceException for '{0}'. Retrying once." -f $TargetPath)
        }
    }
}

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$settingsPath = Join-Path $repositoryRoot 'PSScriptAnalyzerSettings.psd1'

if (-not (Test-Path -LiteralPath $settingsPath -PathType Leaf)) {
    throw "PSScriptAnalyzer settings file not found: $settingsPath"
}

$analyzerModule = Get-Module -ListAvailable PSScriptAnalyzer |
    Where-Object Version -EQ $AnalyzerVersion |
    Sort-Object Version -Descending |
    Select-Object -First 1

if ($null -eq $analyzerModule) {
    throw "PSScriptAnalyzer $AnalyzerVersion is required. Install that version from the PowerShell Gallery."
}

Import-Module $analyzerModule.Path -Force -ErrorAction Stop

$targetFiles = @(
    Get-Item -LiteralPath (Join-Path $repositoryRoot 'NetClean.ps1')
    Get-Item -LiteralPath (Join-Path $repositoryRoot 'NetClean.psd1')
    Get-ChildItem -LiteralPath @(
        (Join-Path $repositoryRoot 'Modules'),
        (Join-Path $repositoryRoot 'examples'),
        (Join-Path $repositoryRoot 'tests')
    ) -Recurse -File |
        Where-Object Extension -In @('.ps1', '.psm1', '.psd1')
) | Sort-Object FullName -Unique

$findings = [System.Collections.Generic.List[object]]::new()

foreach ($targetFile in $targetFiles) {
    try {
        foreach ($finding in @(Invoke-NetCleanTargetAnalysis -TargetPath $targetFile.FullName -SettingsPath $settingsPath)) {
            $findings.Add($finding)
        }
    }
    catch {
        throw "PSScriptAnalyzer failed for '$($targetFile.FullName)' [$($_.Exception.GetType().FullName)]: $($_.Exception.Message)"
    }
}

if ($findings.Count -gt 0) {
    $findings |
        Sort-Object Severity, ScriptName, Line |
        Format-Table Severity, RuleName, ScriptName, Line, Message -AutoSize |
        Out-String |
        Write-Information -InformationAction Continue

    throw "PSScriptAnalyzer reported $($findings.Count) rule violation(s)."
}

[pscustomobject]@{
    AnalyzerVersion = $analyzerModule.Version.ToString()
    TargetCount     = $targetFiles.Count
    FindingCount    = 0
}
