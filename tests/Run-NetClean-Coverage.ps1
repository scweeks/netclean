[CmdletBinding()]
param(
    [string]$RepoRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$OutputPath = (Join-Path $PSScriptRoot 'TestResults'),
    [version]$PesterVersion = [version]'6.0.1',
    [string[]]$CoveragePath,
    [ValidateRange(0, 100)]
    [double]$MinimumCoverage = 90.0,
    [switch]$PassThru
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$manifestPath = Join-Path $RepoRoot 'NetClean.psd1'
$scriptPath   = Join-Path $RepoRoot 'NetClean.ps1'
$testsPath    = Join-Path $RepoRoot 'tests'

if (-not (Test-Path -LiteralPath $manifestPath)) {
    throw "NetClean.psd1 not found at path: $manifestPath"
}

if (-not (Test-Path -LiteralPath $scriptPath)) {
    throw "NetClean.ps1 not found at path: $scriptPath"
}

if (-not (Test-Path -LiteralPath $testsPath)) {
    throw "tests folder not found at path: $testsPath"
}

if (-not (Test-Path -LiteralPath $OutputPath)) {
    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
}

if ($PSBoundParameters.ContainsKey('CoveragePath')) {
    $coverageFiles = @(
        $CoveragePath |
            ForEach-Object {
                if ([System.IO.Path]::IsPathRooted($_)) {
                    $_
                }
                else {
                    Join-Path $RepoRoot $_
                }
            } |
            Where-Object { Test-Path -LiteralPath $_ -PathType Leaf }
    )
}
else {
    $coverageFiles = @(
        (Join-Path $RepoRoot 'NetClean.ps1'),
        (Join-Path $RepoRoot 'Modules\NetClean.psm1'),
        (Join-Path $RepoRoot 'Modules\NetCleanPhase1.ps1'),
        (Join-Path $RepoRoot 'Modules\NetCleanPhase2.ps1'),
        (Join-Path $RepoRoot 'Modules\NetCleanPhase3.ps1'),
        (Join-Path $RepoRoot 'Modules\NetCleanPhase4.ps1')
    ) | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf }
}

$testsRoot = [System.IO.Path]::GetFullPath($testsPath).TrimEnd('\', '/') + '\'
$testCoverageFiles = @(
    $coverageFiles |
        Where-Object {
            [System.IO.Path]::GetFullPath($_).StartsWith(
                $testsRoot,
                [System.StringComparison]::OrdinalIgnoreCase
            )
        }
)
if ($testCoverageFiles.Count -gt 0) {
    throw 'CoveragePath must not include files under tests.'
}

$pesterModule = Get-Module -ListAvailable Pester |
    Where-Object Version -EQ $PesterVersion |
    Sort-Object Version -Descending |
    Select-Object -First 1
if ($null -eq $pesterModule) {
    throw "Run-NetClean-Coverage.ps1 requires Pester $PesterVersion."
}
Import-Module $pesterModule.Path -Force -ErrorAction Stop

$testFiles = @(
    Get-ChildItem -Path (Join-Path $testsPath 'Unit') -Filter '*.Tests.ps1' -File -ErrorAction SilentlyContinue
    Get-ChildItem -Path (Join-Path $testsPath 'Functional') -Filter '*.Tests.ps1' -File -ErrorAction SilentlyContinue
    Get-ChildItem -Path (Join-Path $testsPath 'Integration') -Filter '*.Tests.ps1' -File -ErrorAction SilentlyContinue
    Get-ChildItem -Path (Join-Path $testsPath 'System') -Filter '*.Tests.ps1' -File -ErrorAction SilentlyContinue
) | Sort-Object FullName

if (-not $testFiles -or $testFiles.Count -eq 0) {
    throw "No test files found under tests\Unit, tests\Functional, tests\Integration, or tests\System."
}

$coverageXml = Join-Path $OutputPath 'coverage.xml'
$testXml     = Join-Path $OutputPath 'pester-results.xml'

$config = New-PesterConfiguration

$config.Run.Path = $testFiles.FullName
$config.Run.PassThru = $true
$config.Run.Exit = $false
$config.Run.Throw = $true

$config.Output.Verbosity = 'Normal'

$config.TestResult.Enabled = $true
$config.TestResult.OutputFormat = 'JUnitXml'
$config.TestResult.OutputPath = $testXml

$config.CodeCoverage.Enabled = $true
$config.CodeCoverage.Path = $coverageFiles
$config.CodeCoverage.ExcludeTests = $true
$config.CodeCoverage.CoveragePercentTarget = $MinimumCoverage
$config.CodeCoverage.OutputFormat = 'JaCoCo'
$config.CodeCoverage.OutputPath = $coverageXml

Write-Information '' -InformationAction Continue
Write-Information 'Running Pester with coverage...' -InformationAction Continue
Write-Information "RepoRoot:    $RepoRoot" -InformationAction Continue
Write-Information "Tests:       $($testFiles.Count)" -InformationAction Continue
Write-Information "Coverage on: $($coverageFiles.Count) files" -InformationAction Continue
Write-Information ''

$result = Invoke-Pester -Configuration $config

Write-Information '' -InformationAction Continue
Write-Information 'Pester summary' -InformationAction Continue
Write-Information "Passed: $($result.PassedCount)" -InformationAction Continue
Write-Information "Failed: $($result.FailedCount)" -InformationAction Continue
Write-Information "Skipped: $($result.SkippedCount)" -InformationAction Continue
Write-Information '' -InformationAction Continue

if ($null -ne $result.CodeCoverage) {
    $analyzedCount = if ($result.CodeCoverage.PSObject.Properties.Name -contains 'CommandsAnalyzedCount') {
        $result.CodeCoverage.CommandsAnalyzedCount
    }
    else {
        $result.CodeCoverage.NumberOfCommandsAnalyzed
    }
    $executedCount = if ($result.CodeCoverage.PSObject.Properties.Name -contains 'CommandsExecutedCount') {
        $result.CodeCoverage.CommandsExecutedCount
    }
    else {
        $result.CodeCoverage.NumberOfCommandsExecuted
    }

    Write-Information 'Coverage summary' -InformationAction Continue
    Write-Information ("Commands analyzed: {0}" -f $analyzedCount) -InformationAction Continue
    Write-Information ("Commands executed: {0}" -f $executedCount) -InformationAction Continue
    Write-Information ("Percent covered:   {0:N2}%" -f $result.CodeCoverage.CoveragePercent) -InformationAction Continue
    Write-Information '' -InformationAction Continue
}

Write-Information "JUnit XML:  $testXml" -InformationAction Continue
Write-Information "JaCoCo XML: $coverageXml" -InformationAction Continue
Write-Information '' -InformationAction Continue

if ($PassThru) {
    Write-Output $result
}

if ($result.FailedCount -gt 0) {
    Write-Error ("Pester reported {0} failed test(s)." -f $result.FailedCount)
    exit 1
}

if ($null -eq $result.CodeCoverage -or $result.CodeCoverage.CoveragePercent -lt $MinimumCoverage) {
    Write-Error "Coverage below required threshold ($MinimumCoverage%)."
    exit 1
}
