[CmdletBinding()]
param(
    [string]$RepoRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$OutputPath = (Join-Path $PSScriptRoot 'TestResults'),
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

$coverageFiles = @(
    (Join-Path $RepoRoot 'NetClean.ps1'),
    (Join-Path $RepoRoot 'Modules\NetClean.psm1'),
    (Join-Path $RepoRoot 'Modules\NetCleanPhase1.ps1'),
    (Join-Path $RepoRoot 'Modules\NetCleanPhase2.ps1'),
    (Join-Path $RepoRoot 'Modules\NetCleanPhase3.ps1'),
    (Join-Path $RepoRoot 'Modules\NetCleanPhase4.ps1')
) | Where-Object { Test-Path -LiteralPath $_ }

$testFiles = @(
    Get-ChildItem -Path (Join-Path $testsPath 'Unit') -Filter '*.Tests.ps1' -File -ErrorAction SilentlyContinue
    Get-ChildItem -Path (Join-Path $testsPath 'Functional') -Filter '*.Tests.ps1' -File -ErrorAction SilentlyContinue
    Get-ChildItem -Path (Join-Path $testsPath 'Integration') -Filter '*.Tests.ps1' -File -ErrorAction SilentlyContinue
) | Sort-Object FullName

if (-not $testFiles -or $testFiles.Count -eq 0) {
    throw "No test files found under tests\Unit, tests\Functional, or tests\Integration."
}

$coverageXml = Join-Path $OutputPath 'coverage.xml'
$testXml     = Join-Path $OutputPath 'pester-results.xml'

$config = New-PesterConfiguration

$config.Run.Path = $testFiles.FullName
$config.Run.PassThru = $true
$config.Run.Exit = $false

$config.Output.Verbosity = 'Detailed'

$config.TestResult.Enabled = $true
$config.TestResult.OutputFormat = 'JUnitXml'
$config.TestResult.OutputPath = $testXml

$config.CodeCoverage.Enabled = $true
$config.CodeCoverage.Path = $coverageFiles
$config.CodeCoverage.OutputFormat = 'JaCoCo'
$config.CodeCoverage.OutputPath = $coverageXml

Write-Information '' -InformationAction Continue
Write-Information 'Running Pester with coverage...' -ForegroundColor Cyan -InformationAction Continue
Write-Information "RepoRoot:    $RepoRoot" -InformationAction Continue
Write-Information "Tests:       $($testFiles.Count)" -InformationAction Continue
Write-Information "Coverage on: $($coverageFiles.Count) files" -InformationAction Continue
Write-Information ''

$result = Invoke-Pester -Configuration $config

Write-Information '' -InformationAction Continue
Write-Information 'Pester summary' -ForegroundColor Cyan -InformationAction Continue
Write-Information "Passed: $($result.PassedCount)" -InformationAction Continue
Write-Information "Failed: $($result.FailedCount)" -InformationAction Continue
Write-Information "Skipped: $($result.SkippedCount)" -InformationAction Continue
Write-Information '' -InformationAction Continue

if ($null -ne $result.CodeCoverage) {
    Write-Information 'Coverage summary' -ForegroundColor Cyan -InformationAction Continue
    Write-Information ("Commands analyzed: {0}" -f $result.CodeCoverage.NumberOfCommandsAnalyzed) -InformationAction Continue
    Write-Information ("Commands executed: {0}" -f $result.CodeCoverage.NumberOfCommandsExecuted) -InformationAction Continue
    Write-Information ("Percent covered:   {0:N2}%" -f $result.CodeCoverage.CoveragePercent) -InformationAction Continue
    Write-Information '' -InformationAction Continue
}

Write-Information "JUnit XML:  $testXml" -InformationAction Continue
Write-Information "JaCoCo XML: $coverageXml" -InformationAction Continue
Write-Information '' -InformationAction Continue

if ($PassThru) {
    return $result
}

if ($result.FailedCount -gt 0) {
    exit 1
}