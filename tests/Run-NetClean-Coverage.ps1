param(
    [string]$RepoRoot = (Split-Path -Parent $PSScriptRoot)
)

$testPath = Join-Path $RepoRoot 'tests'
$config = New-PesterConfiguration
$config.Run.Path = $testPath
$config.Run.PassThru = $true
$config.Output.Verbosity = 'Detailed'
$config.CodeCoverage.Enabled = $true
$config.CodeCoverage.Path = @(
    (Join-Path $RepoRoot 'NetClean.ps1'),
    (Join-Path $RepoRoot 'NetClean.psm1')
)
$config.CodeCoverage.OutputFormat = 'JaCoCo'
$config.CodeCoverage.OutputPath = Join-Path $RepoRoot 'coverage.xml'

Invoke-Pester -Configuration $config
