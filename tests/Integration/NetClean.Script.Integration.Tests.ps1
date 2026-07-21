Describe 'NetClean script integration tests' {

    BeforeAll {
        $repoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
        $manifestPath = Join-Path $repoRoot 'NetClean.psd1'
        $scriptPath = Join-Path $repoRoot 'NetClean.ps1'

        if (-not (Test-Path -LiteralPath $manifestPath)) {
            throw "NetClean.psd1 not found at path: $manifestPath"
        }

        if (-not (Test-Path -LiteralPath $scriptPath)) {
            throw "NetClean.ps1 not found at path: $scriptPath"
        }

        Remove-Module NetClean -ErrorAction SilentlyContinue
        Import-Module $manifestPath -Force
    }

    BeforeEach {
        Mock Import-Module {}
        $script:NetCleanTestMode = $true
        . $scriptPath
    }

    It 'dot-sources the launcher script without throwing' {
        { . $scriptPath } | Should -Not -Throw
    }

    It 'exposes the expected launcher functions after dot-sourcing' {
        Get-Command Invoke-NetCleanLauncher -ErrorAction Stop | Should -Not -BeNullOrEmpty
        Get-Command Read-NetCleanMenuSelection -ErrorAction Stop | Should -Not -BeNullOrEmpty
        Get-Command Read-YesNo -ErrorAction Stop | Should -Not -BeNullOrEmpty
        Get-Command Read-NetCleanOption -ErrorAction Stop | Should -Not -BeNullOrEmpty
    }

    It 'Read-NetCleanOption forces DryRun in Preview mode' {
        $result = Read-NetCleanOption -SelectedMode Preview

        $result.SelectedMode | Should -Be 'Preview'
        $result.DryRun | Should -BeTrue
    }

    It 'Read-NetCleanOption requires a PerformanceProfile for PerformanceTune mode' {
        { Read-NetCleanOption -SelectedMode PerformanceTune } | Should -Throw
    }

    It 'Read-NetCleanOption accepts a valid performance profile' {
        $result = Read-NetCleanOption -SelectedMode PerformanceTune -PerformanceProfile Optimal

        $result.SelectedMode | Should -Be 'PerformanceTune'
        $result.PerformanceProfile | Should -Be 'Optimal'
    }
}
