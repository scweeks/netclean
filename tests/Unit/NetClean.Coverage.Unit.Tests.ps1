Describe 'NetClean coverage runner' {
    BeforeAll {
        $script:runnerPath = Join-Path $PSScriptRoot '..\Run-NetClean-Coverage.ps1'
        $script:runnerText = Get-Content -LiteralPath $script:runnerPath -Raw
        $ciPath = Join-Path $PSScriptRoot '..\..\.github\workflows\ci.yml'
        $script:ciText = Get-Content -LiteralPath $ciPath -Raw
    }

    It 'rejects test files as coverage sources' {
        {
            & $script:runnerPath `
                -CoveragePath $PSCommandPath `
                -OutputPath $TestDrive
        } | Should -Throw '*must not include files under tests*'
    }

    It 'pins the selected stable Pester version' {
        $script:runnerText | Should -Match "\[version\]'6\.0\.1'"
    }

    It 'treats discovery and container failures as fatal' {
        $script:runnerText | Should -Match '\$config\.Run\.Throw\s*=\s*\$true'
    }

    It 'includes isolated system-component tests in the coverage run' {
        $script:runnerText | Should -Match 'Join-Path\s+\$testsPath\s+''System'''
    }

    It 'ratchets the runner and pull-request overall coverage gates together' {
        $script:runnerText | Should -Match '\[double\]\$MinimumCoverage\s*=\s*94\.0'
        $script:runnerText | Should -Match '\$config\.CodeCoverage\.CoveragePercentTarget\s*=\s*\$MinimumCoverage'
        $script:ciText | Should -Match 'Run-NetClean-Coverage\.ps1\s+-MinimumCoverage\s+94'
        $script:ciText | Should -Match 'min-coverage-overall:\s+94'
    }

    It 'pins workflow actions to immutable Node.js 24 releases' {
        $script:ciText | Should -Match 'actions/checkout@8e8c483db84b4bee98b60c0593521ed34d9990e8\s+# v6\.0\.1'
        $script:ciText | Should -Match 'actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a\s+# v7\.0\.1'
        $script:ciText | Should -Match 'actions/download-artifact@70fc10c6e5e1ce46ad2ea6f2b72d43f7d47b13c3\s+# v8\.0\.0'
        $script:ciText | Should -Match 'madrapps/jacoco-report@e51ce1f46f7f8b5331593f935e59cbaf44b84920\s+# v1\.8\.0'
    }

    It 'runs the complete suite under Windows PowerShell 5.1 in CI' {
        $jobPattern = '(?ms)^  windows-powershell-compatibility:.*?^  comment-coverage:'
        $jobMatch = [regex]::Match($script:ciText, $jobPattern)
        $jobMatch.Success | Should -BeTrue
        $compatibilityJob = $jobMatch.Value

        $compatibilityJob | Should -Match 'shell:\s+powershell'
        $compatibilityJob | Should -Match 'Install-Module Pester[^\r\n]+RequiredVersion 6\.0\.1'
        $compatibilityJob | Should -Match 'Invoke-Pester'
        $compatibilityJob | Should -Match 'Test-ModuleManifest'
    }
}
