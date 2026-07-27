Describe 'NetClean coverage runner' {
    BeforeAll {
        $script:runnerPath = Join-Path $PSScriptRoot '..\Run-NetClean-Coverage.ps1'
        $script:runnerText = Get-Content -LiteralPath $script:runnerPath -Raw
        $ciPath = Join-Path $PSScriptRoot '..\..\.github\workflows\ci.yml'
        $script:ciText = Get-Content -LiteralPath $ciPath -Raw
        $readmePath = Join-Path $PSScriptRoot '..\..\README.md'
        $script:readmeText = Get-Content -LiteralPath $readmePath -Raw
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

    It 'includes the security test suite in the coverage run' {
        $script:runnerText | Should -Match 'Join-Path\s+\$testsPath\s+''Security'''
    }

    It 'ratchets the runner and pull-request overall coverage gates together' {
        $script:runnerText | Should -Match '\[double\]\$MinimumCoverage\s*=\s*94\.0'
        $script:runnerText | Should -Match '\$config\.CodeCoverage\.CoveragePercentTarget\s*=\s*\$MinimumCoverage'
        $script:ciText | Should -Match 'Run-NetClean-Coverage\.ps1\s+-MinimumCoverage\s+\$env:COVERAGE_GATE'
        $script:ciText | Should -Match 'min-coverage-overall:\s+94'
    }

    It 'computes the coverage badge percentage from the report-level aggregate counter' {
        # A bare "//counter" XPath match's every nested per-package/per-sourcefile/
        # per-class/per-method LINE counter too, not just the overall total - taking
        # the first match in document order silently reports whichever function
        # happens to appear first in the report (observed live: 46.43% instead of
        # the real ~96%). The counter must be selected as a direct child of the
        # root <report> element.
        $script:ciText | Should -Match '\$doc\.SelectSingleNode\(''/report/counter\[@type="LINE"\]''\)'
        $script:ciText | Should -Not -Match '\$doc\.SelectNodes\(''//counter''\)'
    }

    It 'pins workflow actions and Pages deployment steps' {
        $script:ciText | Should -Match 'actions/checkout@8e8c483db84b4bee98b60c0593521ed34d9990e8\s+# v6\.0\.1'
        $script:ciText | Should -Match 'actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a\s+# v7\.0\.1'
        $script:ciText | Should -Match 'actions/download-artifact@70fc10c6e5e1ce46ad2ea6f2b72d43f7d47b13c3\s+# v8\.0\.0'
        $script:ciText | Should -Match 'madrapps/jacoco-report@e51ce1f46f7f8b5331593f935e59cbaf44b84920\s+# v1\.8\.0'
        $script:ciText | Should -Match 'actions/upload-pages-artifact@v3'
        $script:ciText | Should -Match 'actions/deploy-pages@v4'
    }

    It 'exposes the supported badge set in the README' {
        $script:readmeText | Should -Match 'img\.shields\.io/endpoint\?url=https://scweeks\.github\.io/netclean/coverage\.json'
        $script:readmeText | Should -Match 'img\.shields\.io/badge/style-PSScriptAnalyzer-00aaff'
        $script:readmeText | Should -Match 'img\.shields\.io/badge/license-GPLv3-blue\.svg'
        $script:readmeText | Should -Match 'img\.shields\.io/badge/PowerShell-7\.4%2B-blue'
        $script:readmeText | Should -Match 'img\.shields\.io/badge/platform-Windows-blue'
        $script:readmeText | Should -Match 'img\.shields\.io/badge/coverage_target-94%25-green'
    }

    It 'does not run a Windows PowerShell 5.1 compatibility job in CI' {
        $script:ciText | Should -Not -Match 'windows-powershell-compatibility:'
        $script:ciText | Should -Not -Match '(?m)^\s*shell:\s+powershell\s*$'
    }

    It 'requires PowerShell 7.4 or later in the module manifest' {
        $manifestPath = Join-Path $PSScriptRoot '..\..\NetClean.psd1'
        $manifestText = Get-Content -LiteralPath $manifestPath -Raw
        $manifestText | Should -Match "PowerShellVersion\s*=\s*'7\.4'"
        $manifestText | Should -Match "CompatiblePSEditions\s*=\s*@\('Core'\)"
    }
}
