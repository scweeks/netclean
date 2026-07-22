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
        $script:runnerText | Should -Match '\[double\]\$MinimumCoverage\s*=\s*69\.0'
        $script:ciText | Should -Match 'Run-NetClean-Coverage\.ps1\s+-MinimumCoverage\s+69'
        $script:ciText | Should -Match 'min-coverage-overall:\s+69'
    }
}
