Describe 'NetClean coverage runner' {
    BeforeAll {
        $script:runnerPath = Join-Path $PSScriptRoot '..\Run-NetClean-Coverage.ps1'
        $script:runnerText = Get-Content -LiteralPath $script:runnerPath -Raw
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
}
