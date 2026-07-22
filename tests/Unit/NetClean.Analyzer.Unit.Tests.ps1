Describe 'NetClean analyzer runner' {
    BeforeAll {
        $script:analyzerRunner = Join-Path $PSScriptRoot '..\Invoke-NetCleanAnalyzer.ps1'
        Import-Module PSScriptAnalyzer -RequiredVersion 1.25.0 -Force
    }

    BeforeEach {
        [System.AppDomain]::CurrentDomain.SetData('NetCleanAnalyzer.Unit.CallCount', 0)
        Mock Import-Module {}
        Mock Write-Warning {}
    }

    It 'retries one transient analyzer null-reference and completes cleanly' {
        Mock Invoke-ScriptAnalyzer {
            $callCount = [int][System.AppDomain]::CurrentDomain.GetData('NetCleanAnalyzer.Unit.CallCount') + 1
            [System.AppDomain]::CurrentDomain.SetData('NetCleanAnalyzer.Unit.CallCount', $callCount)
            if ($callCount -eq 1) {
                throw [System.NullReferenceException]::new('transient analyzer failure')
            }

            @()
        }

        $result = & $script:analyzerRunner

        $result.FindingCount | Should -Be 0
        [System.AppDomain]::CurrentDomain.GetData('NetCleanAnalyzer.Unit.CallCount') |
            Should -Be ($result.TargetCount + 1)
        Should -Invoke Write-Warning -Times 1 -Exactly
    }

    It 'fails after one retry when the analyzer null-reference repeats' {
        Mock Invoke-ScriptAnalyzer {
            $callCount = [int][System.AppDomain]::CurrentDomain.GetData('NetCleanAnalyzer.Unit.CallCount') + 1
            [System.AppDomain]::CurrentDomain.SetData('NetCleanAnalyzer.Unit.CallCount', $callCount)
            throw [System.NullReferenceException]::new('persistent analyzer failure')
        }

        { & $script:analyzerRunner } | Should -Throw '*persistent analyzer failure*'

        [System.AppDomain]::CurrentDomain.GetData('NetCleanAnalyzer.Unit.CallCount') | Should -Be 2
    }

    It 'does not retry analyzer exceptions that are not null-reference failures' {
        Mock Invoke-ScriptAnalyzer {
            $callCount = [int][System.AppDomain]::CurrentDomain.GetData('NetCleanAnalyzer.Unit.CallCount') + 1
            [System.AppDomain]::CurrentDomain.SetData('NetCleanAnalyzer.Unit.CallCount', $callCount)
            throw [System.InvalidOperationException]::new('ordinary analyzer failure')
        }

        { & $script:analyzerRunner } | Should -Throw '*ordinary analyzer failure*'

        [System.AppDomain]::CurrentDomain.GetData('NetCleanAnalyzer.Unit.CallCount') | Should -Be 1
        Should -Invoke Write-Warning -Times 0 -Exactly
    }
}
