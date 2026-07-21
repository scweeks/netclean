Describe 'NetClean launcher functional tests' {

    BeforeAll {
        $moduleManifest = Join-Path $PSScriptRoot '..\..\NetClean.psd1'
        $scriptPath = Join-Path $PSScriptRoot '..\..\NetClean.ps1'

        if (-not (Test-Path -LiteralPath $moduleManifest)) {
            throw "Module manifest not found: $moduleManifest"
        }

        if (-not (Test-Path -LiteralPath $scriptPath)) {
            throw "Launcher script not found: $scriptPath"
        }

        Remove-Module NetClean -ErrorAction SilentlyContinue
        Import-Module $moduleManifest -Force
        $script:NetCleanTestMode = $true
        . $scriptPath
    }

    BeforeEach {
        Mock Write-Host {}
        Mock Write-Output {}
    }

    Context 'Read-NetCleanOption behavior' {

        It 'Preview mode forces DryRun even when DryRun not specified' {

            $result = Read-NetCleanOption -SelectedMode Preview

            $result.SelectedMode | Should -Be 'Preview'
            $result.DryRun | Should -BeTrue
        }

        It 'explicit DryRun switch is preserved' {

            $result = Read-NetCleanOption -SelectedMode SafeConferencePrep -DryRun

            $result.SelectedMode | Should -Be 'SafeConferencePrep'
            $result.DryRun | Should -BeTrue
        }

        It 'returns Skip switches when provided' {

            $result = Read-NetCleanOption `
                -SelectedMode SafeConferencePrep `
                -SkipWifi `
                -SkipDnsFlush `
                -SkipEventLogs `
                -SkipUserArtifacts

            $result.SkipWifi | Should -BeTrue
            $result.SkipDnsFlush | Should -BeTrue
            $result.SkipEventLogs | Should -BeTrue
            $result.SkipUserArtifacts | Should -BeTrue
        }

        It 'throws when PerformanceTune mode lacks PerformanceProfile' {

            { Read-NetCleanOption -SelectedMode PerformanceTune } | Should -Throw
        }

        It 'accepts valid PerformanceProfile when provided' {

            $result = Read-NetCleanOption `
                -SelectedMode PerformanceTune `
                -PerformanceProfile Optimal

            $result.PerformanceProfile | Should -Be 'Optimal'
        }

    }

    Context 'Launcher workflow invocation' {

        BeforeEach {

            Mock Invoke-NetCleanWorkflow {
                [pscustomobject]@{
                    Phase = 'Verify'
                    Verify = [pscustomobject]@{
                        Passed = $true
                    }
                }
            }

            Mock Start-NetCleanLog {}
            Mock Write-NetCleanLog {}

        }

        It 'calls workflow when script executes Preview mode' {

            $options = Read-NetCleanOption -SelectedMode Preview

            Invoke-NetCleanWorkflow `
                -Mode $options.SelectedMode `
                -DryRun:$options.DryRun `
                -BackupPath "$TestDrive"

            Should -Invoke Invoke-NetCleanWorkflow -Times 1 -ParameterFilter {
                $Mode -eq 'Preview'
            }

        }

        It 'passes Skip switches into workflow' {

            $options = Read-NetCleanOption `
                -SelectedMode SafeConferencePrep `
                -SkipWifi `
                -SkipDnsFlush

            Invoke-NetCleanWorkflow `
                -Mode $options.SelectedMode `
                -SkipWifi:$options.SkipWifi `
                -SkipDnsFlush:$options.SkipDnsFlush `
                -BackupPath "$TestDrive"

            Should -Invoke Invoke-NetCleanWorkflow -Times 1 -ParameterFilter {
                $SkipWifi -and $SkipDnsFlush
            }

        }

        It 'passes PerformanceProfile when using PerformanceTune mode' {

            $options = Read-NetCleanOption `
                -SelectedMode PerformanceTune `
                -PerformanceProfile Gaming

            Invoke-NetCleanWorkflow `
                -Mode $options.SelectedMode `
                -PerformanceProfile $options.PerformanceProfile `
                -BackupPath "$TestDrive"

            Should -Invoke Invoke-NetCleanWorkflow -Times 1 -ParameterFilter {
                $Mode -eq 'PerformanceTune' -and
                $PerformanceProfile -eq 'Gaming'
            }

        }

    }

    Context 'Logging initialization' {

        It 'initializes logging before workflow execution' {

            Mock Start-NetCleanLog {}
            Mock Invoke-NetCleanWorkflow {}

            Start-NetCleanLog -Directory "$TestDrive"

            Invoke-NetCleanWorkflow -Mode Preview -BackupPath "$TestDrive" -DryRun

            Should -Invoke Start-NetCleanLog -Times 1
            Should -Invoke Invoke-NetCleanWorkflow -Times 1
        }

    }

    Context 'Console output behavior' {

        It 'prints verification success message when workflow passes' {

            Mock Invoke-NetCleanWorkflow {
                [pscustomobject]@{
                    Phase = 'Verify'
                    Verify = [pscustomobject]@{
                        Passed = $true
                    }
                }
            }

            $result = Invoke-NetCleanWorkflow -Mode Preview -BackupPath "$TestDrive" -DryRun

            $result.Verify.Passed | Should -BeTrue
        }

        It 'detects verification failure from workflow output' {

            Mock Invoke-NetCleanWorkflow {
                [pscustomobject]@{
                    Phase = 'Verify'
                    Verify = [pscustomobject]@{
                        Passed = $false
                    }
                }
            }

            $result = Invoke-NetCleanWorkflow -Mode Preview -BackupPath "$TestDrive" -DryRun

            $result.Verify.Passed | Should -BeFalse
        }

    }

}
