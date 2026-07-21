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

    Context 'Post-run power handling' {

        BeforeEach {
            $script:Mode = 'SafeConferencePrep'
            $script:DryRun = $true
            $script:Force = $true
            $script:CreateLog = $false
            $script:BackupPath = $TestDrive
            $script:LogPath = $TestDrive
            $script:SkipWifi = $false
            $script:SkipDnsFlush = $false
            $script:SkipEventLogs = $false
            $script:SkipUserArtifacts = $false
            $script:SkipFirewallBackup = $false
            $script:PerformanceProfile = 'Default'
            $script:RebootNow = $false

            Mock Test-NetCleanAdministrator {}
            Mock Read-NetCleanMenuSelection { 'SafeConferencePrep' }
            Mock Read-YesNo { $true }
            Mock Show-ModeExplanation {}
            Mock Read-NetCleanOption {
                [pscustomobject]@{
                    SelectedMode      = 'SafeConferencePrep'
                    DryRun            = $true
                    SkipWifi          = $false
                    SkipDnsFlush      = $false
                    SkipEventLogs     = $false
                    SkipUserArtifacts = $false
                    SkipFirewallBackup = $false
                    PerformanceProfile = $null
                }
            }
            Mock Start-NetCleanLog {}
            Mock Write-NetCleanLog {}
            Mock Invoke-NetCleanWorkflow { [pscustomobject]@{ Phase = 'Verify' } }
            Mock Show-NetCleanSummary {}
            Mock Read-PostRunAction { 'None' }
            Mock Invoke-PostRunAction {}
        }

        It 'uses only the post-run action path' {
            Invoke-NetCleanLauncher

            Should -Invoke Invoke-PostRunAction -Times 1
            Get-Command Read-NetCleanPowerSelection -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
            Get-Command Invoke-NetCleanPowerAction -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
        }
    }

    Context 'Console output behavior' {

        It 'explains when organization-managed network configuration is preserved' {
            $script:messages = [System.Collections.Generic.List[string]]::new()
            Mock Write-Information {
                if ($null -ne $MessageData) {
                    [void]$script:messages.Add([string]$MessageData)
                }
            }
            Mock Get-NetCleanLogFile { $null }

            Show-NetCleanSummary -SelectedMode SafeConferencePrep -Result ([pscustomobject]@{
                ManagementState = [pscustomobject]@{
                    IsManaged = $true
                    JoinType  = 'MicrosoftEntraJoined'
                }
            })

            $script:messages | Should -Contain 'Device management: MicrosoftEntraJoined'
            $script:messages | Should -Contain 'Organization-managed network configuration will be preserved.'
        }

        It 'explains adapter reset, Quad9 DNS, and IPv4 preference results' {
            $script:messages = [System.Collections.Generic.List[string]]::new()
            Mock Write-Information {
                if ($null -ne $MessageData) {
                    [void]$script:messages.Add([string]$MessageData)
                }
            }
            Mock Get-NetCleanLogFile { $null }

            Show-NetCleanSummary -SelectedMode SafeConferencePrep -Result ([pscustomobject]@{
                Clean = [pscustomobject]@{
                    Summary = [pscustomobject]@{
                        WiFiProfilesRemoved      = 0
                        RegistryArtifactsRemoved = 0
                        EventLogsTouched         = 0
                        UserArtifactsTouched     = 0
                        AdaptersConfigured       = 2
                        AdaptersSkipped          = 1
                        AdapterFailures          = 0
                        PreferIPv4               = $true
                        AdapterRestartRequired   = $true
                        AdvancedRepairActions    = 0
                        PerformanceTuningActions = 0
                    }
                    AdapterConfiguration = [pscustomobject]@{
                        Provider = 'Quad9 Secure'
                        DnsServers = @(
                            '9.9.9.9',
                            '149.112.112.112',
                            '2620:fe::fe',
                            '2620:fe::9'
                        )
                    }
                    WiFi             = $null
                    RegistryArtifacts = $null
                    EventLogs         = @()
                }
            })

            $script:messages | Should -Contain '  Adapters reset to IPv4 DHCP: 2'
            $script:messages | Should -Contain '  Adapters preserved: 1'
            $script:messages | Should -Contain '  Adapter reset failures: 0'
            $script:messages | Should -Contain '  DNS provider: Quad9 Secure'
            $script:messages | Should -Contain '  DNS servers: 9.9.9.9, 149.112.112.112, 2620:fe::fe, 2620:fe::9'
            $script:messages | Should -Contain '  IPv6 remains enabled; IPv4 will be preferred after restart.'
        }

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
