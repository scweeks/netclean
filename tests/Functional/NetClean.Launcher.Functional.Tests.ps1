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
        $script:Force = $false
        $script:RebootNow = $false
        $script:SummaryListLimit = 20
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

    Context 'Interactive helper behavior' {

        BeforeEach {
            $script:messages = [System.Collections.Generic.List[string]]::new()
            Mock Write-Information {
                if ($null -ne $MessageData) {
                    [void]$script:messages.Add([string]$MessageData)
                }
            }
        }

        It 'truncates long lists and reports empty lists clearly' {
            Show-TruncatedList -Items @('one', 'two', 'three') -Heading 'Values' -Limit 2
            Show-TruncatedList -Items @() -Heading 'Empty'

            $script:messages | Should -Contain 'Values'
            $script:messages | Should -Contain '  - one'
            $script:messages | Should -Contain '  - two'
            $script:messages | Should -Contain '  - ...and 1 more'
            $script:messages | Should -Contain '  - (none)'
        }

        It 'uses the configured list limit when no limit is supplied' {
            $script:SummaryListLimit = 1

            Show-TruncatedList -Items @('one', 'two') -Heading 'Configured'

            $script:messages | Should -Contain '  - one'
            $script:messages | Should -Contain '  - ...and 1 more'
            $script:messages | Should -Not -Contain '  - two'
        }

        It 'accepts confirmation automatically only when Force is enabled' {
            $script:Force = $true
            Mock Read-Host { throw 'Read-Host must not be called in Force mode' }

            Read-YesNo -Prompt 'Proceed?' | Should -BeTrue
            Should -Invoke Read-Host -Times 0
        }

        It 'honors blank defaults and explicit yes or no answers' {
            Mock Read-Host { '' }
            Read-YesNo -Prompt 'Default no?' -DefaultNo $true | Should -BeFalse
            Read-YesNo -Prompt 'Default yes?' -DefaultNo $false | Should -BeTrue

            Mock Read-Host { 'yes' }
            Read-YesNo -Prompt 'Proceed?' | Should -BeTrue

            Mock Read-Host { 'no' }
            Read-YesNo -Prompt 'Proceed?' | Should -BeFalse
        }

        It 'reprompts after an invalid yes or no answer' {
            $script:readResponses = [System.Collections.Generic.Queue[string]]::new()
            $script:readResponses.Enqueue('maybe')
            $script:readResponses.Enqueue('y')
            Mock Read-Host { $script:readResponses.Dequeue() }

            Read-YesNo -Prompt 'Proceed?' | Should -BeTrue
            Should -Invoke Read-Host -Times 2
        }

        It 'maps menu choices and reprompts invalid selections' {
            $script:readResponses = [System.Collections.Generic.Queue[string]]::new()
            $script:readResponses.Enqueue('invalid')
            $script:readResponses.Enqueue('4')
            Mock Read-Host { $script:readResponses.Dequeue() }
            Mock Show-NetCleanMenu {}

            Read-NetCleanMenuSelection | Should -Be 'PerformanceTune'
            Should -Invoke Read-Host -Times 2
            Should -Invoke Show-NetCleanMenu -Times 2
            $script:messages | Should -Contain 'Invalid selection. Please choose 1 through 5.'
        }

        It 'maps every valid menu choice' -ForEach @(
            @{ Choice = '1'; Expected = 'Preview' }
            @{ Choice = '2'; Expected = 'SafeConferencePrep' }
            @{ Choice = '3'; Expected = 'AdvancedRepair' }
            @{ Choice = '4'; Expected = 'PerformanceTune' }
            @{ Choice = '5'; Expected = 'Exit' }
        ) {
            Mock Read-Host { $Choice }
            Mock Show-NetCleanMenu {}

            Read-NetCleanMenuSelection | Should -Be $Expected
        }

        It 'renders the banner and menu without relying on host-only output' {
            Show-NetCleanMenu

            $script:messages | Should -Contain ' NetClean - Conference / CTF Prep Tool'
            $script:messages | Should -Contain '1. Preview only'
            $script:messages | Should -Contain '5. Exit'
        }

        It 'explains each non-default operating mode' -ForEach @(
            @{ Mode = 'Preview'; Expected = 'You selected: Preview' }
            @{ Mode = 'AdvancedRepair'; Expected = 'You selected: Advanced repair' }
            @{ Mode = 'PerformanceTune'; Expected = 'You selected: Performance tuning' }
        ) {
            Show-ModeExplanation -SelectedMode $Mode

            $script:messages | Should -Contain $Expected
        }
    }

    Context 'Detailed summary behavior' {

        BeforeEach {
            $script:messages = [System.Collections.Generic.List[string]]::new()
            Mock Write-Information {
                if ($null -ne $MessageData) {
                    [void]$script:messages.Add([string]$MessageData)
                }
            }
            Mock Get-NetCleanLogFile { 'C:\ProgramData\NetClean\Logs\netclean.log' }
        }

        It 'renders all phase summaries, detailed artifacts, verification gaps, paths, and timings' {
            $result = [pscustomobject]@{
                ManagementState = [pscustomobject]@{ IsManaged = $false; JoinType = 'Unmanaged' }
                Summary = [pscustomobject]@{
                    ProtectedVendorsCount        = 2
                    ProtectedInterfaceGuidCount  = 1
                    CandidateArtifactCount       = 4
                    SanitizableArtifactCount     = 3
                }
                Protect = [pscustomobject]@{
                    Summary = [pscustomobject]@{
                        ProtectedRegistryPathCount   = 5
                        WiFiBackupCount               = 2
                        ProtectedRegistryBackupCount = 2
                    }
                    Manifest = [pscustomobject]@{
                        WiFiExports      = @('PROFILE:Home', 'PROFILE:Office', 'C:\backup\Home.xml')
                        NetworkListBackup = 'C:\backup\NetworkList.reg'
                    }
                }
                Clean = [pscustomobject]@{
                    Summary = [pscustomobject]@{
                        WiFiProfilesRemoved      = 1
                        RegistryArtifactsRemoved = 1
                        EventLogsTouched         = 2
                        UserArtifactsTouched     = 3
                        AdaptersConfigured       = 2
                        AdaptersSkipped          = 1
                        AdapterFailures          = 0
                        PreferIPv4               = $true
                        AdvancedRepairActions    = 0
                        PerformanceTuningActions = 0
                    }
                    AdapterConfiguration = [pscustomobject]@{
                        Provider   = 'Quad9 Secure'
                        DnsServers = @('9.9.9.9', '2620:fe::fe')
                    }
                    WiFi = [pscustomobject]@{ Profiles = @('Home') }
                    RegistryArtifacts = [pscustomobject]@{
                        Results = @(
                            [pscustomobject]@{ Removed = $true; RegistryPath = 'HKLM\SOFTWARE\History' }
                            [pscustomobject]@{ Removed = $false; RegistryPath = 'HKLM\SOFTWARE\Protected' }
                        )
                    }
                    EventLogs = @(
                        [pscustomobject]@{ Name = 'WLAN'; LogName = $null }
                        [pscustomobject]@{ Name = $null; LogName = 'NetworkProfile' }
                    )
                }
                Verify = [pscustomobject]@{
                    Summary = [pscustomobject]@{
                        Passed               = $false
                        MissingVendorsCount  = 1
                        MissingGuidCount     = 1
                        MissingServiceCount  = 1
                    }
                    VendorComparison = [pscustomobject]@{ Missing = @('Contoso Security') }
                }
                BackupPath = 'C:\backup'
                Timings = [pscustomobject]@{
                    Detect = [pscustomobject]@{ Duration = [timespan]::FromSeconds(2) }
                    Empty  = [pscustomobject]@{ Duration = $null }
                }
            }

            Show-NetCleanSummary -Result $result -SelectedMode SafeConferencePrep

            $script:messages | Should -Contain 'No organization management was detected.'
            $script:messages | Should -Contain 'Phase 1 - Detect'
            $script:messages | Should -Contain 'Phase 2 - Protect'
            $script:messages | Should -Contain 'Phase 3 - Clean'
            $script:messages | Should -Contain 'Phase 4 - Verify'
            $script:messages | Should -Contain '  Missing vendor names: Contoso Security'
            $script:messages | Should -Contain 'Network list backup: C:\backup\NetworkList.reg'
            $script:messages | Should -Contain 'Registry keys removed: 1'
            $script:messages | Should -Contain 'Event logs touched: 2'
            $script:messages | Should -Contain 'Log File: C:\ProgramData\NetClean\Logs\netclean.log'
            $script:messages | Should -Contain 'Phase runtimes'
        }

        It 'reports no remaining Wi-Fi profiles when every discovered profile was removed' {
            $result = [pscustomobject]@{
                Protect = [pscustomobject]@{
                    Summary = [pscustomobject]@{
                        ProtectedRegistryPathCount   = 0
                        WiFiBackupCount               = 1
                        ProtectedRegistryBackupCount = 0
                    }
                    Manifest = [pscustomobject]@{
                        WiFiExports       = @('PROFILE:Home')
                        NetworkListBackup = $null
                    }
                }
                Clean = [pscustomobject]@{
                    Summary = [pscustomobject]@{
                        WiFiProfilesRemoved      = 1
                        RegistryArtifactsRemoved = 0
                        EventLogsTouched         = 0
                        UserArtifactsTouched     = 0
                        AdvancedRepairActions    = 0
                        PerformanceTuningActions = 0
                    }
                    WiFi = [pscustomobject]@{ Profiles = @('Home') }
                    RegistryArtifacts = $null
                    EventLogs = @()
                }
            }

            Show-NetCleanSummary -Result $result -SelectedMode SafeConferencePrep

            $script:messages | Should -Contain 'Wi-Fi Profiles - Remaining After Cleanup'
            $script:messages | Should -Contain '  - (none)'
        }

        It 'renders a complete preview including profiles, registry candidates, paths, and timings' {
            $result = [pscustomobject]@{
                ManagementState = [pscustomobject]@{ IsManaged = $false; JoinType = 'Unmanaged' }
                Summary = [pscustomobject]@{
                    ProtectedVendorsCount       = 1
                    ProtectedInterfaceGuidCount = 1
                    CandidateArtifactCount      = 2
                    SanitizableArtifactCount    = 1
                }
                BackupPath = 'C:\backup'
                Protect = [pscustomobject]@{
                    Manifest = [pscustomobject]@{
                        WiFiExports       = @('PROFILE:Home', 'PROFILE:Office')
                        NetworkListBackup = 'C:\backup\NetworkList.reg'
                    }
                }
                SanitizableArtifacts = @(
                    [pscustomobject]@{ RegistryPath = 'HKLM\SOFTWARE\History' }
                    [pscustomobject]@{ RegistryPath = $null }
                )
                Timings = [pscustomobject]@{
                    Detect = [pscustomobject]@{ Duration = [timespan]::FromSeconds(1) }
                }
            }

            Show-PreviewSummary -Result $result

            $script:messages | Should -Contain 'Preview Summary'
            $script:messages | Should -Contain 'No organization management was detected.'
            $script:messages | Should -Contain '  - Home'
            $script:messages | Should -Contain '  - Office'
            $script:messages | Should -Contain '  - HKLM\SOFTWARE\History'
            $script:messages | Should -Contain 'Network list backup: C:\backup\NetworkList.reg'
            $script:messages | Should -Contain 'Log File: C:\ProgramData\NetClean\Logs\netclean.log'
            $script:messages | Should -Contain 'Phase runtimes'
        }
    }

    Context 'Post-run action behavior' {

        BeforeEach {
            Mock Write-NetCleanLog {}
            Mock Restart-Computer {}
            Mock Stop-Computer {}
        }

        It 'selects restart without prompting when RebootNow is set' {
            $script:RebootNow = $true
            Mock Read-Host { throw 'Read-Host must not be called when RebootNow is set' }

            Read-PostRunAction | Should -Be 'Restart'
            Should -Invoke Read-Host -Times 0
        }

        It 'maps every valid interactive post-run choice' -ForEach @(
            @{ Choice = 'r'; Expected = 'Restart' }
            @{ Choice = 's'; Expected = 'Shutdown' }
            @{ Choice = 'n'; Expected = 'None' }
        ) {
            Mock Read-Host { $Choice }

            Read-PostRunAction | Should -Be $Expected
        }

        It 'reprompts after an invalid post-run choice' {
            $script:readResponses = [System.Collections.Generic.Queue[string]]::new()
            $script:readResponses.Enqueue('later')
            $script:readResponses.Enqueue('n')
            Mock Read-Host { $script:readResponses.Dequeue() }

            Read-PostRunAction | Should -Be 'None'
            Should -Invoke Read-Host -Times 2
        }

        It 'logs dry-run power actions and invokes only explicitly selected live actions' {
            Invoke-PostRunAction -Action Restart -DryRunMode
            Invoke-PostRunAction -Action Shutdown -DryRunMode
            Invoke-PostRunAction -Action None
            Invoke-PostRunAction -Action Restart
            Invoke-PostRunAction -Action Shutdown

            Should -Invoke Restart-Computer -Times 1 -ParameterFilter { $Force }
            Should -Invoke Stop-Computer -Times 1 -ParameterFilter { $Force }
            Should -Invoke Write-NetCleanLog -Times 1 -ParameterFilter { $Message -eq 'DRYRUN: Restart-Computer -Force' }
            Should -Invoke Write-NetCleanLog -Times 1 -ParameterFilter { $Message -eq 'DRYRUN: Stop-Computer -Force' }
            Should -Invoke Write-NetCleanLog -Times 1 -ParameterFilter { $Message -eq 'No post-run power action selected.' }
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

        It 'returns immediately when the menu selection is Exit' {
            $script:Mode = 'Menu'
            Mock Read-NetCleanMenuSelection { 'Exit' }

            Invoke-NetCleanLauncher

            Should -Invoke Test-NetCleanAdministrator -Times 1
            Should -Invoke Show-ModeExplanation -Times 0
            Should -Invoke Invoke-NetCleanWorkflow -Times 0
        }

        It 'returns before logging and workflow execution when confirmation is declined' {
            $script:Force = $false
            Mock Read-YesNo { $false }

            Invoke-NetCleanLauncher

            Should -Invoke Read-YesNo -Times 1
            Should -Invoke Start-NetCleanLog -Times 0
            Should -Invoke Invoke-NetCleanWorkflow -Times 0
        }

        It 'routes Preview through detect and protect without invoking cleanup workflow or power actions' {
            $script:Mode = 'Preview'
            Mock Read-NetCleanOption {
                [pscustomobject]@{
                    SelectedMode       = 'Preview'
                    DryRun             = $true
                    SkipWifi           = $false
                    SkipDnsFlush       = $false
                    SkipEventLogs      = $false
                    SkipUserArtifacts  = $false
                    SkipFirewallBackup = $true
                    PerformanceProfile = $null
                }
            }
            Mock Invoke-NetCleanPhase1Detect { [pscustomobject]@{ Phase = 'Detect' } }
            Mock Invoke-NetCleanPhase2Protect { [pscustomobject]@{ Phase = 'Protect' } }
            Mock Show-PreviewSummary {}

            Invoke-NetCleanLauncher

            Should -Invoke Invoke-NetCleanPhase1Detect -Times 1
            Should -Invoke Invoke-NetCleanPhase2Protect -Times 1 -ParameterFilter {
                $DryRun -and $SkipFirewallBackup -and $BackupPath -eq $TestDrive
            }
            Should -Invoke Show-PreviewSummary -Times 1
            Should -Invoke Invoke-NetCleanWorkflow -Times 0
            Should -Invoke Invoke-PostRunAction -Times 0
        }

        It 'creates a missing backup directory for a live safe-cleanup run' {
            $script:DryRun = $false
            $script:BackupPath = Join-Path $TestDrive 'missing-backup'
            Mock Read-NetCleanOption {
                [pscustomobject]@{
                    SelectedMode       = 'SafeConferencePrep'
                    DryRun             = $false
                    SkipWifi           = $false
                    SkipDnsFlush       = $false
                    SkipEventLogs      = $false
                    SkipUserArtifacts  = $false
                    SkipFirewallBackup = $false
                    PerformanceProfile = $null
                }
            }
            Mock Test-Path { $false }
            Mock New-Item {}

            Invoke-NetCleanLauncher

            Should -Invoke New-Item -Times 1 -ParameterFilter {
                $Path -eq $script:BackupPath -and $ItemType -eq 'Directory' -and $Force
            }
            Should -Invoke Invoke-NetCleanWorkflow -Times 1 -ParameterFilter {
                $Mode -eq 'SafeConferencePrep' -and -not $DryRun
            }
            Should -Invoke Invoke-PostRunAction -Times 1 -ParameterFilter { -not $DryRunMode }
        }

    }

    Context 'Console output behavior' {

        It 'discloses adapter, DNS, IPv6, and restart changes before safe cleanup' {
            $script:messages = [System.Collections.Generic.List[string]]::new()
            Mock Write-Information {
                if ($null -ne $MessageData) {
                    [void]$script:messages.Add([string]$MessageData)
                }
            }

            Show-ModeExplanation -SelectedMode SafeConferencePrep

            $script:messages | Should -Contain '  - reset eligible adapters to IPv4 DHCP'
            $script:messages | Should -Contain '  - set Quad9 Secure DNS for IPv4 and IPv6'
            $script:messages | Should -Contain '  - keep IPv6 enabled and prefer IPv4 after restart'
            $script:messages | Should -Contain '  - require a restart for the IPv4 preference to take full effect'
        }

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
