$manifestPath = Join-Path $PSScriptRoot '..\..\NetClean.psd1'

if (-not (Test-Path -LiteralPath $manifestPath)) {
    throw "NetClean.psd1 not found at path: $manifestPath"
}

Remove-Module NetClean -ErrorAction SilentlyContinue
Import-Module $manifestPath -Force

Describe 'NetClean Phase 3 unit tests' {

    InModuleScope 'NetClean' {

        BeforeEach {
            $script:LogFile = $null
        }

        Context 'Remove-WiFiProfilesSafe' {

            It 'returns empty results when no Wi-Fi profiles are found' {
                Mock Get-WiFiProfileName { @() }

                $result = Remove-WiFiProfilesSafe -DryRun

                $result.Removed | Should -Be 0
                @($result.Profiles).Count | Should -Be 0
                @($result.Operations).Count | Should -Be 0
            }

            It 'returns planned removals in dry-run mode when profiles are discovered automatically' {
                Mock Get-WiFiProfileName { @('HomeSSID', 'OfficeSSID') }

                $result = Remove-WiFiProfilesSafe -DryRun

                $result.Removed | Should -Be 2
                @($result.Profiles) | Should -Contain 'HomeSSID'
                @($result.Profiles) | Should -Contain 'OfficeSSID'
                @($result.Operations).Count | Should -Be 2
                @($result.Operations | Where-Object { $_.Reason -eq 'DryRun' }).Count | Should -Be 2
            }

            It 'uses explicitly supplied WifiProfiles instead of auto-discovery' {
                Mock Get-WiFiProfileName { throw 'Should not be called' }

                $result = Remove-WiFiProfilesSafe -DryRun -WifiProfiles @('LabSSID')

                $result.Removed | Should -Be 1
                @($result.Profiles) | Should -Contain 'LabSSID'
            }

            It 'honors an explicitly empty profile inventory without rescanning' {
                Mock Get-WiFiProfileName { throw 'Should not be called' }

                $result = Remove-WiFiProfilesSafe -DryRun -WifiProfiles @()

                $result.Removed | Should -Be 0
                Should -Invoke Get-WiFiProfileName -Times 0
            }

            It 'returns WhatIf-skipped operations when ShouldProcess declines' {
                Mock Get-WiFiProfileName { @('HomeSSID') }

                $result = Remove-WiFiProfilesSafe -WifiProfiles @('HomeSSID') -WhatIf

                $result.Removed | Should -Be 0
                @($result.Operations).Count | Should -Be 1
                $result.Operations[0].Skipped | Should -BeTrue
                $result.Operations[0].Reason  | Should -Be 'WhatIf'
            }

            It 'returns successful removals when parallel processing succeeds' {
                Mock Invoke-InParallel {
                    @(
                        [pscustomobject]@{ Name = 'HomeSSID'; Succeeded = $true;  Skipped = $false; Reason = 'Removed' }
                        [pscustomobject]@{ Name = 'OfficeSSID'; Succeeded = $true; Skipped = $false; Reason = 'Removed' }
                    )
                }

                $result = Remove-WiFiProfilesSafe -WifiProfiles @('HomeSSID', 'OfficeSSID')

                $result.Removed | Should -Be 2
                @($result.Profiles) | Should -Contain 'HomeSSID'
                @($result.Profiles) | Should -Contain 'OfficeSSID'
                @($result.Operations).Count | Should -Be 2
            }

            It 'falls back to sequential native removal when parallel invocation fails' {
                Mock Invoke-InParallel { throw 'parallel failure' }

                Mock Get-WiFiProfileName { @('HomeSSID') }

                Mock netsh.exe { $global:LASTEXITCODE = 0 }

                $result = Remove-WiFiProfilesSafe -WifiProfiles @('HomeSSID')

                $result.Removed | Should -Be 1
                @($result.Profiles) | Should -Contain 'HomeSSID'
                @($result.Operations).Count | Should -Be 1
                $result.Operations[0].Succeeded | Should -BeTrue
            }
        }

        Context 'Reset-NetCleanAdapterConfigurationSafe' {

            BeforeEach {
                $script:Adapters = @(
                    [pscustomobject]@{
                        Name           = 'Wi-Fi'
                        InterfaceIndex = 12
                        InterfaceGuid  = '{11111111-1111-1111-1111-111111111111}'
                    }
                    [pscustomobject]@{
                        Name           = 'Protected VPN'
                        InterfaceIndex = 13
                        InterfaceGuid  = '{22222222-2222-2222-2222-222222222222}'
                    }
                )

                $script:AdapterContext = [pscustomobject]@{
                    ManagementState = [pscustomobject]@{ IsManaged = $false }
                    ProtectedInterfaceGuids = @('22222222-2222-2222-2222-222222222222')
                }
            }

            It 'plans IPv4 DHCP and Quad9 DNS only for unmanaged unprotected adapters' {
                $result = Reset-NetCleanAdapterConfigurationSafe `
                    -Context $script:AdapterContext `
                    -Adapters $script:Adapters `
                    -DryRun

                $result.Provider | Should -Be 'Quad9 Secure'
                @($result.DnsServers) | Should -Be @(
                    '9.9.9.9',
                    '149.112.112.112',
                    '2620:fe::fe',
                    '2620:fe::9'
                )
                $result.PreferIPv4 | Should -BeTrue
                $result.ConfiguredCount | Should -Be 1
                $result.SkippedCount | Should -Be 1

                $wifi = $result.Operations | Where-Object Name -eq 'Wi-Fi'
                $wifi.DhcpEnabled | Should -BeTrue
                @($wifi.DnsServers) | Should -Be @(
                    '9.9.9.9',
                    '149.112.112.112',
                    '2620:fe::fe',
                    '2620:fe::9'
                )
                $wifi.Reason | Should -Be 'DryRun'

                $vpn = $result.Operations | Where-Object Name -eq 'Protected VPN'
                $vpn.Skipped | Should -BeTrue
                $vpn.Reason | Should -Be 'ProtectedAdapter'
            }

            It 'preserves every adapter on an organization-managed device' {
                $script:AdapterContext.ManagementState.IsManaged = $true

                $result = Reset-NetCleanAdapterConfigurationSafe `
                    -Context $script:AdapterContext `
                    -Adapters $script:Adapters `
                    -DryRun

                $result.ConfiguredCount | Should -Be 0
                $result.SkippedCount | Should -Be 2
                @($result.Operations | Where-Object Reason -eq 'ManagedDevice').Count | Should -Be 2
            }

            It 'applies DHCP, Quad9 DNS, encrypted DNS, and the IPv4 preference' {
                Mock Invoke-ExternalCommandSafe {
                    [pscustomobject]@{
                        Name      = $Name
                        ExitCode  = 0
                        Succeeded = $true
                        Error     = $null
                    }
                }
                Mock Set-DnsClientServerAddress {}
                Mock Get-DnsClientDohServerAddress {
                    [pscustomobject]@{ ServerAddress = $ServerAddress }
                }
                Mock Set-DnsClientDohServerAddress {}
                Mock Add-DnsClientDohServerAddress {}
                Mock Set-ItemProperty {}

                $result = Reset-NetCleanAdapterConfigurationSafe `
                    -Context $script:AdapterContext `
                    -Adapters @($script:Adapters[0]) `
                    -Confirm:$false

                $result.ConfiguredCount | Should -Be 1
                $result.FailedCount | Should -Be 0
                $result.DnsOverHttps.ConfiguredCount | Should -Be 4

                Should -Invoke Invoke-ExternalCommandSafe -Times 1 -ParameterFilter {
                    $FilePath -eq 'netsh.exe' -and
                    $ArgumentList -contains 'ipv4' -and
                    $ArgumentList -contains 'name=12' -and
                    $ArgumentList -contains 'source=dhcp'
                }
                Should -Invoke Set-DnsClientServerAddress -Times 1 -ParameterFilter {
                    $InterfaceIndex -eq 12 -and
                    @($ServerAddresses).Count -eq 4 -and
                    $ServerAddresses -contains '9.9.9.9' -and
                    $ServerAddresses -contains '2620:fe::fe'
                }
                Should -Invoke Set-DnsClientDohServerAddress -Times 4 -ParameterFilter {
                    $DohTemplate -eq 'https://dns.quad9.net/dns-query' -and
                    $AutoUpgrade -eq $true -and
                    $AllowFallbackToUdp -eq $false
                }
                Should -Invoke Add-DnsClientDohServerAddress -Times 0
                Should -Invoke Set-ItemProperty -Times 1 -ParameterFilter {
                    $Name -eq 'DisabledComponents' -and
                    $Value -eq 32 -and
                    $Type -eq 'DWord'
                }
            }

            It 'adds Quad9 to the encrypted DNS table when entries are absent' {
                Mock Invoke-ExternalCommandSafe {
                    [pscustomobject]@{ ExitCode = 0; Succeeded = $true; Error = $null }
                }
                Mock Set-DnsClientServerAddress {}
                Mock Get-DnsClientDohServerAddress { @() }
                Mock Set-DnsClientDohServerAddress {}
                Mock Add-DnsClientDohServerAddress {}
                Mock Set-ItemProperty {}

                $result = Reset-NetCleanAdapterConfigurationSafe `
                    -Context $script:AdapterContext `
                    -Adapters @($script:Adapters[0]) `
                    -Confirm:$false

                $result.DnsOverHttps.ConfiguredCount | Should -Be 4
                Should -Invoke Add-DnsClientDohServerAddress -Times 4 -ParameterFilter {
                    $DohTemplate -eq 'https://dns.quad9.net/dns-query' -and
                    $AutoUpgrade -eq $true -and
                    $AllowFallbackToUdp -eq $false
                }
                Should -Invoke Set-DnsClientDohServerAddress -Times 0
            }

            It 'reports a failed DHCP reset and does not apply DNS to that adapter' {
                Mock Invoke-ExternalCommandSafe {
                    [pscustomobject]@{
                        ExitCode  = 1
                        Succeeded = $false
                        Error     = 'DHCP reset failed'
                    }
                }
                Mock Set-DnsClientServerAddress {}
                Mock Get-DnsClientDohServerAddress { @() }
                Mock Set-DnsClientDohServerAddress {}
                Mock Add-DnsClientDohServerAddress {}
                Mock Set-ItemProperty {}

                $result = Reset-NetCleanAdapterConfigurationSafe `
                    -Context $script:AdapterContext `
                    -Adapters @($script:Adapters[0]) `
                    -Confirm:$false

                $result.ConfiguredCount | Should -Be 0
                $result.FailedCount | Should -Be 1
                $result.Operations[0].Succeeded | Should -BeFalse
                $result.Operations[0].Error | Should -Be 'DHCP reset failed'
                Should -Invoke Set-DnsClientServerAddress -Times 0
            }

            It 'honors WhatIf without changing adapter, DNS, or preference state' {
                Mock Invoke-ExternalCommandSafe {}
                Mock Set-DnsClientServerAddress {}
                Mock Get-DnsClientDohServerAddress {}
                Mock Set-DnsClientDohServerAddress {}
                Mock Add-DnsClientDohServerAddress {}
                Mock Set-ItemProperty {}

                $result = Reset-NetCleanAdapterConfigurationSafe `
                    -Context $script:AdapterContext `
                    -Adapters @($script:Adapters[0]) `
                    -WhatIf

                $result.ConfiguredCount | Should -Be 0
                $result.Operations[0].Reason | Should -Be 'WhatIf'
                Should -Invoke Invoke-ExternalCommandSafe -Times 0
                Should -Invoke Set-DnsClientServerAddress -Times 0
                Should -Invoke Set-DnsClientDohServerAddress -Times 0
                Should -Invoke Add-DnsClientDohServerAddress -Times 0
                Should -Invoke Set-ItemProperty -Times 0
            }
        }

        Context 'Clear-DnsCacheSafe' {

            It 'returns a dry-run result when DryRun is specified' {
                $result = Clear-DnsCacheSafe -DryRun

                $result.DryRun | Should -BeTrue
                $result.Succeeded | Should -BeTrue
                $result.Reason | Should -Be 'DryRun'
            }

            It 'returns a skipped result when WhatIf is used' {
                $result = Clear-DnsCacheSafe -WhatIf

                $result.Skipped | Should -BeTrue
                $result.Reason | Should -Be 'WhatIf'
            }

            It 'returns success when command execution succeeds' {
                Mock Invoke-ExternalCommandSafe {
                    [pscustomobject]@{
                        Name      = 'Clear DNS cache'
                        ExitCode  = 0
                        Succeeded = $true
                        Error     = $null
                    }
                }

                $result = Clear-DnsCacheSafe

                $result.Succeeded | Should -BeTrue
                $result.ExitCode  | Should -Be 0
            }
        }

        Context 'Clear-ArpCacheSafe' {

            It 'returns a dry-run result when DryRun is specified' {
                $result = Clear-ArpCacheSafe -DryRun

                $result.DryRun | Should -BeTrue
                $result.Succeeded | Should -BeTrue
                $result.Reason | Should -Be 'DryRun'
            }

            It 'returns a skipped result when WhatIf is used' {
                $result = Clear-ArpCacheSafe -WhatIf

                $result.Skipped | Should -BeTrue
                $result.Reason | Should -Be 'WhatIf'
            }

            It 'returns success when command execution succeeds' {
                Mock Invoke-ExternalCommandSafe {
                    [pscustomobject]@{
                        Name      = 'Clear ARP cache'
                        ExitCode  = 0
                        Succeeded = $true
                        Error     = $null
                    }
                }

                $result = Clear-ArpCacheSafe

                $result.Succeeded | Should -BeTrue
                $result.ExitCode  | Should -Be 0
            }
        }

        Context 'Remove-RegistryPathSafe' {

            It 'returns a dry-run result when DryRun is specified' {
                Mock Test-Path { $true }

                $result = Remove-RegistryPathSafe -Path 'HKLM\SOFTWARE\Test' -DryRun

                $result.DryRun | Should -BeTrue
                $result.Removed | Should -BeTrue
                $result.Succeeded | Should -BeTrue
                $result.Reason | Should -Be 'DryRun'
            }

            It 'returns not found when path does not exist' {
                Mock Test-Path { $false }

                $result = Remove-RegistryPathSafe -Path 'HKLM\SOFTWARE\Test'

                $result.Succeeded | Should -BeTrue
                $result.Removed | Should -BeFalse
                $result.Reason | Should -Be 'NotFound'
            }

            It 'returns skipped when WhatIf is used' {
                Mock Test-Path { $true }

                $result = Remove-RegistryPathSafe -Path 'HKLM\SOFTWARE\Test' -WhatIf

                $result.Skipped | Should -BeTrue
                $result.Reason | Should -Be 'WhatIf'
            }

            It 'removes a registry path when it exists' {
                Mock Test-Path { $true }
                Mock Remove-Item {}

                $result = Remove-RegistryPathSafe -Path 'HKLM\SOFTWARE\Test'

                $result.Succeeded | Should -BeTrue
                $result.Removed | Should -BeTrue
                Should -Invoke Remove-Item -Times 1
            }

            It 'returns failure details when Remove-Item throws' {
                Mock Test-Path { $true }
                Mock Remove-Item { throw 'remove failed' }

                $result = Remove-RegistryPathSafe -Path 'HKLM\SOFTWARE\Test'

                $result.Succeeded | Should -BeFalse
                $result.Removed | Should -BeFalse
                $result.Reason | Should -Match 'remove failed'
            }
        }

        Context 'Remove-NetworkPrivacyArtifactsSafe' {

            BeforeEach {
                $script:Artifacts = @(
                    [pscustomobject]@{
                        RegistryPath = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles'
                    },
                    [pscustomobject]@{
                        RegistryPath = 'HKLM\SOFTWARE\Microsoft\WlanSvc\Interfaces'
                    }
                )
            }

            It 'returns dry-run results without removing artifacts' {
                $context = [pscustomobject]@{ SanitizableArtifacts = $script:Artifacts }
                Mock Remove-RegistryPathSafe {
                    [pscustomobject]@{
                        RegistryPath = $RegistryPath
                        Removed      = $true
                        Skipped      = $false
                        Succeeded    = $true
                        Reason       = 'DryRun'
                        DryRun       = $true
                    }
                }

                $result = Remove-NetworkPrivacyArtifactsSafe -Context $context -DryRun

                $result.TotalCandidates | Should -Be 2
                $result.RemovedCount | Should -Be 2
                $result.SkippedCount | Should -Be 0
                @($result.Results).Count | Should -Be 2
                Should -Invoke Remove-RegistryPathSafe -Times 2 -ParameterFilter { $DryRun }
            }

            It 'calls Remove-RegistryPathSafe for each artifact in normal mode' {
                $context = [pscustomobject]@{ SanitizableArtifacts = $script:Artifacts }
                Mock Remove-RegistryPathSafe {
                    [pscustomobject]@{
                        RegistryPath = $RegistryPath
                        Removed      = $true
                        Skipped      = $false
                        DryRun       = $false
                        Succeeded    = $true
                        Reason       = $null
                    }
                }

                $result = Remove-NetworkPrivacyArtifactsSafe -Context $context

                $result.TotalCandidates | Should -Be 2
                $result.RemovedCount | Should -Be 2
                Should -Invoke Remove-RegistryPathSafe -Times 2
            }

            It 'returns empty summary when no artifacts are supplied' {
                $result = Remove-NetworkPrivacyArtifactsSafe -Context ([pscustomobject]@{ SanitizableArtifacts = @() })

                $result.TotalCandidates | Should -Be 0
                $result.RemovedCount | Should -Be 0
                $result.SkippedCount | Should -Be 0
                @($result.Results).Count | Should -Be 0
            }
        }

        Context 'Clear-NetworkEventLogsSafe' {

            It 'returns dry-run result objects for event logs' {
                $result = @(Clear-NetworkEventLogsSafe -DryRun)

                $result.Count | Should -BeGreaterThan 0
                @($result | Where-Object { $_.Reason -eq 'DryRun' }).Count | Should -Be $result.Count
            }

            It 'returns skipped result objects when WhatIf is used' {
                $result = @(Clear-NetworkEventLogsSafe -WhatIf)

                $result.Count | Should -BeGreaterThan 0
                @($result | Where-Object { $_.Reason -eq 'WhatIf' }).Count | Should -Be $result.Count
            }

            It 'calls external helper for each configured event log' {
                Mock Invoke-ExternalCommandSafe {
                    [pscustomobject]@{
                        Name      = $Name
                        ExitCode  = 0
                        Succeeded = $true
                        Error     = $null
                    }
                }

                $result = @(Clear-NetworkEventLogsSafe)

                $result.Count | Should -BeGreaterThan 0
                Should -Invoke Invoke-ExternalCommandSafe -Times $result.Count
                Should -Invoke Invoke-ExternalCommandSafe -Times $result.Count -ParameterFilter { -not $IgnoreExitCode }
            }
        }

        Context 'Clear-UserNetworkArtifactsSafe' {

            It 'returns dry-run result objects for configured paths' {
                $result = @(Clear-UserNetworkArtifactsSafe -DryRun)

                $result.Count | Should -BeGreaterThan 0
                @($result | Where-Object { $_.Reason -eq 'DryRun' }).Count | Should -Be $result.Count
            }

            It 'returns not-found entries when paths do not exist' {
                Mock Test-Path { $false }

                $result = @(Clear-UserNetworkArtifactsSafe)

                $result.Count | Should -BeGreaterThan 0
                @($result | Where-Object { $_.Reason -eq 'NotFound' }).Count | Should -Be $result.Count
            }

            It 'returns skipped entries when WhatIf is used' {
                Mock Test-Path { $true }

                $result = @(Clear-UserNetworkArtifactsSafe -WhatIf)

                $result.Count | Should -BeGreaterThan 0
                @($result | Where-Object { $_.Reason -eq 'WhatIf' }).Count | Should -Be $result.Count
            }

            It 'removes paths when they exist and execution is allowed' {
                Mock Test-Path { $true }
                Mock Remove-Item {}

                $result = @(Clear-UserNetworkArtifactsSafe)

                $result.Count | Should -BeGreaterThan 0
                @($result | Where-Object { $_.Removed }).Count | Should -Be $result.Count
                Should -Invoke Remove-Item -Times $result.Count
            }
        }

        Context 'Invoke-AdvancedNetworkRepair' {

            It 'returns dry-run actions when DryRun is specified' {
                $result = @(Invoke-AdvancedNetworkRepair -DryRun)

                $result.Count | Should -BeGreaterThan 0
                @($result | Where-Object { $_.Reason -eq 'DryRun' }).Count | Should -Be $result.Count
            }

            It 'returns skipped actions when WhatIf is used' {
                $result = @(Invoke-AdvancedNetworkRepair -WhatIf)

                $result.Count | Should -BeGreaterThan 0
                @($result | Where-Object { $_.Reason -eq 'WhatIf' }).Count | Should -Be $result.Count
            }

            It 'executes each configured repair command in normal mode' {
                Mock Invoke-ExternalCommandSafe {
                    [pscustomobject]@{
                        Name      = $Name
                        ExitCode  = 0
                        Succeeded = $true
                        Error     = $null
                    }
                }

                $result = @(Invoke-AdvancedNetworkRepair)

                $result.Count | Should -BeGreaterThan 0
                @($result | Where-Object { $_.Succeeded }).Count | Should -Be $result.Count
                Should -Invoke Invoke-ExternalCommandSafe -Times $result.Count
                Should -Invoke Invoke-ExternalCommandSafe -Times $result.Count -ParameterFilter { -not $IgnoreExitCode }
            }
        }

        Context 'Invoke-NetworkPerformanceTune' {

            It 'throws when PerformanceProfile is missing or invalid if required by the function' {
                { Invoke-NetworkPerformanceTune -PerformanceProfile Bogus } | Should -Throw
            }

            It 'returns dry-run actions for the Conservative profile' {
                $result = @(Invoke-NetworkPerformanceTune -PerformanceProfile Conservative -DryRun)

                $result.Count | Should -BeGreaterThan 0
                @($result | Where-Object { $_.Profile -eq 'Conservative' -and $_.Reason -eq 'DryRun' }).Count |
                    Should -Be $result.Count
            }

            It 'returns dry-run actions for the Optimal profile' {
                $result = @(Invoke-NetworkPerformanceTune -PerformanceProfile Optimal -DryRun)

                $result.Count | Should -BeGreaterThan 0
                @($result | Where-Object { $_.Profile -eq 'Optimal' -and $_.Reason -eq 'DryRun' }).Count |
                    Should -Be $result.Count
            }

            It 'returns dry-run actions for the Gaming profile' {
                $result = @(Invoke-NetworkPerformanceTune -PerformanceProfile Gaming -DryRun)

                $result.Count | Should -BeGreaterThan 0
                @($result | Where-Object { $_.Profile -eq 'Gaming' -and $_.Reason -eq 'DryRun' }).Count |
                    Should -Be $result.Count
            }

            It 'returns dry-run actions for the Default profile' {
                $result = @(Invoke-NetworkPerformanceTune -PerformanceProfile Default -DryRun)

                $result.Count | Should -BeGreaterThan 0
                @($result | Where-Object { $_.Profile -eq 'Default' -and $_.Reason -eq 'DryRun' }).Count |
                    Should -Be $result.Count
            }

            It 'returns skipped actions when WhatIf is used' {
                $result = @(Invoke-NetworkPerformanceTune -PerformanceProfile Optimal -WhatIf)

                $result.Count | Should -BeGreaterThan 0
                @($result | Where-Object { $_.Reason -eq 'WhatIf' }).Count | Should -Be $result.Count
            }

            It 'executes tuning actions in normal mode' {
                Mock Invoke-ExternalCommandSafe {
                    [pscustomobject]@{
                        Name      = $Name
                        ExitCode  = 0
                        Succeeded = $true
                        Error     = $null
                    }
                }

                $result = @(Invoke-NetworkPerformanceTune -PerformanceProfile Optimal)

                $result.Count | Should -BeGreaterThan 0
                @($result | Where-Object { $_.Succeeded }).Count | Should -Be $result.Count
                Should -Invoke Invoke-ExternalCommandSafe -Times $result.Count
            }
        }

        Context 'Invoke-NetCleanPhase3Clean' {

            BeforeEach {
                $script:Context = [pscustomobject]@{
                    Phase                  = 'Protect'
                    Inventory              = @()
                    ProtectedRegistryPaths = @('HKLM\SOFTWARE\CrowdStrike')
                    SanitizableArtifacts   = @(
                        [pscustomobject]@{
                            RegistryPath = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles'
                        }
                    )
                }

                Mock Remove-WiFiProfilesSafe {
                    [pscustomobject]@{
                        Removed    = 2
                        Profiles   = @('ssid1', 'ssid2')
                        Operations = @()
                    }
                }

                Mock Clear-DnsCacheSafe {
                    [pscustomobject]@{
                        Name      = 'Clear DNS cache'
                        ExitCode  = 0
                        Succeeded = $true
                    }
                }

                Mock Clear-ArpCacheSafe {
                    [pscustomobject]@{
                        Name      = 'Clear ARP cache'
                        ExitCode  = 0
                        Succeeded = $true
                    }
                }

                Mock Reset-NetCleanAdapterConfigurationSafe {
                    [pscustomobject]@{
                        Provider        = 'Quad9 Secure'
                        DnsServers      = @(
                            '9.9.9.9',
                            '149.112.112.112',
                            '2620:fe::fe',
                            '2620:fe::9'
                        )
                        PreferIPv4      = $true
                        RequiresRestart = $true
                        ConfiguredCount = 1
                        SkippedCount    = 0
                        FailedCount     = 0
                        Succeeded       = $true
                        Operations      = @()
                    }
                }

                Mock Remove-NetworkPrivacyArtifactsSafe {
                    [pscustomobject]@{
                        TotalCandidates = 1
                        RemovedCount    = 1
                        SkippedCount    = 0
                        Results         = @(
                            [pscustomobject]@{
                                RegistryPath = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles'
                                Removed      = $true
                            }
                        )
                    }
                }

                Mock Clear-NetworkEventLogsSafe {
                    @([pscustomobject]@{ Name = 'Clear test event log'; Succeeded = $true; Error = $null })
                }
                Mock Clear-UserNetworkArtifactsSafe {
                    @([pscustomobject]@{ Removed = $true; Path = 'HKCU:\Software\Test'; Succeeded = $true; Reason = $null })
                }
                Mock Invoke-AdvancedNetworkRepair {
                    @([pscustomobject]@{ Name = 'Repair'; ExitCode = 0; Succeeded = $true })
                }
                Mock Invoke-NetworkPerformanceTune {
                    @([pscustomobject]@{ Name = 'Tune'; ExitCode = 0; Succeeded = $true; Applied = $true; Profile = 'Optimal' })
                }
            }

            It 'runs safe conference prep without advanced repair by default' {
                $result = Invoke-NetCleanPhase3Clean -Context $script:Context -Mode SafeConferencePrep -DryRun

                $result.Phase | Should -Be 'Clean'
                $result.Clean.Summary.WiFiProfilesRemoved | Should -Be 2
                $result.Clean.Summary.RegistryArtifactsRemoved | Should -Be 1
                $result.Clean.Summary.AdvancedRepairActions | Should -Be 0
                $result.Clean.Summary.PerformanceTuningActions | Should -Be 0
            }

            It 'resets eligible adapter state and propagates dry-run behavior' {
                $result = Invoke-NetCleanPhase3Clean -Context $script:Context -Mode SafeConferencePrep -DryRun

                $result.Clean.AdapterConfiguration.Provider | Should -Be 'Quad9 Secure'
                $result.Clean.Summary.AdaptersConfigured | Should -Be 1
                $result.Clean.Summary.AdaptersSkipped | Should -Be 0
                $result.Clean.Summary.AdapterFailures | Should -Be 0
                $result.Clean.Summary.PreferIPv4 | Should -BeTrue
                Should -Invoke Reset-NetCleanAdapterConfigurationSafe -Times 1 -ParameterFilter {
                    $Context -eq $script:Context -and $DryRun
                }
            }

            It 'preserves NLA connectivity-probe configuration during privacy cleanup' {
                $result = Invoke-NetCleanPhase3Clean -Context $script:Context -Mode SafeConferencePrep -DryRun

                @($result.Clean.Nla).Count | Should -Be 0
                Get-Command Clear-NlaProbeStateSafe -ErrorAction SilentlyContinue |
                    Should -BeNullOrEmpty
            }

            It 'skips Wi-Fi cleanup when SkipWifi is used' {
                $result = Invoke-NetCleanPhase3Clean -Context $script:Context -Mode SafeConferencePrep -DryRun -SkipWifi

                $result.Clean.Summary.WiFiProfilesRemoved | Should -Be 0
                Should -Invoke Remove-WiFiProfilesSafe -Times 0
            }

            It 'removes the union of backed-up and newly discovered Wi-Fi profiles' {
                $script:Context | Add-Member -NotePropertyName Protect -NotePropertyValue ([pscustomobject]@{
                    Summary = [pscustomobject]@{
                        WiFiProfilesFound = @('BackedUpSSID')
                    }
                })
                Mock Get-WiFiProfileName { @('NewSSID') }

                $null = Invoke-NetCleanPhase3Clean -Context $script:Context -Mode SafeConferencePrep -DryRun

                Should -Invoke Remove-WiFiProfilesSafe -Times 1 -ParameterFilter {
                    @($WifiProfiles).Count -eq 2 -and
                    $WifiProfiles -contains 'BackedUpSSID' -and
                    $WifiProfiles -contains 'NewSSID'
                }
            }

            It 'skips DNS cleanup when SkipDnsFlush is used' {
                $null = Invoke-NetCleanPhase3Clean -Context $script:Context -Mode SafeConferencePrep -DryRun -SkipDnsFlush

                Should -Invoke Clear-DnsCacheSafe -Times 0
                Should -Invoke Clear-ArpCacheSafe -Times 1
            }

            It 'skips event log cleanup when SkipEventLogs is used' {
                $result = Invoke-NetCleanPhase3Clean -Context $script:Context -Mode SafeConferencePrep -DryRun -SkipEventLogs

                $result.Clean.Summary.EventLogsTouched | Should -Be 0
                Should -Invoke Clear-NetworkEventLogsSafe -Times 0
            }

            It 'skips user artifact cleanup when SkipUserArtifacts is used' {
                $result = Invoke-NetCleanPhase3Clean -Context $script:Context -Mode SafeConferencePrep -DryRun -SkipUserArtifacts

                $result.Clean.Summary.UserArtifactsTouched | Should -Be 0
                Should -Invoke Clear-UserNetworkArtifactsSafe -Times 0
            }

            It 'includes advanced repair actions in AdvancedRepair mode' {
                $result = Invoke-NetCleanPhase3Clean -Context $script:Context -Mode AdvancedRepair -DryRun

                $result.Clean.Summary.AdvancedRepairActions | Should -Be 1
                Should -Invoke Invoke-AdvancedNetworkRepair -Times 1
            }

            It 'includes performance tuning actions in PerformanceTune mode' {
                $result = Invoke-NetCleanPhase3Clean -Context $script:Context -Mode PerformanceTune -PerformanceProfile Optimal -DryRun

                $result.Clean.Summary.PerformanceTuningActions | Should -Be 1
                Should -Invoke Invoke-NetworkPerformanceTune -Times 1
            }

            It 'throws when PerformanceTune mode is used without a PerformanceProfile' {
                { Invoke-NetCleanPhase3Clean -Context $script:Context -Mode PerformanceTune -DryRun } | Should -Throw
            }

            It 'logs the event operation name instead of a boolean expression result' {
                $script:logMessages = [System.Collections.Generic.List[string]]::new()
                Mock Write-NetCleanLog { [void]$script:logMessages.Add($Message) }

                $null = Invoke-NetCleanPhase3Clean -Context $script:Context -Mode SafeConferencePrep -DryRun

                $script:logMessages | Should -Contain 'Event log operation: Clear test event log => OK'
                $script:logMessages | Should -Not -Contain 'Event log operation: True => OK'
            }
        }
    }
}
