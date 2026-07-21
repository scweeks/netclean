$manifestPath = Join-Path $PSScriptRoot '..\..\NetClean.psd1'

if (-not (Test-Path -LiteralPath $manifestPath)) {
    throw "NetClean.psd1 not found at path: $manifestPath"
}

Remove-Module NetClean -ErrorAction SilentlyContinue
Import-Module $manifestPath -Force

Describe 'NetClean Phase 4 unit tests' {

    InModuleScope 'NetClean' {

        BeforeEach {
            $script:preInventory = @(
                [pscustomobject]@{
                    Vendor                  = 'Contoso Security'
                    Services                = @('ContosoAgent')
                    ProtectedInterfaceGuids = @('aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee')
                }
            )

            $script:postInventory = @(
                [pscustomobject]@{
                    Vendor                  = 'Contoso Security'
                    Services                = @('ContosoAgent')
                    ProtectedInterfaceGuids = @('aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee')
                }
            )

            $script:context = [pscustomobject]@{
                Phase      = 'Clean'
                BackupPath = 'C:\backup'
                Inventory  = $script:preInventory
            }

            Mock Get-ProtectionInventory { $script:postInventory }
            Mock Get-WiFiProfileName { @() }
            Mock Get-NetworkListProfileName { @() }
            Mock Export-NetCleanVerificationReport { 'C:\backup\VerificationReport.json' }
            Mock Write-NetCleanLog {}
            Mock Write-Information {}
        }

        Context 'Test-NetCleanAdapterPostState' {

            BeforeEach {
                $script:context | Add-Member -NotePropertyName Clean -NotePropertyValue ([pscustomobject]@{
                    DryRun = $false
                    AdapterConfiguration = [pscustomobject]@{
                        DnsServers = @(
                            '9.9.9.9',
                            '149.112.112.112',
                            '2620:fe::fe',
                            '2620:fe::9'
                        )
                        PreferIPv4 = $true
                        IPv4Preference = [pscustomobject]@{
                            Succeeded = $true
                            Skipped   = $false
                        }
                        DnsOverHttps = [pscustomobject]@{
                            Supported       = $true
                            ConfiguredCount = 4
                        }
                        Operations = @(
                            [pscustomobject]@{
                                Name           = 'Wi-Fi'
                                InterfaceIndex = 12
                                Succeeded      = $true
                                Skipped        = $false
                                DryRun         = $false
                            }
                        )
                    }
                })

                Mock Get-NetIPInterface {
                    [pscustomobject]@{ InterfaceIndex = 12; Dhcp = 'Enabled' }
                }
                Mock Get-DnsClientServerAddress {
                    @(
                        [pscustomobject]@{
                            InterfaceIndex  = 12
                            AddressFamily   = 'IPv4'
                            ServerAddresses = @('9.9.9.9', '149.112.112.112')
                        }
                        [pscustomobject]@{
                            InterfaceIndex  = 12
                            AddressFamily   = 'IPv6'
                            ServerAddresses = @('2620:fe::fe', '2620:fe::9')
                        }
                    )
                }
                Mock Get-ItemProperty {
                    [pscustomobject]@{ DisabledComponents = 32 }
                }
                Mock Get-DnsClientDohServerAddress {
                    [pscustomobject]@{
                        ServerAddress      = $ServerAddress
                        DohTemplate        = 'https://dns.quad9.net/dns-query'
                        AutoUpgrade        = $true
                        AllowFallbackToUdp = $false
                    }
                }
            }

            It 'passes only when DHCP, the full Quad9 set, IPv4 preference, and DoH are observed' {
                $result = Test-NetCleanAdapterPostState -Context $script:context

                $result.Applicable | Should -BeTrue
                $result.Passed | Should -BeTrue
                @($result.Checks | Where-Object { -not $_.Passed }).Count | Should -Be 0
            }

            It 'fails when an adapter is missing any configured Quad9 resolver' {
                Mock Get-DnsClientServerAddress {
                    [pscustomobject]@{
                        InterfaceIndex  = 12
                        AddressFamily   = 'IPv4'
                        ServerAddresses = @('9.9.9.9')
                    }
                }

                (Test-NetCleanAdapterPostState -Context $script:context).Passed | Should -BeFalse
            }

            It 'fails when the registry does not prefer IPv4' {
                Mock Get-ItemProperty {
                    [pscustomobject]@{ DisabledComponents = 0 }
                }

                (Test-NetCleanAdapterPostState -Context $script:context).Passed | Should -BeFalse
            }

            It 'fails when encrypted DNS permits plaintext fallback' {
                Mock Get-DnsClientDohServerAddress {
                    [pscustomobject]@{
                        ServerAddress      = $ServerAddress
                        DohTemplate        = 'https://dns.quad9.net/dns-query'
                        AutoUpgrade        = $true
                        AllowFallbackToUdp = $true
                    }
                }

                (Test-NetCleanAdapterPostState -Context $script:context).Passed | Should -BeFalse
            }

            It 'marks adapter post-state checks not applicable during a dry run' {
                $script:context.Clean.DryRun = $true

                $result = Test-NetCleanAdapterPostState -Context $script:context

                $result.Applicable | Should -BeFalse
                $result.Passed | Should -BeTrue
                $result.Reason | Should -Be 'DryRun'
                Should -Invoke Get-NetIPInterface -Times 0
            }
        }

        Context 'Test-NetCleanCleanupPostState' {

            BeforeEach {
                $script:context | Add-Member -NotePropertyName Clean -NotePropertyValue ([pscustomobject]@{
                    DryRun = $false
                    Dns = [pscustomobject]@{
                        Name      = 'Flush DNS cache'
                        Succeeded = $true
                        Skipped   = $false
                    }
                    Arp = [pscustomobject]@{
                        Name      = 'Clear ARP cache'
                        Succeeded = $true
                        Skipped   = $false
                    }
                    WiFi = [pscustomobject]@{
                        Skipped    = $false
                        Operations = @(
                            [pscustomobject]@{
                                Name      = 'ConferenceWiFi'
                                Succeeded = $true
                                Skipped   = $false
                            }
                        )
                    }
                    RegistryArtifacts = [pscustomobject]@{
                        Results = @(
                            [pscustomobject]@{
                                RegistryPath = 'HKLM\SOFTWARE\Microsoft\TestArtifact'
                                Removed      = $true
                                Succeeded    = $true
                                Skipped      = $false
                                Reason       = 'Removed'
                            }
                        )
                    }
                    UserArtifacts = @(
                        [pscustomobject]@{
                            Path      = 'HKCU:\Software\Microsoft\TestArtifact'
                            Removed   = $true
                            Succeeded = $true
                            Reason    = $null
                        }
                    )
                    EventLogs = @(
                        [pscustomobject]@{
                            LogName     = 'Microsoft-Windows-NetworkProfile/Operational'
                            Cleared     = $true
                            Succeeded   = $true
                            Skipped     = $false
                            CompletedAt = [datetime]'2026-07-20T12:00:00'
                            Error       = $null
                        }
                    )
                    AdvancedRepair = @(
                        [pscustomobject]@{
                            Name      = 'Reset Winsock'
                            Succeeded = $true
                            Skipped   = $false
                        }
                    )
                    PerformanceTuning = @(
                        [pscustomobject]@{
                            Name      = 'Set TCP autotuning to normal'
                            Succeeded = $true
                            Skipped   = $false
                        }
                    )
                })

                Mock Test-RegistryPathExist { $false }
                Mock Test-Path { $false }
                Mock Get-WinEvent { @() }
                Mock Get-NetAdapter {
                    [pscustomobject]@{
                        Name               = 'Wi-Fi'
                        InterfaceIndex     = 12
                        Status             = 'Disconnected'
                        MediaType          = 'Native 802.11'
                        PhysicalMediaType  = 'Native 802.11'
                        NdisPhysicalMedium = 9
                    }
                }
                Mock Get-DnsClientCache { @() }
                Mock Get-NetNeighbor {
                    [pscustomobject]@{
                        InterfaceIndex = 12
                        IPAddress      = '255.255.255.255'
                        State          = 'Permanent'
                    }
                }
            }

            It 'passes when persistent artifacts remain absent and volatile actions succeeded' {
                $result = Test-NetCleanCleanupPostState -Context $script:context

                $result.Applicable | Should -BeTrue
                @($result.Checks | Where-Object { -not $_.Passed }).Count |
                    Should -Be 0 -Because ($result.Checks | ConvertTo-Json -Depth 5 -Compress)
                $result.Passed | Should -BeTrue
                @($result.Checks.Category) | Should -Contain 'RegistryArtifact'
                @($result.Checks.Category) | Should -Contain 'UserArtifact'
                @($result.Checks.Category) | Should -Contain 'EventLog'
                @($result.Checks.Category) | Should -Contain 'VolatileCacheAction'
                @($result.Checks.Category) | Should -Contain 'WiFiConnection'
                @($result.Checks.Category) | Should -Contain 'DnsCache'
                @($result.Checks.Category) | Should -Contain 'ArpCache'
                Should -Invoke Test-RegistryPathExist -Times 1 -ParameterFilter {
                    $RegistryPath -eq 'HKLM\SOFTWARE\Microsoft\TestArtifact'
                }
                Should -Invoke Get-WinEvent -Times 1 -ParameterFilter {
                    $FilterHashtable.LogName -eq 'Microsoft-Windows-NetworkProfile/Operational' -and
                    $FilterHashtable.EndTime -eq [datetime]'2026-07-20T12:00:00'
                }
            }

            It 'does not use DNS or ARP contents as evidence while a wired LAN is connected' {
                Mock Get-NetAdapter {
                    [pscustomobject]@{
                        Name               = 'Ethernet'
                        InterfaceIndex     = 4
                        Status             = 'Up'
                        MediaType          = '802.3'
                        PhysicalMediaType  = '802.3'
                        NdisPhysicalMedium = 14
                    }
                }
                Mock Get-DnsClientCache {
                    [pscustomobject]@{ Entry = 'expected-lan-traffic.example' }
                }
                Mock Get-NetNeighbor {
                    [pscustomobject]@{ InterfaceIndex = 4; State = 'Reachable' }
                }

                $result = Test-NetCleanCleanupPostState -Context $script:context

                $result.Passed | Should -BeTrue
                @($result.Checks | Where-Object {
                    $_.Category -in @('DnsCache', 'ArpCache') -and $_.Applicable
                }).Count | Should -Be 0
                Should -Invoke Get-DnsClientCache -Times 0
                Should -Invoke Get-NetNeighbor -Times 0
            }

            It 'fails when DNS cache entries remain without a connected wired LAN' {
                Mock Get-DnsClientCache {
                    [pscustomobject]@{ Entry = 'home-network.example' }
                }

                $result = Test-NetCleanCleanupPostState -Context $script:context

                $result.Passed | Should -BeFalse
                @($result.Checks | Where-Object {
                    $_.Category -eq 'DnsCache' -and -not $_.Passed
                }).Count | Should -Be 1
            }

            It 'fails when a dynamic ARP neighbor remains without a connected wired LAN' {
                Mock Get-NetNeighbor {
                    [pscustomobject]@{
                        InterfaceIndex = 12
                        IPAddress      = '192.0.2.1'
                        State          = 'Stale'
                    }
                }

                $result = Test-NetCleanCleanupPostState -Context $script:context

                $result.Passed | Should -BeFalse
                @($result.Checks | Where-Object {
                    $_.Category -eq 'ArpCache' -and -not $_.Passed
                }).Count | Should -Be 1
            }

            It 'fails when Wi-Fi remains connected after profile cleanup' {
                Mock Get-NetAdapter {
                    [pscustomobject]@{
                        Name               = 'Wi-Fi'
                        InterfaceIndex     = 12
                        Status             = 'Up'
                        MediaType          = 'Native 802.11'
                        PhysicalMediaType  = 'Native 802.11'
                        NdisPhysicalMedium = 9
                    }
                }

                $result = Test-NetCleanCleanupPostState -Context $script:context

                $result.Passed | Should -BeFalse
                @($result.Checks | Where-Object {
                    $_.Category -eq 'WiFiConnection' -and -not $_.Passed
                }).Count | Should -Be 1
            }

            It 'fails when a removed registry artifact is still present' {
                Mock Test-RegistryPathExist { $true }

                $result = Test-NetCleanCleanupPostState -Context $script:context

                $result.Passed | Should -BeFalse
                @($result.Checks | Where-Object {
                    $_.Category -eq 'RegistryArtifact' -and -not $_.Passed
                }).Count | Should -Be 1
            }

            It 'fails when an event from before the clear completion remains' {
                Mock Get-WinEvent {
                    [pscustomobject]@{ Id = 10000; TimeCreated = [datetime]'2026-07-20T11:59:00' }
                }

                $result = Test-NetCleanCleanupPostState -Context $script:context

                $result.Passed | Should -BeFalse
                @($result.Checks | Where-Object {
                    $_.Category -eq 'EventLog' -and -not $_.Passed
                }).Count | Should -Be 1
            }

            It 'fails when a cleanup command reported failure' {
                $script:context.Clean.Dns.Succeeded = $false
                $script:context.Clean.Dns | Add-Member -NotePropertyName Error -NotePropertyValue 'flush failed'

                $result = Test-NetCleanCleanupPostState -Context $script:context

                $result.Passed | Should -BeFalse
                @($result.Checks | Where-Object {
                    $_.Target -eq 'Flush DNS cache' -and -not $_.Passed
                }).Count | Should -Be 1
            }

            It 'marks cleanup post-state checks not applicable during a dry run' {
                $script:context.Clean.DryRun = $true

                $result = Test-NetCleanCleanupPostState -Context $script:context

                $result.Applicable | Should -BeFalse
                $result.Passed | Should -BeTrue
                $result.Reason | Should -Be 'DryRun'
                Should -Invoke Test-RegistryPathExist -Times 0
                Should -Invoke Test-Path -Times 0
                Should -Invoke Get-WinEvent -Times 0
                Should -Invoke Get-NetAdapter -Times 0
                Should -Invoke Get-DnsClientCache -Times 0
                Should -Invoke Get-NetNeighbor -Times 0
            }
        }

        Context 'Test-NetCleanPostState' {

            It 'passes when protected vendors, GUIDs, and services remain present' {
                $result = Test-NetCleanPostState -Context $script:context

                $result.Passed | Should -BeTrue
                @($result.VendorComparison.Missing).Count | Should -Be 0
                @($result.GuidComparison.Missing).Count | Should -Be 0
                @($result.ServiceComparison.Missing).Count | Should -Be 0
                @($result.RemainingWiFiProfiles).Count | Should -Be 0
                @($result.RemainingNetworkProfiles).Count | Should -Be 0
            }

            It 'fails when a protected vendor is missing' {
                $script:postInventory = @()

                (Test-NetCleanPostState -Context $script:context).Passed | Should -BeFalse
            }

            It 'fails when a protected interface GUID is missing' {
                $script:postInventory[0].ProtectedInterfaceGuids = @()

                $result = Test-NetCleanPostState -Context $script:context

                $result.Passed | Should -BeFalse
                @($result.GuidComparison.Missing) | Should -Contain 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
            }

            It 'fails when a protected service is missing' {
                $script:postInventory[0].Services = @()

                $result = Test-NetCleanPostState -Context $script:context

                $result.Passed | Should -BeFalse
                @($result.ServiceComparison.Missing) | Should -Contain 'ContosoAgent'
            }

            It 'does not fail only because new protected items were detected' {
                $script:postInventory += [pscustomobject]@{
                    Vendor                  = 'Fabrikam Security'
                    Services                = @('FabrikamAgent')
                    ProtectedInterfaceGuids = @('11111111-2222-3333-4444-555555555555')
                }

                (Test-NetCleanPostState -Context $script:context).Passed | Should -BeTrue
            }

            It 'fails when a saved Wi-Fi profile remains' {
                Mock Get-WiFiProfileName { @('HomeSSID') }

                $result = Test-NetCleanPostState -Context $script:context

                $result.Passed | Should -BeFalse
                $result.RemainingWiFiProfiles | Should -Contain 'HomeSSID'
            }

            It 'fails when a Windows NetworkList profile remains' {
                Mock Get-NetworkListProfileName { @('Home network') }

                $result = Test-NetCleanPostState -Context $script:context

                $result.Passed | Should -BeFalse
                $result.RemainingNetworkProfiles | Should -Contain 'Home network'
            }

            It 'fails the overall verification when adapter post-state does not match' {
                Mock Test-NetCleanAdapterPostState {
                    [pscustomobject]@{
                        Applicable = $true
                        Passed     = $false
                        Reason     = 'Verified'
                        Checks     = @(
                            [pscustomobject]@{
                                Category = 'DnsServers'
                                Target   = 'Wi-Fi'
                                Passed   = $false
                            }
                        )
                    }
                }

                $result = Test-NetCleanPostState -Context $script:context

                $result.Passed | Should -BeFalse
                $result.AdapterVerification.Passed | Should -BeFalse
                Should -Invoke Test-NetCleanAdapterPostState -Times 1
            }

            It 'fails the overall verification when cleanup post-state does not match' {
                Mock Test-NetCleanCleanupPostState {
                    [pscustomobject]@{
                        Applicable = $true
                        Passed     = $false
                        Reason     = 'Verified'
                        Checks     = @(
                            [pscustomobject]@{
                                Category = 'DnsCache'
                                Target   = 'DNS client cache'
                                Passed   = $false
                            }
                        )
                    }
                }

                $result = Test-NetCleanPostState -Context $script:context

                $result.Passed | Should -BeFalse
                $result.CleanupVerification.Passed | Should -BeFalse
                Should -Invoke Test-NetCleanCleanupPostState -Times 1
            }

            It 'does not require cleanup post-state during a dry run' {
                $script:context | Add-Member -NotePropertyName Clean -NotePropertyValue ([pscustomobject]@{
                    DryRun = $true
                })
                Mock Get-WiFiProfileName { @('HomeSSID') }
                Mock Get-NetworkListProfileName { @('Home network') }

                $result = Test-NetCleanPostState -Context $script:context

                $result.Passed | Should -BeTrue
                $result.VerificationMode | Should -Be 'Planned'
                @($result.RemainingWiFiProfiles).Count | Should -Be 0
                @($result.RemainingNetworkProfiles).Count | Should -Be 0
                Should -Invoke Get-WiFiProfileName -Times 0
                Should -Invoke Get-NetworkListProfileName -Times 0
            }
        }

        Context 'Export-NetCleanVerificationReport' {

            It 'returns a planned report path without writing during a dry run' {
                Mock WriteAllText {}

                $result = Export-NetCleanVerificationReport `
                    -Dest 'C:\backup' `
                    -Verification ([pscustomobject]@{ Passed = $true }) `
                    -DryRun

                $result | Should -Match 'VerificationReport'
                Should -Invoke WriteAllText -Times 0
            }

            It 'writes the verification ledger as UTF-8 JSON' {
                Mock New-DirectoryIfNotExist {}
                Mock Set-NetCleanPrivateDirectoryAcl {}
                Mock WriteAllText {}

                $verification = [pscustomobject]@{
                    Passed = $false
                    VerificationMode = 'Observed'
                    VendorComparison = [pscustomobject]@{ Missing = @('Missing vendor') }
                    GuidComparison = [pscustomobject]@{ Missing = @() }
                    ServiceComparison = [pscustomobject]@{ Missing = @() }
                    RemainingWiFiProfiles = @('HomeSSID')
                    RemainingNetworkProfiles = @()
                    AdapterVerification = [pscustomobject]@{
                        Applicable = $true
                        Passed     = $false
                        Checks     = @(
                            [pscustomobject]@{
                                Category = 'DnsServers'
                                Target   = 'Wi-Fi'
                                Passed   = $false
                            }
                        )
                    }
                    CleanupVerification = [pscustomobject]@{
                        Applicable = $true
                        Passed     = $false
                        Checks     = @(
                            [pscustomobject]@{
                                Category = 'UserArtifact'
                                Target   = 'HKCU:\Software\Microsoft\TestArtifact'
                                Passed   = $false
                            }
                        )
                    }
                }

                $result = Export-NetCleanVerificationReport `
                    -Dest 'C:\backup' `
                    -Verification $verification

                Should -Invoke Set-NetCleanPrivateDirectoryAcl -Times 1 -ParameterFilter {
                    $Path -eq 'C:\backup'
                }
                Should -Invoke WriteAllText -Times 1 -Exactly -ParameterFilter {
                    $Path -eq $result -and
                    $Contents -match 'DnsServers' -and
                    $Contents -match 'UserArtifact' -and
                    $Contents -match 'HomeSSID' -and
                    $Encoding.WebName -eq 'utf-8'
                }
            }
        }

        Context 'Invoke-NetCleanPhase4Verify' {

            It 'preserves the incoming context and adds a passing verification summary' {
                $result = Invoke-NetCleanPhase4Verify -Context $script:context

                $result.Phase | Should -Be 'Verify'
                $result.BackupPath | Should -Be 'C:\backup'
                $result.Verify.Passed | Should -BeTrue
                $result.Verify.Summary.Passed | Should -BeTrue
                $result.Verify.Summary.MissingVendorsCount | Should -Be 0
                $result.Verify.Summary.MissingGuidCount | Should -Be 0
                $result.Verify.Summary.MissingServiceCount | Should -Be 0
                $result.Verify.Summary.RemainingWiFiProfileCount | Should -Be 0
                $result.Verify.Summary.RemainingNetworkProfileCount | Should -Be 0
                $result.Verify.AdapterVerification.Passed | Should -BeTrue
                $result.Verify.Summary.AdapterCheckFailureCount | Should -Be 0
                $result.Verify.CleanupVerification.Passed | Should -BeTrue
                $result.Verify.Summary.CleanupCheckFailureCount | Should -Be 0
                $result.Verify.VerificationReport | Should -Be 'C:\backup\VerificationReport.json'
                Should -Invoke Export-NetCleanVerificationReport -Times 1 -ParameterFilter {
                    $Dest -eq 'C:\backup' -and -not $DryRun
                }
            }

            It 'reports all missing protected categories in the summary' {
                $script:postInventory = @()

                $result = Invoke-NetCleanPhase4Verify -Context $script:context

                $result.Verify.Passed | Should -BeFalse
                $result.Verify.Summary.Passed | Should -BeFalse
                $result.Verify.Summary.MissingVendorsCount | Should -Be 1
                $result.Verify.Summary.MissingGuidCount | Should -Be 1
                $result.Verify.Summary.MissingServiceCount | Should -Be 1
            }

            It 'reports cleanup check failures in the summary' {
                Mock Test-NetCleanCleanupPostState {
                    [pscustomobject]@{
                        Applicable = $true
                        Passed     = $false
                        Reason     = 'Verified'
                        Checks     = @(
                            [pscustomobject]@{
                                Category = 'ArpCache'
                                Target   = 'Physical-adapter IPv4 neighbor cache'
                                Passed   = $false
                            }
                        )
                    }
                }

                $result = Invoke-NetCleanPhase4Verify -Context $script:context

                $result.Verify.Passed | Should -BeFalse
                $result.Verify.Summary.CleanupCheckFailureCount | Should -Be 1
            }
        }
    }
}
