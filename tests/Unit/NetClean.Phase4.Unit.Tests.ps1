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
        }
    }
}
