$manifestPath = Join-Path $PSScriptRoot '..\..\NetClean.psd1'

if (-not (Test-Path -LiteralPath $manifestPath)) {
    throw "NetClean.psd1 not found at path: $manifestPath"
}

Remove-Module NetClean -ErrorAction SilentlyContinue
Import-Module $manifestPath -Force

Describe 'NetClean Phase 1 unit tests' {

    InModuleScope 'NetClean' {

        Context 'Resolve-VendorFromText' {

            It 'returns the matched vendor when known text is present' {
                $result = Resolve-VendorFromText -Text 'CrowdStrike Falcon Sensor service'
                $result | Should -Be 'CrowdStrike'
            }

            It 'returns null when no vendor text matches' {
                $result = Resolve-VendorFromText -Text 'Some random text without a known vendor'
                $result | Should -BeNullOrEmpty
            }

            It 'returns null when input text is null' {
                $result = Resolve-VendorFromText -Text $null
                $result | Should -BeNullOrEmpty
            }
        }

        Context 'Get-VendorSignature' {

            It 'returns the normalized signature table' {
                $result = Get-VendorSignature

                $result | Should -BeOfType [hashtable]
                $result.ContainsKey('CrowdStrike') | Should -BeTrue
            }

            It 'includes the fields required for vendor matching and protection' {
                $signature = (Get-VendorSignature)['CrowdStrike']

                @($signature.Patterns).Count | Should -BeGreaterThan 0
                @($signature.Categories).Count | Should -BeGreaterThan 0
                @($signature.RegistryRoots) | Should -Contain 'HKLM\SOFTWARE\CrowdStrike'
            }
        }

        Context 'Get-WfpStateEvidence' {

            It 'returns evidence when firewall/WFP state is present' {
                Mock netsh {}
                Mock Test-Path { $true }
                Mock Get-Content { '<wfpState><provider><name>CrowdStrike WFP Provider</name></provider></wfpState>' }
                Mock Remove-Item {}

                $result = Get-WfpStateEvidence
                $result | Should -Not -BeNullOrEmpty
                $result[0].InferredVendor | Should -Be 'CrowdStrike'
            }

            It 'returns empty when no WFP state evidence is present' {
                Mock netsh {}
                Mock Test-Path { $false }

                $result = @(Get-WfpStateEvidence)
                $result.Count | Should -Be 0
            }
        }

        Context 'Get-NdisFilterClassEvidence' {

            It 'returns evidence when NDIS filter classes are detected' {
                Mock Get-RegistryChildKeyNamesSafe { @('0001') }
                Mock Get-RegistryValuesSafe {
                    [pscustomobject]@{
                        FilterClass = 'compression'
                        ComponentId = 'CrowdStrikeFilter'
                    }
                }

                $result = @(Get-NdisFilterClassEvidence)
                $result.Count | Should -BeGreaterThan 0
            }

            It 'returns empty when filter keys are absent' {
                Mock Get-RegistryChildKeyNamesSafe { @() }

                $result = @(Get-NdisFilterClassEvidence)
                $result.Count | Should -Be 0
            }
        }

        Context 'Get-NdisServiceBindingEvidence' {

            It 'returns evidence when service bindings are present' {
                Mock Get-RegistryChildKeyNamesSafe { @('CSFalconService') }
                Mock Get-RegistryValuesSafe {
                    [pscustomobject]@{
                        Bind = @('CSFalconService')
                    }
                }

                $result = @(Get-NdisServiceBindingEvidence)
                $result.Count | Should -BeGreaterThan 0
            }

            It 'returns empty when no service bindings are found' {
                Mock Get-RegistryChildKeyNamesSafe { @() }

                $result = @(Get-NdisServiceBindingEvidence)
                $result.Count | Should -Be 0
            }

            It 'preserves service metadata plus bind, export, and route linkage evidence' {
                Mock Get-RegistryChildKeyNamesSafe { @('ContosoFilter') }
                Mock Get-RegistryValuesSafe {
                    if ($RegistryPath -like '*\Linkage') {
                        [pscustomobject]@{
                            Bind   = @($null, '', '\Device\ContosoFilter')
                            Export = @($null, '\Device\ContosoExport')
                            Route  = @('', 'ContosoVpnRoute')
                        }
                    }
                    else {
                        [pscustomobject]@{
                            DisplayName = 'Contoso NDIS Filter'
                            Group       = 'NDIS'
                            ImagePath   = 'C:\Windows\System32\drivers\contoso.sys'
                        }
                    }
                }
                Mock Resolve-VendorFromText { 'Contoso' }

                $result = @(Get-NdisServiceBindingEvidence)

                $result.Count | Should -Be 1
                $result[0].DisplayName | Should -Be 'Contoso NDIS Filter'
                $result[0].Path | Should -Be 'C:\Windows\System32\drivers\contoso.sys'
                $result[0].InferredVendor | Should -Be 'Contoso'
                @($result[0].Instance.Linkage.Export) | Should -Contain '\Device\ContosoExport'
                @($result[0].Instance.Linkage.Route) | Should -Contain 'ContosoVpnRoute'
            }

            It 'falls back to the service name when the display name is blank' {
                Mock Get-RegistryChildKeyNamesSafe { @('PacketFilter') }
                Mock Get-RegistryValuesSafe {
                    if ($RegistryPath -like '*\Linkage') {
                        [pscustomobject]@{ Bind = @('packet filter') }
                    }
                    else {
                        [pscustomobject]@{ DisplayName = '  '; Group = ''; ImagePath = $null }
                    }
                }

                $result = @(Get-NdisServiceBindingEvidence)

                $result.Count | Should -Be 1
                $result[0].DisplayName | Should -Be 'PacketFilter'
            }

            It 'uses a supplied service snapshot without rereading registry values' {
                Mock Get-RegistryChildKeyNamesSafe { throw 'registry should not be queried' }
                Mock Get-RegistryValuesSafe { throw 'registry should not be queried' }
                $snapshot = @(
                    [pscustomobject]@{
                        Name          = 'ContosoFilter'
                        RegistryPath  = 'HKLM\SYSTEM\CurrentControlSet\Services\ContosoFilter'
                        Values        = [pscustomobject]@{
                            DisplayName = 'Contoso Network Filter'
                            Group       = 'NDIS'
                            ImagePath   = 'C:\Contoso\filter.sys'
                        }
                        LinkageValues = [pscustomobject]@{
                            Bind   = @('\Device\ContosoFilter')
                            Export = @()
                            Route  = @()
                        }
                    }
                )

                $result = @(Get-NdisServiceBindingEvidence -ServiceRegistrySnapshot $snapshot)

                $result.Count | Should -Be 1
                $result[0].Name | Should -Be 'ContosoFilter'
                Should -Invoke Get-RegistryChildKeyNamesSafe -Times 0 -Exactly
                Should -Invoke Get-RegistryValuesSafe -Times 0 -Exactly
            }

            It 'accepts a supplied snapshot entry with no LinkageValues property at all' {
                # Get-ProtectionEvidence builds its own internal snapshot with
                # only Name/RegistryPath/Values - no LinkageValues field - so
                # this function must not assume every caller-supplied entry
                # has that property.
                Mock Get-RegistryChildKeyNamesSafe { throw 'registry should not be queried' }
                Mock Get-RegistryValuesSafe { throw 'registry should not be queried' }
                $snapshot = @(
                    [pscustomobject]@{
                        Name         = 'ContosoService'
                        RegistryPath = 'HKLM\SYSTEM\CurrentControlSet\Services\ContosoService'
                        Values       = [pscustomobject]@{
                            DisplayName = 'Contoso Service'
                            ImagePath   = 'C:\Program Files\Contoso\service.exe'
                        }
                    }
                )

                { $script:NoLinkageResult = @(Get-NdisServiceBindingEvidence -ServiceRegistrySnapshot $snapshot) } |
                    Should -Not -Throw

                $script:NoLinkageResult.Count | Should -Be 0
            }
        }

        Context 'Get-MsiRegistryEvidence' {

            It 'returns evidence when MSI uninstall entries exist' {
                Mock Get-RegistryChildKeyNamesSafe { @('{ABC-123}') }
                Mock Get-RegistryValuesSafe {
                    [pscustomobject]@{
                        DisplayName    = 'CrowdStrike Falcon Sensor'
                        Publisher      = 'CrowdStrike'
                        UninstallString = 'msiexec /x {ABC-123}'
                    }
                }

                $result = @(Get-MsiRegistryEvidence)
                $result.Count | Should -BeGreaterThan 0
            }

            It 'returns empty when no uninstall entries exist' {
                Mock Get-RegistryChildKeyNamesSafe { @() }

                $result = @(Get-MsiRegistryEvidence)
                $result.Count | Should -Be 0
            }
        }

        Context 'Get-InfFileEvidence' {

            It 'returns evidence when INF files contain vendor text' {
                Mock Test-Path { $true }
                Mock Get-ChildItem {
                    @([pscustomobject]@{
                            Name     = 'oem42.inf'
                            FullName = 'C:\Windows\INF\oem42.inf'
                        })
                }
                Mock Get-Content { @('Provider = CrowdStrike') }

                $result = @(Get-InfFileEvidence)
                $result.Count | Should -BeGreaterThan 0
            }

            It 'returns empty when no INF files match' {
                Mock Get-ChildItem { @() }

                $result = @(Get-InfFileEvidence)
                $result.Count | Should -Be 0
            }
        }

        Context 'Get-ScheduledTaskEvidence' {

            It 'returns evidence when a scheduled task contains known vendor text' {
                Mock Get-ScheduledTask {
                    @(
                        [pscustomobject]@{
                            TaskName = 'CrowdStrikeSensorTask'
                            TaskPath = '\'
                            Actions  = @(
                                [pscustomobject]@{
                                    Execute          = 'C:\Program Files\CrowdStrike\sensor.exe'
                                    Arguments        = ''
                                    WorkingDirectory = 'C:\Program Files\CrowdStrike'
                                }
                            )
                        }
                    )
                }

                $result = @(Get-ScheduledTaskEvidence)
                $result.Count | Should -BeGreaterThan 0
            }

            It 'returns empty when no scheduled tasks are found' {
                Mock Get-ScheduledTask { @() }

                $result = @(Get-ScheduledTaskEvidence)
                $result.Count | Should -Be 0
            }
        }

        Context 'Get-AppxPackageEvidence' {

            It 'returns evidence when an app package contains known vendor text' {
                Mock Get-AppxPackage {
                    @(
                        [pscustomobject]@{
                            Name                 = 'Cisco.SecureClient'
                            PackageFamilyName    = 'Cisco.SecureClient_abc123'
                            PublisherDisplayName = 'Cisco'
                            InstallLocation      = 'C:\Program Files\WindowsApps\Cisco.SecureClient'
                            Publisher            = 'CN=Cisco'
                        }
                    )
                }

                $result = @(Get-AppxPackageEvidence)
                $result.Count | Should -BeGreaterThan 0
            }

            It 'returns empty when no matching app packages are found' {
                Mock Get-AppxPackage { @() }

                $result = @(Get-AppxPackageEvidence)
                $result.Count | Should -Be 0
            }
        }

        Context 'Get-SupplementalProtectionEvidence' {

            It 'uses one bounded parallel invocation for balanced read-only collector groups' {
                Mock Invoke-InParallel {
                    foreach ($inputItem in $InputObjects) {
                        [pscustomobject]@{ Source = $inputItem.Collector; Name = $inputItem.Collector }
                    }
                }

                $result = @(Get-SupplementalProtectionEvidence -ThrottleLimit 2)

                $result.Count | Should -Be 2
                Should -Invoke Invoke-InParallel -Times 1 -Exactly -ParameterFilter {
                    @($InputObjects).Count -eq 2 -and $ThrottleLimit -eq 2
                }
            }
        }

        Context 'Get-ProtectionEvidence' {

            BeforeEach {
                Mock Get-CimInstance { @() }
                Mock Get-ItemProperty { @() }
                Mock Get-NetAdapter { @() }
                Mock Get-PnpDevice { @() }
                Mock Get-RegistryChildKeyNamesSafe { @() }
                Mock Get-WfpStateEvidence { @() }
                Mock Get-NdisFilterClassEvidence { @() }
                Mock Get-NdisServiceBindingEvidence { @() }
                Mock Get-MsiRegistryEvidence { @() }
                Mock Get-InfFileEvidence { @() }
                Mock Get-ScheduledTaskEvidence { @() }
                Mock Get-AppxPackageEvidence { @() }
            }

            It 'aggregates evidence from all enabled evidence sources' {
                Mock Get-WfpStateEvidence { @([pscustomobject]@{ Vendor = 'CrowdStrike'; Evidence = 'WFP' }) }
                Mock Get-NdisFilterClassEvidence { @([pscustomobject]@{ Vendor = 'CrowdStrike'; Evidence = 'NDIS' }) }
                Mock Get-NdisServiceBindingEvidence { @([pscustomobject]@{ Vendor = 'CrowdStrike'; Evidence = 'Binding' }) }
                Mock Get-MsiRegistryEvidence { @([pscustomobject]@{ Vendor = 'CrowdStrike'; Evidence = 'MSI' }) }
                Mock Get-InfFileEvidence { @([pscustomobject]@{ Vendor = 'CrowdStrike'; Evidence = 'INF' }) }
                Mock Get-ScheduledTaskEvidence { @([pscustomobject]@{ Vendor = 'CrowdStrike'; Evidence = 'Task' }) }
                Mock Get-AppxPackageEvidence { @([pscustomobject]@{ Vendor = 'CrowdStrike'; Evidence = 'AppX' }) }

                $result = @(Get-ProtectionEvidence)
                $result.Count | Should -Be 7
            }

            It 'uses the parallel supplemental collector only when requested' {
                Mock Get-SupplementalProtectionEvidence {
                    @([pscustomobject]@{ Source = 'WFP'; Name = 'ParallelEvidence' })
                }

                $result = @(
                    Get-ProtectionEvidence `
                        -ServiceRegistrySnapshot @() `
                        -ParallelSupplementalEvidence
                )

                $result.Count | Should -Be 1
                $result[0].Name | Should -Be 'ParallelEvidence'
                Should -Invoke Get-SupplementalProtectionEvidence -Times 1 -Exactly
                Should -Invoke Get-WfpStateEvidence -Times 0 -Exactly
                Should -Invoke Get-MsiRegistryEvidence -Times 0 -Exactly
            }

            It 'falls back to sequential supplemental evidence collection when the parallel collector fails' {
                Mock Get-SupplementalProtectionEvidence { throw 'runspace pool unavailable' }
                Mock Get-WfpStateEvidence { @([pscustomobject]@{ Source = 'WFP'; Name = 'SequentialWfp' }) }
                Mock Get-NdisFilterClassEvidence { @([pscustomobject]@{ Source = 'NdisFilterClass'; Name = 'SequentialNdis' }) }
                Mock Get-MsiRegistryEvidence { @([pscustomobject]@{ Source = 'MsiRegistry'; Name = 'SequentialMsi' }) }
                Mock Get-InfFileEvidence { @([pscustomobject]@{ Source = 'InfFile'; Name = 'SequentialInf' }) }
                Mock Get-ScheduledTaskEvidence { @([pscustomobject]@{ Source = 'ScheduledTask'; Name = 'SequentialTask' }) }
                Mock Get-AppxPackageEvidence { @([pscustomobject]@{ Source = 'AppxPackage'; Name = 'SequentialAppx' }) }

                $result = @(
                    Get-ProtectionEvidence `
                        -ServiceRegistrySnapshot @() `
                        -ParallelSupplementalEvidence
                )

                @($result | ForEach-Object Name) | Should -Contain 'SequentialWfp'
                @($result | ForEach-Object Name) | Should -Contain 'SequentialNdis'
                @($result | ForEach-Object Name) | Should -Contain 'SequentialMsi'
                @($result | ForEach-Object Name) | Should -Contain 'SequentialInf'
                @($result | ForEach-Object Name) | Should -Contain 'SequentialTask'
                @($result | ForEach-Object Name) | Should -Contain 'SequentialAppx'
                Should -Invoke Get-SupplementalProtectionEvidence -Times 1 -Exactly
                Should -Invoke Get-WfpStateEvidence -Times 1 -Exactly
            }

            It 'returns empty when no evidence sources produce results' {
                $result = @(Get-ProtectionEvidence)
                $result.Count | Should -Be 0
            }

            It 'collects Security Center antivirus and firewall evidence with metadata fallbacks' {
                Mock Get-CimInstance {
                    [pscustomobject]@{
                        displayName            = 'CrowdStrike Falcon Sensor'
                        pathToSignedProductExe = 'C:\Program Files\CrowdStrike\sensor.exe'
                    }
                } -ParameterFilter { $Namespace -eq 'root/SecurityCenter2' -and $ClassName -eq 'AntivirusProduct' }
                Mock Get-CimInstance {
                    [pscustomobject]@{
                        displayName            = 'Contoso Firewall'
                        pathToSignedProductExe = 'C:\Program Files\Contoso\firewall.exe'
                    }
                } -ParameterFilter { $Namespace -eq 'root/SecurityCenter2' -and $ClassName -eq 'FirewallProduct' }
                Mock Get-FileMetadatum {
                    if ($Path -like '*sensor.exe') {
                        [pscustomobject]@{
                            CompanyName     = 'CrowdStrike, Inc.'
                            FileDescription = 'Falcon Sensor'
                            ProductName     = 'Falcon'
                            SignerSubject   = 'CN=CrowdStrike'
                            InferredVendor  = 'CrowdStrike'
                        }
                    }
                }
                Mock Resolve-VendorFromText { 'Contoso' }

                $result = @(Get-ProtectionEvidence)
                $antivirus = $result | Where-Object ProductClass -EQ 'AntivirusProduct'
                $firewall = $result | Where-Object ProductClass -EQ 'FirewallProduct'

                $antivirus.CompanyName | Should -Be 'CrowdStrike, Inc.'
                $antivirus.InferredVendor | Should -Be 'CrowdStrike'
                $firewall.CompanyName | Should -BeNullOrEmpty
                $firewall.InferredVendor | Should -Be 'Contoso'
            }

            It 'collects service and driver evidence with operational state' {
                Mock Get-CimInstance {
                    [pscustomobject]@{
                        Name        = 'CSFalconService'
                        DisplayName = 'CrowdStrike Falcon Sensor'
                        PathName    = 'C:\Program Files\CrowdStrike\sensor.exe'
                        State       = 'Running'
                        StartMode   = 'Auto'
                        ServiceType = 'Own Process'
                    }
                } -ParameterFilter { $ClassName -eq 'Win32_Service' }
                Mock Get-CimInstance {
                    [pscustomobject]@{
                        Name        = 'ContosoFilter'
                        DisplayName = 'Contoso Filter Driver'
                        PathName    = 'C:\Windows\System32\drivers\contoso.sys'
                        State       = 'Running'
                        StartMode   = 'System'
                        ServiceType = 'Kernel Driver'
                    }
                } -ParameterFilter { $ClassName -eq 'Win32_SystemDriver' }
                Mock Get-FileMetadatum {
                    if ($Path -like '*sensor.exe') {
                        [pscustomobject]@{
                            CompanyName     = 'CrowdStrike, Inc.'
                            FileDescription = 'Falcon Sensor'
                            ProductName     = 'Falcon'
                            SignerSubject   = 'CN=CrowdStrike'
                            InferredVendor  = 'CrowdStrike'
                        }
                    }
                }
                Mock Resolve-VendorFromText { 'Contoso' }

                $result = @(Get-ProtectionEvidence)
                $service = $result | Where-Object Source -EQ 'Service'
                $driver = $result | Where-Object Source -EQ 'Driver'

                $service.State | Should -Be 'Running'
                $service.InferredVendor | Should -Be 'CrowdStrike'
                $driver.ServiceType | Should -Be 'Kernel Driver'
                $driver.InferredVendor | Should -Be 'Contoso'
            }

            It 'falls back to textual vendor detection when file metadata has no inferred vendor' {
                Mock Get-CimInstance {
                    [pscustomobject]@{
                        displayName            = 'Contoso Endpoint'
                        pathToSignedProductExe = 'C:\Contoso\endpoint.exe'
                    }
                } -ParameterFilter { $Namespace -eq 'root/SecurityCenter2' -and $ClassName -eq 'AntivirusProduct' }
                Mock Get-CimInstance {
                    [pscustomobject]@{
                        displayName            = 'Contoso Firewall'
                        pathToSignedProductExe = 'C:\Contoso\firewall.exe'
                    }
                } -ParameterFilter { $Namespace -eq 'root/SecurityCenter2' -and $ClassName -eq 'FirewallProduct' }
                Mock Get-CimInstance {
                    [pscustomobject]@{
                        Name = 'ContosoService'; DisplayName = 'Contoso Service'
                        PathName = 'C:\Contoso\service.exe'; State = 'Running'
                        StartMode = 'Auto'; ServiceType = 'Own Process'
                    }
                } -ParameterFilter { $ClassName -eq 'Win32_Service' }
                Mock Get-CimInstance {
                    [pscustomobject]@{
                        Name = 'ContosoDriver'; DisplayName = 'Contoso Driver'
                        PathName = 'C:\Contoso\driver.sys'; State = 'Running'
                        StartMode = 'System'; ServiceType = 'Kernel Driver'
                    }
                } -ParameterFilter { $ClassName -eq 'Win32_SystemDriver' }
                Mock Get-FileMetadatum {
                    [pscustomobject]@{
                        CompanyName = 'Contoso'; FileDescription = 'Endpoint component'
                        ProductName = 'Contoso Endpoint'; SignerSubject = 'CN=Contoso'
                        InferredVendor = $null
                    }
                }
                Mock Resolve-VendorFromText { 'Contoso' }

                $result = @(Get-ProtectionEvidence)

                @($result | Where-Object {
                    $_.Source -in @('SecurityCenter2', 'Service', 'Driver') -and
                    $_.InferredVendor -eq 'Contoso'
                }).Count | Should -Be 4
            }

            It 'collects uninstall evidence with metadata and registry fallbacks' {
                Mock Get-ItemProperty {
                    @(
                        [pscustomobject]@{
                            DisplayName     = 'CrowdStrike Falcon Sensor'
                            DisplayIcon     = 'C:\Program Files\CrowdStrike\sensor.exe,0'
                            Publisher       = 'CrowdStrike, Inc.'
                            InstallLocation = 'C:\Program Files\CrowdStrike'
                            UninstallString = 'msiexec /x {FALCON}'
                        },
                        [pscustomobject]@{
                            DisplayName     = 'Contoso Secure Client'
                            DisplayIcon     = $null
                            Publisher       = 'Contoso'
                            InstallLocation = 'C:\Program Files\Contoso'
                            UninstallString = 'uninstall.exe'
                        }
                    )
                } -ParameterFilter { $Path -notlike '*WOW6432Node*' }
                Mock Get-FileMetadatum {
                    [pscustomobject]@{
                        CompanyName     = 'CrowdStrike, Inc.'
                        FileDescription = 'Falcon Sensor'
                        ProductName     = 'Falcon'
                        SignerSubject   = 'CN=CrowdStrike'
                        InferredVendor  = 'CrowdStrike'
                    }
                }
                Mock Resolve-VendorFromText { 'Contoso' }

                $result = @(Get-ProtectionEvidence | Where-Object Source -EQ 'Uninstall')

                $result.Count | Should -Be 2
                ($result | Where-Object Name -EQ 'CrowdStrike Falcon Sensor').ProductName | Should -Be 'Falcon'
                ($result | Where-Object Name -EQ 'Contoso Secure Client').CompanyName | Should -Be 'Contoso'
                ($result | Where-Object Name -EQ 'Contoso Secure Client').InferredVendor | Should -Be 'Contoso'
            }

            It 'collects minimal uninstall evidence for a real entry missing DisplayIcon, Publisher, InstallLocation, and UninstallString' {
                # A real Uninstall subkey (common for hotfix/update entries) may
                # have only DisplayName set - Get-ItemProperty's returned object
                # then genuinely lacks the other properties, not just null values.
                Mock Get-ItemProperty {
                    @([pscustomobject]@{ DisplayName = 'Minimal App' })
                } -ParameterFilter { $Path -notlike '*WOW6432Node*' }

                { $script:MinimalUninstallResult = @(Get-ProtectionEvidence | Where-Object Source -EQ 'Uninstall') } |
                    Should -Not -Throw

                $script:MinimalUninstallResult.Count | Should -Be 1
                $script:MinimalUninstallResult[0].Name | Should -Be 'Minimal App'
                $script:MinimalUninstallResult[0].Publisher | Should -BeNullOrEmpty
                $script:MinimalUninstallResult[0].InstallPath | Should -BeNullOrEmpty
                $script:MinimalUninstallResult[0].UninstallString | Should -BeNullOrEmpty
            }

            It 'normalizes adapter GUIDs and preserves adapter identity evidence' {
                Mock Get-NetAdapter {
                    @(
                        [pscustomobject]@{
                            Name                 = 'Falcon Adapter'
                            InterfaceDescription = 'CrowdStrike Network Filter'
                            DriverDescription    = 'CrowdStrike Driver'
                            DriverFileName       = 'csfilter.sys'
                            InterfaceGuid        = [pscustomobject]@{ Guid = [guid]'11111111-2222-3333-4444-555555555555' }
                            MacAddress            = '00-11-22-33-44-55'
                            Status                = 'Up'
                        },
                        [pscustomobject]@{
                            Name                 = 'Contoso Adapter'
                            InterfaceDescription = 'Contoso VPN'
                            DriverDescription    = 'Contoso Driver'
                            DriverFileName       = 'contoso.sys'
                            InterfaceGuid        = '{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}'
                            MacAddress            = 'AA-BB-CC-DD-EE-FF'
                            Status                = 'Disconnected'
                        },
                        [pscustomobject]@{
                            Name                 = 'Unknown Adapter'
                            InterfaceDescription = 'Unknown'
                            DriverDescription    = 'Unknown'
                            DriverFileName       = 'unknown.sys'
                            InterfaceGuid        = $null
                            MacAddress            = $null
                            Status                = 'Not Present'
                        }
                    )
                }
                Mock Resolve-VendorFromText { 'DetectedVendor' }

                $result = @(Get-ProtectionEvidence | Where-Object Source -EQ 'NetAdapter')

                $result.Count | Should -Be 3
                $result[0].InterfaceGuid | Should -Be '11111111-2222-3333-4444-555555555555'
                $result[1].InterfaceGuid | Should -Be 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
                $result[2].InterfaceGuid | Should -BeNullOrEmpty
                $result[0].InferredVendor | Should -Be 'DetectedVendor'
            }

            It 'collects PnP network-device evidence' {
                Mock Get-PnpDevice {
                    [pscustomobject]@{
                        FriendlyName = 'Cisco Secure Client Adapter'
                        Manufacturer = 'Cisco Systems'
                        InstanceId   = 'ROOT\NET\0001'
                        Status       = 'OK'
                        Class        = 'Net'
                    }
                }
                Mock Resolve-VendorFromText { 'Cisco' }

                $result = @(Get-ProtectionEvidence | Where-Object Source -EQ 'PnpDevice')

                $result.Count | Should -Be 1
                $result[0].Manufacturer | Should -Be 'Cisco Systems'
                $result[0].InstanceId | Should -Be 'ROOT\NET\0001'
                $result[0].InferredVendor | Should -Be 'Cisco'
            }

            It 'collects service-registry evidence and skips unreadable service keys' {
                Mock Get-RegistryChildKeyNamesSafe { @('UnreadableService', 'CSFalconService') }
                Mock Get-RegistryValuesSafe {
                    if ($RegistryPath -like '*CSFalconService') {
                        [pscustomobject]@{
                            ImagePath   = 'C:\Program Files\CrowdStrike\sensor.exe'
                            DisplayName = 'CrowdStrike Falcon Sensor'
                            Start       = 2
                            Type        = 16
                            Group       = 'NetworkProvider'
                        }
                    }
                }
                Mock Get-FileMetadatum {
                    [pscustomobject]@{
                        CompanyName     = 'CrowdStrike, Inc.'
                        FileDescription = 'Falcon Sensor'
                        ProductName     = 'Falcon'
                        SignerSubject   = 'CN=CrowdStrike'
                        InferredVendor  = 'CrowdStrike'
                    }
                }

                $result = @(Get-ProtectionEvidence | Where-Object Source -EQ 'ServiceRegistry')

                $result.Count | Should -Be 1
                $result[0].Name | Should -Be 'CSFalconService'
                $result[0].ServiceRegistryPath | Should -Be 'HKLM\SYSTEM\CurrentControlSet\Services\CSFalconService'
                $result[0].Start | Should -Be 2
            }

            It 'collects partial service-registry evidence when a real service is missing Group, DisplayName, Start, and Type' {
                # A real service key very commonly has only a subset of these
                # values populated (empirically: ~50% of real services lack
                # Group, ~9% lack DisplayName, on a real Windows machine).
                Mock Get-RegistryChildKeyNamesSafe { @('MinimalService') }
                Mock Get-RegistryValuesSafe {
                    [pscustomobject]@{
                        ImagePath = 'C:\Program Files\Contoso\minimal.exe'
                    }
                }

                { $script:MinimalResult = @(Get-ProtectionEvidence | Where-Object Source -EQ 'ServiceRegistry') } |
                    Should -Not -Throw

                $script:MinimalResult.Count | Should -Be 1
                $script:MinimalResult[0].Name | Should -Be 'MinimalService'
                $script:MinimalResult[0].Path | Should -Be 'C:\Program Files\Contoso\minimal.exe'
                $script:MinimalResult[0].DisplayName | Should -BeNullOrEmpty
                $script:MinimalResult[0].Start | Should -BeNullOrEmpty
                $script:MinimalResult[0].Type | Should -BeNullOrEmpty
                $script:MinimalResult[0].Group | Should -BeNullOrEmpty
            }

            It 'still collects evidence for other services when an earlier service is missing registry values' {
                # Regression guard: the whole per-service loop shares a single
                # try/catch, so one service missing a property must not
                # silently drop every other service's evidence too.
                Mock Get-RegistryChildKeyNamesSafe { @('MinimalService', 'CSFalconService') }
                Mock Get-RegistryValuesSafe {
                    if ($RegistryPath -like '*CSFalconService') {
                        [pscustomobject]@{
                            ImagePath   = 'C:\Program Files\CrowdStrike\sensor.exe'
                            DisplayName = 'CrowdStrike Falcon Sensor'
                            Start       = 2
                            Type        = 16
                            Group       = 'NetworkProvider'
                        }
                    }
                    else {
                        [pscustomobject]@{ ImagePath = 'C:\Program Files\Contoso\minimal.exe' }
                    }
                }

                $result = @(Get-ProtectionEvidence | Where-Object Source -EQ 'ServiceRegistry')

                @($result | Where-Object Name -EQ 'MinimalService').Count | Should -Be 1
                @($result | Where-Object Name -EQ 'CSFalconService').Count | Should -Be 1
            }

            It 'inspects a service binary only once across CIM and registry evidence' {
                Mock Get-CimInstance {
                    [pscustomobject]@{
                        Name        = 'ContosoService'
                        DisplayName = 'Contoso Service'
                        PathName    = 'C:\Program Files\Contoso\agent.exe'
                        State       = 'Running'
                        StartMode   = 'Auto'
                        ServiceType = 'Own Process'
                    }
                } -ParameterFilter { $ClassName -eq 'Win32_Service' }
                Mock Get-RegistryChildKeyNamesSafe { @('ContosoService') }
                Mock Get-RegistryValuesSafe {
                    [pscustomobject]@{
                        ImagePath   = '"C:\Program Files\Contoso\agent.exe" --service'
                        DisplayName = 'Contoso Service'
                        Start       = 2
                        Type        = 16
                        Group       = $null
                    }
                }
                Mock Get-NormalizedFilePathFromCommandLine { 'C:\Program Files\Contoso\agent.exe' }
                Mock Get-FileMetadatum {
                    [pscustomobject]@{
                        Path            = 'C:\Program Files\Contoso\agent.exe'
                        CompanyName     = 'Contoso'
                        FileDescription = 'Contoso Agent'
                        ProductName     = 'Contoso Endpoint'
                        SignerSubject   = 'CN=Contoso'
                        InferredVendor  = 'Contoso'
                    }
                }

                $result = @(Get-ProtectionEvidence)

                @($result | Where-Object Source -In @('Service', 'ServiceRegistry')).Count | Should -Be 2
                Should -Invoke Get-FileMetadatum -Times 1 -Exactly
            }

            It 'isolates unavailable native evidence sources and retains supplemental evidence' {
                Mock Get-CimInstance { throw 'cim-failure' }
                Mock Get-ItemProperty { throw 'registry-failure' }
                Mock Get-NetAdapter { throw 'adapter-failure' }
                Mock Get-PnpDevice { throw 'pnp-failure' }
                Mock Get-RegistryChildKeyNamesSafe { throw 'service-registry-failure' }
                Mock Get-WfpStateEvidence { @([pscustomobject]@{ Vendor = 'CrowdStrike'; Evidence = 'WFP' }) }

                $res = @(Get-ProtectionEvidence)
                $res.Count | Should -Be 1
                $res[0].Evidence | Should -Be 'WFP'
            }
        }

        Context 'Get-ProtectionInventory' {

            BeforeEach {
                Mock Get-VendorSignature {
                    @{
                        CrowdStrike = @{
                            Categories    = @('EDR')
                            Patterns      = @('crowdstrike', 'csfalcon')
                            RegistryRoots = @('HKLM\SOFTWARE\CrowdStrike')
                        }
                    }
                }
                Mock Get-ServiceRegistryMap { @{} }
                Mock Get-ServiceRegistrySnapshot { @() }
                Mock Get-AdapterRegistryCorrelation { @() }
            }

            It 'collects the service registry once and shares that snapshot' {
                $script:serviceSnapshot = @(
                    [pscustomobject]@{
                        Name         = 'ContosoFilter'
                        RegistryPath = 'HKLM\SYSTEM\CurrentControlSet\Services\ContosoFilter'
                    }
                )
                Mock Get-ServiceRegistrySnapshot { $script:serviceSnapshot }
                Mock Get-ProtectionEvidence { @() }

                $result = @(Get-ProtectionInventory)

                $result.Count | Should -Be 0
                Should -Invoke Get-ServiceRegistrySnapshot -Times 1 -Exactly
                Should -Invoke Get-ProtectionEvidence -Times 1 -Exactly -ParameterFilter {
                    @($ServiceRegistrySnapshot).Count -eq 1 -and
                    $ServiceRegistrySnapshot[0].Name -eq 'ContosoFilter'
                }
                Should -Invoke Get-ServiceRegistryMap -Times 1 -Exactly -ParameterFilter {
                    @($Snapshot).Count -eq 1 -and
                    $Snapshot[0].Name -eq 'ContosoFilter'
                }
            }

            It 'builds vendor inventory from evidence' {
                Mock Get-ProtectionEvidence {
                    @(
                        [pscustomobject]@{
                            Source               = 'Service'
                            ProductClass         = 'Service'
                            Name                 = 'CSFalconService'
                            DisplayName          = 'CrowdStrike Falcon Sensor'
                            Path                 = 'C:\Program Files\CrowdStrike\sensor.exe'
                            Publisher            = 'CrowdStrike'
                            InstallPath          = $null
                            InterfaceDescription = $null
                            Manufacturer         = 'CrowdStrike'
                            CompanyName          = 'CrowdStrike'
                            FileDescription      = 'Falcon Sensor'
                            ProductName          = 'CrowdStrike Falcon Sensor'
                            SignerSubject        = 'CN=CrowdStrike'
                            InferredVendor       = 'CrowdStrike'
                            Instance             = $null
                        }
                    )
                }

                $result = @(Get-ProtectionInventory)

                $result.Count | Should -Be 1
                $result[0].Vendor | Should -Be 'CrowdStrike'
                @($result[0].Services) | Should -Contain 'CSFalconService'
            }

            It 'returns empty inventory when no evidence exists' {
                Mock Get-ProtectionEvidence { @() }

                $result = @(Get-ProtectionInventory)
                $result.Count | Should -Be 0
            }

            It 'correlates service, driver, adapter, registry, and filter evidence into protection boundaries' {
                $script:complexEvidence = @(
                    @{ Source = 'Service'; Name = 'vmfalconvpnfire' }
                    @{ Source = 'ServiceRegistry'; Name = 'RegistryService'; RegistryPath = 'HKLM\SOFTWARE\CrowdStrike\Service' }
                    @{ Source = 'NDIS'; Name = 'NdisFilter'; RegistryPath = 'HKLM\SYSTEM\CurrentControlSet\Services\NdisFilter' }
                    @{ Source = 'Driver'; Name = 'vboxdriver' }
                    @{
                        Source               = 'NetAdapter'
                        Name                 = 'FalconAdapter'
                        DisplayName          = 'VMware VPN Adapter'
                        InterfaceDescription = 'vEthernet VMware'
                        InterfaceGuid        = '11111111-2222-3333-4444-555555555555'
                    }
                    @{ Source = 'WFP'; Name = 'FalconProvider' }
                    @{ Source = 'UnknownSource'; Name = 'AdditionalEvidence' }
                ) | ForEach-Object {
                    $record = [ordered]@{
                        Source               = $_['Source']
                        Name                 = $_['Name']
                        DisplayName          = $_['DisplayName']
                        Path                 = $null
                        InterfaceDescription = $_['InterfaceDescription']
                        CompanyName          = 'CrowdStrike'
                        InferredVendor       = 'CrowdStrike'
                        InstallPath          = $null
                    }
                    foreach ($optionalProperty in @('RegistryPath', 'InterfaceGuid')) {
                        if ($_.ContainsKey($optionalProperty)) {
                            $record[$optionalProperty] = $_[$optionalProperty]
                        }
                    }
                    [pscustomobject]$record
                }
                Mock Get-ProtectionEvidence { $script:complexEvidence }
                Mock Test-VendorPatternMatch { $true }
                Mock Get-ServiceRegistryMap {
                    @{
                        vmfalconvpnfire = [pscustomobject]@{
                            RegistryPath  = 'HKLM\SYSTEM\CurrentControlSet\Services\vmfalconvpnfire'
                            EnumPath      = 'HKLM\SYSTEM\CurrentControlSet\Services\vmfalconvpnfire\Enum'
                            LinkagePath   = 'HKLM\SYSTEM\CurrentControlSet\Services\vmfalconvpnfire\Linkage'
                            ParamsPath    = 'HKLM\SYSTEM\CurrentControlSet\Services\vmfalconvpnfire\Parameters'
                            InstancesPath = 'HKLM\SYSTEM\CurrentControlSet\Services\vmfalconvpnfire\Instances'
                            ImagePath     = 'C:\Program Files\CrowdStrike\sensor.exe'
                        }
                        vboxdriver = [pscustomobject]@{
                            RegistryPath  = 'HKLM\SYSTEM\CurrentControlSet\Services\vboxdriver'
                            EnumPath      = $null
                            LinkagePath   = 'HKLM\SYSTEM\CurrentControlSet\Services\vboxdriver\Linkage'
                            ParamsPath    = $null
                            InstancesPath = $null
                            ImagePath     = 'C:\Windows\System32\drivers\vboxdriver.sys'
                        }
                    }
                }
                Mock Get-AdapterRegistryCorrelation {
                    [pscustomobject]@{
                        ComponentId    = 'crowdstrike_filter'
                        DriverDesc     = 'CrowdStrike Network Adapter'
                        ProviderName   = 'CrowdStrike, Inc.'
                        InterfaceGuid  = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
                        ClassPath      = 'HKLM\SYSTEM\Class\0001'
                        NetworkPath    = 'HKLM\SYSTEM\Network\{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}'
                        ConnectionPath = 'HKLM\SYSTEM\Network\{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}\Connection'
                        TcpipPath      = 'HKLM\SYSTEM\Tcpip\{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}'
                    }
                }
                Mock Get-FileMetadatum { [pscustomobject]@{ Path = 'C:\Program Files\CrowdStrike\sensor.exe' } }

                $result = @(Get-ProtectionInventory)

                $result.Count | Should -Be 1
                @($result[0].Services) | Should -Contain 'vmfalconvpnfire'
                @($result[0].Services) | Should -Contain 'NdisFilter'
                @($result[0].Drivers) | Should -Contain 'vboxdriver'
                @($result[0].ProtectedInterfaceGuids) | Should -Contain '11111111-2222-3333-4444-555555555555'
                @($result[0].ProtectedInterfaceGuids) | Should -Contain 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
                @($result[0].RegistryKeys) | Should -Contain 'HKLM\SYSTEM\CurrentControlSet\Services\vmfalconvpnfire\Parameters'
                @($result[0].RegistryKeys) | Should -Contain 'HKLM\SYSTEM\Class\0001'
                @($result[0].Categories) | Should -Contain 'NetworkFilter'
                @($result[0].Categories) | Should -Contain 'Hypervisor'
                @($result[0].Categories) | Should -Contain 'VPN'
                $result[0].Confidence | Should -Be 100
            }

            It 'infers VirtualBox, Sentinel, Defender, and Hyper-V protection categories' {
                $script:categoryEvidence = @(
                    @{ Source = 'Service'; Name = 'vboxfilter'; DisplayName = 'VirtualBox Filter' }
                    @{ Source = 'Service'; Name = 'SentinelAgent'; DisplayName = 'Sentinel Agent' }
                    @{ Source = 'Service'; Name = 'DefenderService'; DisplayName = 'Defender Service' }
                    @{ Source = 'NetAdapter'; Name = 'VirtualBox'; DisplayName = 'VirtualBox Adapter'; InterfaceDescription = 'VirtualBox Host-Only Ethernet Adapter' }
                    @{ Source = 'NetAdapter'; Name = 'VBox'; DisplayName = 'VBox Adapter'; InterfaceDescription = 'VBox Network Adapter' }
                    @{ Source = 'NetAdapter'; Name = 'Hyper-V'; DisplayName = 'Hyper-V Adapter'; InterfaceDescription = 'Hyper-V Virtual Ethernet Adapter' }
                ) | ForEach-Object {
                    [pscustomobject]@{
                        Source               = $_.Source
                        Name                 = $_.Name
                        DisplayName          = $_.DisplayName
                        Path                 = $null
                        InterfaceDescription = $_['InterfaceDescription']
                        CompanyName          = 'CrowdStrike'
                        InferredVendor       = 'CrowdStrike'
                        InstallPath          = $null
                    }
                }
                Mock Get-ProtectionEvidence { $script:categoryEvidence }
                Mock Test-VendorPatternMatch { $true }

                $result = @(Get-ProtectionInventory)

                @($result[0].Categories) | Should -Contain 'VirtualAdapter'
                @($result[0].Categories) | Should -Contain 'Hypervisor'
                @($result[0].Categories) | Should -Contain 'EDR'
                @($result[0].Categories) | Should -Contain 'XDR'
                @($result[0].Categories) | Should -Contain 'AV'
            }
        }

        Context 'Get-ProtectionRegistryMap' {

            It 'returns a registry map based on inventory' {
                Mock Get-ProtectionInventory {
                    @(
                        [pscustomobject]@{
                            Vendor                  = 'CrowdStrike'
                            Categories              = @('EDR')
                            Confidence              = 100
                            Services                = @('CSFalconService')
                            Drivers                 = @('csagent')
                            Adapters                = @('CrowdStrike Adapter')
                            ProtectedInterfaceGuids = @('aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee')
                            RegistryKeys            = @('HKLM\SOFTWARE\CrowdStrike')
                            Evidence                = @('Service | CSFalconService')
                        }
                    )
                }

                $result = @(Get-ProtectionRegistryMap)
                $result.Count | Should -Be 1
                $result[0].Vendor | Should -Be 'CrowdStrike'
                @($result[0].RegistryKeys) | Should -Contain 'HKLM\SOFTWARE\CrowdStrike'
            }

            It 'returns empty when inventory is empty' {
                Mock Get-ProtectionInventory { @() }

                $result = @(Get-ProtectionRegistryMap)
                $result.Count | Should -Be 0
            }
        }

        Context 'Get-ProtectedInterfaceGuidSet' {

            It 'returns distinct protected interface GUIDs from inventory' {
                Mock Get-ProtectionInventory {
                    @(
                        [pscustomobject]@{
                            Vendor                  = 'CrowdStrike'
                            ProtectedInterfaceGuids = @(
                                'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
                                'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
                            )
                        }
                        [pscustomobject]@{
                            Vendor                  = 'Cisco'
                            ProtectedInterfaceGuids = @('11111111-2222-3333-4444-555555555555')
                        }
                    )
                }

                $result = @(Get-ProtectedInterfaceGuidSet)
                $result.Count | Should -Be 2
                $result | Should -Contain 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
                $result | Should -Contain '11111111-2222-3333-4444-555555555555'
            }

            It 'returns empty when no protected GUIDs exist' {
                Mock Get-ProtectionInventory { @() }

                $result = @(Get-ProtectedInterfaceGuidSet)
                $result.Count | Should -Be 0
            }
        }

        Context 'Get-NetworkPrivacyArtifactCandidate' {

            It 'returns candidate artifacts when registry paths exist' {
                Mock Test-RegistryPathExist { $true }
                Mock Get-RegistryChildKeyNamesSafe { @('Profile1') }

                $result = @(Get-NetworkPrivacyArtifactCandidate -Inventory @())
                $result.Count | Should -BeGreaterThan 0
                @($result | Where-Object { $_.Decision -notin @('Remove', 'Preserve') }).Count | Should -Be 0
                @($result | Where-Object { [string]::IsNullOrWhiteSpace($_.Reason) }).Count | Should -Be 0
            }

            It 'identifies the vendor protecting each correlated interface path' {
                $guid = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
                Mock Test-RegistryPathExist { $true }
                Mock Get-RegistryChildKeyNamesSafe { @($guid) }
                $inventory = @(
                    [pscustomobject]@{
                        Vendor                  = 'CrowdStrike'
                        ProtectedInterfaceGuids = @($guid)
                    }
                )

                $result = @(
                    Get-NetworkPrivacyArtifactCandidate -Inventory $inventory |
                        Where-Object { $_.InterfaceGuid -eq $guid }
                )

                $result.Count | Should -BeGreaterThan 0
                @($result | Where-Object Decision -NE 'Preserve').Count | Should -Be 0
                @($result | Where-Object { $_.ProtectionSource -notmatch 'CrowdStrike' }).Count | Should -Be 0
                @($result | Where-Object { $_.Reason -notmatch 'CrowdStrike' }).Count | Should -Be 0
            }

            It 'returns empty when candidate paths do not exist' {
                Mock Test-RegistryPathExist { $false }
                Mock Get-RegistryChildKeyNamesSafe { @() }

                $result = @(Get-NetworkPrivacyArtifactCandidate -Inventory @())
                $result.Count | Should -Be 0
            }
        }

        Context 'Get-NetworkProfileDecision' {

            It 'marks a user Wi-Fi profile as removable with no protection source' {
                $result = @(
                    Get-NetworkProfileDecision -WiFiProfiles @(
                        [pscustomobject]@{ Name = 'HomeSSID'; IsPolicyManaged = $false }
                    )
                )

                $result.Count | Should -Be 1
                $result[0].ArtifactType | Should -Be 'WiFiProfile'
                $result[0].NetworkType | Should -Be 'Wi-Fi'
                $result[0].Decision | Should -Be 'Remove'
                $result[0].IsProtected | Should -BeFalse
                $result[0].CanSanitize | Should -BeTrue
                $result[0].ProtectionSource | Should -BeNullOrEmpty
                $result[0].Reason | Should -Match 'Saved user Wi-Fi profile'
            }

            It 'marks a Group Policy Wi-Fi profile as preserved with a protection source' {
                $result = @(
                    Get-NetworkProfileDecision -WiFiProfiles @(
                        [pscustomobject]@{ Name = 'CorpSSID'; IsPolicyManaged = $true }
                    )
                )

                $result.Count | Should -Be 1
                $result[0].Decision | Should -Be 'Preserve'
                $result[0].IsProtected | Should -BeTrue
                $result[0].CanSanitize | Should -BeFalse
                $result[0].ProtectionSource | Should -Be 'Windows Group Policy'
                $result[0].Reason | Should -Match 'Group Policy'
            }

            It 'skips Wi-Fi profile records without a name' {
                $result = @(
                    Get-NetworkProfileDecision -WiFiProfiles @(
                        [pscustomobject]@{ Name = $null; IsPolicyManaged = $false }
                    )
                )

                $result.Count | Should -Be 0
            }

            It 'labels a NetworkList profile as Wi-Fi history when its name matches a discovered Wi-Fi profile' {
                $result = @(
                    Get-NetworkProfileDecision `
                        -WiFiProfiles @([pscustomobject]@{ Name = 'HomeSSID'; IsPolicyManaged = $false }) `
                        -NetworkListProfiles @([pscustomobject]@{ Name = 'HomeSSID'; RegistryPath = 'HKLM\...\Profiles\{GUID}'; ProfileGuid = '{GUID}' })
                )

                $networkListEntry = $result | Where-Object ArtifactType -EQ 'NetworkListProfile'
                $networkListEntry.NetworkType | Should -Be 'Wi-Fi history'
                $networkListEntry.Decision | Should -Be 'Remove'
                $networkListEntry.IsProtected | Should -BeFalse
                $networkListEntry.CanSanitize | Should -BeTrue
                $networkListEntry.ProfileGuid | Should -Be '{GUID}'
            }

            It 'labels a NetworkList profile as LAN/other history when its name has no matching Wi-Fi profile' {
                $result = @(
                    Get-NetworkProfileDecision -NetworkListProfiles @(
                        [pscustomobject]@{ Name = 'OfficeLAN'; RegistryPath = 'HKLM\...\Profiles\{GUID2}'; ProfileGuid = '{GUID2}' }
                    )
                )

                $result.Count | Should -Be 1
                $result[0].NetworkType | Should -Be 'LAN/other history'
                $result[0].Decision | Should -Be 'Remove'
            }

            It 'skips NetworkList profile records without a name' {
                $result = @(
                    Get-NetworkProfileDecision -NetworkListProfiles @(
                        [pscustomobject]@{ Name = ''; RegistryPath = 'HKLM\...\Profiles\{GUID3}' }
                    )
                )

                $result.Count | Should -Be 0
            }

            It 'returns an empty array when no profiles are supplied' {
                $result = @(Get-NetworkProfileDecision)
                $result.Count | Should -Be 0
            }
        }

        Context 'Get-SanitizableNetworkArtifact' {

            It 'filters out protected artifacts and keeps sanitizable ones' {
                Mock Get-NetworkPrivacyArtifactCandidate {
                    @(
                        [pscustomobject]@{
                            ArtifactType  = 'NetworkList'
                            RegistryPath  = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles'
                            InterfaceGuid = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
                            IsProtected   = $false
                            Reason        = 'history'
                        },
                        [pscustomobject]@{
                            ArtifactType  = 'NetworkList'
                            RegistryPath  = 'HKLM\SOFTWARE\Vendor\Protected'
                            InterfaceGuid = '11111111-2222-3333-4444-555555555555'
                            IsProtected   = $true
                            Reason        = 'protected'
                        }
                    )
                }

                $result = @(Get-SanitizableNetworkArtifact -Inventory @())
                $result.Count | Should -Be 1
                $result[0].RegistryPath | Should -Be 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles'
            }

            It 'returns empty when no candidate artifacts are sanitizable' {
                Mock Get-NetworkPrivacyArtifactCandidate {
                    @(
                        [pscustomobject]@{
                            ArtifactType  = 'NetworkList'
                            RegistryPath  = 'HKLM\SOFTWARE\Vendor\Protected'
                            InterfaceGuid = '11111111-2222-3333-4444-555555555555'
                            IsProtected   = $true
                            Reason        = 'protected'
                        }
                    )
                }

                $result = @(Get-SanitizableNetworkArtifact -Inventory @())
                $result.Count | Should -Be 0
            }
        }

        Context 'Invoke-NetCleanPhase1Detect' {

            BeforeEach {
                Mock Get-ProtectionInventory {
                    @(
                        [pscustomobject]@{
                            Vendor                  = 'CrowdStrike'
                            Categories              = @('EDR')
                            Confidence              = 100
                            Services                = @('CSFalconService')
                            Drivers                 = @('csagent')
                            Adapters                = @('CrowdStrike Adapter')
                            ProtectedInterfaceGuids = @('aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee')
                            RegistryKeys            = @('HKLM\SOFTWARE\CrowdStrike')
                            Evidence                = @('Service | CSFalconService')
                        }
                    )
                }

                Mock Get-ProtectionRegistryMap {
                    @(
                        [pscustomobject]@{
                            Vendor                  = 'CrowdStrike'
                            Categories              = @('EDR')
                            Confidence              = 100
                            Services                = @('CSFalconService')
                            Drivers                 = @('csagent')
                            Adapters                = @('CrowdStrike Adapter')
                            ProtectedInterfaceGuids = @('aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee')
                            RegistryKeys            = @('HKLM\SOFTWARE\CrowdStrike')
                            Evidence                = @('Service | CSFalconService')
                        }
                    )
                }

                Mock Get-ProtectedInterfaceGuidSet {
                    @('aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee')
                }

                Mock Get-NetworkPrivacyArtifactCandidate {
                    @(
                        [pscustomobject]@{
                            ArtifactType  = 'NetworkList'
                            RegistryPath  = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles'
                            InterfaceGuid = $null
                            IsProtected   = $false
                            Reason        = 'history'
                        }
                    )
                }

                Mock Get-SanitizableNetworkArtifact {
                    @(
                        [pscustomobject]@{
                            ArtifactType  = 'NetworkList'
                            RegistryPath  = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles'
                            InterfaceGuid = $null
                            IsProtected   = $false
                            Reason        = 'history'
                        }
                    )
                }

                Mock Get-NetCleanDeviceManagementState {
                    [pscustomobject]@{
                        IsManaged      = $true
                        JoinType       = 'MicrosoftEntraJoined'
                        DomainJoined   = $false
                        EntraJoined    = $true
                        MdmEnrolled    = $true
                        WorkplaceJoined = $false
                    }
                }
                Mock Get-ServiceRegistrySnapshot { @([pscustomobject]@{ Name = 'CSFalconService' }) }
                Mock Get-WiFiProfileSnapshot {
                    @([pscustomobject]@{ Name = 'ConferenceSSID'; IsPolicyManaged = $false })
                }
                Mock Get-NetworkListProfileSnapshot {
                    @([pscustomobject]@{ Name = 'ConferenceSSID'; ProfileGuid = '{PROFILE}' })
                }
                Mock Get-NetworkProfileDecision {
                    @([pscustomobject]@{ Name = 'ConferenceSSID'; Decision = 'Remove'; Reason = 'Saved user Wi-Fi profile' })
                }
            }

            It 'returns a detect context with populated summary fields' {
                $ctx = Invoke-NetCleanPhase1Detect

                $ctx.Phase | Should -Be 'Detect'
                $ctx.Summary.ProtectedVendorsCount | Should -Be 1
                $ctx.Summary.ProtectedInterfaceGuidCount | Should -Be 1
                $ctx.Summary.CandidateArtifactCount | Should -Be 1
                $ctx.Summary.SanitizableArtifactCount | Should -Be 1
                $ctx.ManagementState.IsManaged | Should -BeTrue
                $ctx.Summary.ManagedDevice | Should -BeTrue
                $ctx.CollectionSnapshot.WiFiProfiles[0].Name | Should -Be 'ConferenceSSID'
                $ctx.CollectionSnapshot.NetworkListProfiles[0].ProfileGuid | Should -Be '{PROFILE}'
                $ctx.NetworkProfileDecisions[0].Decision | Should -Be 'Remove'
                Should -Invoke Get-WiFiProfileSnapshot -Times 1 -Exactly
                Should -Invoke Get-NetworkListProfileSnapshot -Times 1 -Exactly
            }

            It 'returns zero counts when no inventory or artifacts are found' {
                Mock Get-ProtectionInventory { @() }
                Mock Get-ProtectionRegistryMap { @() }
                Mock Get-ProtectedInterfaceGuidSet { @() }
                Mock Get-NetworkPrivacyArtifactCandidate { @() }
                Mock Get-SanitizableNetworkArtifact { @() }

                $ctx = Invoke-NetCleanPhase1Detect

                $ctx.Phase | Should -Be 'Detect'
                $ctx.Summary.ProtectedVendorsCount | Should -Be 0
                $ctx.Summary.ProtectedInterfaceGuidCount | Should -Be 0
                $ctx.Summary.CandidateArtifactCount | Should -Be 0
                $ctx.Summary.SanitizableArtifactCount | Should -Be 0
            }
        }
    }
}
