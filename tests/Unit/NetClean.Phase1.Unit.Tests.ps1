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
                Mock Get-ProtectionList { @('CrowdStrike', 'Cisco', 'VMware') }

                $result = Resolve-VendorFromText -Text 'CrowdStrike Falcon Sensor service'
                $result | Should -Be 'CrowdStrike'
            }

            It 'returns null when no vendor text matches' {
                Mock Get-ProtectionList { @('CrowdStrike', 'Cisco', 'VMware') }

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
                Mock Get-AdapterRegistryCorrelation { @() }
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
            }

            It 'returns empty when candidate paths do not exist' {
                Mock Test-RegistryPathExist { $false }
                Mock Get-RegistryChildKeyNamesSafe { @() }

                $result = @(Get-NetworkPrivacyArtifactCandidate -Inventory @())
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
