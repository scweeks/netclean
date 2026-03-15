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

            It 'returns a normalized vendor signature object when evidence exists' {
                $inventory = [pscustomobject]@{
                    Vendor                  = 'CrowdStrike'
                    Services                = @('CSFalconService')
                    Drivers                 = @('csagent')
                    Adapters                = @('CrowdStrike Adapter')
                    ProtectedInterfaceGuids = @('aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee')
                    RegistryKeys            = @('HKLM\SOFTWARE\CrowdStrike')
                    Evidence                = @('Service | CSFalconService')
                }

                $result = Get-VendorSignature -Item $inventory

                $result | Should -Not -BeNullOrEmpty
                $result.Vendor | Should -Be 'CrowdStrike'
            }

            It 'returns null when item is null' {
                $result = Get-VendorSignature -Item $null
                $result | Should -BeNullOrEmpty
            }
        }

        Context 'Get-WfpStateEvidence' {

            It 'returns evidence when firewall/WFP state is present' {
                Mock Get-RegistryValuesSafe {
                    [pscustomobject]@{
                        DisplayName = 'CrowdStrike WFP Provider'
                    }
                }

                $result = Get-WfpStateEvidence
                $result | Should -Not -BeNullOrEmpty
            }

            It 'returns empty when no WFP state evidence is present' {
                Mock Get-RegistryValuesSafe { $null }

                $result = @(Get-WfpStateEvidence)
                $result.Count | Should -Be 0
            }
        }

        Context 'Get-NdisFilterClassEvidence' {

            It 'returns evidence when NDIS filter classes are detected' {
                Mock Get-RegistryChildKeyNamesSafe { @('CrowdStrikeFilter') }
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
                Mock Get-ChildItem {
                    @([pscustomobject]@{ FullName = 'C:\Windows\INF\oem42.inf' })
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
                            Name      = 'Cisco.SecureClient'
                            Publisher = 'Cisco'
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

            It 'aggregates evidence from all enabled evidence sources' {
                Mock Get-WfpStateEvidence { @([pscustomobject]@{ Vendor = 'CrowdStrike'; Evidence = 'WFP' }) }
                Mock Get-NdisFilterClassEvidence { @([pscustomobject]@{ Vendor = 'CrowdStrike'; Evidence = 'NDIS' }) }
                Mock Get-NdisServiceBindingEvidence { @() }
                Mock Get-MsiRegistryEvidence { @() }
                Mock Get-InfFileEvidence { @() }
                Mock Get-ScheduledTaskEvidence { @() }
                Mock Get-AppxPackageEvidence { @() }

                $result = @(Get-ProtectionEvidence)
                $result.Count | Should -Be 2
            }

            It 'returns empty when no evidence sources produce results' {
                Mock Get-WfpStateEvidence { @() }
                Mock Get-NdisFilterClassEvidence { @() }
                Mock Get-NdisServiceBindingEvidence { @() }
                Mock Get-MsiRegistryEvidence { @() }
                Mock Get-InfFileEvidence { @() }
                Mock Get-ScheduledTaskEvidence { @() }
                Mock Get-AppxPackageEvidence { @() }

                $result = @(Get-ProtectionEvidence)
                $result.Count | Should -Be 0
            }

            It 'continues when Get-CimInstance throws for some classes' {
                Mock Get-CimInstance {
                    if ($ClassName -eq 'AntivirusProduct') { throw 'cim-failure' }
                    else { @() }
                }

                { Get-ProtectionEvidence } | Should -Not -Throw
                $res = @(Get-ProtectionEvidence)
                $res | Should -Be @() -Because 'No other evidence providers were mocked to return results'
            }
        }

        Context 'Get-ProtectionInventory' {

            It 'builds vendor inventory from evidence' {
                Mock Get-ProtectionEvidence {
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

                $result = @(Get-NetworkPrivacyArtifactCandidate)
                $result.Count | Should -BeGreaterThan 0
            }

            It 'returns empty when candidate paths do not exist' {
                Mock Test-RegistryPathExist { $false }

                $result = @(Get-NetworkPrivacyArtifactCandidate)
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

                $result = @(Get-SanitizableNetworkArtifact)
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

                $result = @(Get-SanitizableNetworkArtifact)
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
            }

            It 'returns a detect context with populated summary fields' {
                $ctx = Invoke-NetCleanPhase1Detect

                $ctx.Phase | Should -Be 'Detect'
                $ctx.Summary.ProtectedVendorsCount | Should -Be 1
                $ctx.Summary.ProtectedInterfaceGuidCount | Should -Be 1
                $ctx.Summary.CandidateArtifactCount | Should -Be 1
                $ctx.Summary.SanitizableArtifactCount | Should -Be 1
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