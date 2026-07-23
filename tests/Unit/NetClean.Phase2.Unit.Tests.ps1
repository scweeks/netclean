$manifestPath = Join-Path $PSScriptRoot '..\..\NetClean.psd1'

if (-not (Test-Path -LiteralPath $manifestPath)) {
    throw "NetClean.psd1 not found at path: $manifestPath"
}

Remove-Module NetClean -ErrorAction SilentlyContinue
Import-Module $manifestPath -Force

Describe 'NetClean Phase 2 unit tests' {

    InModuleScope 'NetClean' {

        BeforeEach {
            $script:LogFile = $null
        }

        Context 'Get-WiFiProfileName' {

            It 'returns Wi-Fi profile names parsed from netsh output' {
                Mock Invoke-NetCleanNativeCapture {
                    [pscustomobject]@{
                        Name      = 'List Wi-Fi profiles'
                        ExitCode  = 0
                        Succeeded = $true
                        Output    = @(
                            'Profiles on interface Wi-Fi:'
                            'Group policy profiles (read only)'
                            '<None>'
                            'User profiles'
                            '-------------'
                            '    All User Profile     : HomeSSID'
                            '    All User Profile     : OfficeSSID'
                        )
                        Error     = $null
                    }
                }

                $result = @(Get-WiFiProfileName)

                $result.Count | Should -Be 2
                $result | Should -Contain 'HomeSSID'
                $result | Should -Contain 'OfficeSSID'
            }

            It 'returns distinct profile names only' {
                Mock Invoke-NetCleanNativeCapture {
                    [pscustomobject]@{
                        Name      = 'List Wi-Fi profiles'
                        ExitCode  = 0
                        Succeeded = $true
                        Output    = @(
                            '    All User Profile     : HomeSSID'
                            '    All User Profile     : HomeSSID'
                            '    All User Profile     : OfficeSSID'
                        )
                        Error     = $null
                    }
                }

                $result = @(Get-WiFiProfileName)

                $result.Count | Should -Be 2
                @($result | Where-Object { $_ -eq 'HomeSSID' }).Count | Should -Be 1
            }

            It 'preserves profile names that differ only by case' {
                Mock Invoke-NetCleanNativeCapture {
                    [pscustomobject]@{
                        Name      = 'List Wi-Fi profiles'
                        ExitCode  = 0
                        Succeeded = $true
                        Output    = @(
                            '    All User Profile     : x-meh'
                            '    All User Profile     : X-meh'
                            '    All User Profile     : x-meh'
                        )
                        Error     = $null
                    }
                }

                $result = @(Get-WiFiProfileName)

                $result.Count | Should -Be 2
                $result | Should -Contain 'x-meh'
                $result | Should -Contain 'X-meh'
            }

            It 'classifies policy and user profiles in one native capture' {
                Mock Invoke-NetCleanNativeCapture {
                    [pscustomobject]@{
                        Name      = 'List Wi-Fi profiles'
                        ExitCode  = 0
                        Succeeded = $true
                        Output    = @(
                            'Group policy profiles (read only)'
                            '    Group Policy Profile : SchoolSSID'
                            'User profiles'
                            '    All User Profile     : ConferenceSSID'
                        )
                        Error     = $null
                    }
                }

                $result = @(Get-WiFiProfileSnapshot)

                $result.Count | Should -Be 2
                ($result | Where-Object Name -EQ 'SchoolSSID').IsPolicyManaged | Should -BeTrue
                ($result | Where-Object Name -EQ 'ConferenceSSID').IsPolicyManaged | Should -BeFalse
                Should -Invoke Invoke-NetCleanNativeCapture -Times 1 -Exactly
            }

            It 'captures netsh profile names as UTF-8 and restores the host encoding' {
                $originalEncoding = [Console]::OutputEncoding
                $testHostEncoding = [System.Text.Encoding]::GetEncoding(437)
                $profileName = 'Edward{0}s iPhone' -f [char]0x2019
                $script:captureEncoding = $null

                try {
                    [Console]::OutputEncoding = $testHostEncoding
                    Mock Invoke-NetCleanNativeCapture {
                        $script:captureEncoding = [Console]::OutputEncoding.WebName
                        [pscustomobject]@{
                            Name      = 'List Wi-Fi profiles'
                            ExitCode  = 0
                            Succeeded = $true
                            Output    = @("    All User Profile     : $profileName")
                            Error     = $null
                        }
                    }

                    $result = @(Get-WiFiProfileName)
                    $restoredEncoding = [Console]::OutputEncoding.WebName
                }
                finally {
                    [Console]::OutputEncoding = $originalEncoding
                }

                $script:captureEncoding | Should -Be 'utf-8'
                $restoredEncoding | Should -Be $testHostEncoding.WebName
                $result | Should -Be @($profileName)
            }

            It 'returns an empty collection when netsh returns no output' {
                Mock Invoke-NetCleanNativeCapture {
                    [pscustomobject]@{
                        Name      = 'List Wi-Fi profiles'
                        ExitCode  = 0
                        Succeeded = $true
                        Output    = @()
                        Error     = $null
                    }
                }

                @((Get-WiFiProfileName)).Count | Should -Be 0
            }

            It 'returns an empty collection when native capture reports failure' {
                Mock Invoke-NetCleanNativeCapture {
                    [pscustomobject]@{
                        Name      = 'List Wi-Fi profiles'
                        ExitCode  = 1
                        Succeeded = $false
                        Output    = @()
                        Error     = 'netsh failed'
                    }
                }

                @((Get-WiFiProfileName)).Count | Should -Be 0
            }

            It 'ignores null output and parses alternate profile labels' {
                Mock Invoke-NetCleanNativeCapture {
                    [pscustomobject]@{
                        Name      = 'List Wi-Fi profiles'
                        ExitCode  = 0
                        Succeeded = $true
                        Output    = @(
                            $null
                            '    Current Profile      : ConferenceSSID'
                        )
                        Error     = $null
                    }
                }

                $result = @(Get-WiFiProfileName)

                $result | Should -Be @('ConferenceSSID')
            }
        }

        Context 'Export-WiFiProfile' {

            BeforeEach {
                Mock New-DirectoryIfNotExist {}
            }

            It 'returns empty when no Wi-Fi profiles are detected' {
                Mock Get-WiFiProfileName { @() }

                $result = @(Export-WiFiProfile -Dest 'C:\backup')

                $result.Count | Should -Be 0
            }

            It 'returns planned outputs in dry-run mode' {
                Mock Get-WiFiProfileName { @('HomeSSID', 'OfficeSSID') }

                $result = @(Export-WiFiProfile -Dest 'C:\backup' -DryRun)

                $result.Count | Should -Be 3
                $result[0] | Should -Match 'WiFiProfiles_'
                $result | Should -Contain 'PROFILE:HomeSSID'
                $result | Should -Contain 'PROFILE:OfficeSSID'
                Should -Invoke New-DirectoryIfNotExist -Times 0
            }

            It 'uses supplied profile names without collecting them again' {
                Mock Get-WiFiProfileName { throw 'profiles should come from Phase 1' }

                $result = @(Export-WiFiProfile -Dest 'C:\backup' -Profiles @('HomeSSID') -DryRun)

                $result | Should -Contain 'PROFILE:HomeSSID'
                Should -Invoke Get-WiFiProfileName -Times 0 -Exactly
            }

            It 'writes the list file and records exported XMLs when bulk export succeeds' {
                Mock Get-WiFiProfileName { @('HomeSSID') }
                Mock Invoke-ExternalCommandSafe {
                    [pscustomobject]@{
                        Name      = 'Export Wi-Fi profiles (bulk)'
                        ExitCode  = 0
                        Succeeded = $true
                        Error     = $null
                    }
                }

                $script:BulkCallSeen = $false
                Mock Get-ChildItem {
                    if (-not $script:BulkCallSeen) {
                        $script:BulkCallSeen = $true
                        @()
                    }
                    else {
                        @(
                            [pscustomobject]@{ FullName = 'C:\backup\Wi-Fi-HomeSSID.xml' }
                        )
                    }
                }

                Mock WriteAllLines {}

                $result = @(Export-WiFiProfile -Dest 'C:\backup')

                $result.Count | Should -Be 2
                $result[0] | Should -Match 'WiFiProfiles_'
                $result | Should -Contain 'C:\backup\Wi-Fi-HomeSSID.xml'
                Should -Invoke Invoke-ExternalCommandSafe -Times 1 -ParameterFilter { $Name -eq 'Export Wi-Fi profiles (bulk)' }
            }

            It 'falls back to per-profile export when bulk export creates no files' {
                Mock Get-WiFiProfileName { @('HomeSSID', 'OfficeSSID') }

                # Model the real netsh/filesystem relationship as state (a virtual
                # file list that grows only when a per-profile export "succeeds"),
                # rather than a hardcoded call-order sequence: the bulk export
                # never creates a file (forcing the per-profile fallback), and
                # each per-profile export creates exactly its own named file.
                # This is robust to how many times or in what order the
                # production code happens to call Get-ChildItem.
                $script:virtualExportedFiles = [System.Collections.Generic.List[string]]::new()
                Mock Invoke-ExternalCommandSafe {
                    if ($Name -like 'Export Wi-Fi profile *') {
                        $profileName = $Name -replace '^Export Wi-Fi profile ', ''
                        [void]$script:virtualExportedFiles.Add("C:\backup\Wi-Fi-$profileName.xml")
                    }

                    [pscustomobject]@{
                        Name      = $Name
                        ExitCode  = 0
                        Succeeded = $true
                        Error     = $null
                    }
                }

                Mock Get-ChildItem {
                    @($script:virtualExportedFiles | ForEach-Object { [pscustomobject]@{ FullName = $_ } })
                }

                $result = @(Export-WiFiProfile -Dest 'C:\backup')

                $result[0] | Should -Match 'WiFiProfiles_'
                $result | Should -Contain 'C:\backup\Wi-Fi-HomeSSID.xml'
                $result | Should -Contain 'C:\backup\Wi-Fi-OfficeSSID.xml'

                Should -Invoke Invoke-ExternalCommandSafe -Times 1 -ParameterFilter { $Name -eq 'Export Wi-Fi profiles (bulk)' }
                Should -Invoke Invoke-ExternalCommandSafe -Times 1 -ParameterFilter { $Name -eq 'Export Wi-Fi profile HomeSSID' }
                Should -Invoke Invoke-ExternalCommandSafe -Times 1 -ParameterFilter { $Name -eq 'Export Wi-Fi profile OfficeSSID' }
            }

            It 'continues when a per-profile export fails and still returns successful exports' {
                Mock Get-WiFiProfileName { @('FailSSID', 'GoodSSID') }

                Mock Invoke-ExternalCommandSafe {
                    if ($Name -match 'FailSSID') { [pscustomobject]@{ Name=$Name; ExitCode=1; Succeeded=$false; Error='fail' } }
                    else { [pscustomobject]@{ Name=$Name; ExitCode=0; Succeeded=$true; Error=$null } }
                }

                $script:ChildItemCall = 0
                Mock Get-ChildItem {
                    $script:ChildItemCall++

                    switch ($script:ChildItemCall) {
                        1 { @() } # bulk before
                        2 { @() } # bulk after -> no new files
                        3 { @() } # FailSSID before
                        4 { @() } # FailSSID after -> still no file
                        5 { @() } # GoodSSID before
                        6 { @([pscustomobject]@{ FullName = 'C:\backup\Wi-Fi-GoodSSID.xml' }) } # GoodSSID after
                        default { @() }
                    }
                }

                Mock WriteAllLines {}

                $result = @(Export-WiFiProfile -Dest 'C:\backup')

                # list file + one successful xml
                $result.Count | Should -Be 2
                $result | Should -Contain 'C:\backup\Wi-Fi-GoodSSID.xml'
                $result | Should -Not -Contain 'C:\backup\Wi-Fi-FailSSID.xml'
            }
        }

        Context 'Export-NetworkList' {

            It 'returns the expected file path in dry-run mode' {
                $result = Export-NetworkList -Dest 'C:\backup' -DryRun
                $result | Should -Match 'NetworkList'
            }

            It 'calls reg export through safe external command helper' {
                Mock Invoke-RegExport {
                    param($Key, $FilePath, $DryRun)
                    $null = $Key, $DryRun
                    $FilePath
                }

                $result = Export-NetworkList -Dest 'C:\backup'
                $result | Should -Match 'NetworkList'

                Should -Invoke Invoke-RegExport -Times 1
            }
        }

        Context 'Export-ProtectedRegistryKey' {

            It 'returns planned output in dry-run mode' {
                $result = @(Export-ProtectedRegistryKey -Paths @('HKLM\SOFTWARE\CrowdStrike') -Dest 'C:\backup' -DryRun)

                $result.Count | Should -Be 1
                $result[0] | Should -Match 'CrowdStrike'
            }

            It 'exports each protected registry key path' {
                Mock Invoke-RegExport {
                    param($Key, $FilePath, $DryRun)
                    $null = $Key, $DryRun
                    $FilePath
                }

                $result = @(Export-ProtectedRegistryKey -Paths @(
                    'HKLM\SOFTWARE\CrowdStrike',
                    'HKLM\SOFTWARE\Cisco'
                ) -Dest 'C:\backup')

                $result.Count | Should -Be 2
                Should -Invoke Invoke-RegExport -Times 2
            }

            It 'returns empty when no registry paths are supplied' {
                $result = @(Export-ProtectedRegistryKey -Paths @() -Dest 'C:\backup')
                $result.Count | Should -Be 0
            }

            It 'skips invalid registry paths and continues exporting valid ones' {
                Mock Convert-RegKeyPath {
                    param($Path)
                    if ($Path -match 'badpath$') { throw 'invalid' } else { 'Registry::HKEY_LOCAL_MACHINE\\SOFTWARE\\Good' }
                }

                Mock Invoke-RegExport {
                    param($Key, $FilePath, $DryRun)
                    $null = $Key, $DryRun
                    $FilePath
                }

                $result = @(Export-ProtectedRegistryKey -Paths @('badpath', 'HKLM\\SOFTWARE\\Good') -Dest 'C:\\backup' -DryRun)

                $result.Count | Should -Be 1
                $result[0] | Should -Match 'reg_backup'
            }
        }

        Context 'Export-ProtectionInventory' {

            It 'returns expected output path in dry-run mode' {
                $inventory = @([pscustomobject]@{ Vendor = 'CrowdStrike' })

                $result = Export-ProtectionInventory -Inventory $inventory -Dest 'C:\backup' -DryRun
                $result | Should -Match 'ProtectionInventory'
            }

            It 'writes inventory JSON to disk' {
                Mock WriteAllText {}

                $inventory = @([pscustomobject]@{ Vendor = 'CrowdStrike' })
                $result = Export-ProtectionInventory -Inventory $inventory -Dest $TestDrive

                $result | Should -Match 'ProtectionInventory'
                Should -Invoke WriteAllText -Times 1 -Exactly -ParameterFilter {
                    $Path -eq $result -and
                    $Contents -match 'CrowdStrike' -and
                    $Encoding.WebName -eq 'utf-8'
                }
            }

            It 'detects the current inventory when none is supplied' {
                Mock Get-ProtectionInventory {
                    @([pscustomobject]@{ Vendor = 'Microsoft Defender' })
                }

                $result = Export-ProtectionInventory -Dest 'C:\backup' -DryRun

                $result | Should -Match 'ProtectionInventory'
                Should -Invoke Get-ProtectionInventory -Times 1 -Exactly
            }
        }

        Context 'Export-ProtectionRegistryMap' {

            It 'returns expected output path in dry-run mode' {
                Mock Get-ProtectionRegistryMap {
                    @([pscustomobject]@{ Vendor = 'CrowdStrike' })
                }

                $result = Export-ProtectionRegistryMap -Inventory @() -Dest 'C:\backup' -DryRun
                $result | Should -Match 'ProtectionRegistryMap'
            }

            It 'writes the registry map through the UTF-8 text seam' {
                Mock Get-ProtectionRegistryMap {
                    @([pscustomobject]@{ Vendor = 'CrowdStrike' })
                }
                Mock WriteAllText {}

                $result = Export-ProtectionRegistryMap -Inventory @() -Dest $TestDrive

                Should -Invoke WriteAllText -Times 1 -Exactly -ParameterFilter {
                    $Path -eq $result -and
                    $Contents -match 'CrowdStrike' -and
                    $Encoding.WebName -eq 'utf-8'
                }
            }

        }

        Context 'Export-SanitizableNetworkArtifact' {

            It 'returns expected output path in dry-run mode' {
                Mock Get-SanitizableNetworkArtifact {
                    @([pscustomobject]@{ RegistryPath = 'HKLM\SOFTWARE\Test' })
                }

                $result = Export-SanitizableNetworkArtifact -Inventory @() -Dest 'C:\backup' -DryRun
                $result | Should -Match 'SanitizableNetworkArtifact'
            }

            It 'writes sanitizable artifacts through the UTF-8 text seam' {
                Mock Get-SanitizableNetworkArtifact {
                    @([pscustomobject]@{ RegistryPath = 'HKLM\SOFTWARE\Test' })
                }
                Mock WriteAllText {}

                $result = Export-SanitizableNetworkArtifact -Inventory @() -Dest $TestDrive

                Should -Invoke WriteAllText -Times 1 -Exactly -ParameterFilter {
                    $Path -eq $result -and
                    $Contents -match 'RegistryPath' -and
                    $Encoding.WebName -eq 'utf-8'
                }
            }
        }

        Context 'Export-FirewallPolicy' {

            It 'returns expected output path in dry-run mode' {
                $result = Export-FirewallPolicy -Dest 'C:\backup' -DryRun
                $result | Should -Match 'FirewallPolicy'
            }

            It 'uses external command helper when not in dry-run mode' {
                Mock Invoke-ExternalCommandSafe {
                    [pscustomobject]@{
                        Name      = 'Export firewall policy'
                        ExitCode  = 0
                        Succeeded = $true
                        Error     = $null
                    }
                }

                $result = Export-FirewallPolicy -Dest 'C:\backup'
                $result | Should -Match 'FirewallPolicy'

                Should -Invoke Invoke-ExternalCommandSafe -Times 1
            }
        }

        Context 'Export-NetCleanAdapterConfiguration' {

            It 'returns the planned adapter snapshot path in dry-run mode' {
                $result = Export-NetCleanAdapterConfiguration -Dest 'C:\backup' -DryRun

                $result | Should -Match 'AdapterConfiguration'
            }

            It 'writes compact addressing, route, DNS, and IPv6 preference state' {
                Mock Get-NetAdapter {
                    [pscustomobject]@{
                        Name                 = 'Wi-Fi'
                        InterfaceDescription = 'Test adapter'
                        InterfaceIndex       = 12
                        InterfaceGuid        = '{11111111-1111-1111-1111-111111111111}'
                        Status               = 'Up'
                        MacAddress           = '00-11-22-33-44-55'
                    }
                }
                Mock Get-NetIPInterface {
                    [pscustomobject]@{
                        InterfaceIndex = 12
                        AddressFamily  = 'IPv4'
                        Dhcp           = 'Disabled'
                    }
                }
                Mock Get-NetIPAddress {
                    [pscustomobject]@{
                        InterfaceIndex = 12
                        IPAddress      = '192.0.2.10'
                        PrefixLength   = 24
                        PrefixOrigin   = 'Manual'
                        SuffixOrigin   = 'Manual'
                    }
                }
                Mock Get-NetRoute {
                    [pscustomobject]@{
                        InterfaceIndex    = 12
                        DestinationPrefix = '0.0.0.0/0'
                        NextHop           = '192.0.2.1'
                        RouteMetric       = 10
                        Protocol          = 'NetMgmt'
                    }
                }
                Mock Get-DnsClientServerAddress {
                    [pscustomobject]@{
                        InterfaceIndex = 12
                        AddressFamily  = 'IPv4'
                        ServerAddresses = @('192.0.2.53')
                    }
                }
                Mock Get-ItemProperty {
                    [pscustomobject]@{ DisabledComponents = 0 }
                }
                Mock WriteAllText {}

                $result = Export-NetCleanAdapterConfiguration -Dest $TestDrive

                Should -Invoke WriteAllText -Times 1 -Exactly -ParameterFilter {
                    $Path -eq $result -and
                    $Contents -match '192.0.2.10' -and
                    $Contents -match '192.0.2.53' -and
                    $Contents -match 'DisabledComponents' -and
                    $Encoding.WebName -eq 'utf-8'
                }
            }
        }

        Context 'Export-NetCleanManifest' {

            It 'returns expected output path in dry-run mode' {
                $manifest = @{ BackupPath = 'C:\backup' }

                $result = Export-NetCleanManifest -Manifest $manifest -Dest 'C:\backup' -DryRun
                $result | Should -Match 'Manifest'
            }

            It 'writes manifest JSON when not in dry-run mode' {
                Mock WriteAllText {}

                $manifest = @{ BackupPath = 'C:\backup' }
                $result = Export-NetCleanManifest -Manifest $manifest -Dest $TestDrive

                $result | Should -Match 'Manifest'
                Should -Invoke WriteAllText -Times 1 -Exactly -ParameterFilter {
                    $Path -eq $result -and
                    $Contents -match 'BackupPath' -and
                    $Encoding.WebName -eq 'utf-8'
                }
            }
        }

        Context 'Invoke-NetCleanPhase2Protect' {

            BeforeEach {
                $script:context = [pscustomobject]@{
                    Phase                  = 'Detect'
                    Inventory              = @(
                        [pscustomobject]@{
                            Vendor                  = 'CrowdStrike'
                            Services                = @('CSFalconService')
                            Drivers                 = @()
                            Adapters                = @()
                            ProtectedInterfaceGuids = @()
                            RegistryKeys            = @('HKLM\SOFTWARE\CrowdStrike')
                            Evidence                = @()
                        }
                    )
                    ProtectedRegistryPaths = @('HKLM\SOFTWARE\CrowdStrike')
                    SanitizableArtifacts   = @(
                        [pscustomobject]@{
                            RegistryPath = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles'
                        }
                    )
                }

                Mock New-DirectoryIfNotExist {}
                Mock Set-NetCleanPrivateDirectoryAcl {}
                Mock Export-ProtectionInventory { 'C:\backup\ProtectionInventory.json' }
                Mock Export-ProtectionRegistryMap { 'C:\backup\ProtectionRegistryMap.json' }
                Mock Export-SanitizableNetworkArtifact { 'C:\backup\SanitizableNetworkArtifacts.json' }
                Mock Export-NetworkList { 'C:\backup\NetworkList.reg' }
                Mock Export-WiFiProfile { @('C:\backup\WiFiProfiles.txt') }
                Mock Export-FirewallPolicy { 'C:\backup\FirewallPolicy.wfw' }
                Mock Export-NetCleanAdapterConfiguration { 'C:\backup\AdapterConfiguration.json' }
                Mock Export-ProtectedRegistryKey { @('C:\backup\CrowdStrike.reg') }
                Mock Export-NetCleanManifest { 'C:\backup\Manifest.json' }
            }

            It 'returns a protect context with manifest and summary in dry-run mode' {
                $result = Invoke-NetCleanPhase2Protect -Context $script:context -BackupPath 'C:\backup' -DryRun

                $result.Phase | Should -Be 'Protect'
                $result.BackupPath | Should -Be 'C:\backup'
                $result.Protect.Manifest.NetworkListBackup | Should -Be 'C:\backup\NetworkList.reg'
                $result.Protect.Manifest.FirewallPolicyBackup | Should -Be 'C:\backup\FirewallPolicy.wfw'
                $result.Protect.Manifest.AdapterConfigurationJson | Should -Be 'C:\backup\AdapterConfiguration.json'
                $result.Protect.Summary.ProtectedRegistryPathCount | Should -Be 1
                $result.Protect.Summary.HasAdapterConfigurationBackup | Should -BeTrue
                $result.Protect.Summary.WiFiBackupCount | Should -Be 1
                $result.Protect.Summary.ProtectedRegistryBackupCount | Should -Be 1
            }

            It 'reports no adapter configuration backup when the export produced no path' {
                Mock Export-NetCleanAdapterConfiguration { $null }

                $result = Invoke-NetCleanPhase2Protect -Context $script:context -BackupPath 'C:\backup' -DryRun

                $result.Protect.Summary.HasAdapterConfigurationBackup | Should -BeFalse
            }

            It 'skips firewall backup when requested' {
                $result = Invoke-NetCleanPhase2Protect -Context $script:context -BackupPath 'C:\backup' -DryRun -SkipFirewallBackup

                $result.Protect.Manifest.FirewallPolicyBackup | Should -BeNullOrEmpty
                Should -Invoke Export-FirewallPolicy -Times 0
            }

            It 'degrades gracefully instead of aborting when protection-inventory backup fails' {
                Mock Export-ProtectionInventory { throw 'disk full' }

                $result = Invoke-NetCleanPhase2Protect -Context $script:context -BackupPath 'C:\backup' -DryRun

                $result.Protect.Manifest.ProtectionInventoryJson | Should -BeNullOrEmpty
                $result.Phase | Should -Be 'Protect'
            }

            It 'degrades gracefully instead of aborting when protection-registry-map backup fails' {
                Mock Export-ProtectionRegistryMap { throw 'disk full' }

                $result = Invoke-NetCleanPhase2Protect -Context $script:context -BackupPath 'C:\backup' -DryRun

                $result.Protect.Manifest.ProtectionRegistryMapJson | Should -BeNullOrEmpty
                $result.Phase | Should -Be 'Protect'
            }

            It 'degrades gracefully instead of aborting when sanitizable-artifact backup fails' {
                Mock Export-SanitizableNetworkArtifact { throw 'disk full' }

                $result = Invoke-NetCleanPhase2Protect -Context $script:context -BackupPath 'C:\backup' -DryRun

                $result.Protect.Manifest.SanitizableArtifactsJson | Should -BeNullOrEmpty
                $result.Phase | Should -Be 'Protect'
            }

            It 'degrades gracefully instead of aborting when adapter-configuration backup fails' {
                Mock Export-NetCleanAdapterConfiguration { throw 'wmi unavailable' }

                $result = Invoke-NetCleanPhase2Protect -Context $script:context -BackupPath 'C:\backup' -DryRun

                $result.Protect.Manifest.AdapterConfigurationJson | Should -BeNullOrEmpty
                $result.Phase | Should -Be 'Protect'
            }

            It 'degrades gracefully instead of aborting when network-list backup fails' {
                Mock Export-NetworkList { throw 'disk full' }

                $result = Invoke-NetCleanPhase2Protect -Context $script:context -BackupPath 'C:\backup' -DryRun

                $result.Protect.Manifest.NetworkListBackup | Should -BeNullOrEmpty
                $result.Phase | Should -Be 'Protect'
            }

            It 'degrades gracefully instead of aborting when Wi-Fi profile backup fails' {
                Mock Export-WiFiProfile { throw 'netsh unavailable' }

                $result = Invoke-NetCleanPhase2Protect -Context $script:context -BackupPath 'C:\backup' -DryRun

                @($result.Protect.Manifest.WiFiExports).Count | Should -Be 0
                $result.Phase | Should -Be 'Protect'
            }

            It 'degrades gracefully instead of aborting when protected-registry-key backup fails' {
                Mock Export-ProtectedRegistryKey { throw 'reg.exe failed' }

                $result = Invoke-NetCleanPhase2Protect -Context $script:context -BackupPath 'C:\backup' -DryRun

                @($result.Protect.Manifest.ProtectedRegistryBackups).Count | Should -Be 0
                $result.Phase | Should -Be 'Protect'
            }

            It 'creates backup directory when not in dry-run mode' {
                $null = Invoke-NetCleanPhase2Protect -Context $script:context -BackupPath 'C:\backup'

                Should -Invoke New-DirectoryIfNotExist -Times 1 -ParameterFilter { $Path -eq 'C:\backup' }
                Should -Invoke Set-NetCleanPrivateDirectoryAcl -Times 1 -ParameterFilter { $Path -eq 'C:\backup' }
            }

            It 'handles empty protected registry paths gracefully' {
                $script:context.ProtectedRegistryPaths = @()
                Mock Export-ProtectedRegistryKey { @() }

                $result = Invoke-NetCleanPhase2Protect -Context $script:context -BackupPath 'C:\backup' -DryRun

                $result.Protect.Summary.ProtectedRegistryPathCount | Should -Be 0
                $result.Protect.Summary.ProtectedRegistryBackupCount | Should -Be 0
            }

            It 'passes through manifest file path from export' {
                $result = Invoke-NetCleanPhase2Protect -Context $script:context -BackupPath 'C:\backup' -DryRun

                $result.Protect.ManifestFile | Should -Be 'C:\backup\Manifest.json'
            }
        }
    }
}
