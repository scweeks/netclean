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

                Mock Invoke-ExternalCommandSafe {
                    [pscustomobject]@{
                        Name      = $Name
                        ExitCode  = 0
                        Succeeded = $true
                        Error     = $null
                    }
                }

                $script:ChildItemCall = 0
                Mock Get-ChildItem {
                    $script:ChildItemCall++

                    switch ($script:ChildItemCall) {
                        1 { @() } # bulk before
                        2 { @() } # bulk after -> no new files
                        3 { @() } # HomeSSID before
                        4 { @([pscustomobject]@{ FullName = 'C:\backup\Wi-Fi-HomeSSID.xml' }) } # HomeSSID after
                        5 { @([pscustomobject]@{ FullName = 'C:\backup\Wi-Fi-HomeSSID.xml' }) } # OfficeSSID before
                        6 {
                            @(
                                [pscustomobject]@{ FullName = 'C:\backup\Wi-Fi-HomeSSID.xml' }
                                [pscustomobject]@{ FullName = 'C:\backup\Wi-Fi-OfficeSSID.xml' }
                            )
                        } # OfficeSSID after
                        default { @() }
                    }
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
                Mock Invoke-RegExport { param($Key, $FilePath, $DryRun) $FilePath }

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
                Mock Invoke-RegExport { param($Path, $OutputPath) $OutputPath }

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

                Mock Invoke-RegExport { param($Key, $FilePath, $DryRun) $FilePath }

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
                $result = Export-ProtectionInventory -Inventory $inventory -Dest 'C:\backup'

                $result | Should -Match 'ProtectionInventory'
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
        }

        Context 'Export-SanitizableNetworkArtifact' {

            It 'returns expected output path in dry-run mode' {
                Mock Get-SanitizableNetworkArtifact {
                    @([pscustomobject]@{ RegistryPath = 'HKLM\SOFTWARE\Test' })
                }

                $result = Export-SanitizableNetworkArtifact -Inventory @() -Dest 'C:\backup' -DryRun
                $result | Should -Match 'SanitizableNetworkArtifact'
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

        Context 'Export-NetCleanManifest' {

            It 'returns expected output path in dry-run mode' {
                $manifest = @{ BackupPath = 'C:\backup' }

                $result = Export-NetCleanManifest -Manifest $manifest -Dest 'C:\backup' -DryRun
                $result | Should -Match 'Manifest'
            }

            It 'writes manifest JSON when not in dry-run mode' {
                Mock WriteAllText {}

                $manifest = @{ BackupPath = 'C:\backup' }
                $result = Export-NetCleanManifest -Manifest $manifest -Dest 'C:\backup'

                $result | Should -Match 'Manifest'
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
                Mock Export-ProtectionInventory { 'C:\backup\ProtectionInventory.json' }
                Mock Export-ProtectionRegistryMap { 'C:\backup\ProtectionRegistryMap.json' }
                Mock Export-SanitizableNetworkArtifact { 'C:\backup\SanitizableNetworkArtifacts.json' }
                Mock Export-NetworkList { 'C:\backup\NetworkList.reg' }
                Mock Export-WiFiProfile { @('C:\backup\WiFiProfiles.txt') }
                Mock Export-FirewallPolicy { 'C:\backup\FirewallPolicy.wfw' }
                Mock Export-ProtectedRegistryKey { @('C:\backup\CrowdStrike.reg') }
                Mock Export-NetCleanManifest { 'C:\backup\Manifest.json' }
            }

            It 'returns a protect context with manifest and summary in dry-run mode' {
                $result = Invoke-NetCleanPhase2Protect -Context $script:context -BackupPath 'C:\backup' -DryRun

                $result.Phase | Should -Be 'Protect'
                $result.BackupPath | Should -Be 'C:\backup'
                $result.Protect.Manifest.NetworkListBackup | Should -Be 'C:\backup\NetworkList.reg'
                $result.Protect.Manifest.FirewallPolicyBackup | Should -Be 'C:\backup\FirewallPolicy.wfw'
                $result.Protect.Summary.ProtectedRegistryPathCount | Should -Be 1
                $result.Protect.Summary.WiFiBackupCount | Should -Be 1
                $result.Protect.Summary.ProtectedRegistryBackupCount | Should -Be 1
            }

            It 'skips firewall backup when requested' {
                $result = Invoke-NetCleanPhase2Protect -Context $script:context -BackupPath 'C:\backup' -DryRun -SkipFirewallBackup

                $result.Protect.Manifest.FirewallPolicyBackup | Should -BeNullOrEmpty
                Should -Invoke Export-FirewallPolicy -Times 0
            }

            It 'creates backup directory when not in dry-run mode' {
                $null = Invoke-NetCleanPhase2Protect -Context $script:context -BackupPath 'C:\backup'

                Should -Invoke New-DirectoryIfNotExist -Times 1 -ParameterFilter { $Path -eq 'C:\backup' }
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
