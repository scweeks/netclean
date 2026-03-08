$ProjectRoot = Split-Path -Parent $PSScriptRoot
$ModulePath  = Join-Path $ProjectRoot 'NetClean.psm1'
$ModuleName  = 'NetClean'

Import-Module $ModulePath -Force -ErrorAction Stop

Describe 'NetClean.psm1 import/export surface' {
    It 'imports the module without throwing' {
        { Import-Module $ModulePath -Force } | Should -Not -Throw
    }

    It 'exports the expected primary phase functions' {
        $module = Get-Module $ModuleName
        $module | Should -Not -BeNullOrEmpty

        $expected = @(
            'Invoke-NetCleanPhase1Detect',
            'Invoke-NetCleanPhase2Protect',
            'Invoke-NetCleanPhase3Clean',
            'Invoke-NetCleanPhase4Verify',
            'Invoke-NetCleanWorkflow'
        )

        foreach ($name in $expected) {
            $module.ExportedFunctions.Keys | Should -Contain $name
        }
    }
}

DDescribe 'NetClean.psm1 utility helpers' {
    InModuleScope NetClean {
        It 'Convert-RegKeyPath normalizes registry provider paths' {
            Convert-RegKeyPath -Path 'Microsoft.PowerShell.Core\Registry::HKLM:\SOFTWARE\Test' |
                Should -Be 'HKLM\SOFTWARE\Test'
        }
    }
}

Describe 'NetClean.psm1 external command helper' {
    BeforeAll {
        Import-Module $ModulePath -Force
    }

    InModuleScope NetClean {
        It 'Invoke-ExternalCommandSafe returns a successful dry-run result' {
            $r = Invoke-ExternalCommandSafe -Name Test -FilePath cmd.exe -ArgumentList '/c','echo ok' -DryRun
            $r.Succeeded | Should -BeTrue
            $r.DryRun    | Should -BeTrue
            $r.ExitCode  | Should -Be 0
        }

        It 'Invoke-ExternalCommandSafe captures successful process execution' {
            Mock Start-Process { [pscustomobject]@{ ExitCode = 0 } }
            $r = Invoke-ExternalCommandSafe -Name Test -FilePath cmd.exe -ArgumentList '/c','echo ok'
            $r.Succeeded | Should -BeTrue
            $r.ExitCode  | Should -Be 0
            Should -Invoke Start-Process -Times 1
        }

        It 'Invoke-ExternalCommandSafe captures a non-zero exit code' {
            Mock Start-Process { [pscustomobject]@{ ExitCode = 5 } }
            $r = Invoke-ExternalCommandSafe -Name Test -FilePath cmd.exe -ArgumentList '/c','exit 5'
            $r.Succeeded | Should -BeFalse
            $r.ExitCode  | Should -Be 5
        }
    }
}

Describe 'NetClean.psm1 phase orchestration' {
    BeforeAll {
        Import-Module $ModulePath -Force
    }

    InModuleScope NetClean {
        Context 'Phase 1 detect' {
            BeforeEach {
                Mock Get-ProtectionInventory {
                    @([pscustomobject]@{
                        Vendor = 'CrowdStrike'
                        Categories = @('EDR')
                        Confidence = 100
                        Services = @('CSFalconService')
                        Drivers = @('csagent')
                        Adapters = @('CrowdStrike Adapter')
                        ProtectedInterfaceGuids = @('aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee')
                        RegistryKeys = @('HKLM\SOFTWARE\CrowdStrike')
                        Evidence = @('Service | CSFalconService')
                    })
                }
                Mock Get-ProtectionRegistryMap {
                    @([pscustomobject]@{
                        Vendor = 'CrowdStrike'
                        Categories = @('EDR')
                        Confidence = 100
                        Services = @('CSFalconService')
                        Drivers = @('csagent')
                        Adapters = @('CrowdStrike Adapter')
                        ProtectedInterfaceGuids = @('aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee')
                        RegistryKeys = @('HKLM\SOFTWARE\CrowdStrike')
                        Evidence = @('Service | CSFalconService')
                    })
                }
                Mock Get-ProtectedInterfaceGuidSet { @('aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee') }
                Mock Get-NetworkPrivacyArtifactCandidate {
                    @([pscustomobject]@{ ArtifactType='NetworkList'; RegistryPath='HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles'; InterfaceGuid=$null; IsProtected=$false; Reason='history' })
                }
                Mock Get-SanitizableNetworkArtifact {
                    @([pscustomobject]@{ ArtifactType='NetworkList'; RegistryPath='HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles'; InterfaceGuid=$null; IsProtected=$false; Reason='history' })
                }
            }

            It 'returns a detect context object with summary fields populated' {
                $ctx = Invoke-NetCleanPhase1Detect
                $ctx.Phase | Should -Be 'Detect'
                $ctx.Summary.ProtectedVendorsCount    | Should -Be 1
                $ctx.Summary.CandidateArtifactCount   | Should -Be 1
                $ctx.Summary.SanitizableArtifactCount | Should -Be 1
            }
        }

        Context 'Phase 2 protect' {
            BeforeEach {
                $ctx = [pscustomobject]@{
                    Inventory = @([pscustomobject]@{ Vendor='CrowdStrike'; Services=@('CSFalconService'); Drivers=@(); Adapters=@(); ProtectedInterfaceGuids=@(); RegistryKeys=@('HKLM\SOFTWARE\CrowdStrike'); Evidence=@() })
                    ProtectedRegistryPaths = @('HKLM\SOFTWARE\CrowdStrike')
                }
                Mock Export-ProtectionInventory { 'C:\backup\ProtectionInventory.json' }
                Mock Export-ProtectionRegistryMap { 'C:\backup\ProtectionRegistryMap.json' }
                Mock Export-SanitizableNetworkArtifact { 'C:\backup\SanitizableNetworkArtifacts.json' }
                Mock Export-NetworkList { 'C:\backup\NetworkList.reg' }
                Mock Export-WiFiProfile { @('C:\backup\WiFiProfiles.txt') }
                Mock Export-FirewallPolicy { 'C:\backup\FirewallPolicy.wfw' }
                Mock Export-ProtectedRegistryKey { @('C:\backup\CrowdStrike.reg') }
                Mock Export-NetCleanManifest { 'C:\backup\Manifest.json' }
                Mock Ensure-Directory {}
            }

            It 'returns a protect context with manifest and summary' {
                $r = Invoke-NetCleanPhase2Protect -Context $ctx -BackupPath 'C:\backup' -DryRun
                $r.Phase | Should -Be 'Protect'
                $r.Protect.Manifest.NetworkListBackup | Should -Be 'C:\backup\NetworkList.reg'
                $r.Protect.Summary.ProtectedRegistryPathCount | Should -Be 1
            }
        }

        Context 'Phase 3 clean' {
            BeforeEach {
                $ctx = [pscustomobject]@{
                    Inventory = @()
                    ProtectedRegistryPaths = @('HKLM\SOFTWARE\CrowdStrike')
                    SanitizableArtifacts = @([pscustomobject]@{ RegistryPath='HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles' })
                }
                Mock Remove-WiFiProfilesSafe { [pscustomobject]@{ Removed=2; Profiles=@('ssid1','ssid2'); Operations=@() } }
                Mock Clear-DnsCacheSafe { [pscustomobject]@{ Succeeded=$true } }
                Mock Clear-ArpCacheSafe { [pscustomobject]@{ Succeeded=$true } }
                Mock Remove-NetworkPrivacyArtifactsSafe { [pscustomobject]@{ TotalCandidates=1; RemovedCount=1; SkippedCount=0; Results=@() } }
                Mock Clear-NlaProbeStateSafe { @() }
                Mock Clear-NetworkEventLogsSafe { @([pscustomobject]@{ Succeeded=$true }) }
                Mock Clear-UserNetworkArtifactsSafe { @([pscustomobject]@{ Removed=$true }) }
                Mock Invoke-AdvancedNetworkRepair { @([pscustomobject]@{ Succeeded=$true }) }
                Mock Invoke-ConservativePerformanceTune { @([pscustomobject]@{ Succeeded=$true }) }
            }

            It 'runs safe conference prep without advanced repair by default' {
                $r = Invoke-NetCleanPhase3Clean -Context $ctx -Mode SafeConferencePrep -DryRun
                $r.Phase | Should -Be 'Clean'
                $r.Clean.Summary.WiFiProfilesRemoved | Should -Be 2
                $r.Clean.Summary.AdvancedRepairActions | Should -Be 0
            }

            It 'includes advanced repair actions in AdvancedRepair mode' {
                $r = Invoke-NetCleanPhase3Clean -Context $ctx -Mode AdvancedRepair -DryRun
                $r.Clean.Summary.AdvancedRepairActions | Should -Be 1
            }

            It 'includes performance tuning actions in PerformanceTune mode' {
                $r = Invoke-NetCleanPhase3Clean -Context $ctx -Mode PerformanceTune -DryRun
                $r.Clean.Summary.PerformanceTuningActions | Should -Be 1
            }
        }

        Context 'Phase 4 verify' {
            BeforeEach {
                $ctx = [pscustomobject]@{
                    Inventory = @([pscustomobject]@{
                        Vendor='CrowdStrike'; Services=@('CSFalconService'); Drivers=@('csagent'); Adapters=@('Adapter'); ProtectedInterfaceGuids=@('aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'); RegistryKeys=@('HKLM\SOFTWARE\CrowdStrike'); Evidence=@()
                    })
                }
            }

            It 'marks verification as passed when no protected vendors are missing' {
                Mock Get-ProtectionInventory {
                    @([pscustomobject]@{
                        Vendor='CrowdStrike'; Services=@('CSFalconService'); Drivers=@('csagent'); Adapters=@('Adapter'); ProtectedInterfaceGuids=@('aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'); RegistryKeys=@('HKLM\SOFTWARE\CrowdStrike'); Evidence=@()
                    })
                }
                Mock Get-ProtectedInterfaceGuidSet { @('aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee') }
                $r = Invoke-NetCleanPhase4Verify -Context $ctx
                $r.Verify.Passed | Should -BeTrue
            }

            It 'marks verification as failed when a vendor disappears' {
                Mock Get-ProtectionInventory { @() }
                Mock Get-ProtectedInterfaceGuidSet { @() }
                $r = Invoke-NetCleanPhase4Verify -Context $ctx
                $r.Verify.Passed | Should -BeFalse
                @($r.Verify.VendorComparison.Missing).Count | Should -Be 1
            }
        }

        Context 'Full workflow' {
            It 'runs detect->protect only in Preview mode' {
                Mock Invoke-NetCleanPhase1Detect { [pscustomobject]@{ Phase='Detect'; Inventory=@(); ProtectedRegistryPaths=@() } }
                Mock Invoke-NetCleanPhase2Protect { param($Context,$BackupPath,[switch]$DryRun,[switch]$SkipFirewallBackup) [pscustomobject]@{ Phase='Protect'; BackupPath=$BackupPath } }
                Mock Invoke-NetCleanPhase3Clean {}
                Mock Invoke-NetCleanPhase4Verify {}

                $r = Invoke-NetCleanWorkflow -Mode Preview -BackupPath 'C:\backup' -DryRun
                $r.Phase | Should -Be 'Protect'
                Should -Invoke Invoke-NetCleanPhase3Clean -Times 0
                Should -Invoke Invoke-NetCleanPhase4Verify -Times 0
            }

            It 'runs all phases in SafeConferencePrep mode' {
                Mock Invoke-NetCleanPhase1Detect { [pscustomobject]@{ Phase='Detect'; Inventory=@(); ProtectedRegistryPaths=@() } }
                Mock Invoke-NetCleanPhase2Protect { param($Context,$BackupPath,[switch]$DryRun,[switch]$SkipFirewallBackup) [pscustomobject]@{ Phase='Protect'; Inventory=@(); ProtectedRegistryPaths=@(); BackupPath=$BackupPath } }
                Mock Invoke-NetCleanPhase3Clean { param($Context,[string]$Mode) [pscustomobject]@{ Phase='Clean'; Inventory=@(); ProtectedRegistryPaths=@(); Clean=[pscustomobject]@{} } }
                Mock Invoke-NetCleanPhase4Verify { param($Context) [pscustomobject]@{ Phase='Verify'; Verify=[pscustomobject]@{ Passed=$true } } }

                $r = Invoke-NetCleanWorkflow -Mode SafeConferencePrep -BackupPath 'C:\backup' -DryRun
                $r.Phase | Should -Be 'Verify'
                Should -Invoke Invoke-NetCleanPhase3Clean -Times 1
                Should -Invoke Invoke-NetCleanPhase4Verify -Times 1
            }
        }
    }
}
