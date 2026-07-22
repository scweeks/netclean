$manifestPath = Join-Path $PSScriptRoot '..\..\NetClean.psd1'

if (-not (Test-Path -LiteralPath $manifestPath)) {
    throw "NetClean.psd1 not found at path: $manifestPath"
}

Remove-Module NetClean -ErrorAction SilentlyContinue
Import-Module $manifestPath -Force

Describe 'NetClean workflow functional tests' {

    InModuleScope 'NetClean' {

        BeforeEach {
            $script:LogFile = $null
            Mock Write-NetCleanLog {}
        }

        Context 'Preview mode' {

            It 'runs Detect and Protect only, then returns the Protect context with timings' {
                Mock Invoke-NetCleanPhase1Detect {
                    [pscustomobject]@{
                        Phase                  = 'Detect'
                        Inventory              = @()
                        ProtectedRegistryPaths = @()
                        SanitizableArtifacts   = @()
                        Summary                = [pscustomobject]@{
                            ProtectedVendorsCount       = 0
                            ProtectedInterfaceGuidCount = 0
                            CandidateArtifactCount      = 0
                            SanitizableArtifactCount    = 0
                        }
                    }
                }

                Mock Invoke-NetCleanPhase2Protect {
                    param($Context, $BackupPath, $DryRun, $SkipFirewallBackup)
                    $null = $Context, $DryRun, $SkipFirewallBackup

                    [pscustomobject]@{
                        Phase      = 'Protect'
                        BackupPath = $BackupPath
                        Protect    = [pscustomobject]@{
                            Summary = [pscustomobject]@{
                                ProtectedRegistryPathCount    = 0
                                WiFiBackupCount               = 0
                                ProtectedRegistryBackupCount  = 0
                            }
                            Manifest = [pscustomobject]@{
                                WiFiExports       = @()
                                NetworkListBackup = 'C:\backup\NetworkList.reg'
                            }
                        }
                    }
                }

                Mock Invoke-NetCleanPhase3Clean {}
                Mock Invoke-NetCleanPhase4Verify {}
                Mock Get-WiFiProfileName { @() }
                Mock Get-NetworkListProfileName { @() }

                $result = Invoke-NetCleanWorkflow -Mode Preview -BackupPath 'C:\backup' -DryRun

                $result.Phase | Should -Be 'Protect'
                $result.BackupPath | Should -Be 'C:\backup'
                $result.Timings | Should -Not -BeNullOrEmpty

                Should -Invoke Invoke-NetCleanPhase1Detect -Times 1
                Should -Invoke Invoke-NetCleanPhase2Protect -Times 1
                Should -Invoke Invoke-NetCleanPhase3Clean -Times 0
                Should -Invoke Invoke-NetCleanPhase4Verify -Times 0
            }

            It 'restores profile names from planned and exported Wi-Fi manifest entries' {
                Mock Invoke-NetCleanPhase1Detect { [pscustomobject]@{ Phase = 'Detect' } }
                Mock Invoke-NetCleanPhase2Protect {
                    [pscustomobject]@{
                        Phase      = 'Protect'
                        BackupPath = $BackupPath
                        Protect    = [pscustomobject]@{
                            Summary  = [pscustomobject]@{}
                            Manifest = [pscustomobject]@{
                                WiFiExports = @(
                                    'PROFILE:HomeSSID'
                                    'C:\backup\Wi-Fi-OfficeSSID.xml'
                                    42
                                )
                            }
                        }
                    }
                }
                Mock Get-WiFiProfileName { throw 'Manifest entries should be sufficient' }
                Mock Get-NetworkListProfileName { @('Private network') }

                $result = Invoke-NetCleanWorkflow -Mode Preview -BackupPath 'C:\backup' -DryRun

                @($result.Protect.Summary.WiFiProfilesFound) | Should -Be @('HomeSSID', 'OfficeSSID')
                $result.Protect.Summary.WiFiProfilesFoundCount | Should -Be 2
                @($result.Protect.Summary.NetworkProfilesFound) | Should -Be @('Private network')
                Should -Invoke Get-WiFiProfileName -Times 0
            }

            It 'returns the protected context when cache population fails' {
                Mock Invoke-NetCleanPhase1Detect { [pscustomobject]@{ Phase = 'Detect' } }
                Mock Invoke-NetCleanPhase2Protect {
                    [pscustomobject]@{
                        Phase      = 'Protect'
                        BackupPath = $BackupPath
                        Protect    = [pscustomobject]@{
                            Summary  = [pscustomobject]@{}
                            Manifest = [pscustomobject]@{ WiFiExports = @() }
                        }
                    }
                }
                Mock Get-WiFiProfileName { throw 'profile enumeration failed' }

                $result = Invoke-NetCleanWorkflow -Mode Preview -BackupPath 'C:\backup' -DryRun

                $result.Phase | Should -Be 'Protect'
                $result.Timings.Protect | Should -Not -BeNullOrEmpty
            }
        }

        Context 'SafeConferencePrep mode' {

            It 'runs all four phases and returns a Verify context' {
                Mock Invoke-NetCleanPhase1Detect {
                    [pscustomobject]@{
                        Phase                  = 'Detect'
                        Inventory              = @()
                        ProtectedRegistryPaths = @()
                        SanitizableArtifacts   = @()
                        Summary                = [pscustomobject]@{}
                    }
                }

                Mock Invoke-NetCleanPhase2Protect {
                    param($Context, $BackupPath, $DryRun, $SkipFirewallBackup)
                    $null = $Context, $DryRun, $SkipFirewallBackup

                    [pscustomobject]@{
                        Phase      = 'Protect'
                        BackupPath = $BackupPath
                        Protect    = [pscustomobject]@{
                            Summary = [pscustomobject]@{}
                            Manifest = [pscustomobject]@{
                                WiFiExports       = @()
                                NetworkListBackup = 'C:\backup\NetworkList.reg'
                            }
                        }
                    }
                }

                Mock Invoke-NetCleanPhase3Clean {
                    [pscustomobject]@{
                        Phase      = 'Clean'
                        BackupPath = 'C:\backup'
                        Clean      = [pscustomobject]@{
                            Summary = [pscustomobject]@{
                                WiFiProfilesRemoved      = 1
                                RegistryArtifactsRemoved = 1
                                EventLogsTouched         = 1
                                UserArtifactsTouched     = 1
                                AdvancedRepairActions    = 0
                                PerformanceTuningActions = 0
                            }
                            WiFi = [pscustomobject]@{
                                Profiles = @('ssid1')
                            }
                            RegistryArtifacts = [pscustomobject]@{
                                Results = @(
                                    [pscustomobject]@{
                                        RegistryPath = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles'
                                        Removed      = $true
                                    }
                                )
                            }
                            EventLogs = @(
                                [pscustomobject]@{
                                    LogName = 'Microsoft-Windows-WLAN-AutoConfig/Operational'
                                }
                            )
                            UserArtifacts = @(
                                [pscustomobject]@{
                                    Path    = 'HKCU:\Software\Test'
                                    Removed = $true
                                }
                            )
                        }
                    }
                }

                Mock Invoke-NetCleanPhase4Verify {
                    [pscustomobject]@{
                        Phase      = 'Verify'
                        BackupPath = 'C:\backup'
                        Verify     = [pscustomobject]@{
                            Passed = $true
                            Summary = [pscustomobject]@{
                                Passed              = $true
                                MissingVendorsCount = 0
                                MissingGuidCount    = 0
                                MissingServiceCount = 0
                            }
                            VendorComparison = [pscustomobject]@{
                                Missing = @()
                            }
                            GuidComparison = [pscustomobject]@{
                                Missing = @()
                            }
                            ServiceComparison = [pscustomobject]@{
                                Missing = @()
                            }
                        }
                    }
                }

                Mock Get-WiFiProfileName { @() }
                Mock Get-NetworkListProfileName { @() }

                $result = Invoke-NetCleanWorkflow -Mode SafeConferencePrep -BackupPath 'C:\backup' -DryRun

                $result.Phase | Should -Be 'Verify'
                $result.Verify.Summary.Passed | Should -BeTrue
                $result.Timings | Should -Not -BeNullOrEmpty

                Should -Invoke Invoke-NetCleanPhase1Detect -Times 1
                Should -Invoke Invoke-NetCleanPhase2Protect -Times 1
                Should -Invoke Invoke-NetCleanPhase3Clean -Times 1
                Should -Invoke Invoke-NetCleanPhase4Verify -Times 1
            }

            It 'passes skip switches through to Phase 3' {
                Mock Invoke-NetCleanPhase1Detect {
                    [pscustomobject]@{
                        Phase                  = 'Detect'
                        Inventory              = @()
                        ProtectedRegistryPaths = @()
                        SanitizableArtifacts   = @()
                        Summary                = [pscustomobject]@{}
                    }
                }

                Mock Invoke-NetCleanPhase2Protect {
                    [pscustomobject]@{
                        Phase      = 'Protect'
                        BackupPath = 'C:\backup'
                        Protect    = [pscustomobject]@{
                            Summary = [pscustomobject]@{}
                            Manifest = [pscustomobject]@{
                                WiFiExports       = @()
                                NetworkListBackup = 'C:\backup\NetworkList.reg'
                            }
                        }
                    }
                }

                Mock Invoke-NetCleanPhase3Clean {
                    [pscustomobject]@{
                        Phase      = 'Clean'
                        BackupPath = 'C:\backup'
                        Clean      = [pscustomobject]@{
                            Summary = [pscustomobject]@{
                                WiFiProfilesRemoved      = 0
                                RegistryArtifactsRemoved = 0
                                EventLogsTouched         = 0
                                UserArtifactsTouched     = 0
                                AdvancedRepairActions    = 0
                                PerformanceTuningActions = 0
                            }
                            WiFi = [pscustomobject]@{ Profiles = @() }
                            RegistryArtifacts = [pscustomobject]@{ Results = @() }
                            EventLogs = @()
                            UserArtifacts = @()
                        }
                    }
                }

                Mock Invoke-NetCleanPhase4Verify {
                    [pscustomobject]@{
                        Phase      = 'Verify'
                        BackupPath = 'C:\backup'
                        Verify     = [pscustomobject]@{
                            Passed = $true
                            Summary = [pscustomobject]@{
                                Passed              = $true
                                MissingVendorsCount = 0
                                MissingGuidCount    = 0
                                MissingServiceCount = 0
                            }
                            VendorComparison = [pscustomobject]@{ Missing = @() }
                            GuidComparison   = [pscustomobject]@{ Missing = @() }
                            ServiceComparison= [pscustomobject]@{ Missing = @() }
                        }
                    }
                }

                Mock Get-WiFiProfileName { @() }
                Mock Get-NetworkListProfileName { @() }

                $null = Invoke-NetCleanWorkflow `
                    -Mode SafeConferencePrep `
                    -BackupPath 'C:\backup' `
                    -DryRun `
                    -SkipWifi `
                    -SkipDnsFlush `
                    -SkipEventLogs `
                    -SkipUserArtifacts

                Should -Invoke Invoke-NetCleanPhase3Clean -Times 1 -ParameterFilter {
                    $Mode -eq 'SafeConferencePrep' -and
                    $DryRun -and
                    $SkipWifi -and
                    $SkipDnsFlush -and
                    $SkipEventLogs -and
                    $SkipUserArtifacts
                }
            }
        }

        Context 'AdvancedRepair mode' {

            It 'passes AdvancedRepair mode through to Phase 3' {
                Mock Invoke-NetCleanPhase1Detect {
                    [pscustomobject]@{
                        Phase                  = 'Detect'
                        Inventory              = @()
                        ProtectedRegistryPaths = @()
                        SanitizableArtifacts   = @()
                        Summary                = [pscustomobject]@{}
                    }
                }

                Mock Invoke-NetCleanPhase2Protect {
                    [pscustomobject]@{
                        Phase      = 'Protect'
                        BackupPath = 'C:\backup'
                        Protect    = [pscustomobject]@{
                            Summary = [pscustomobject]@{}
                            Manifest = [pscustomobject]@{
                                WiFiExports       = @()
                                NetworkListBackup = 'C:\backup\NetworkList.reg'
                            }
                        }
                    }
                }

                Mock Invoke-NetCleanPhase3Clean {
                    [pscustomobject]@{
                        Phase      = 'Clean'
                        BackupPath = 'C:\backup'
                        Clean      = [pscustomobject]@{
                            Summary = [pscustomobject]@{
                                WiFiProfilesRemoved      = 0
                                RegistryArtifactsRemoved = 0
                                EventLogsTouched         = 0
                                UserArtifactsTouched     = 0
                                AdvancedRepairActions    = 1
                                PerformanceTuningActions = 0
                            }
                            WiFi = [pscustomobject]@{ Profiles = @() }
                            RegistryArtifacts = [pscustomobject]@{ Results = @() }
                            EventLogs = @()
                            UserArtifacts = @()
                        }
                    }
                }

                Mock Invoke-NetCleanPhase4Verify {
                    [pscustomobject]@{
                        Phase      = 'Verify'
                        BackupPath = 'C:\backup'
                        Verify     = [pscustomobject]@{
                            Passed = $true
                            Summary = [pscustomobject]@{
                                Passed              = $true
                                MissingVendorsCount = 0
                                MissingGuidCount    = 0
                                MissingServiceCount = 0
                            }
                            VendorComparison = [pscustomobject]@{ Missing = @() }
                            GuidComparison   = [pscustomobject]@{ Missing = @() }
                            ServiceComparison= [pscustomobject]@{ Missing = @() }
                        }
                    }
                }

                Mock Get-WiFiProfileName { @() }
                Mock Get-NetworkListProfileName { @() }

                $result = Invoke-NetCleanWorkflow -Mode AdvancedRepair -BackupPath 'C:\backup' -DryRun

                $result.Phase | Should -Be 'Verify'
                Should -Invoke Invoke-NetCleanPhase3Clean -Times 1 -ParameterFilter { $Mode -eq 'AdvancedRepair' }
            }
        }

        Context 'PerformanceTune mode' {

            It 'throws when PerformanceProfile is not provided' {
                Mock Invoke-NetCleanPhase1Detect {
                    [pscustomobject]@{
                        Phase                  = 'Detect'
                        Inventory              = @()
                        ProtectedRegistryPaths = @()
                        SanitizableArtifacts   = @()
                        Summary                = [pscustomobject]@{}
                    }
                }

                Mock Invoke-NetCleanPhase2Protect {
                    [pscustomobject]@{
                        Phase      = 'Protect'
                        BackupPath = 'C:\backup'
                        Protect    = [pscustomobject]@{
                            Summary = [pscustomobject]@{}
                            Manifest = [pscustomobject]@{
                                WiFiExports       = @()
                                NetworkListBackup = 'C:\backup\NetworkList.reg'
                            }
                        }
                    }
                }

                Mock Get-WiFiProfileName { @() }
                Mock Get-NetworkListProfileName { @() }

                { Invoke-NetCleanWorkflow -Mode PerformanceTune -BackupPath 'C:\backup' -DryRun } | Should -Throw
            }

            It 'passes PerformanceProfile through to Phase 3' {
                Mock Invoke-NetCleanPhase1Detect {
                    [pscustomobject]@{
                        Phase                  = 'Detect'
                        Inventory              = @()
                        ProtectedRegistryPaths = @()
                        SanitizableArtifacts   = @()
                        Summary                = [pscustomobject]@{}
                    }
                }

                Mock Invoke-NetCleanPhase2Protect {
                    [pscustomobject]@{
                        Phase      = 'Protect'
                        BackupPath = 'C:\backup'
                        Protect    = [pscustomobject]@{
                            Summary = [pscustomobject]@{}
                            Manifest = [pscustomobject]@{
                                WiFiExports       = @()
                                NetworkListBackup = 'C:\backup\NetworkList.reg'
                            }
                        }
                    }
                }

                Mock Invoke-NetCleanPhase3Clean {
                    [pscustomobject]@{
                        Phase              = 'Clean'
                        BackupPath         = 'C:\backup'
                        PerformanceProfile = 'Optimal'
                        Clean              = [pscustomobject]@{
                            Summary = [pscustomobject]@{
                                WiFiProfilesRemoved      = 0
                                RegistryArtifactsRemoved = 0
                                EventLogsTouched         = 0
                                UserArtifactsTouched     = 0
                                AdvancedRepairActions    = 0
                                PerformanceTuningActions = 1
                            }
                            WiFi = [pscustomobject]@{ Profiles = @() }
                            RegistryArtifacts = [pscustomobject]@{ Results = @() }
                            EventLogs = @()
                            UserArtifacts = @()
                        }
                    }
                }

                Mock Invoke-NetCleanPhase4Verify {
                    [pscustomobject]@{
                        Phase      = 'Verify'
                        BackupPath = 'C:\backup'
                        Verify     = [pscustomobject]@{
                            Passed = $true
                            Summary = [pscustomobject]@{
                                Passed              = $true
                                MissingVendorsCount = 0
                                MissingGuidCount    = 0
                                MissingServiceCount = 0
                            }
                            VendorComparison = [pscustomobject]@{ Missing = @() }
                            GuidComparison   = [pscustomobject]@{ Missing = @() }
                            ServiceComparison= [pscustomobject]@{ Missing = @() }
                        }
                    }
                }

                Mock Get-WiFiProfileName { @() }
                Mock Get-NetworkListProfileName { @() }

                $result = Invoke-NetCleanWorkflow -Mode PerformanceTune -BackupPath 'C:\backup' -PerformanceProfile Optimal -DryRun

                $result.Phase | Should -Be 'Verify'
                Should -Invoke Invoke-NetCleanPhase3Clean -Times 1 -ParameterFilter {
                    $Mode -eq 'PerformanceTune' -and
                    $PerformanceProfile -eq 'Optimal'
                }
            }

            It 'stores PerformanceProfile on the returned context' {
                Mock Invoke-NetCleanPhase1Detect {
                    [pscustomobject]@{
                        Phase                  = 'Detect'
                        Inventory              = @()
                        ProtectedRegistryPaths = @()
                        SanitizableArtifacts   = @()
                        Summary                = [pscustomobject]@{}
                    }
                }

                Mock Invoke-NetCleanPhase2Protect {
                    [pscustomobject]@{
                        Phase      = 'Protect'
                        BackupPath = 'C:\backup'
                        Protect    = [pscustomobject]@{
                            Summary = [pscustomobject]@{}
                            Manifest = [pscustomobject]@{
                                WiFiExports       = @()
                                NetworkListBackup = 'C:\backup\NetworkList.reg'
                            }
                        }
                    }
                }

                Mock Invoke-NetCleanPhase3Clean {
                    [pscustomobject]@{
                        Phase              = 'Clean'
                        BackupPath         = 'C:\backup'
                        PerformanceProfile = 'Gaming'
                        Clean              = [pscustomobject]@{
                            Summary = [pscustomobject]@{
                                WiFiProfilesRemoved      = 0
                                RegistryArtifactsRemoved = 0
                                EventLogsTouched         = 0
                                UserArtifactsTouched     = 0
                                AdvancedRepairActions    = 0
                                PerformanceTuningActions = 1
                            }
                            WiFi = [pscustomobject]@{ Profiles = @() }
                            RegistryArtifacts = [pscustomobject]@{ Results = @() }
                            EventLogs = @()
                            UserArtifacts = @()
                        }
                    }
                }

                Mock Invoke-NetCleanPhase4Verify {
                    [pscustomobject]@{
                        Phase      = 'Verify'
                        BackupPath = 'C:\backup'
                        Verify     = [pscustomobject]@{
                            Passed = $true
                            Summary = [pscustomobject]@{
                                Passed              = $true
                                MissingVendorsCount = 0
                                MissingGuidCount    = 0
                                MissingServiceCount = 0
                            }
                            VendorComparison = [pscustomobject]@{ Missing = @() }
                            GuidComparison   = [pscustomobject]@{ Missing = @() }
                            ServiceComparison= [pscustomobject]@{ Missing = @() }
                        }
                    }
                }

                Mock Get-WiFiProfileName { @() }
                Mock Get-NetworkListProfileName { @() }

                $result = Invoke-NetCleanWorkflow -Mode PerformanceTune -BackupPath 'C:\backup' -PerformanceProfile Gaming -DryRun

                $result.PerformanceProfile | Should -Be 'Gaming'
            }
        }

        Context 'Shared workflow behavior' {

            It 'preserves BackupPath across phases even when later phases omit it' {
                Mock Invoke-NetCleanPhase1Detect {
                    [pscustomobject]@{
                        Phase                  = 'Detect'
                        Inventory              = @()
                        ProtectedRegistryPaths = @()
                        SanitizableArtifacts   = @()
                        Summary                = [pscustomobject]@{}
                    }
                }

                Mock Invoke-NetCleanPhase2Protect {
                    [pscustomobject]@{
                        Phase      = 'Protect'
                        BackupPath = 'C:\backup'
                        Protect    = [pscustomobject]@{
                            Summary = [pscustomobject]@{}
                            Manifest = [pscustomobject]@{
                                WiFiExports       = @()
                                NetworkListBackup = 'C:\backup\NetworkList.reg'
                            }
                        }
                    }
                }

                Mock Invoke-NetCleanPhase3Clean {
                    [pscustomobject]@{
                        Phase = 'Clean'
                        Clean = [pscustomobject]@{
                            Summary = [pscustomobject]@{
                                WiFiProfilesRemoved      = 0
                                RegistryArtifactsRemoved = 0
                                EventLogsTouched         = 0
                                UserArtifactsTouched     = 0
                                AdvancedRepairActions    = 0
                                PerformanceTuningActions = 0
                            }
                            WiFi = [pscustomobject]@{ Profiles = @() }
                            RegistryArtifacts = [pscustomobject]@{ Results = @() }
                            EventLogs = @()
                            UserArtifacts = @()
                        }
                    }
                }

                Mock Invoke-NetCleanPhase4Verify {
                    [pscustomobject]@{
                        Phase  = 'Verify'
                        Verify = [pscustomobject]@{
                            Passed = $true
                            Summary = [pscustomobject]@{
                                Passed              = $true
                                MissingVendorsCount = 0
                                MissingGuidCount    = 0
                                MissingServiceCount = 0
                            }
                            VendorComparison = [pscustomobject]@{ Missing = @() }
                            GuidComparison   = [pscustomobject]@{ Missing = @() }
                            ServiceComparison= [pscustomobject]@{ Missing = @() }
                        }
                    }
                }

                Mock Get-WiFiProfileName { @() }
                Mock Get-NetworkListProfileName { @() }

                $result = Invoke-NetCleanWorkflow -Mode SafeConferencePrep -BackupPath 'C:\backup' -DryRun

                $result.BackupPath | Should -Be 'C:\backup'
            }

            It 'adds timings for all phases in non-preview flows' {
                Mock Invoke-NetCleanPhase1Detect {
                    [pscustomobject]@{
                        Phase                  = 'Detect'
                        Inventory              = @()
                        ProtectedRegistryPaths = @()
                        SanitizableArtifacts   = @()
                        Summary                = [pscustomobject]@{}
                    }
                }

                Mock Invoke-NetCleanPhase2Protect {
                    [pscustomobject]@{
                        Phase      = 'Protect'
                        BackupPath = 'C:\backup'
                        Protect    = [pscustomobject]@{
                            Summary = [pscustomobject]@{}
                            Manifest = [pscustomobject]@{
                                WiFiExports       = @()
                                NetworkListBackup = 'C:\backup\NetworkList.reg'
                            }
                        }
                    }
                }

                Mock Invoke-NetCleanPhase3Clean {
                    [pscustomobject]@{
                        Phase      = 'Clean'
                        BackupPath = 'C:\backup'
                        Clean      = [pscustomobject]@{
                            Summary = [pscustomobject]@{
                                WiFiProfilesRemoved      = 0
                                RegistryArtifactsRemoved = 0
                                EventLogsTouched         = 0
                                UserArtifactsTouched     = 0
                                AdvancedRepairActions    = 0
                                PerformanceTuningActions = 0
                            }
                            WiFi = [pscustomobject]@{ Profiles = @() }
                            RegistryArtifacts = [pscustomobject]@{ Results = @() }
                            EventLogs = @()
                            UserArtifacts = @()
                        }
                    }
                }

                Mock Invoke-NetCleanPhase4Verify {
                    [pscustomobject]@{
                        Phase      = 'Verify'
                        BackupPath = 'C:\backup'
                        Verify     = [pscustomobject]@{
                            Passed = $true
                            Summary = [pscustomobject]@{
                                Passed              = $true
                                MissingVendorsCount = 0
                                MissingGuidCount    = 0
                                MissingServiceCount = 0
                            }
                            VendorComparison = [pscustomobject]@{ Missing = @() }
                            GuidComparison   = [pscustomobject]@{ Missing = @() }
                            ServiceComparison= [pscustomobject]@{ Missing = @() }
                        }
                    }
                }

                Mock Get-WiFiProfileName { @() }
                Mock Get-NetworkListProfileName { @() }

                $result = Invoke-NetCleanWorkflow -Mode SafeConferencePrep -BackupPath 'C:\backup' -DryRun

                $result.Timings | Should -Not -BeNullOrEmpty
                $result.Timings.Detect | Should -Not -BeNullOrEmpty
                $result.Timings.Protect | Should -Not -BeNullOrEmpty
                $result.Timings.Clean | Should -Not -BeNullOrEmpty
                $result.Timings.Verify | Should -Not -BeNullOrEmpty
            }

            It 'writes a complete live audit summary from the preserved workflow context' {
                Mock Invoke-NetCleanPhase1Detect { [pscustomobject]@{ Phase = 'Detect' } }
                Mock Invoke-NetCleanPhase2Protect {
                    [pscustomobject]@{
                        Phase   = 'Protect'
                        Protect = [pscustomobject]@{
                            Summary      = [pscustomobject]@{}
                            Manifest     = [pscustomobject]@{ WiFiExports = @() }
                            ManifestFile = 'C:\backup\RestoreManifest.json'
                        }
                    }
                }
                Mock Get-WiFiProfileName { @() }
                Mock Get-NetworkListProfileName { @() }
                Mock Invoke-NetCleanPhase3Clean {
                    $Context | Add-Member -NotePropertyName Phase -NotePropertyValue 'Clean' -Force
                    $Context | Add-Member -NotePropertyName Clean -NotePropertyValue ([pscustomobject]@{
                        WiFi = [pscustomobject]@{ Profiles = @('HomeSSID', 'OfficeSSID') }
                        RegistryArtifacts = [pscustomobject]@{
                            Results = @(
                                [pscustomobject]@{ RegistryPath = 'HKLM:\Removed'; Removed = $true }
                                [pscustomobject]@{ RegistryPath = 'HKLM:\Retained'; Removed = $false }
                            )
                        }
                        EventLogs = @('WLAN', 'NetworkProfile')
                        UserArtifacts = @(
                            [pscustomobject]@{ Path = 'HKCU:\Removed'; Removed = $true }
                            [pscustomobject]@{ Path = 'HKCU:\Retained'; Removed = $false }
                        )
                    }) -Force
                    $Context
                }
                Mock Invoke-NetCleanPhase4Verify {
                    $Context | Add-Member -NotePropertyName Phase -NotePropertyValue 'Verify' -Force
                    $Context | Add-Member -NotePropertyName Verify -NotePropertyValue ([pscustomobject]@{
                        Summary           = [pscustomobject]@{ Passed = $true }
                        VendorComparison  = [pscustomobject]@{ Missing = @() }
                        GuidComparison    = [pscustomobject]@{ Missing = @() }
                        ServiceComparison = [pscustomobject]@{ Missing = @() }
                    }) -Force
                    $Context
                }
                $script:logMessages = [System.Collections.Generic.List[string]]::new()
                Mock Write-NetCleanLog { [void]$script:logMessages.Add($Message) }

                $result = Invoke-NetCleanWorkflow -Mode SafeConferencePrep -BackupPath 'C:\backup'

                $result.Phase | Should -Be 'Verify'
                $script:logMessages | Should -Contain 'Final summary: Mode=SafeConferencePrep DryRun=False BackupPath=(none) ManifestFile=C:\backup\RestoreManifest.json'
                $script:logMessages | Should -Contain 'Wi-Fi profiles removed/wouldRemove: HomeSSID, OfficeSSID'
                $script:logMessages | Should -Contain 'Registry artifacts removed count: 1'
                $script:logMessages | Should -Contain 'Registry removed: HKLM:\Removed'
                $script:logMessages | Should -Contain 'Event logs touched: 2'
                $script:logMessages | Should -Contain 'User artifacts touched count: 1'
                $script:logMessages | Should -Contain 'Verification passed: True'
            }
        }
    }
}
