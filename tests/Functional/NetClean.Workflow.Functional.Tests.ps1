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
        }
    }
}
