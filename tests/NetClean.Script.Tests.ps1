BeforeAll {
    $repoRoot = Split-Path -Parent $PSScriptRoot
    $manifestPath = Join-Path $repoRoot 'NetClean.psd1'

    if (-not (Test-Path -LiteralPath $manifestPath)) {
        throw "NetClean.psd1 not found at path: $manifestPath"
    }

    Remove-Module NetClean, NetCleanPhase1, NetCleanPhase2, NetCleanPhase3, NetCleanPhase4 -ErrorAction SilentlyContinue
    Import-Module $manifestPath -Force
}

Describe 'NetClean.ps1 launcher / UX functions' {
    BeforeAll {
        $scriptPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'NetClean.ps1'
        Mock Import-Module {}
        $script:NetCleanTestMode = $true
        . $scriptPath
    }

    It 'Read-YesNo returns true when Force is set' {
        Mock Read-Host { throw "Prompt should not be called when Force is set" }

        $script:Force = $true
        Read-YesNo -Prompt 'Continue?' | Should -BeTrue
        Should -Not -Invoke Read-Host
        $script:Force = $false
    }

    It 'Read-NetCleanMenuSelection maps menu option 1 to Preview' {
        Mock Show-NetCleanMenu {}
        Mock Read-Host { '1' }
        Read-NetCleanMenuSelection | Should -Be 'Preview'
    }

    It 'Read-NetCleanMenuSelection maps menu option 5 to Exit' {
        Mock Show-NetCleanMenu {}
        Mock Read-Host { '5' }
        Read-NetCleanMenuSelection | Should -Be 'Exit'
    }

    It 'Read-NetCleanOption forces DryRun in Preview mode' {
        $r = Read-NetCleanOption -SelectedMode Preview
        $r.SelectedMode | Should -Be 'Preview'
        $r.DryRun | Should -BeTrue
    }

    It 'Read-NetCleanOption preserves explicit DryRun in non-preview mode' {
        $r = Read-NetCleanOption -SelectedMode SafeConferencePrep -DryRun
        $r.SelectedMode | Should -Be 'SafeConferencePrep'
        $r.DryRun | Should -BeTrue
    }

    It 'Read-NetCleanOption defaults DryRun to false in non-preview mode' {
        $r = Read-NetCleanOption -SelectedMode SafeConferencePrep
        $r.SelectedMode | Should -Be 'SafeConferencePrep'
        $r.DryRun | Should -BeFalse
    }

    It 'Read-NetCleanOption throws when PerformanceTune has no profile' {
        { Read-NetCleanOption -SelectedMode PerformanceTune } | Should -Throw
    }

    It 'Read-NetCleanOption accepts PerformanceTune when profile is provided' {
        $r = Read-NetCleanOption -SelectedMode PerformanceTune -PerformanceProfile Optimal
        $r.SelectedMode | Should -Be 'PerformanceTune'
        $r.PerformanceProfile | Should -Be 'Optimal'
    }

    It 'Prompt/Read post run action returns Restart for R' {
        Mock Read-Host { 'R' }
        Read-PostRunAction | Should -Be 'Restart'
    }

    It 'Invoke-PostRunAction does nothing destructive in dry-run mode' {
        Mock Restart-Computer {}
        Invoke-PostRunAction -Action Restart -DryRunMode
        Should -Invoke Restart-Computer -Times 0
    }
}

Describe 'NetClean.ps1 launcher orchestration' {
    BeforeEach {
        $scriptPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'NetClean.ps1'
        Mock Import-Module {}
        $script:NetCleanTestMode = $true
        . $scriptPath

        Mock Test-NetCleanAdministrator {}
        Mock Start-NetCleanLog {}
        Mock Write-NetCleanLog {}
        Mock Read-Host { 'Y' }
        Mock Read-YesNo { $true }
        Mock Show-ModeExplanation {}
        Mock New-DirectoryIfNotExist {}
        Mock Read-PostRunAction { 'None' }
        Mock Invoke-PostRunAction {}
    }

    It 'runs preview path when preview mode is selected' {
        Mock Read-NetCleanOption {
            [pscustomobject]@{
                SelectedMode = 'Preview'
                DryRun = $true
                SkipWifi = $false
                SkipDnsFlush = $false
                SkipEventLogs = $false
                SkipUserArtifacts = $false
                SkipFirewallBackup = $false
                PerformanceProfile = $null
            }
        }

        Mock Invoke-NetCleanPhase1Detect {
            [pscustomobject]@{
                Summary = [pscustomobject]@{
                    ProtectedVendorsCount = 1
                    ProtectedInterfaceGuidCount = 1
                    CandidateArtifactCount = 1
                    SanitizableArtifactCount = 1
                }
            }
        }

        Mock Invoke-NetCleanPhase2Protect {
            param($Context, $BackupPath, $DryRun, $SkipFirewallBackup)
            $Context | Add-Member -NotePropertyName BackupPath -NotePropertyValue $BackupPath -Force
            return $Context
        }

        Mock Show-PreviewSummary {}

        $Mode = 'Preview'
        Invoke-NetCleanLauncher

        Should -Invoke Show-PreviewSummary -Times 1
        Should -Invoke Invoke-NetCleanPhase1Detect -Times 1
        Should -Invoke Invoke-NetCleanPhase2Protect -Times 1
    }

    It 'runs full workflow for non-preview mode' {
        Mock Read-NetCleanOption {
            [pscustomobject]@{
                SelectedMode = 'SafeConferencePrep'
                DryRun = $true
                SkipWifi = $false
                SkipDnsFlush = $false
                SkipEventLogs = $false
                SkipUserArtifacts = $false
                SkipFirewallBackup = $false
                PerformanceProfile = $null
            }
        }

        Mock Invoke-NetCleanWorkflow {
            [pscustomobject]@{
                Summary = [pscustomobject]@{
                    ProtectedVendorsCount = 1
                    ProtectedInterfaceGuidCount = 1
                    CandidateArtifactCount = 1
                    SanitizableArtifactCount = 1
                }
                Protect = [pscustomobject]@{
                    Summary = [pscustomobject]@{
                        ProtectedRegistryPathCount = 1
                        WiFiBackupCount = 1
                        ProtectedRegistryBackupCount = 1
                    }
                }
                Clean = [pscustomobject]@{
                    Summary = [pscustomobject]@{
                        WiFiProfilesRemoved = 1
                        RegistryArtifactsRemoved = 1
                        EventLogsTouched = 1
                        UserArtifactsTouched = 1
                        AdvancedRepairActions = 0
                        PerformanceTuningActions = 0
                    }
                }
                Verify = [pscustomobject]@{
                    Summary = [pscustomobject]@{
                        Passed = $true
                        MissingVendorsCount = 0
                        MissingGuidCount = 0
                        MissingServiceCount = 0
                    }
                    VendorComparison = [pscustomobject]@{
                        Missing = @()
                    }
                }
                BackupPath = 'C:\ProgramData\NetClean\Backups'
            }
        }

        Mock Show-NetCleanSummary {}

        $Mode = 'SafeConferencePrep'
        Invoke-NetCleanLauncher

        Should -Invoke Invoke-NetCleanWorkflow -Times 1
        Should -Invoke Show-NetCleanSummary -Times 1
    }
}