$ProjectRoot = Split-Path -Parent $PSScriptRoot
$ScriptPath  = Join-Path $ProjectRoot 'NetClean.ps1'
$ModulePath  = Join-Path $ProjectRoot 'NetClean.psm1'

Import-Module $ModulePath -Force -ErrorAction Stop

function Load-NetCleanScriptFunctions {
    $script:NetCleanTestMode = $true
    . $ScriptPath
}

function Load-NetCleanScriptFunctions {
    $content = Get-Content -LiteralPath $scriptPath -Raw
    # Remove the terminal launcher invocation so the file can be dot-sourced for testing.
    $content = $content -replace '(?ms)\nInvoke-NetCleanLauncher\s*$', "`n"
    $temp = Join-Path $TestDrive 'NetClean.NoRun.ps1'
    Set-Content -LiteralPath $temp -Value $content -Encoding UTF8
    . $temp
}

Describe 'NetClean.ps1 launcher / UX functions' {
    BeforeAll {
        Mock Import-Module {}
        Load-NetCleanScriptFunctions
    }

    It 'Read-YesNo returns true when Force is set' {
        $script:Force = $true
        Read-YesNo -Prompt 'Continue?' | Should -BeTrue
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
        $r.Mode   | Should -Be 'Preview'
        $r.DryRun | Should -BeTrue
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
        Mock Import-Module {}
        Load-NetCleanScriptFunctions
        Mock Test-NetCleanAdministrator {}
        Mock Start-NetCleanLog {}
        Mock Ensure-Directory {}
        Mock Write-NetCleanLog {}
        Mock Show-ModeExplanation {}
        Mock Show-NetCleanSummary {}
        Mock Show-PreviewSummary {}
        Mock Invoke-PostRunAction {}
    }

    It 'runs preview path when preview mode is selected' {
        Mock Read-NetCleanMenuSelection { 'Preview' }
        Mock Read-NetCleanOption { [pscustomobject]@{ Mode='Preview'; DryRun=$true; SkipWifi=$false; SkipDnsFlush=$false; SkipEventLogs=$false; SkipUserArtifacts=$false; SkipFirewallBackup=$false; EnableConservativePerformanceTuning=$false } }
        Mock Read-YesNo { $true }
        Mock Invoke-NetCleanPhase1Detect { [pscustomobject]@{ Summary=[pscustomobject]@{ ProtectedVendorsCount=1; ProtectedInterfaceGuidCount=1; CandidateArtifactCount=1; SanitizableArtifactCount=1 }; ProtectedRegistryPaths=@(); Inventory=@() } }
        Mock Invoke-NetCleanPhase2Protect { param($Context,$BackupPath,[switch]$DryRun,[switch]$SkipFirewallBackup) [pscustomobject]@{ BackupPath=$BackupPath; Summary=$Context.Summary; ProtectedRegistryPaths=@(); Inventory=@() } }

        Invoke-NetCleanLauncher
        Should -Invoke Invoke-NetCleanPhase1Detect -Times 1
        Should -Invoke Invoke-NetCleanPhase2Protect -Times 1
        Should -Invoke Show-PreviewSummary -Times 1
    }

    It 'runs full workflow for non-preview mode' {
        Mock Read-NetCleanMenuSelection { 'SafeConferencePrep' }
        Mock Read-NetCleanOption { [pscustomobject]@{ Mode='SafeConferencePrep'; DryRun=$true; SkipWifi=$false; SkipDnsFlush=$false; SkipEventLogs=$false; SkipUserArtifacts=$false; SkipFirewallBackup=$false; EnableConservativePerformanceTuning=$false } }
        Mock Read-YesNo { $true }
        Mock Invoke-NetCleanWorkflow { [pscustomobject]@{ BackupPath='C:\backup'; Summary=[pscustomobject]@{ ProtectedVendorsCount=1; ProtectedInterfaceGuidCount=1; CandidateArtifactCount=1; SanitizableArtifactCount=1 }; Protect=[pscustomobject]@{ Summary=[pscustomobject]@{ ProtectedRegistryPathCount=1; WiFiBackupCount=1; ProtectedRegistryBackupCount=1 } }; Clean=[pscustomobject]@{ Summary=[pscustomobject]@{ WiFiProfilesRemoved=1; RegistryArtifactsRemoved=1; EventLogsTouched=1; UserArtifactsTouched=1; AdvancedRepairActions=0; PerformanceTuningActions=0 } }; Verify=[pscustomobject]@{ Summary=[pscustomobject]@{ Passed=$true; MissingVendorsCount=0; MissingGuidCount=0; MissingServiceCount=0 }; VendorComparison=[pscustomobject]@{ Missing=@() } } } }
        Mock Read-PostRunAction { 'None' }

        Invoke-NetCleanLauncher
        Should -Invoke Invoke-NetCleanWorkflow -Times 1
        Should -Invoke Show-NetCleanSummary -Times 1
    }
}
