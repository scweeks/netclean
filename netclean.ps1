<#
.SYNOPSIS
    NetClean launcher / UX shell.

.DESCRIPTION
    Thin orchestration layer for NetClean.psm1.

    Responsibilities of this script:
    - parameter handling
    - admin check
    - menu / UX
    - logging
    - calling module phase/workflow functions
    - displaying summaries
    - optional reboot prompt

    Responsibilities of NetClean.psm1:
    - detect
    - protect
    - clean
    - verify
    - backup/export
    - repair/tuning helpers
#>

[CmdletBinding()]
param(
    [ValidateSet('Menu', 'Preview', 'SafeConferencePrep', 'AdvancedRepair', 'PerformanceTune')]
    [string]$Mode = 'Menu',

    [switch]$DryRun,
    [switch]$Force,
    [switch]$CreateLog,

    [string]$BackupPath = "$env:ProgramData\NetClean\Backups",
    [string]$LogPath    = "$env:ProgramData\NetClean\Logs",

    [switch]$SkipWifi,
    [switch]$SkipDnsFlush,
    [switch]$SkipEventLogs,
    [switch]$SkipUserArtifacts,
    [switch]$SkipFirewallBackup,

    [switch]$EnableConservativePerformanceTuning,
    [switch]$RebootNow
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Module import
# ---------------------------------------------------------------------------

$modulePath = Join-Path $PSScriptRoot 'NetClean.psm1'
Import-Module -Name $modulePath -Force -ErrorAction Stop

# ---------------------------------------------------------------------------
# Script state
# ---------------------------------------------------------------------------

$script:LogFile = $null

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

function Start-NetCleanLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Directory
    )

    if (-not (Test-Path -LiteralPath $Directory)) {
        New-Item -Path $Directory -ItemType Directory -Force | Out-Null
    }

    $script:LogFile = Join-Path $Directory ("NetClean_{0}.log" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
    "[$(Get-Date -Format s)] [INFO] Log started" | Out-File -FilePath $script:LogFile -Encoding UTF8
}

function Write-NetCleanLog {
    [CmdletBinding()]
    param(
        [ValidateSet('INFO', 'WARN', 'ERROR', 'DEBUG')]
        [string]$Level = 'INFO',

        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    $line = "[$(Get-Date -Format s)] [$Level] $Message"

    if ($script:LogFile) {
        $line | Out-File -FilePath $script:LogFile -Encoding UTF8 -Append
    }

    switch ($Level) {
        'ERROR' { Write-Error $Message }
        'WARN'  { Write-Warning $Message }
        'DEBUG' { Write-Verbose $Message }
        default { Write-Verbose $Message }
    }
}

# ---------------------------------------------------------------------------
# UX helpers
# ---------------------------------------------------------------------------

function Test-NetCleanAdministrator {
    [CmdletBinding()]
    param()

    $principal = [Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
    $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    if (-not $isAdmin) {
        throw 'NetClean must be run as Administrator.'
    }
}

function Read-YesNo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Prompt,

        [bool]$DefaultNo = $true
    )

    if ($Force) {
        return $true
    }

    while ($true) {
        $suffix = if ($DefaultNo) { '[y/N]' } else { '[Y/n]' }
        $answer = Read-Host "$Prompt $suffix"

        if ([string]::IsNullOrWhiteSpace($answer)) {
            return (-not $DefaultNo)
        }

        if ($answer -match '^[Yy]') { return $true }
        if ($answer -match '^[Nn]') { return $false }

        Write-Host 'Please enter Y or N.' -ForegroundColor Yellow
    }
}

function Show-NetCleanBanner {
    [CmdletBinding()]
    param()

    Write-Host ''
    Write-Host '==========================================' -ForegroundColor Cyan
    Write-Host ' NetClean - Conference / CTF Prep Tool' -ForegroundColor Cyan
    Write-Host '==========================================' -ForegroundColor Cyan
    Write-Host ''
    Write-Host 'This tool helps remove network history and metadata while preserving'
    Write-Host 'security products, firewalls, hypervisors, and protected adapters.'
    Write-Host ''
}

function Show-NetCleanMenu {
    [CmdletBinding()]
    param()

    Show-NetCleanBanner

    Write-Host '1. Preview only'
    Write-Host '   Detect and show what would be cleaned. No changes made.'
    Write-Host ''
    Write-Host '2. Safe conference prep'
    Write-Host '   Backup, remove network history, preserve security and virtualization tools.'
    Write-Host ''
    Write-Host '3. Advanced repair'
    Write-Host '   Includes deeper network reset actions. May affect installed software.'
    Write-Host ''
    Write-Host '4. Performance tuning'
    Write-Host '   Apply conservative network performance tuning.'
    Write-Host ''
    Write-Host '5. Exit'
    Write-Host ''
}

function Read-NetCleanMenuSelection {
    [CmdletBinding()]
    param()

    while ($true) {
        Show-NetCleanMenu
        $choice = Read-Host 'Select an option (1-5)'

        switch ($choice) {
            '1' { return 'Preview' }
            '2' { return 'SafeConferencePrep' }
            '3' { return 'AdvancedRepair' }
            '4' { return 'PerformanceTune' }
            '5' { return 'Exit' }
            default {
                Write-Host ''
                Write-Host 'Invalid selection. Please choose 1 through 5.' -ForegroundColor Yellow
                Write-Host ''
            }
        }
    }
}

function Show-ModeExplanation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Preview', 'SafeConferencePrep', 'AdvancedRepair', 'PerformanceTune')]
        [string]$SelectedMode
    )

    Write-Host ''
    switch ($SelectedMode) {
        'Preview' {
            Write-Host 'You selected: Preview'
            Write-Host ''
            Write-Host 'This will:'
            Write-Host '  - detect protection software and protected adapters'
            Write-Host '  - build a protected registry map'
            Write-Host '  - export backup/restore metadata'
            Write-Host '  - make no cleanup changes'
        }
        'SafeConferencePrep' {
            Write-Host 'You selected: Safe conference prep'
            Write-Host ''
            Write-Host 'This will:'
            Write-Host '  - detect protection software and protected adapters'
            Write-Host '  - back up protected registry, firewall policy, and Wi-Fi profiles'
            Write-Host '  - remove saved Wi-Fi profiles'
            Write-Host '  - flush DNS cache'
            Write-Host '  - remove non-protected network history and metadata'
            Write-Host '  - verify protected products remain present'
        }
        'AdvancedRepair' {
            Write-Host 'You selected: Advanced repair'
            Write-Host ''
            Write-Host 'This will do everything in Safe conference prep, plus:'
            Write-Host '  - run advanced network repair/reset actions'
            Write-Host '  - this may affect installed networking/security software'
        }
        'PerformanceTune' {
            Write-Host 'You selected: Performance tuning'
            Write-Host ''
            Write-Host 'This will do Safe conference prep, plus:'
            Write-Host '  - apply conservative, Microsoft-supported TCP tuning actions'
            Write-Host '  - no third-party code or proprietary settings are used'
        }
    }
    Write-Host ''
}

function Read-NetCleanOptions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Preview', 'SafeConferencePrep', 'AdvancedRepair', 'PerformanceTune')]
        [string]$SelectedMode
    )

    $options = [ordered]@{
        Mode                              = $SelectedMode
        DryRun                            = $DryRun
        SkipWifi                          = $SkipWifi
        SkipDnsFlush                      = $SkipDnsFlush
        SkipEventLogs                     = $SkipEventLogs
        SkipUserArtifacts                 = $SkipUserArtifacts
        SkipFirewallBackup                = $SkipFirewallBackup
        EnableConservativePerformanceTuning = $EnableConservativePerformanceTuning
    }

    if ($PSBoundParameters.ContainsKey('DryRun') -or
        $PSBoundParameters.ContainsKey('SkipWifi') -or
        $PSBoundParameters.ContainsKey('SkipDnsFlush') -or
        $PSBoundParameters.ContainsKey('SkipEventLogs') -or
        $PSBoundParameters.ContainsKey('SkipUserArtifacts') -or
        $PSBoundParameters.ContainsKey('SkipFirewallBackup') -or
        $PSBoundParameters.ContainsKey('EnableConservativePerformanceTuning')) {
        return [pscustomobject]$options
    }

    if ($SelectedMode -eq 'Preview') {
        $options.DryRun = $true
        return [pscustomobject]$options
    }

    $options.DryRun = Read-YesNo -Prompt 'Run in dry-run mode?' -DefaultNo $true
    $options.SkipWifi = -not (Read-YesNo -Prompt 'Remove saved Wi-Fi profiles?' -DefaultNo $false)
    $options.SkipDnsFlush = -not (Read-YesNo -Prompt 'Flush DNS cache?' -DefaultNo $false)
    $options.SkipEventLogs = -not (Read-YesNo -Prompt 'Clear selected network-related event logs?' -DefaultNo $false)
    $options.SkipUserArtifacts = -not (Read-YesNo -Prompt 'Clear selected user-level network artifacts (RDP / mapped drive history)?' -DefaultNo $false)
    $options.SkipFirewallBackup = -not (Read-YesNo -Prompt 'Back up firewall policy?' -DefaultNo $false)

    if ($SelectedMode -eq 'PerformanceTune') {
        $options.EnableConservativePerformanceTuning = $true
    }

    return [pscustomobject]$options
}

function Show-NetCleanSummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Result,

        [Parameter(Mandatory = $true)]
        [string]$SelectedMode
    )

    Write-Host ''
    Write-Host 'NetClean Summary'
    Write-Host '----------------'
    Write-Host "Mode: $SelectedMode"

    if ($Result.PSObject.Properties.Name -contains 'Summary') {
        Write-Host ''
        Write-Host 'Phase 1 - Detect'
        Write-Host "  Protected vendors detected: $($Result.Summary.ProtectedVendorsCount)"
        Write-Host "  Protected interface GUIDs: $($Result.Summary.ProtectedInterfaceGuidCount)"
        Write-Host "  Candidate artifacts: $($Result.Summary.CandidateArtifactCount)"
        Write-Host "  Sanitizable artifacts: $($Result.Summary.SanitizableArtifactCount)"
    }

    if ($Result.PSObject.Properties.Name -contains 'Protect') {
        Write-Host ''
        Write-Host 'Phase 2 - Protect'
        Write-Host "  Protected registry paths: $($Result.Protect.Summary.ProtectedRegistryPathCount)"
        Write-Host "  Wi-Fi backup items: $($Result.Protect.Summary.WiFiBackupCount)"
        Write-Host "  Protected registry backups: $($Result.Protect.Summary.ProtectedRegistryBackupCount)"
    }

    if ($Result.PSObject.Properties.Name -contains 'Clean') {
        Write-Host ''
        Write-Host 'Phase 3 - Clean'
        Write-Host "  Wi-Fi profiles removed: $($Result.Clean.Summary.WiFiProfilesRemoved)"
        Write-Host "  Registry artifacts removed: $($Result.Clean.Summary.RegistryArtifactsRemoved)"
        Write-Host "  Event logs touched: $($Result.Clean.Summary.EventLogsTouched)"
        Write-Host "  User artifacts touched: $($Result.Clean.Summary.UserArtifactsTouched)"
        Write-Host "  Advanced repair actions: $($Result.Clean.Summary.AdvancedRepairActions)"
        Write-Host "  Performance tuning actions: $($Result.Clean.Summary.PerformanceTuningActions)"
    }

    if ($Result.PSObject.Properties.Name -contains 'Verify') {
        Write-Host ''
        Write-Host 'Phase 4 - Verify'
        Write-Host "  Verification passed: $($Result.Verify.Summary.Passed)"
        Write-Host "  Missing vendors: $($Result.Verify.Summary.MissingVendorsCount)"
        Write-Host "  Missing protected GUIDs: $($Result.Verify.Summary.MissingGuidCount)"
        Write-Host "  Missing services: $($Result.Verify.Summary.MissingServiceCount)"

        if (@($Result.Verify.VendorComparison.Missing).Count -gt 0) {
            Write-Host ("  Missing vendor names: " + ($Result.Verify.VendorComparison.Missing -join ', ')) -ForegroundColor Yellow
        }
    }

    if ($Result.PSObject.Properties.Name -contains 'BackupPath') {
        Write-Host ''
        Write-Host "Backup Path: $($Result.BackupPath)"
    }

    if ($script:LogFile) {
        Write-Host "Log File: $script:LogFile"
    }

    Write-Host ''
}

function Show-PreviewSummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Result
    )

    Write-Host ''
    Write-Host 'Preview Summary'
    Write-Host '---------------'
    Write-Host "Protected vendors detected: $($Result.Summary.ProtectedVendorsCount)"
    Write-Host "Protected interface GUIDs: $($Result.Summary.ProtectedInterfaceGuidCount)"
    Write-Host "Candidate artifacts: $($Result.Summary.CandidateArtifactCount)"
    Write-Host "Sanitizable artifacts: $($Result.Summary.SanitizableArtifactCount)"
    Write-Host ''
    Write-Host "Backup Path: $($Result.BackupPath)"
    if ($script:LogFile) {
        Write-Host "Log File: $script:LogFile"
    }
    Write-Host ''
}

function Prompt-PostRunAction {
    [CmdletBinding()]
    param()

    if ($RebootNow) {
        return 'Restart'
    }

    while ($true) {
        $choice = Read-Host 'Choose post-run action: [R]estart / [S]hutdown / [N]o action'
        switch ($choice.ToUpperInvariant()) {
            'R' { return 'Restart' }
            'S' { return 'Shutdown' }
            'N' { return 'None' }
            default {
                Write-Host 'Please enter R, S, or N.' -ForegroundColor Yellow
            }
        }
    }
}

function Invoke-PostRunAction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Restart', 'Shutdown', 'None')]
        [string]$Action,

        [switch]$DryRunMode
    )

    switch ($Action) {
        'Restart' {
            if ($DryRunMode) {
                Write-NetCleanLog -Level INFO -Message 'DRYRUN: Restart-Computer -Force'
            }
            else {
                Restart-Computer -Force
            }
        }
        'Shutdown' {
            if ($DryRunMode) {
                Write-NetCleanLog -Level INFO -Message 'DRYRUN: Stop-Computer -Force'
            }
            else {
                Stop-Computer -Force
            }
        }
        'None' {
            Write-NetCleanLog -Level INFO -Message 'No post-run power action selected.'
        }
    }
}

# ---------------------------------------------------------------------------
# Main orchestration
# ---------------------------------------------------------------------------

function Invoke-NetCleanLauncher {
    [CmdletBinding()]
    param()

    Test-NetCleanAdministrator

    $selectedMode = $Mode
    if ($selectedMode -eq 'Menu') {
        $selectedMode = Read-NetCleanMenuSelection
        if ($selectedMode -eq 'Exit') {
            return
        }
    }

    Show-ModeExplanation -SelectedMode $selectedMode
    $options = Read-NetCleanOptions -SelectedMode $selectedMode

    if (-not $Force) {
        if (-not (Read-YesNo -Prompt 'Proceed with the selected NetClean operation?' -DefaultNo $true)) {
            Write-Host 'Operation cancelled.'
            return
        }
    }

    if ($CreateLog -or $selectedMode -ne 'Menu') {
        Start-NetCleanLog -Directory $LogPath
    }

    Write-NetCleanLog -Level INFO -Message "NetClean starting. Mode=$selectedMode DryRun=$($options.DryRun)"

    Ensure-Directory -Path $BackupPath

    if ($selectedMode -eq 'Preview') {
        $ctx = Invoke-NetCleanPhase1Detect
        $ctx = Invoke-NetCleanPhase2Protect `
            -Context $ctx `
            -BackupPath $BackupPath `
            -DryRun:$true `
            -SkipFirewallBackup:$options.SkipFirewallBackup

        Show-PreviewSummary -Result $ctx
        return
    }

    $result = Invoke-NetCleanWorkflow `
        -Mode $selectedMode `
        -BackupPath $BackupPath `
        -DryRun:$options.DryRun `
        -SkipWifi:$options.SkipWifi `
        -SkipDnsFlush:$options.SkipDnsFlush `
        -SkipEventLogs:$options.SkipEventLogs `
        -SkipUserArtifacts:$options.SkipUserArtifacts `
        -SkipFirewallBackup:$options.SkipFirewallBackup `
        -EnableConservativePerformanceTuning:$options.EnableConservativePerformanceTuning

    Show-NetCleanSummary -Result $result -SelectedMode $selectedMode

    $postRunAction = Prompt-PostRunAction
    Invoke-PostRunAction -Action $postRunAction -DryRunMode:$options.DryRun
}

Invoke-NetCleanLauncher