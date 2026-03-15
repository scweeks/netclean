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

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [ValidateSet('Menu', 'Preview', 'SafeConferencePrep', 'AdvancedRepair', 'PerformanceTune')]
    [string]$Mode = 'Menu',
    [switch]$DryRun,
    [switch]$Force,
    [switch]$CreateLog,
    [ValidateNotNullOrEmpty()]
    [string]$BackupPath = "$env:ProgramData\NetClean\Backups",
    [ValidateNotNullOrEmpty()]
    [string]$LogPath = "$env:ProgramData\NetClean\Logs",
    [switch]$SkipWifi,
    [switch]$SkipDnsFlush,
    [switch]$SkipEventLogs,
    [switch]$SkipUserArtifacts,
    [switch]$SkipFirewallBackup,
    [ValidateSet('Conservative', 'Optimal', 'Gaming', 'Default')]
    [string]$PerformanceProfile = 'Default',
    [switch]$RebootNow
)

# Set test mode variables to default to false
if (-not (Get-Variable NetCleanTestMode -Scope Script -ErrorAction SilentlyContinue)) {
    $script:NetCleanTestMode = $false
}

# Normalize default paths using Join-Path when the caller did not provide overrides
if (-not $PSBoundParameters.ContainsKey('BackupPath')) {
    $BackupPath = Join-Path $env:ProgramData 'NetClean\Backups'
}

if (-not $PSBoundParameters.ContainsKey('LogPath')) {
    $LogPath = Join-Path $env:ProgramData 'NetClean\Logs'
}

if ($false) {
    $null = $Mode
    $null = $DryRun
    $null = $Force
    $null = $CreateLog
    $null = $BackupPath
    $null = $LogPath
    $null = $SkipWifi
    $null = $SkipDnsFlush
    $null = $SkipEventLogs
    $null = $SkipUserArtifacts
    $null = $SkipFirewallBackup
    $null = $PerformanceProfile
    $null = $RebootNow
}

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Record script start time for runtime reporting
$script:RunStart = Get-Date

# ---------------------------------------------------------------------------
# Module import
# ---------------------------------------------------------------------------

Import-Module (Join-Path $PSScriptRoot 'Netclean.psd1') -Force

# ---------------------------------------------------------------------------
# Script state
# ---------------------------------------------------------------------------

# $script:LogFile = $null

# Maximum items to show in lists; remaining count will be summarized.
$script:SummaryListLimit = 20

function Show-TruncatedList {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Items,
        [Parameter(Mandatory = $false)]
        [string]$Heading = 'Items',
        [Parameter(Mandatory = $false)]
        [int]$Limit
    )
    if (-not $Limit) { $Limit = $script:SummaryListLimit }
    Write-Information '' -InformationAction Continue
    Write-Information $Heading -InformationAction Continue
    if ($Items -and $Items.Count -gt 0) {
        $count = $Items.Count
        $toShow = $Items[0..([Math]::Min($Limit - 1, $count - 1))]
        foreach ($i in $toShow) { Write-Information "  - $i" -InformationAction Continue }
        if ($count -gt $Limit) { Write-Information "  - ...and $($count - $Limit) more" -InformationAction Continue }
    }
    else { Write-Information '  - (none)' -InformationAction Continue }
}

# ---------------------------------------------------------------------------
# UX helpers
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Tests if the current user is an administrator.
.DESCRIPTION
    This function checks if the current user has administrator privileges.
.EXAMPLE
    Test-NetCleanAdministrator
.NOTES
    The function throws an error if the user is not an administrator.
#>
function Test-NetCleanAdministrator {
    [CmdletBinding()]
    param()

    $principal = [Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
    $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    if (-not $isAdmin) {
        throw 'NetClean must be run as Administrator.'
    }
}

<#
.SYNOPSIS
    Prompts the user for a yes/no response.
.DESCRIPTION
    This function displays a prompt and waits for the user to enter 'y' or 'n'.
.PARAMETER Prompt
    The prompt message to display.
.PARAMETER DefaultNo
    Indicates whether the default response is no.
.EXAMPLE
    Read-YesNo -Prompt "Do you want to continue?"
.OUTPUTS
    System.Boolean - The user's response.
.NOTES
    The function uses the Convert-RegToProviderPath function to normalize the input path.
#>
function Read-YesNo {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Prompt,

        [bool]$DefaultNo = $true
    )

    if ($script:Force) {
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

        Write-Verbose 'Please enter Y or N.' -ForegroundColor Yellow
    }
}

<#
.SYNOPSIS
    Shows the NetClean banner.
.DESCRIPTION
    This function displays the NetClean banner with version information.
.EXAMPLE
    Show-NetCleanBanner
#>
function Show-NetCleanBanner {
    [CmdletBinding()]
    param()

    Write-Information '' -InformationAction Continue
    Write-Information '==========================================' -InformationAction Continue
    Write-Information ' NetClean - Conference / CTF Prep Tool' -InformationAction Continue
    Write-Information '==========================================' -InformationAction Continue
    Write-Information '' -InformationAction Continue
    Write-Information 'This tool helps remove network history and metadata while preserving' -InformationAction Continue
    Write-Information 'security products, firewalls, hypervisors, and protected adapters.' -InformationAction Continue
    Write-Information '' -InformationAction Continue
}

<#
.SYNOPSIS
    Shows the NetClean menu.
.DESCRIPTION
    This function displays the main NetClean menu options.
.EXAMPLE
    Show-NetCleanMenu
#>
function Show-NetCleanMenu {
    [CmdletBinding()]
    param()

    Show-NetCleanBanner

    Write-Information '1. Preview only' -InformationAction Continue
    Write-Information '   Detect and show what would be cleaned. No changes made.' -InformationAction Continue
    Write-Information '' -InformationAction Continue
    Write-Information '2. Safe conference prep' -InformationAction Continue
    Write-Information '   Backup, remove network history, preserve security and virtualization tools.' -InformationAction Continue
    Write-Information '' -InformationAction Continue
    Write-Information '3. Advanced repair' -InformationAction Continue
    Write-Information '   Includes deeper network reset actions. May affect installed software.' -InformationAction Continue
    Write-Information '' -InformationAction Continue
    Write-Information '4. Performance tuning' -InformationAction Continue
    Write-Information '   Apply conservative network performance tuning.' -InformationAction Continue
    Write-Information '' -InformationAction Continue
    Write-Information '5. Exit' -InformationAction Continue
    Write-Information '' -InformationAction Continue
}

<#
.SYNOPSIS
    Reads the menu selection for the NetClean process.
.DESCRIPTION
    This function prompts the user to select an option from the NetClean menu.
.EXAMPLE
    Read-NetCleanMenuSelection
.OUTPUTS
    System.String - The selected menu option.
.NOTES
    The function uses the Convert-RegToProviderPath function to normalize the input path.
#>
function Read-NetCleanMenuSelection {
    [CmdletBinding()]
    [OutputType([string])]
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
                Write-Information '' -InformationAction Continue
                Write-Information 'Invalid selection. Please choose 1 through 5.' -InformationAction Continue
                Write-Information '' -InformationAction Continue
            }
        }
    }
}

<#
.SYNOPSIS
    Reads the power selection for the NetClean process.
.DESCRIPTION
    This function prompts the user to select a power option from the NetClean menu.
.EXAMPLE
    Read-NetCleanPowerSelection
.OUTPUTS
    System.String - The selected power option.
#>
function Read-NetCleanPowerSelection {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    while ($true) {

        Write-Information "==========================================" -InformationAction Continue
        Write-Information " NetClean - System Power Options" -InformationAction Continue
        Write-Information "==========================================" -InformationAction Continue
        Write-Information "" -InformationAction Continue
        Write-Information "Some network changes may require a restart" -InformationAction Continue
        Write-Information "to fully apply." -InformationAction Continue
        Write-Information "" -InformationAction Continue
        Write-Information "1. Restart now" -InformationAction Continue
        Write-Information "2. Shut down now" -InformationAction Continue
        Write-Information "3. Restart / shut down later" -InformationAction Continue
        Write-Information "" -InformationAction Continue

        $choice = Read-Host "Select an option (1-3)"

        switch ($choice) {
            '1' { return 'Restart' }
            '2' { return 'Shutdown' }
            '3' { return 'Later' }
            default {
                Write-Information "" -InformationAction Continue
                Write-Information "Invalid selection. Please choose 1 through 3." -InformationAction Continue
                Write-Information "" -InformationAction Continue
            }
        }
    }
}

<#
.SYNOPSIS
    Invokes the selected power action for the NetClean process.
.DESCRIPTION
    This function executes the chosen power action (restart, shutdown, or later).
.PARAMETER Action
    The power action to execute.
.EXAMPLE
    Invoke-NetCleanPowerAction -Action 'Restart'
#>
function Invoke-NetCleanPowerAction {

    param(
        [Parameter(Mandatory)]
        [ValidateSet('Restart', 'Shutdown', 'Later')]
        [string]$Action
    )

    switch ($Action) {

        'Restart' {

            Write-Information "" -InformationAction Continue
            Write-Information "Restarting system..." -InformationAction Continue
            shutdown.exe /r /t 0
        }

        'Shutdown' {

            Write-Information "" -InformationAction Continue
            Write-Information "Shutting down system..." -InformationAction Continue
            shutdown.exe /s /t 0
        }

        'Later' {

            Write-Information "" -InformationAction Continue
            Write-Information "No power action selected." -InformationAction Continue
            Write-Information "You may restart or shut down later if needed." -InformationAction Continue
        }
    }
}

<#
.SYNOPSIS
    Shows the explanation for the selected NetClean mode.
.DESCRIPTION
    This function displays the explanation for the selected NetClean mode.
.PARAMETER SelectedMode
    The mode selected by the user.
.EXAMPLE
    Show-ModeExplanation -SelectedMode 'Preview'
#>
function Show-ModeExplanation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Preview', 'SafeConferencePrep', 'AdvancedRepair', 'PerformanceTune')]
        [string]$SelectedMode
    )

    Write-Information '' -InformationAction Continue
    switch ($SelectedMode) {
        'Preview' {
            Write-Information 'You selected: Preview' -InformationAction Continue
            Write-Information '' -InformationAction Continue
            Write-Information 'This will:' -InformationAction Continue
            Write-Information '  - detect protection software and protected adapters' -InformationAction Continue
            Write-Information '  - build a protected registry map' -InformationAction Continue
            Write-Information '  - export backup/restore metadata' -InformationAction Continue
            Write-Information '  - make no cleanup changes' -InformationAction Continue
        }
        'SafeConferencePrep' {
            Write-Information 'You selected: Safe conference prep' -InformationAction Continue
            Write-Information '' -InformationAction Continue
            Write-Information 'This will:' -InformationAction Continue
            Write-Information '  - detect protection software and protected adapters' -InformationAction Continue
            Write-Information '  - back up protected registry, firewall policy, and Wi-Fi profiles' -InformationAction Continue
            Write-Information '  - remove saved Wi-Fi profiles' -InformationAction Continue
            Write-Information '  - flush DNS cache' -InformationAction Continue
            Write-Information '  - remove non-protected network history and metadata' -InformationAction Continue
            Write-Information '  - verify protected products remain present' -InformationAction Continue
        }
        'AdvancedRepair' {
            Write-Information 'You selected: Advanced repair' -InformationAction Continue
            Write-Information '' -InformationAction Continue
            Write-Information 'This will do everything in Safe conference prep, plus:' -InformationAction Continue
            Write-Information '  - run advanced network repair/reset actions' -InformationAction Continue
            Write-Information '  - this may affect installed networking/security software' -InformationAction Continue
        }
        'PerformanceTune' {
            Write-Information 'You selected: Performance tuning' -InformationAction Continue
            Write-Information '' -InformationAction Continue
            Write-Information 'This will do Safe conference prep, plus:' -InformationAction Continue
            Write-Information '  - apply conservative, Microsoft-supported TCP tuning actions' -InformationAction Continue
            Write-Information '  - no third-party code or proprietary settings are used' -InformationAction Continue
        }
    }
    Write-Information '' -InformationAction Continue
}

<#
.SYNOPSIS
    Reads the options for the NetClean process.
.DESCRIPTION
    This function prompts the user to select options for the NetClean process.
.PARAMETER SelectedMode
    The mode selected by the user.
.EXAMPLE
    Read-NetCleanOption -SelectedMode 'Preview'
.OUTPUTS
    System.Object - The selected options.
.NOTES
    The function uses the Convert-RegToProviderPath function to normalize the input path.
#>
function Read-NetCleanOption {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SelectedMode,

        [switch]$DryRun,
        [switch]$SkipWifi,
        [switch]$SkipDnsFlush,
        [switch]$SkipEventLogs,
        [switch]$SkipUserArtifacts,
        [switch]$SkipFirewallBackup,

        [ValidateSet('Conservative', 'Optimal', 'Gaming', 'Default')]
        [string]$PerformanceProfile
    )

    if ($SelectedMode -eq 'PerformanceTune' -and [string]::IsNullOrWhiteSpace($PerformanceProfile)) {
        throw "PerformanceProfile is required when SelectedMode is 'PerformanceTune'."
    }

    if ($SelectedMode -eq 'Preview') {
        $DryRun = $true
    }

    return [pscustomobject]@{
        SelectedMode       = $SelectedMode
        DryRun             = [bool]$DryRun
        SkipWifi           = [bool]$SkipWifi
        SkipDnsFlush       = [bool]$SkipDnsFlush
        SkipEventLogs      = [bool]$SkipEventLogs
        SkipUserArtifacts  = [bool]$SkipUserArtifacts
        SkipFirewallBackup = [bool]$SkipFirewallBackup
        PerformanceProfile = $PerformanceProfile
    }
}

<#
.SYNOPSIS
    Shows the summary for the NetClean process.
.DESCRIPTION
    This function displays a summary of the actions that will be taken by the NetClean process.
.PARAMETER Result
    The result object containing the summary information.
.PARAMETER SelectedMode
    The mode selected by the user.
.EXAMPLE
    Show-NetCleanSummary -Result $result -SelectedMode 'Preview'
#>
function Show-NetCleanSummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Result,

        [Parameter(Mandatory = $true)]
        [string]$SelectedMode
    )

    Write-Information '' -InformationAction Continue
    Write-Information 'NetClean Summary' -InformationAction Continue
    Write-Information '----------------' -InformationAction Continue
    Write-Information "Mode: $SelectedMode" -InformationAction Continue

    if ($Result.PSObject.Properties.Name -contains 'Summary') {
        Write-Information '' -InformationAction Continue
        Write-Information 'Phase 1 - Detect' -InformationAction Continue
        Write-Information "  Protected vendors detected: $($Result.Summary.ProtectedVendorsCount)" -InformationAction Continue
        Write-Information "  Protected interface GUIDs: $($Result.Summary.ProtectedInterfaceGuidCount)" -InformationAction Continue
        Write-Information "  Candidate artifacts: $($Result.Summary.CandidateArtifactCount)" -InformationAction Continue
        Write-Information "  Sanitizable artifacts: $($Result.Summary.SanitizableArtifactCount)" -InformationAction Continue
    }

    if ($Result.PSObject.Properties.Name -contains 'Protect') {
        Write-Information '' -InformationAction Continue
        Write-Information 'Phase 2 - Protect' -InformationAction Continue
        Write-Information "  Protected registry paths: $($Result.Protect.Summary.ProtectedRegistryPathCount)" -InformationAction Continue
        Write-Information "  Wi-Fi backup items: $($Result.Protect.Summary.WiFiBackupCount)" -InformationAction Continue
        Write-Information "  Protected registry backups: $($Result.Protect.Summary.ProtectedRegistryBackupCount)" -InformationAction Continue
    }

    if ($Result.PSObject.Properties.Name -contains 'Clean') {
        Write-Information '' -InformationAction Continue
        Write-Information 'Phase 3 - Clean' -InformationAction Continue
        Write-Information "  Wi-Fi profiles removed: $($Result.Clean.Summary.WiFiProfilesRemoved)" -InformationAction Continue
        Write-Information "  Registry artifacts removed: $($Result.Clean.Summary.RegistryArtifactsRemoved)" -InformationAction Continue
        Write-Information "  Event logs touched: $($Result.Clean.Summary.EventLogsTouched)" -InformationAction Continue
        Write-Information "  User artifacts touched: $($Result.Clean.Summary.UserArtifactsTouched)" -InformationAction Continue
        Write-Information "  Advanced repair actions: $($Result.Clean.Summary.AdvancedRepairActions)" -InformationAction Continue
        Write-Information "  Performance tuning actions: $($Result.Clean.Summary.PerformanceTuningActions)" -InformationAction Continue
    }

    # Detailed lists: Wi-Fi & network profile details and removed artifacts
    # Wi-Fi: initial list comes from Protect.Manifest.WiFiExports (entries include "PROFILE:<name>")
    if ($Result.PSObject.Properties.Name -contains 'Protect') {
        $manifest = $Result.Protect.Manifest
        if ($manifest -and $manifest.WiFiExports -and $manifest.WiFiExports.Count -gt 0) {
            $found = @($manifest.WiFiExports | Where-Object { $_ -is [string] -and $_ -like 'PROFILE:*' } | ForEach-Object { $_ -replace '^PROFILE:', '' })
            if ($found.Count -gt 0) {
                Show-TruncatedList -Items $found -Heading 'Wi-Fi Profiles - Found'
            }

            if ($manifest.NetworkListBackup) {
                Write-Information '' -InformationAction Continue
                Write-Information "Network list backup: $($manifest.NetworkListBackup)" -InformationAction Continue
            }
        }
    }

    # If Clean phase ran, show removed items and remaining Wi-Fi profiles
    if ($Result.PSObject.Properties.Name -contains 'Clean') {
        $clean = $Result.Clean

        # Removed Wi-Fi profiles (names)
        if ($clean.WiFi -and $clean.WiFi.Profiles) {
            Show-TruncatedList -Items @($clean.WiFi.Profiles) -Heading 'Wi-Fi Profiles - Removed'

            # Compute remaining if we have the original found list
            if ($Result.PSObject.Properties.Name -contains 'Protect' -and $Result.Protect.Manifest -and $Result.Protect.Manifest.WiFiExports) {
                $original = @($Result.Protect.Manifest.WiFiExports | Where-Object { $_ -is [string] -and $_ -like 'PROFILE:*' } | ForEach-Object { $_ -replace '^PROFILE:', '' })
                $remaining = @($original | Where-Object { $_ -notin $clean.WiFi.Profiles })
                if ($remaining.Count -gt 0) { Show-TruncatedList -Items $remaining -Heading 'Wi-Fi Profiles - Remaining After Cleanup' }
                else { Write-Information '' -InformationAction Continue; Write-Information 'Wi-Fi Profiles - Remaining After Cleanup' -InformationAction Continue; Write-Information '  - (none)' -InformationAction Continue }
            }
        }

        # Registry keys removed
        if ($clean.RegistryArtifacts -and $clean.RegistryArtifacts.Results) {
            $removedKeys = @($clean.RegistryArtifacts.Results | Where-Object { $_.Removed } | ForEach-Object { $_.RegistryPath })
            if ($removedKeys.Count -gt 0) {
                Write-Information '' -InformationAction Continue
                Write-Information ("Registry keys removed: {0}" -f $removedKeys.Count) -InformationAction Continue
                Show-TruncatedList -Items $removedKeys -Heading 'Registry keys removed'
            }
        }

        # Event logs cleared (names)
        if ($clean.EventLogs) {
            $logs = @($clean.EventLogs | ForEach-Object { if ($_.Name) { $_.Name } elseif ($_.LogName) { $_.LogName } else { $_ } })
            if ($logs.Count -gt 0) {
                Write-Information '' -InformationAction Continue
                Write-Information ("Event logs touched: {0}" -f $logs.Count) -InformationAction Continue
                Show-TruncatedList -Items $logs -Heading 'Event logs touched'
            }
        }
    }

    if ($Result.PSObject.Properties.Name -contains 'Verify') {
        Write-Information '' -InformationAction Continue
        Write-Information 'Phase 4 - Verify' -InformationAction Continue
        Write-Information "  Verification passed: $($Result.Verify.Summary.Passed)" -InformationAction Continue
        Write-Information "  Missing vendors: $($Result.Verify.Summary.MissingVendorsCount)" -InformationAction Continue
        Write-Information "  Missing protected GUIDs: $($Result.Verify.Summary.MissingGuidCount)" -InformationAction Continue
        Write-Information "  Missing services: $($Result.Verify.Summary.MissingServiceCount)" -InformationAction Continue

        if (@($Result.Verify.VendorComparison.Missing).Count -gt 0) {
            Write-Information ("  Missing vendor names: " + ($Result.Verify.VendorComparison.Missing -join ', ')) -InformationAction Continue
        }
    }

    if ($Result.PSObject.Properties.Name -contains 'BackupPath') {
        Write-Information '' -InformationAction Continue
        Write-Information "Backup Path: $($Result.BackupPath)" -InformationAction Continue
    }

    $logFile = Get-NetCleanLogFile
    if ($logFile) {
        Write-Information "Log File: $logFile" -InformationAction Continue
    }

    Write-Information '' -InformationAction Continue

    # Show total runtime (if start time recorded)
    if ($script:RunStart) {
        $elapsed = (Get-Date) - $script:RunStart
        Write-Information ("Total runtime: {0}" -f $elapsed.ToString()) -InformationAction Continue
    }

    # Per-phase timings (if available)
    if ($Result.PSObject.Properties.Name -contains 'Timings') {
        Write-Information '' -InformationAction Continue
        Write-Information 'Phase runtimes' -InformationAction Continue
        foreach ($phase in $Result.Timings.PSObject.Properties.Name) {
            $t = $Result.Timings.$phase
            if ($t -and $t.Duration) {
                Write-Information ("  {0}: {1}" -f $phase, $t.Duration.ToString()) -InformationAction Continue
            }
        }
    }
}

<#
.SYNOPSIS
    Shows the preview summary for the NetClean process.
.DESCRIPTION
    This function displays a preview of the actions that will be taken by the NetClean process.
.PARAMETER Result
    The result object containing the preview information.
.EXAMPLE
    Show-PreviewSummary -Result $result
#>
function Show-PreviewSummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Result
    )

    Write-Information '' -InformationAction Continue
    Write-Information 'Preview Summary' -InformationAction Continue
    Write-Information '---------------' -InformationAction Continue
    Write-Information "Protected vendors detected: $($Result.Summary.ProtectedVendorsCount)" -InformationAction Continue
    Write-Information "Protected interface GUIDs: $($Result.Summary.ProtectedInterfaceGuidCount)" -InformationAction Continue
    Write-Information "Candidate artifacts: $($Result.Summary.CandidateArtifactCount)" -InformationAction Continue
    Write-Information "Sanitizable artifacts: $($Result.Summary.SanitizableArtifactCount)" -InformationAction Continue
    Write-Information '' -InformationAction Continue
    Write-Information "Backup Path: $($Result.BackupPath)" -InformationAction Continue

    $logFile = Get-NetCleanLogFile
    if ($logFile) {
        Write-Information "Log File: $logFile" -InformationAction Continue
    }

    # Show Wi-Fi profiles found (from Protect.Manifest if available)
    if ($Result.PSObject.Properties.Name -contains 'Protect') {
        $manifest = $Result.Protect.Manifest
        if ($manifest -and $manifest.WiFiExports -and $manifest.WiFiExports.Count -gt 0) {
            $found = @($manifest.WiFiExports | Where-Object { $_ -is [string] -and $_ -like 'PROFILE:*' } | ForEach-Object { $_ -replace '^PROFILE:', '' })
            if ($found.Count -gt 0) {
                Write-Information '' -InformationAction Continue
                Write-Information 'Wi-Fi Profiles - Found' -InformationAction Continue
                foreach ($p in $found) { Write-Information "  - $p" -InformationAction Continue }
            }

            if ($manifest.NetworkListBackup) {
                Write-Information '' -InformationAction Continue
                Write-Information "Network list backup: $($manifest.NetworkListBackup)" -InformationAction Continue
            }
        }
    }

    # Show sanitizable registry artifacts (preview of what would be removed)
    if ($Result.PSObject.Properties.Name -contains 'SanitizableArtifacts' -and $Result.SanitizableArtifacts.Count -gt 0) {
        Write-Information '' -InformationAction Continue
        Write-Information "Sanitizable registry artifacts (candidates): $($Result.SanitizableArtifacts.Count)" -InformationAction Continue
        foreach ($a in $Result.SanitizableArtifacts) {
            if ($a.PSObject.Properties.Name -contains 'RegistryPath' -and $a.RegistryPath) {
                Write-Information "  - $($a.RegistryPath)" -InformationAction Continue
            }
        }
    }
    Write-Information '' -InformationAction Continue

    # Show total runtime (if start time recorded)
    if ($script:RunStart) {
        $elapsed = (Get-Date) - $script:RunStart
        Write-Information ("Total runtime: {0}" -f $elapsed.ToString()) -InformationAction Continue
    }

    if ($Result.PSObject.Properties.Name -contains 'Timings') {
        Write-Information '' -InformationAction Continue
        Write-Information 'Phase runtimes' -InformationAction Continue
        foreach ($phase in $Result.Timings.PSObject.Properties.Name) {
            $t = $Result.Timings.$phase
            if ($t -and $t.Duration) {
                Write-Information ("  {0}: {1}" -f $phase, $t.Duration.ToString()) -InformationAction Continue
            }
        }
    }
}

function Read-PostRunAction {
    [CmdletBinding()]
    [OutputType([string])]
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
                Write-Information 'Please enter R, S, or N.' -InformationAction Continue
            }
        }
    }
}

<#
.SYNOPSIS
    Invokes the post-run action.
.DESCRIPTION
    This function performs the selected post-run action (restart, shutdown, or no action).
.PARAMETER Action
    The post-run action to perform.
.PARAMETER DryRunMode
    Indicates whether to run in dry-run mode.
.EXAMPLE
    Invoke-PostRunAction -Action 'Restart' -DryRunMode:$false
.NOTES
    The function uses the Convert-RegToProviderPath function to normalize the input path.
#>
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

<#
.SYNOPSIS
    Invokes the NetClean launcher.
.DESCRIPTION
    This function starts the NetClean process with the specified options.
.EXAMPLE
    Invoke-NetCleanLauncher
.OUTPUTS
    System.Void
.NOTES
    The function tests for administrator privileges before proceeding.
#>
function Invoke-NetCleanLauncher {
    [CmdletBinding()]
    [OutputType([void])]
    param()

    Test-NetCleanAdministrator

    $selectedMode = $Mode
    if ($selectedMode -eq 'Menu') {
        $selectedMode = Read-NetCleanMenuSelection
        if ($selectedMode -eq 'Exit') {
            return
        }
    }

    $selectedPerformanceProfile = $null

    if ($selectedMode -eq 'PerformanceTune') {
        $selectedPerformanceProfile = Read-NetCleanPerformanceProfileSelection

        if ($selectedPerformanceProfile -eq 'Cancel') {
            Write-Information 'Performance tuning cancelled.' -InformationAction Continue
            return
        }
    }

    Show-ModeExplanation -SelectedMode $selectedMode

    $options = Read-NetCleanOption `
        -SelectedMode $selectedMode `
        -DryRun:$DryRun `
        -SkipWifi:$SkipWifi `
        -SkipDnsFlush:$SkipDnsFlush `
        -SkipEventLogs:$SkipEventLogs `
        -SkipUserArtifacts:$SkipUserArtifacts `
        -SkipFirewallBackup:$SkipFirewallBackup `
        -PerformanceProfile $selectedPerformanceProfile

    if (-not $Force) {
        if (-not (Read-YesNo -Prompt 'Proceed with the selected NetClean operation?' -DefaultNo $true)) {
            Write-Information 'Operation cancelled.' -InformationAction Continue
            return
        }
    }

    if ($CreateLog -or $selectedMode -ne 'Menu') {
        Start-NetCleanLog -Directory $LogPath
    }

    if ($selectedMode -eq 'PerformanceTune' -and $selectedPerformanceProfile) {
        Write-NetCleanLog -Level INFO -Message ("NetClean starting. Mode={0} DryRun={1} PerformanceProfile={2}" -f $selectedMode, $options.DryRun, $selectedPerformanceProfile)
    }
    else {
        Write-NetCleanLog -Level INFO -Message ("NetClean starting. Mode={0} DryRun={1}" -f $selectedMode, $options.DryRun)
    }

    if (-not $options.DryRun) {
        New-DirectoryIfNotExist -Path $BackupPath
    }

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
        -PerformanceProfile $options.PerformanceProfile

    Show-NetCleanSummary -Result $result -SelectedMode $selectedMode

    $postRunAction = Read-PostRunAction
    Invoke-PostRunAction -Action $postRunAction -DryRunMode:$options.DryRun

    if ($selectedMode -in @(
            'SafeConferencePrep',
            'AdvancedRepair',
            'PerformanceTune'
        )) {
        $powerChoice = Read-NetCleanPowerSelection
        Invoke-NetCleanPowerAction -Action $powerChoice
    }
}

if (-not $script:NetCleanTestMode -and $MyInvocation.InvocationName -ne '.') {
    Invoke-NetCleanLauncher
}