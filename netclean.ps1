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
    [string]$LogPath    = "$env:ProgramData\NetClean\Logs",
    [switch]$SkipWifi,
    [switch]$SkipDnsFlush,
    [switch]$SkipEventLogs,
    [switch]$SkipUserArtifacts,
    [switch]$SkipFirewallBackup,
    [switch]$EnableConservativePerformanceTuning,
    [switch]$RebootNow
)

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
    $null = $EnableConservativePerformanceTuning
    $null = $RebootNow
}

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

<#
.SYNOPSIS
    Starts the NetClean logging.
.DESCRIPTION
    This function initializes the logging for the NetClean process.
.PARAMETER Directory
    The directory where log files will be stored.
.EXAMPLE
    Start-NetCleanLog -Directory "C:\Logs"
.NOTES
    The function creates the log directory if it does not exist.
#>
function Start-NetCleanLog {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Directory
    )

    if (-not (Test-Path -LiteralPath $Directory)) {
        if ($PSCmdlet.ShouldProcess($Directory, "Create directory")) {
            New-Item -Path $Directory -ItemType Directory -Force | Out-Null
        }
    }

    $script:LogFile = Join-Path $Directory ("NetClean_{0}.log" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
    if ($PSCmdlet.ShouldProcess($script:LogFile, "Create log file")) {
        "[$(Get-Date -Format s)] [INFO] Log started" | Out-File -FilePath $script:LogFile -Encoding UTF8
    }
}

<#
.SYNOPSIS
    Writes a message to the NetClean log.
.DESCRIPTION
    This function writes a message to the NetClean log with the specified level.
.PARAMETER Level
    The level of the log message.
.PARAMETER Message
    The message to write to the log.
.EXAMPLE
    Write-NetCleanLog -Level 'INFO' -Message 'Starting NetClean process'
.NOTES
    The function uses the Convert-RegToProviderPath function to normalize the input path.
#>
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

        Write-Output 'Please enter Y or N.'
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

    Write-Output ''
    Write-Output '=========================================='
    Write-Output ' NetClean - Conference / CTF Prep Tool'
    Write-Output '=========================================='
    Write-Output ''
    Write-Output 'This tool helps remove network history and metadata while preserving'
    Write-Output 'security products, firewalls, hypervisors, and protected adapters.'
    Write-Output ''
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

    Write-Output '1. Preview only'
    Write-Output '   Detect and show what would be cleaned. No changes made.'
    Write-Output ''
    Write-Output '2. Safe conference prep'
    Write-Output '   Backup, remove network history, preserve security and virtualization tools.'
    Write-Output ''
    Write-Output '3. Advanced repair'
    Write-Output '   Includes deeper network reset actions. May affect installed software.'
    Write-Output ''
    Write-Output '4. Performance tuning'
    Write-Output '   Apply conservative network performance tuning.'
    Write-Output ''
    Write-Output '5. Exit'
    Write-Output ''
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
                Write-Output ''
                Write-Output 'Invalid selection. Please choose 1 through 5.'
                Write-Output ''
            }
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

    Write-Output ''
    switch ($SelectedMode) {
        'Preview' {
            Write-Output 'You selected: Preview'
            Write-Output ''
            Write-Output 'This will:'
            Write-Output '  - detect protection software and protected adapters'
            Write-Output '  - build a protected registry map'
            Write-Output '  - export backup/restore metadata'
            Write-Output '  - make no cleanup changes'
        }
        'SafeConferencePrep' {
            Write-Output 'You selected: Safe conference prep'
            Write-Output ''
            Write-Output 'This will:'
            Write-Output '  - detect protection software and protected adapters'
            Write-Output '  - back up protected registry, firewall policy, and Wi-Fi profiles'
            Write-Output '  - remove saved Wi-Fi profiles'
            Write-Output '  - flush DNS cache'
            Write-Output '  - remove non-protected network history and metadata'
            Write-Output '  - verify protected products remain present'
        }
        'AdvancedRepair' {
            Write-Output 'You selected: Advanced repair'
            Write-Output ''
            Write-Output 'This will do everything in Safe conference prep, plus:'
            Write-Output '  - run advanced network repair/reset actions'
            Write-Output '  - this may affect installed networking/security software'
        }
        'PerformanceTune' {
            Write-Output 'You selected: Performance tuning'
            Write-Output ''
            Write-Output 'This will do Safe conference prep, plus:'
            Write-Output '  - apply conservative, Microsoft-supported TCP tuning actions'
            Write-Output '  - no third-party code or proprietary settings are used'
        }
    }
    Write-Output ''
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
    [OutputType([System.Object])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SelectedMode,
        [switch]$DryRun,
        [switch]$SkipWifi,
        [switch]$SkipDnsFlush,
        [switch]$SkipEventLogs,
        [switch]$SkipUserArtifacts,
        [switch]$SkipFirewallBackup,
        [switch]$EnableConservativePerformanceTuning
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

    Write-Output ''
    Write-Output 'NetClean Summary'
    Write-Output '----------------'
    Write-Output "Mode: $SelectedMode"

    if ($Result.PSObject.Properties.Name -contains 'Summary') {
        Write-Output ''
        Write-Output 'Phase 1 - Detect'
        Write-Output "  Protected vendors detected: $($Result.Summary.ProtectedVendorsCount)"
        Write-Output "  Protected interface GUIDs: $($Result.Summary.ProtectedInterfaceGuidCount)"
        Write-Output "  Candidate artifacts: $($Result.Summary.CandidateArtifactCount)"
        Write-Output "  Sanitizable artifacts: $($Result.Summary.SanitizableArtifactCount)"
    }

    if ($Result.PSObject.Properties.Name -contains 'Protect') {
        Write-Output ''
        Write-Output 'Phase 2 - Protect'
        Write-Output "  Protected registry paths: $($Result.Protect.Summary.ProtectedRegistryPathCount)"
        Write-Output "  Wi-Fi backup items: $($Result.Protect.Summary.WiFiBackupCount)"
        Write-Output "  Protected registry backups: $($Result.Protect.Summary.ProtectedRegistryBackupCount)"
    }

    if ($Result.PSObject.Properties.Name -contains 'Clean') {
        Write-Output ''
        Write-Output 'Phase 3 - Clean'
        Write-Output "  Wi-Fi profiles removed: $($Result.Clean.Summary.WiFiProfilesRemoved)"
        Write-Output "  Registry artifacts removed: $($Result.Clean.Summary.RegistryArtifactsRemoved)"
        Write-Output "  Event logs touched: $($Result.Clean.Summary.EventLogsTouched)"
        Write-Output "  User artifacts touched: $($Result.Clean.Summary.UserArtifactsTouched)"
        Write-Output "  Advanced repair actions: $($Result.Clean.Summary.AdvancedRepairActions)"
        Write-Output "  Performance tuning actions: $($Result.Clean.Summary.PerformanceTuningActions)"
    }

    if ($Result.PSObject.Properties.Name -contains 'Verify') {
        Write-Output ''
        Write-Output 'Phase 4 - Verify'
        Write-Output "  Verification passed: $($Result.Verify.Summary.Passed)"
        Write-Output "  Missing vendors: $($Result.Verify.Summary.MissingVendorsCount)"
        Write-Output "  Missing protected GUIDs: $($Result.Verify.Summary.MissingGuidCount)"
        Write-Output "  Missing services: $($Result.Verify.Summary.MissingServiceCount)"

        if (@($Result.Verify.VendorComparison.Missing).Count -gt 0) {
            Write-Output ("  Missing vendor names: " + ($Result.Verify.VendorComparison.Missing -join ', '))
        }
    }

    if ($Result.PSObject.Properties.Name -contains 'BackupPath') {
        Write-Output ''
        Write-Output "Backup Path: $($Result.BackupPath)"
    }

    if ($script:LogFile) {
        Write-Output "Log File: $script:LogFile"
    }

    Write-Output ''
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
                Write-Output 'Please enter R, S, or N.'
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

    Show-ModeExplanation -SelectedMode $selectedMode
    $options = Read-NetCleanOption `
        -SelectedMode $selectedMode `
        -DryRun:$DryRun `
        -SkipWifi:$SkipWifi `
        -SkipDnsFlush:$SkipDnsFlush `
        -SkipEventLogs:$SkipEventLogs `
        -SkipUserArtifacts:$SkipUserArtifacts `
        -SkipFirewallBackup:$SkipFirewallBackup `
        -EnableConservativePerformanceTuning:$EnableConservativePerformanceTuning

    if (-not $Force) {
        if (-not (Read-YesNo -Prompt 'Proceed with the selected NetClean operation?' -DefaultNo $true)) {
            Write-Output 'Operation cancelled.'
            return
        }
    }

    if ($CreateLog -or $selectedMode -ne 'Menu') {
        Start-NetCleanLog -Directory $LogPath
    }

    Write-NetCleanLog -Level INFO -Message "NetClean starting. Mode=$selectedMode DryRun=$($options.DryRun)"

    New-DirectoryIfNotExist -Path $BackupPath

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

    $postRunAction = Read-PostRunAction
    Invoke-PostRunAction -Action $postRunAction -DryRunMode:$options.DryRun
}

if (-not $script:NetCleanTestMode -and $MyInvocation.InvocationName -ne '.') {
    Invoke-NetCleanLauncher
}