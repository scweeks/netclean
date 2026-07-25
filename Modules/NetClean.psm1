<#
.SYNOPSIS
    NetClean PowerShell module
.DESCRIPTION
    Phase-oriented engine for:
    - Phase 1: Detect
    - Phase 2: Protect
    - Phase 3: Clean
    - Phase 4: Verify
.FUNCTIONALITY
    System, Security, Diagnostics
    Goal:
    Remove user/environment-identifying network history and metadata while
    preserving required security, virtualization, firewall, VPN, and network
    infrastructure software.
#>
Set-StrictMode -Version Latest

$script:ModuleRoot = Split-Path -Parent $PSCommandPath

. (Join-Path $script:ModuleRoot 'NetCleanPhase1.ps1')
. (Join-Path $script:ModuleRoot 'NetCleanPhase2.ps1')
. (Join-Path $script:ModuleRoot 'NetCleanPhase3.ps1')
. (Join-Path $script:ModuleRoot 'NetCleanPhase4.ps1')

# Invoke independent work in a bounded runspace pool for in-process multithreading.
function Invoke-InParallel {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$ScriptBlock,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$InputObjects,

        [ValidateRange(1, 256)]
        [int]$ThrottleLimit = ([System.Environment]::ProcessorCount)
    )

    if ($InputObjects.Count -eq 0) {
        return @()
    }

    if ($InputObjects.Count -eq 1) {
        try {
            return @(& $ScriptBlock $InputObjects[0])
        }
        catch {
            Write-Verbose "Invoke-InParallel worker failed: $($_.Exception.Message)"
            return @()
        }
    }

    $workerCount = [System.Math]::Min($ThrottleLimit, $InputObjects.Count)
    $runspacePool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $workerCount)
    $workers = [System.Collections.Generic.List[object]]::new()
    $results = [System.Collections.Generic.List[object]]::new()

    try {
        $runspacePool.Open()

        foreach ($item in $InputObjects) {
            $powerShell = [System.Management.Automation.PowerShell]::Create()
            $powerShell.RunspacePool = $runspacePool
            [void]$powerShell.AddScript($ScriptBlock.ToString()).AddArgument($item)

            $workers.Add([pscustomobject]@{
                    PowerShell = $powerShell
                    AsyncResult = $powerShell.BeginInvoke()
                })
        }

        foreach ($worker in $workers) {
            try {
                foreach ($outputItem in @($worker.PowerShell.EndInvoke($worker.AsyncResult))) {
                    if ($null -ne $outputItem) {
                        $results.Add($outputItem)
                    }
                }
            }
            catch {
                Write-Verbose "Invoke-InParallel worker failed: $($_.Exception.Message)"
            }
        }
    }
    finally {
        foreach ($worker in $workers) {
            $worker.PowerShell.Dispose()
        }

        $runspacePool.Close()
        $runspacePool.Dispose()
    }

    return $results.ToArray()
}


<#
.SYNOPSIS
    NetClean PowerShell module
.DESCRIPTION
    Phase-oriented engine for:
    - Phase 1: Detect
    - Phase 2: Protect
    - Phase 3: Clean
    - Phase 4: Verify
.FUNCTIONALITY
    System, Security, Diagnostics
    Goal:
    Remove user/environment-identifying network history and metadata while
    preserving required security, virtualization, firewall, VPN, and network
    infrastructure software.

.NOTES
    - Best fidelity requires administrative privileges
    - The default workflow is intentionally conservative
    - Advanced repair and performance tuning are opt-in
    - This module favors explainability, backup, and verification
#>

Set-StrictMode -Version Latest
$script:NetCleanModuleVersion = '1.0.0'
$script:RegistryHiveMap = [ordered]@{
    HKLM = 'HKEY_LOCAL_MACHINE'
    HKCU = 'HKEY_CURRENT_USER'
    HKCR = 'HKEY_CLASSES_ROOT'
    HKU  = 'HKEY_USERS'
    HKCC = 'HKEY_CURRENT_CONFIG'
}
$script:RegistryRootMap = $null

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

$script:LogFile = $null
$script:NewLine = [Environment]::NewLine
$script:Utf8NoBom = [System.Text.UTF8Encoding]::new($false)

<#
.SYNOPSIS
Detects whether Windows is connected to organization management.
.DESCRIPTION
Uses dsregcmd /status for Active Directory, Microsoft Entra, enterprise, and
workplace registration state. Workplace registration alone is not treated as
device management. EnterpriseMgmt scheduled-task evidence is treated as MDM
enrollment evidence. If dsregcmd is unavailable, domain join state falls back
to Win32_ComputerSystem. No tenant or domain identifier is returned or logged.
.OUTPUTS
A PSCustomObject describing the management state and detection warnings.
#>
function Get-NetCleanDeviceManagementState {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    $warnings = [System.Collections.Generic.List[string]]::new()
    $state = [ordered]@{
        EntraJoined       = $false
        EnterpriseJoined  = $false
        DomainJoined      = $false
        WorkplaceJoined   = $false
    }

    $dsregSucceeded = $false
    try {
        $dsreg = Invoke-NetCleanNativeCapture -Name 'Detect Windows organization join state' -FilePath 'dsregcmd.exe' -ArgumentList @('/status')

        if ($dsreg.Succeeded) {
            foreach ($line in @($dsreg.Output)) {
                if ($line -match '^\s*(AzureAdJoined|EnterpriseJoined|DomainJoined|WorkplaceJoined)\s*:\s*(YES|NO)\s*$') {
                    $propertyName = if ($Matches[1] -eq 'AzureAdJoined') { 'EntraJoined' } else { $Matches[1] }
                    $state[$propertyName] = $Matches[2] -eq 'YES'
                    $dsregSucceeded = $true
                }
            }
        }

        if (-not $dsregSucceeded) {
            [void]$warnings.Add('Microsoft Entra join-state detection was unavailable.')
        }
    }
    catch {
        [void]$warnings.Add('Microsoft Entra join-state detection was unavailable.')
    }

    if (-not $dsregSucceeded) {
        try {
            $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
            $state.DomainJoined = [bool]$computerSystem.PartOfDomain
        }
        catch {
            [void]$warnings.Add('Active Directory domain-state fallback was unavailable.')
        }
    }

    $mdmEnrolled = $false
    try {
        $mdmTasks = @(Get-ScheduledTask -TaskPath '\Microsoft\Windows\EnterpriseMgmt\*' -ErrorAction Stop)
        $mdmEnrolled = $mdmTasks.Count -gt 0
    }
    catch {
        [void]$warnings.Add('MDM enrollment-task detection was unavailable.')
    }

    $isManaged = (
        $state.EntraJoined -or
        $state.EnterpriseJoined -or
        $state.DomainJoined -or
        $mdmEnrolled
    )

    $joinType = if ($state.EntraJoined -and $state.DomainJoined) {
        'MicrosoftEntraHybridJoined'
    }
    elseif ($state.EntraJoined) {
        'MicrosoftEntraJoined'
    }
    elseif ($state.DomainJoined) {
        'DomainJoined'
    }
    elseif ($state.EnterpriseJoined) {
        'EnterpriseJoined'
    }
    elseif ($state.WorkplaceJoined) {
        'WorkplaceRegistered'
    }
    elseif ($mdmEnrolled) {
        'MdmEnrolled'
    }
    else {
        'Workgroup'
    }

    return [pscustomobject]@{
        IsManaged        = [bool]$isManaged
        JoinType         = $joinType
        DomainJoined     = [bool]$state.DomainJoined
        EntraJoined      = [bool]$state.EntraJoined
        EnterpriseJoined = [bool]$state.EnterpriseJoined
        WorkplaceJoined  = [bool]$state.WorkplaceJoined
        MdmEnrolled      = [bool]$mdmEnrolled
        Warnings         = $warnings.ToArray()
    }
}

<#
.SYNOPSIS
Returns the active NetClean log-file path.
.DESCRIPTION
Returns the path initialized by Start-NetCleanLog, or null when logging has
not been initialized.
.OUTPUTS
System.String
#>
function Get-NetCleanLogFile {
    [CmdletBinding()]
    param()

    return $script:LogFile
}

<#
.SYNOPSIS
Restricts a NetClean data directory to the current user, Administrators, and SYSTEM.
.DESCRIPTION
Replaces inherited access rules so sensitive backups and logs are not readable
through broad parent-directory permissions.
.PARAMETER Path
Existing directory whose access control list will be replaced.
#>
function Set-NetCleanPrivateDirectoryAcl {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        throw "Private data directory does not exist: $Path"
    }

    $acl = [System.Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)

    $identities = @(
        [System.Security.Principal.WindowsIdentity]::GetCurrent().User,
        [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'),
        [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    ) | Select-Object -Unique

    $inheritance = (
        [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    )

    foreach ($identity in $identities) {
        $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
            $identity,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            $inheritance,
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow
        )
        [void]$acl.AddAccessRule($rule)
    }

    if ($PSCmdlet.ShouldProcess($Path, 'Restrict directory access')) {
        Set-Acl -LiteralPath $Path -AclObject $acl -ErrorAction Stop
    }
}

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

    if (Test-Path -LiteralPath $Directory -PathType Container) {
        Set-NetCleanPrivateDirectoryAcl -Path $Directory
    }
    elseif (-not $WhatIfPreference) {
        throw "Unable to create private log directory: $Directory"
    }

    $candidateLogFile = Join-Path $Directory ("NetClean_{0}.log" -f (Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'))

    if ($PSCmdlet.ShouldProcess($candidateLogFile, "Create log file")) {
        try {
            [System.IO.File]::WriteAllText(
                $candidateLogFile,
                "[$(Get-Date -Format s)] [INFO] Log started" + $script:NewLine,
                $script:Utf8NoBom
            )

            $script:LogFile = $candidateLogFile
        }
        catch {
            $script:LogFile = $null
            Write-Verbose "Failed to create log file '$candidateLogFile': $_"
        }
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
        [ValidateSet('INFO', 'WARN', 'ERROR', 'DEBUG', 'TRACE')]
        [string]$Level = 'INFO',

        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    $line = "[$(Get-Date -Format s)] [$Level] $Message"

    $logFile = Get-NetCleanLogFile
    if ($logFile) {
        try {
            [System.IO.File]::AppendAllText($logFile, $line + $script:NewLine, $script:Utf8NoBom)
        }
        catch {
            Write-Verbose "Failed to append to log file '$logFile': $_"
        }
    }

    switch ($Level) {
        'ERROR' { Write-Error $Message -ErrorAction Continue }
        'WARN' { Write-Warning $Message }
        'INFO' { Write-Information $Message -InformationAction Continue }
        'DEBUG' { Write-Verbose $Message }
        'TRACE' { Write-Debug $Message }
    }
}

# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
Normalize a registry key path to a canonical form.
.DESCRIPTION
Removes provider prefixes and normalizes separators for a registry path. Validates common registry hives.
.PARAMETER Path
The registry path to normalize.
.EXAMPLE
Convert-RegKeyPath -Path 'HKLM:\SOFTWARE\\MyKey'
#>
function Convert-RegKeyPath {
    [CmdletBinding()]
    [OutputType([System.String])]
    param(
        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Path
    )

    if ($null -eq $Path) { return $null }
    if ($Path -eq '') { return '' }
    $p = $Path.Trim()
    $p = $p -replace '^Microsoft\.PowerShell\.Core\\Registry::', ''
    $p = $p -replace '^Registry::', ''
    $p = $p -replace '/', '\'

    try {
        $parts = [regex]::Split($p, '[\\/]+') | Where-Object { $_ -and $_.Trim() -ne '' }
        $p = ($parts -join '\')
    }
    catch {
        while ($p -match '\\\\') {
            $p = $p -replace '\\\\', '\'
        }
        $p = $p -replace '^\\+|\\+$', ''
    }

    $p = $p -replace '^(HKLM|HKCU|HKCR|HKU|HKCC):', '$1'

    if ($p -notmatch '^(HKLM|HKEY_LOCAL_MACHINE|HKCU|HKEY_CURRENT_USER|HKCR|HKEY_CLASSES_ROOT|HKU|HKEY_USERS|HKCC|HKEY_CURRENT_CONFIG)(\\.*)?$') {
        throw "Invalid registry path: '$Path'"
    }

    return $p.Trim()
}

<#
.SYNOPSIS
Parses a normalized registry path into its root and suffix.
.DESCRIPTION
Returns the short logical root, native root name, suffix, and normalized input
for a path accepted by Convert-RegKeyPath.
#>
function Get-NetCleanRegistryPathInfo {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$RegistryPath
    )

    $normalized = Convert-RegKeyPath -Path $RegistryPath
    foreach ($entry in $script:RegistryHiveMap.GetEnumerator()) {
        $pattern = '^(?:{0}|{1})(?:\\(?<Suffix>.*))?$' -f
            [regex]::Escape($entry.Key),
            [regex]::Escape($entry.Value)
        $match = [regex]::Match($normalized, $pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        if ($match.Success) {
            return [pscustomobject]@{
                Root       = $entry.Key
                NativeRoot = $entry.Value
                Suffix     = $match.Groups['Suffix'].Value
                Normalized = $normalized
            }
        }
    }

    throw "Unsupported registry root in path '$RegistryPath'"
}

function Get-NetCleanRegistryProviderPath {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$RegistryPath
    )

    $info = Get-NetCleanRegistryPathInfo -RegistryPath $RegistryPath
    if ([string]::IsNullOrWhiteSpace($info.Suffix)) {
        return "Registry::$($info.NativeRoot)"
    }

    return "Registry::$($info.NativeRoot)\$($info.Suffix)"
}

<#
.SYNOPSIS
Sets private logical registry-root mappings for an isolated registry tree.
.DESCRIPTION
Validates all target roots as existing Registry-provider keys, then atomically
replaces the private map. This helper is intentionally not exported.
#>
function Set-NetCleanRegistryRootMap {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [hashtable]$RootMap
    )

    if ($RootMap.Count -eq 0) {
        throw 'Registry root map must contain at least one mapping.'
    }

    $validated = @{}
    foreach ($entry in $RootMap.GetEnumerator()) {
        $logical = Get-NetCleanRegistryPathInfo -RegistryPath ([string]$entry.Key)
        if (-not [string]::IsNullOrWhiteSpace($logical.Suffix)) {
            throw "Registry root map key must be a hive root: '$($entry.Key)'"
        }
        if ($validated.ContainsKey($logical.Root)) {
            throw "Registry root map contains a duplicate logical root: '$($logical.Root)'"
        }

        $target = Convert-RegKeyPath -Path ([string]$entry.Value)
        $targetProviderPath = Get-NetCleanRegistryProviderPath -RegistryPath $target
        $targetItem = Get-Item -LiteralPath $targetProviderPath -ErrorAction Stop
        if ($targetItem.PSProvider.Name -ne 'Registry') {
            throw "Registry root map target is not a Registry-provider key: '$($entry.Value)'"
        }

        $validated[$logical.Root] = $target
    }

    if ($PSCmdlet.ShouldProcess('private registry-root map', 'Replace registry-root mappings')) {
        $script:RegistryRootMap = $validated
    }
}

function Clear-NetCleanRegistryRootMap {
    [CmdletBinding()]
    param()

    $script:RegistryRootMap = $null
}

function Resolve-NetCleanRegistryPath {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$RegistryPath
    )

    $info = Get-NetCleanRegistryPathInfo -RegistryPath $RegistryPath
    if ($null -eq $script:RegistryRootMap -or -not $script:RegistryRootMap.ContainsKey($info.Root)) {
        return $info.Normalized
    }

    $mappedRoot = $script:RegistryRootMap[$info.Root]
    if ([string]::IsNullOrWhiteSpace($info.Suffix)) {
        return $mappedRoot
    }

    return "$mappedRoot\$($info.Suffix)"
}

<#
.SYNOPSIS
Validates and normalizes a GUID string.
.DESCRIPTION
Parses a GUID string and returns the canonical lowercase GUID form. Returns `$null` for empty input.
.PARAMETER Guid
The GUID string to validate and convert.
.EXAMPLE
Convert-Guid -Guid 'A0E6C2D0-...'
#>
function Convert-Guid {
    [CmdletBinding()]
    [OutputType([System.String])]
    param(
        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Guid
    )

    if ([string]::IsNullOrWhiteSpace($Guid)) {
        return $null
    }

    $parsed = [guid]::Empty
    if (-not [guid]::TryParse($Guid, [ref]$parsed)) {
        throw "Invalid GUID: '$Guid'"
    }

    return $parsed.ToString().ToLowerInvariant()
}

<#
.SYNOPSIS
Convert a registry key path to the provider-qualified path.
.DESCRIPTION
Transforms a normalized registry path into a Provider:: style path usable by provider cmdlets (e.g., Registry::HKEY_LOCAL_MACHINE\...).
.PARAMETER RegistryPath
The registry path to convert.
.EXAMPLE
Convert-RegToProviderPath -RegistryPath 'HKLM:\SOFTWARE\\MyKey'
#>
function Convert-RegToProviderPath {
    [CmdletBinding()]
    [OutputType([System.String])]
    param(
        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [Alias('Path')]
        [string]$RegistryPath
    )

    if ([string]::IsNullOrWhiteSpace($RegistryPath)) { return $null }

    $resolvedPath = Resolve-NetCleanRegistryPath -RegistryPath $RegistryPath
    return Get-NetCleanRegistryProviderPath -RegistryPath $resolvedPath
}

<#
.SYNOPSIS
Maps a short registry hive root to its .NET RegistryKey handle.
.DESCRIPTION
Private helper for the raw-registry-API read path. Throws for any root not
present in $script:RegistryHiveMap, matching Get-NetCleanRegistryPathInfo's
own unsupported-root contract.
#>
function Get-NetCleanRegistryHiveRoot {
    [CmdletBinding()]
    [OutputType([Microsoft.Win32.RegistryKey])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Root
    )

    switch ($Root) {
        'HKLM' { return [Microsoft.Win32.Registry]::LocalMachine }
        'HKCU' { return [Microsoft.Win32.Registry]::CurrentUser }
        'HKCR' { return [Microsoft.Win32.Registry]::ClassesRoot }
        'HKU' { return [Microsoft.Win32.Registry]::Users }
        'HKCC' { return [Microsoft.Win32.Registry]::CurrentConfig }
        default { throw "Unsupported registry hive root: '$Root'" }
    }
}

<#
.SYNOPSIS
Opens a registry key via the raw .NET registry API, honoring the existing
path-resolution and TestRegistry-redirection contract.
.DESCRIPTION
Resolves the path exactly as the provider-cmdlet path did (Resolve-
NetCleanRegistryPath, then Get-NetCleanRegistryPathInfo), so redirection set
up by Set-NetCleanRegistryRootMap continues to work unchanged. Returns $null
when the key does not exist (OpenSubKey's own not-found contract) rather than
throwing; throws for an unsupported registry root or an access-denied key, to
be caught by each caller's existing fail-soft/fail-closed wrapper. The
returned key, if any, is a handle the caller owns and must Close().
.PARAMETER RegistryPath
The registry path to open.
.OUTPUTS
Microsoft.Win32.RegistryKey or $null.
#>
function Open-NetCleanRegistryKey {
    [CmdletBinding()]
    [OutputType([Microsoft.Win32.RegistryKey])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$RegistryPath
    )

    $resolvedPath = Resolve-NetCleanRegistryPath -RegistryPath $RegistryPath
    $info = Get-NetCleanRegistryPathInfo -RegistryPath $resolvedPath
    $hiveRoot = Get-NetCleanRegistryHiveRoot -Root $info.Root

    return $hiveRoot.OpenSubKey($info.Suffix)
}

<#
.SYNOPSIS
    Tests if a registry path exists.
.DESCRIPTION
    This function checks if a specified registry path exists.
.PARAMETER RegistryPath
    The registry path to test.
.PARAMETER ThrowOnError
    Rethrows provider errors so verification callers can fail closed. Discovery callers remain fail-soft by default.
.EXAMPLE
    Test-RegistryPathExist -RegistryPath "HKLM:\SOFTWARE\MyKey"
.OUTPUTS
    System.Boolean - True if the path exists, false otherwise.
#>
function Test-RegistryPathExist {
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param(
        [Parameter(Mandatory = $true)]
        [Alias('Path')]
        [string]$RegistryPath,

        [switch]$ThrowOnError
    )

    $key = $null
    try {
        $key = Open-NetCleanRegistryKey -RegistryPath $RegistryPath
        return ($null -ne $key)
    }
    catch {
        if ($ThrowOnError) {
            throw
        }
        return $false
    }
    finally {
        if ($key) { $key.Close() }
    }
}

<#
.SYNOPSIS
    Gets the values of a registry key.
.DESCRIPTION
    This function retrieves the values of a specified registry key.
.PARAMETER RegistryPath
    The registry path to query.
.EXAMPLE
    Get-RegistryValuesSafe -RegistryPath "HKLM:\SOFTWARE\MyKey"
.OUTPUTS
    System.Object - The registry values.
#>
function Get-RegistryValuesSafe {
    [CmdletBinding()]
    [OutputType([System.Object])]
    param(
        [Parameter(Mandatory = $true)]
        [Alias('Path')]
        [string]$RegistryPath
    )

    $key = $null
    try {
        $key = Open-NetCleanRegistryKey -RegistryPath $RegistryPath
        if ($null -eq $key) {
            return $null
        }

        $values = [ordered]@{}
        foreach ($valueName in $key.GetValueNames()) {
            $propertyName = if ([string]::IsNullOrEmpty($valueName)) { '(default)' } else { $valueName }
            $values[$propertyName] = $key.GetValue($valueName, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        }

        if ($values.Count -eq 0) {
            # A zero-property PSCustomObject makes any later
            # `.PSObject.Properties.Name -contains 'X'` check throw under
            # Set-StrictMode -Version Latest (enumerating .Name over an
            # empty PSMemberInfoCollection behaves differently than over a
            # non-empty one). Every caller uses that idiom to test for a
            # specific value name, so a key that exists with zero registry
            # values must still carry at least one property to keep those
            # checks safe - this mirrors the old Get-ItemProperty-based
            # implementation, whose returned object always carried PSPath/
            # PSProvider metadata properties even for a value-less key.
            return [pscustomobject]@{ NetCleanNoRegistryValues = $true }
        }

        return [pscustomobject]$values
    }
    catch {
        return $null
    }
    finally {
        if ($key) { $key.Close() }
    }
}

<#
.SYNOPSIS
    Gets the names of child keys in a registry path.
.DESCRIPTION
    This function retrieves the names of child keys in a specified registry path.
.PARAMETER RegistryPath
    The registry path to query.
.EXAMPLE
    Get-RegistryChildKeyNamesSafe -RegistryPath "HKLM:\SOFTWARE\MyKey"
.OUTPUTS
    System.String[] - A list of child key names.
#>
function Get-RegistryChildKeyNamesSafe {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param(
        [Parameter(Mandatory = $true)]
        [Alias('Path')]
        [string]$RegistryPath
    )

    $key = $null
    try {
        $key = Open-NetCleanRegistryKey -RegistryPath $RegistryPath
        if ($null -eq $key) {
            return @()
        }

        return @($key.GetSubKeyNames())
    }
    catch {
        return @()
    }
    finally {
        if ($key) { $key.Close() }
    }
}

<#
.SYNOPSIS
    Gets unique, non-empty strings from an array.
.DESCRIPTION
    This function takes an array of objects and returns a list of unique, non-empty strings.
.PARAMETER InputObject
    The array of objects to process.
.EXAMPLE
    Get-UniqueNonEmptyString -InputObject @("apple", $null, "banana", "apple")
.OUTPUTS
    System.String[] - A list of unique, non-empty strings.
.NOTES
    The function trims whitespace from each string before checking if it's empty.
#>
function Get-UniqueNonEmptyString {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param(
        [Parameter()]
        [AllowNull()]
        [object[]]$InputObject
    )

    $list = New-Object System.Collections.Generic.List[string]

    foreach ($item in @($InputObject)) {
        if ($null -eq $item) { continue }

        if ($item -is [System.Array]) {
            foreach ($inner in $item) {
                if ($null -eq $inner) { continue }
                $s2 = $inner.ToString().Trim()
                if ([string]::IsNullOrWhiteSpace($s2)) { continue }
                [void]$list.Add($s2)
            }
            continue
        }

        $s = $item.ToString().Trim()
        if ([string]::IsNullOrWhiteSpace($s)) { continue }

        [void]$list.Add($s)
    }

    return $list.ToArray() | Sort-Object -Unique
}

<#
.SYNOPSIS
    Adds a value to a HashSet.
.DESCRIPTION
    This function adds a string value to a HashSet if it is not null or whitespace.
.PARAMETER Set
    The HashSet to which the value will be added.
.PARAMETER Values
    The value(s) to add to the HashSet.
.EXAMPLE
    Add-HashSetValue -Set $mySet -Values "apple"
.OUTPUTS
    System.Void
.NOTES
    The function uses the Get-UniqueNonEmptyString function to normalize the input arrays.
#>
function Add-HashSetValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.HashSet[string]]$Set,

        [Parameter()]
        [AllowNull()]
        [object[]]$Values
    )

    foreach ($value in @($Values)) {
        if ($null -eq $value) { continue }

        if ($value -is [System.Array]) {
            foreach ($inner in $value) {
                if ($null -eq $inner) { continue }
                $s2 = $inner.ToString().Trim()
                if ([string]::IsNullOrWhiteSpace($s2)) { continue }
                [void]$Set.Add($s2)
            }
            continue
        }

        $s = $value.ToString().Trim()
        if ([string]::IsNullOrWhiteSpace($s)) { continue }
        [void]$Set.Add($s)
    }
}

<#
.SYNOPSIS
    Compares two sets of strings and returns the differences.
.DESCRIPTION
    This function compares two arrays of strings and returns a custom object containing the unique strings from each array.
.PARAMETER Before
    The first array of strings to compare.
.PARAMETER After
    The second array of strings to compare.
.EXAMPLE
    Compare-StringSet -Before @("apple", "banana") -After @("banana", "cherry")
.OUTPUTS
    System.Management.Automation.PSCustomObject - A custom object containing the comparison results.
.NOTES
    The function uses the Get-UniqueNonEmptyString function to normalize the input arrays.
#>
function Compare-StringSet {
    [CmdletBinding()]
    [OutputType([System.Management.Automation.PSCustomObject])]
    param(
        [Parameter()]
        [AllowNull()]
        [string[]]$Before,

        [Parameter()]
        [AllowNull()]
        [string[]]$After
    )

    $beforeSet = @(Get-UniqueNonEmptyString -InputObject $Before)
    $afterSet = @(Get-UniqueNonEmptyString -InputObject $After)

    return [pscustomobject]@{
        Before  = $beforeSet
        After   = $afterSet
        Missing = @($beforeSet | Where-Object { $_ -notin $afterSet })
        Added   = @($afterSet  | Where-Object { $_ -notin $beforeSet })
    }
}

<#
.SYNOPSIS
    Creates a directory if it does not exist.
.DESCRIPTION
    This function checks if a directory exists and creates it if it does not.
.PARAMETER Path
    The path of the directory to create.
.EXAMPLE
    New-DirectoryIfNotExist -Path "C:\MyDirectory"
.OUTPUTS
    System.Void
.NOTES
    The function uses the -Force parameter to create the directory if it does not exist.
#>
function New-DirectoryIfNotExist {
    [CmdletBinding(SupportsShouldProcess = $true)]
    [OutputType([System.Void])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        if ($PSCmdlet.ShouldProcess($Path, 'Create directory')) {
            New-Item -Path $Path -ItemType Directory -Force | Out-Null
        }
    }
}

# Thin wrappers for file IO so tests can Mock these easily
function WriteAllLines {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][object[]]$Contents,
        $Encoding
    )

    if ($null -eq $Encoding) {
        [System.IO.File]::WriteAllLines($Path, $Contents)
    }
    else {
        [System.IO.File]::WriteAllLines($Path, $Contents, $Encoding)
    }
}

function WriteAllText {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][string]$Contents,
        $Encoding
    )

    if ($null -eq $Encoding) {
        [System.IO.File]::WriteAllText($Path, $Contents)
    }
    else {
        [System.IO.File]::WriteAllText($Path, $Contents, $Encoding)
    }
}

<#
.SYNOPSIS
    Normalizes a file path from a command line argument.
.DESCRIPTION
    This function attempts to extract and normalize a file path from a command line string.
.PARAMETER CommandLine
    The command line string containing the file path.
.EXAMPLE
    Get-NormalizedFilePathFromCommandLine -CommandLine '"C:\Program Files\Example\example.exe"'
.OUTPUTS
    System.String - The normalized file path or $null if not found.
.NOTES
    The function trims whitespace and removes surrounding quotes from the command line argument.
#>
function Get-NormalizedFilePathFromCommandLine {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$CommandLine
    )

    if ([string]::IsNullOrWhiteSpace($CommandLine)) {
        return $null
    }

    $text = $CommandLine.Trim()

    $text = [Environment]::ExpandEnvironmentVariables($text)

    if ($text.StartsWith('\SystemRoot\', [System.StringComparison]::OrdinalIgnoreCase)) {
        $text = Join-Path $env:windir $text.Substring(12)
    }

    if ($text.StartsWith('"')) {
        $m = [regex]::Match($text, '^"([^"]+\.(exe|dll|sys|com|cpl|ocx))"', 'IgnoreCase')
        if ($m.Success) {
            return $m.Groups[1].Value
        }
    }

    $m = [regex]::Match($text, '^[^\s"]+\.(exe|dll|sys|com|cpl|ocx)', 'IgnoreCase')
    if ($m.Success) {
        return $m.Value
    }

    $m = [regex]::Match($text, '^[A-Za-z]:\\.*?\.(exe|dll|sys|com|cpl|ocx)', 'IgnoreCase')
    if ($m.Success) {
        return $m.Value.Trim('"')
    }

    return $text.Trim('"')
}

<#
.SYNOPSIS
    Resolves the vendor name from a given text.
.DESCRIPTION
    This function attempts to identify the vendor associated with a given text by checking for known vendor hints.
.PARAMETER Text
    The text to analyze for vendor information.
.EXAMPLE
    Resolve-VendorFromText -Text "Microsoft Windows Defender"
.OUTPUTS
    System.String - The resolved vendor name or $null if not found.
.NOTES
    The function uses a predefined set of vendor hints to match against the input text. It returns the first matching vendor name based on the hints provided.
#>
function Resolve-VendorFromText {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        [AllowNull()]
        [string[]]$Text
    )

    $joined = (@($Text) | Where-Object { $_ } | ForEach-Object { $_.ToString() }) -join ' '
    if ([string]::IsNullOrWhiteSpace($joined)) {
        return $null
    }

    $joined = $joined.ToLowerInvariant()

    $vendorHints = @{
        'Microsoft'          = @('microsoft', 'windows defender', 'microsoft corporation', 'hyper-v')
        'VMware'             = @('vmware', 'vmware, inc')
        'VirtualBox'         = @('virtualbox', 'oracle virtualbox')
        'Parallels'          = @('parallels')
        'CrowdStrike'        = @('crowdstrike', 'falcon')
        'SentinelOne'        = @('sentinelone', 'sentinel')
        'Sophos'             = @('sophos')
        'Bitdefender'        = @('bitdefender')
        'Malwarebytes'       = @('malwarebytes', 'mbam')
        'Symantec'           = @('symantec', 'broadcom endpoint', 'sep')
        'Trellix/McAfee'     = @('trellix', 'mcafee', 'mfe')
        'Palo Alto Networks' = @('palo alto', 'cortex', 'globalprotect', 'traps')
        'Cisco'              = @('cisco', 'anyconnect', 'secure client', 'umbrella', 'amp')
        'Zscaler'            = @('zscaler')
        'ESET'               = @('eset')
        'Trend Micro'        = @('trend micro', 'apex one')
        'Check Point'        = @('check point', 'capsule', 'snx')
        'Fortinet'           = @('fortinet', 'forticlient', 'fortiedr')
    }

    foreach ($vendor in $vendorHints.Keys) {
        foreach ($hint in $vendorHints[$vendor]) {
            if ($joined -like "*$hint*") {
                return $vendor
            }
        }
    }

    return $null
}

<#
.SYNOPSIS
    Retrieves metadata for a given file.
.DESCRIPTION
    This function returns detailed metadata for a specified file, including version information and digital signature details.
.PARAMETER Path
    The path to the file for which to retrieve metadata.
.EXAMPLE
    Get-FileMetadatum -Path "C:\Windows\System32\ntdll.dll"
.OUTPUTS
    System.Management.Automation.PSCustomObject - A custom object containing the file's metadata.
.NOTES
    The function will display verbose information about the file being processed and any errors encountered.
#>
<# Duplicate helper removed; use Get-FileMetadata instead. #>

<#
.SYNOPSIS
    Retrieves the registry roots for a given vendor.
.DESCRIPTION
    This function returns the registry paths commonly associated with a specified vendor's software.
.PARAMETER Vendor
    The name of the vendor for which to retrieve registry roots.
.EXAMPLE
    Get-VendorRoots -Vendor "Microsoft"
.OUTPUTS
    System.String[] - An array of registry paths associated with the vendor.
.NOTES
    The function will display verbose information about the registry paths being retrieved.
#>
function Get-VendorRootsFromInstallPath {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter()]
        [AllowNull()]
        [string]$InstallPath
    )

    if ([string]::IsNullOrWhiteSpace($InstallPath)) {
        return [string[]] @()
    }

    $roots = New-Object System.Collections.Generic.List[string]

    try {
        $resolved = $InstallPath.Trim().Trim('"')
        if (-not [string]::IsNullOrWhiteSpace($resolved)) {
            $leaf = Split-Path -Path $resolved -Leaf
            $parent = Split-Path -Path $resolved -Parent

            if (-not [string]::IsNullOrWhiteSpace($leaf)) {
                [void]$roots.Add("HKLM\SOFTWARE\$leaf")
                [void]$roots.Add("HKLM\SOFTWARE\WOW6432Node\$leaf")
            }

            if (-not [string]::IsNullOrWhiteSpace($parent)) {
                $parentLeaf = Split-Path -Path $parent -Leaf
                if (-not [string]::IsNullOrWhiteSpace($parentLeaf)) {
                    [void]$roots.Add("HKLM\SOFTWARE\$parentLeaf")
                    [void]$roots.Add("HKLM\SOFTWARE\WOW6432Node\$parentLeaf")
                }
            }
        }
    }
    catch {
        Write-Verbose "Ignored error: $_"
    }

    [string[]]$result = @(Get-UniqueNonEmptyString -InputObject $roots)
    return [string[]] $result
}

<#
.SYNOPSIS
    Tests whether a string is safe to embed as a native-command argument value.
.DESCRIPTION
    Rejects values containing characters that could alter argument-boundary
    parsing when embedded in a single native command-line argument (e.g. an
    embedded double quote closing the argument early). Used to validate
    externally-sourced, attacker-influenceable identifiers - such as Wi-Fi
    profile names - before they reach any external command.
.PARAMETER Value
    The string to validate.
.OUTPUTS
    System.Boolean
#>
function Test-NetCleanSafeIdentifier {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [AllowNull()]
        [string]$Value
    )

    if ([string]::IsNullOrEmpty($Value)) {
        return $false
    }

    return $Value -notmatch '["`;&|<>\r\n\x00]'
}

<#
.SYNOPSIS
    Invokes an external command safely.
.DESCRIPTION
    This function executes an external command and handles potential errors gracefully.
.PARAMETER Name
    The name of the command to invoke.
.PARAMETER FilePath
    The path to the executable file.
.PARAMETER ArgumentList
    The list of arguments for the command.
.PARAMETER DryRun
    Indicates whether to perform a dry run without actually executing the command.
.PARAMETER IgnoreExitCode
    Indicates whether to ignore the exit code of the command.
.EXAMPLE
    Invoke-ExternalCommandSafe -Name "Example" -FilePath "C:\Example.exe" -ArgumentList @("-arg1", "-arg2")
.OUTPUTS
    System.Object - A custom object representing the result of the command execution.
.NOTES
    The function will display verbose information about the command being executed and any errors encountered.
#>
function Invoke-ExternalCommandSafe {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter(Mandatory = $true)]
        [string[]]$ArgumentList,

        [switch]$DryRun,
        [switch]$IgnoreExitCode
    )

    $display = "$FilePath $($ArgumentList -join ' ')"

    if ($DryRun) {
        return [pscustomobject]@{
            Name      = $Name
            Command   = $display
            ExitCode  = 0
            Succeeded = $true
            DryRun    = $true
            Error     = $null
        }
    }

    try {
        $proc = Start-Process -FilePath $FilePath -ArgumentList $ArgumentList -NoNewWindow -Wait -PassThru -ErrorAction Stop

        if (-not $IgnoreExitCode -and $proc.ExitCode -ne 0) {
            return [pscustomobject]@{
                Name      = $Name
                Command   = $display
                ExitCode  = $proc.ExitCode
                Succeeded = $false
                DryRun    = $false
                Error     = "$Name failed with exit code $($proc.ExitCode)"
            }
        }

        return [pscustomobject]@{
            Name      = $Name
            Command   = $display
            ExitCode  = $proc.ExitCode
            Succeeded = $true
            DryRun    = $false
            Error     = $null
        }
    }
    catch {
        return [pscustomobject]@{
            Name      = $Name
            Command   = $display
            ExitCode  = -1
            Succeeded = $false
            DryRun    = $false
            Error     = $_.Exception.Message
        }
    }
}

<#
.SYNOPSIS
    Tests if a registry path is protected.
.DESCRIPTION
    This function checks if a given registry path is protected based on the provided context.
.PARAMETER Path
    The registry path to test.
.PARAMETER Context
    The context containing protected registry paths.
.EXAMPLE
    Test-RegistryPathProtected -Path "HKLM\SOFTWARE\Microsoft" -Context $context
.OUTPUTS
    System.Boolean - True if the path is protected, false otherwise.
.NOTES
    The context should have a property named 'ProtectedRegistryPaths' which is a collection of registry paths that are considered protected. The function checks if the input path matches or is a subpath of any of the protected paths.
#>
function Test-RegistryPathProtected {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter()]
        [AllowNull()]
        [pscustomobject]$Context
    )

    if ($null -eq $Context) { return $false }

    if (-not $Context.PSObject.Properties.Name.Contains('ProtectedRegistryPaths')) {
        return $false
    }

    try {
        $normalizedPath = Convert-RegKeyPath -Path $Path
    }
    catch {
        return $false
    }

    foreach ($protected in @($Context.ProtectedRegistryPaths)) {
        if ([string]::IsNullOrWhiteSpace($protected)) { continue }

        try {
            $normalizedProtected = Convert-RegKeyPath -Path $protected
        }
        catch {
            continue
        }

        $pathIsProtected = $normalizedPath.Equals(
            $normalizedProtected,
            [System.StringComparison]::OrdinalIgnoreCase
        ) -or $normalizedPath.StartsWith(
            "$normalizedProtected\",
            [System.StringComparison]::OrdinalIgnoreCase
        ) -or $normalizedProtected.StartsWith(
            "$normalizedPath\",
            [System.StringComparison]::OrdinalIgnoreCase
        )

        if ($pathIsProtected) {
            return $true
        }
    }

    return $false
}

# ---------------------------------------------------------------------------
# Signature model
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Retrieves the signature for a given vendor.
.DESCRIPTION
    This function returns the signature information for a specified vendor, including categories, patterns, and registry roots.
.PARAMETER Vendor
    The name of the vendor for which to retrieve signature information.
.EXAMPLE
    Get-VendorSignature -Vendor "Microsoft"
.OUTPUTS
    System.Collections.Hashtable - A hashtable containing the vendor's signature information.
.NOTES
    The returned hashtable includes the following keys:
    - Categories: An array of categories associated with the vendor (e.g., AV, Firewall).
    - Patterns: An array of strings used to identify the vendor in various contexts.
    - RegistryRoots: An array of registry paths commonly associated with the vendor's software.
#>
function Get-VendorSignature {
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param()

    @{
        'Microsoft'          = @{
            Categories    = @('AV', 'Firewall', 'Hypervisor', 'VirtualAdapter', 'NetworkFilter', 'EndpointAgent')
            Patterns      = @(
                'microsoft defender', 'windows defender', 'msmpsvc', 'windefend', 'sense',
                'wdfilter', 'vmcompute', 'vmms', 'vmswitch', 'vmsmp', 'hns', 'hyper-v',
                'vethernet', 'microsoft'
            )
            RegistryRoots = @(
                'HKLM\SOFTWARE\Microsoft\Windows Defender',
                'HKLM\SOFTWARE\Microsoft\Windows Advanced Threat Protection',
                'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization'
            )
        }
        'Bitdefender'        = @{
            Categories    = @('AV', 'Firewall', 'EndpointAgent', 'NetworkFilter')
            Patterns      = @('bitdefender', 'vsserv', 'bdservice', 'bdredline', 'bdc', 'epsecurityservice')
            RegistryRoots = @('HKLM\SOFTWARE\Bitdefender')
        }
        'Malwarebytes'       = @{
            Categories    = @('AV', 'EndpointAgent')
            Patterns      = @('malwarebytes', 'mbamservice', 'mbamprotector', 'mbam')
            RegistryRoots = @('HKLM\SOFTWARE\Malwarebytes')
        }
        'CrowdStrike'        = @{
            Categories    = @('EDR', 'XDR', 'EndpointAgent', 'NetworkFilter')
            Patterns      = @('crowdstrike', 'falcon', 'csfalconservice', 'csagent', 'crowdstrike falcon')
            RegistryRoots = @('HKLM\SOFTWARE\CrowdStrike')
        }
        'SentinelOne'        = @{
            Categories    = @('EDR', 'XDR', 'EndpointAgent', 'NetworkFilter')
            Patterns      = @('sentinelone', 'sentinelagent', 'sentinelctl', 'sentinel')
            RegistryRoots = @('HKLM\SOFTWARE\SentinelOne')
        }
        'Sophos'             = @{
            Categories    = @('AV', 'Firewall', 'EndpointAgent', 'NetworkFilter')
            Patterns      = @('sophos', 'savservice', 'sophos endpoint', 'hitmanpro', 'sntp')
            RegistryRoots = @('HKLM\SOFTWARE\Sophos')
        }
        'Symantec'           = @{
            Categories    = @('AV', 'EndpointAgent', 'Firewall')
            Patterns      = @('symantec', 'broadcom endpoint', 'sep', 'smc', 'symcorpui')
            RegistryRoots = @('HKLM\SOFTWARE\Symantec')
        }
        'Trellix/McAfee'     = @{
            Categories    = @('AV', 'EDR', 'Firewall', 'EndpointAgent', 'NetworkFilter')
            Patterns      = @('mcafee', 'trellix', 'mfe', 'ens', 'mfefire', 'mfewfpk')
            RegistryRoots = @('HKLM\SOFTWARE\McAfee', 'HKLM\SOFTWARE\Trellix')
        }
        'Palo Alto Networks' = @{
            Categories    = @('EDR', 'XDR', 'Firewall', 'VPN', 'EndpointAgent', 'NetworkFilter')
            Patterns      = @('palo alto', 'cortex', 'globalprotect', 'traps', 'pangps', 'pangpd')
            RegistryRoots = @('HKLM\SOFTWARE\Palo Alto Networks')
        }
        'Cisco'              = @{
            Categories    = @('Firewall', 'VPN', 'EndpointAgent', 'NetworkFilter')
            Patterns      = @('cisco', 'anyconnect', 'secure client', 'amp', 'umbrella', 'ciscosecureclient')
            RegistryRoots = @('HKLM\SOFTWARE\Cisco')
        }
        'Zscaler'            = @{
            Categories    = @('Firewall', 'VPN', 'EndpointAgent', 'NetworkFilter')
            Patterns      = @('zscaler', 'zsa', 'zsatray', 'zscaler tunnel', 'zcc')
            RegistryRoots = @('HKLM\SOFTWARE\Zscaler')
        }
        'VMware'             = @{
            Categories    = @('Hypervisor', 'VirtualAdapter')
            Patterns      = @('vmware', 'vmnet', 'vmnat', 'vmwarehostd', 'vmx86', 'vmci', 'vmusb', 'vmware network adapter')
            RegistryRoots = @('HKLM\SOFTWARE\VMware, Inc.')
        }
        'VirtualBox'         = @{
            Categories    = @('Hypervisor', 'VirtualAdapter')
            Patterns      = @('virtualbox', 'oracle virtualbox', 'vbox', 'vboxnet', 'vboxdrv')
            RegistryRoots = @('HKLM\SOFTWARE\Oracle\VirtualBox')
        }
        'Parallels'          = @{
            Categories    = @('Hypervisor', 'VirtualAdapter')
            Patterns      = @('parallels', 'prl_', 'prl net', 'prl networking')
            RegistryRoots = @('HKLM\SOFTWARE\Parallels')
        }
        'ESET'               = @{
            Categories    = @('AV', 'EndpointAgent', 'Firewall', 'NetworkFilter')
            Patterns      = @('eset', 'ekrn', 'epfw', 'epfwlwf')
            RegistryRoots = @('HKLM\SOFTWARE\ESET')
        }
        'Trend Micro'        = @{
            Categories    = @('AV', 'EDR', 'EndpointAgent', 'NetworkFilter')
            Patterns      = @('trend micro', 'tmlisten', 'ntrtscan', 'ds_agent', 'apex one')
            RegistryRoots = @('HKLM\SOFTWARE\TrendMicro')
        }
        'Check Point'        = @{
            Categories    = @('Firewall', 'VPN', 'EndpointAgent', 'NetworkFilter')
            Patterns      = @('check point', 'endpoint security', 'tracsrvwrapper', 'snx', 'capsule')
            RegistryRoots = @('HKLM\SOFTWARE\CheckPoint')
        }
        'Fortinet'           = @{
            Categories    = @('Firewall', 'VPN', 'EndpointAgent', 'NetworkFilter')
            Patterns      = @('fortinet', 'forticlient', 'fortiedr', 'fortishield')
            RegistryRoots = @('HKLM\SOFTWARE\Fortinet')
        }
    }
}


function Test-VendorPatternMatch {
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Vendor,

        [Parameter(Mandatory = $true)]
        [hashtable]$Signature,

        [Parameter(Mandatory = $true)]
        [pscustomobject]$Evidence
    )

    if ($Evidence.PSObject.Properties.Name -contains 'InferredVendor') {
        if ($Evidence.InferredVendor -and $Evidence.InferredVendor -eq $Vendor) {
            return $true
        }
    }

    $haystackParts = foreach ($propertyName in @(
            'Name',
            'DisplayName',
            'Path',
            'Publisher',
            'InstallPath',
            'InterfaceDescription',
            'Manufacturer',
            'CompanyName',
            'FileDescription',
            'ProductName',
            'SignerSubject'
        )) {
        $property = $Evidence.PSObject.Properties[$propertyName]
        if ($null -ne $property) {
            $property.Value
        }
    }

    $haystack = ($haystackParts | Where-Object { $_ }) -join ' '
    $haystack = $haystack.ToLowerInvariant()

    foreach ($pattern in $Signature.Patterns) {
        if ($haystack -like "*$pattern*") {
            return $true
        }
    }

    return $false
}

<#
.SYNOPSIS
Retrieves metadata for a specified file.
.DESCRIPTION
Gets detailed information about a file, including its version and company details.
.EXAMPLE
Get-FileMetadatum -Path "C:\Windows\System32\notepad.exe"
.OUTPUTS
PSCustomObject - A custom object containing the file's metadata.
#>
function Get-FileMetadatum {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Path
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return $null
    }

    $resolvedPath = Get-NormalizedFilePathFromCommandLine -CommandLine $Path

    if ([string]::IsNullOrWhiteSpace($resolvedPath)) {
        return $null
    }

    try {
        try {
            if (-not (Test-Path -LiteralPath $resolvedPath -ErrorAction Stop)) {
                return [pscustomobject]@{
                    Path             = $resolvedPath
                    Exists           = $false
                    CompanyName      = $null
                    FileDescription  = $null
                    ProductName      = $null
                    OriginalName     = $null
                    FileVersion      = $null
                    SignerSubject    = $null
                    SignerIssuer     = $null
                    SignerThumbprint = $null
                    SignatureStatus  = $null
                    InferredVendor   = $null
                }
            }
        }
        catch {
            Write-Verbose "Invalid path for metadata lookup: $resolvedPath"
            return $null
        }

        $item = Get-Item -LiteralPath $resolvedPath -ErrorAction Stop
        $versionInfo = $item.VersionInfo

        $sig = $null
        try {
            $sig = Get-AuthenticodeSignature -FilePath $item.FullName -ErrorAction Stop
        }
        catch {
            Write-Verbose "Failed to get Authenticode signature for '$($item.FullName)': $_"
        }

        return [pscustomobject]@{
            Path             = $item.FullName
            Exists           = $true
            CompanyName      = if ($versionInfo) { $versionInfo.CompanyName } else { $null }
            FileDescription  = if ($versionInfo) { $versionInfo.FileDescription } else { $null }
            ProductName      = if ($versionInfo) { $versionInfo.ProductName } else { $null }
            OriginalName     = if ($versionInfo) { $versionInfo.OriginalFilename } else { $null }
            FileVersion      = if ($versionInfo) { $versionInfo.FileVersion } else { $null }
            SignerSubject    = if ($sig -and $sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { $null }
            SignerIssuer     = if ($sig -and $sig.SignerCertificate) { $sig.SignerCertificate.Issuer } else { $null }
            SignerThumbprint = if ($sig -and $sig.SignerCertificate) { $sig.SignerCertificate.Thumbprint } else { $null }
            SignatureStatus  = if ($sig) { [string]$sig.Status } else { $null }
            InferredVendor   = Resolve-VendorFromText -Text @(
                if ($versionInfo) { $versionInfo.CompanyName }
                if ($versionInfo) { $versionInfo.FileDescription }
                if ($versionInfo) { $versionInfo.ProductName }
                $item.Name
            )
        }
    }
    catch {
        Write-Verbose "Get-FileMetadatum ignored error for path '$Path': $_"
        return $null
    }
}

function Get-CachedFileMetadatum {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [hashtable]$Cache
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return $null
    }

    $cacheKey = Get-NormalizedFilePathFromCommandLine -CommandLine $Path
    if ([string]::IsNullOrWhiteSpace($cacheKey)) {
        return $null
    }

    if (-not $Cache.ContainsKey($cacheKey)) {
        $Cache[$cacheKey] = Get-FileMetadatum -Path $Path
    }

    return $Cache[$cacheKey]
}

<#
.SYNOPSIS
Reads one property from an object only if that property actually exists.
.DESCRIPTION
Registry-derived and other dynamically-shaped objects (Get-ItemProperty results,
CIM/WMI records) don't reliably carry every property real-world data might omit -
under Set-StrictMode, reading a missing property throws. This is the shared
"read Name from InputObject if present, else null" guard used throughout the
evidence-collection and snapshot code.
#>
function Get-NetCleanSafeProperty {
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [object]$InputObject,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    if ($null -ne $InputObject -and $InputObject.PSObject.Properties.Name -contains $Name) {
        return $InputObject.$Name
    }
    return $null
}

function Get-ServiceRegistrySnapshot {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param()

    $snapshot = [System.Collections.Generic.List[object]]::new()
    $servicesRoot = 'HKLM\SYSTEM\CurrentControlSet\Services'

    foreach ($svcName in @(Get-RegistryChildKeyNamesSafe -RegistryPath $servicesRoot)) {
        $svcPath = "$servicesRoot\$svcName"
        $props = Get-RegistryValuesSafe -RegistryPath $svcPath

        $imagePath = $null
        $displayName = $null
        $type = $null
        $start = $null
        $group = $null

        if ($null -ne $props) {
            if ($props.PSObject.Properties.Name -contains 'ImagePath') {
                $imagePath = $props.ImagePath
            }
            if ($props.PSObject.Properties.Name -contains 'DisplayName') {
                $displayName = $props.DisplayName
            }
            if ($props.PSObject.Properties.Name -contains 'Type') {
                $type = $props.Type
            }
            if ($props.PSObject.Properties.Name -contains 'Start') {
                $start = $props.Start
            }
            if ($props.PSObject.Properties.Name -contains 'Group') {
                $group = $props.Group
            }
        }

        $enumPath = if (Test-RegistryPathExist -RegistryPath "$svcPath\Enum") { "$svcPath\Enum" } else { $null }
        $linkagePath = if (Test-RegistryPathExist -RegistryPath "$svcPath\Linkage") { "$svcPath\Linkage" } else { $null }
        $paramsPath = if (Test-RegistryPathExist -RegistryPath "$svcPath\Parameters") { "$svcPath\Parameters" } else { $null }
        $instancesPath = if (Test-RegistryPathExist -RegistryPath "$svcPath\Instances") { "$svcPath\Instances" } else { $null }
        $linkageValues = Get-RegistryValuesSafe -RegistryPath "$svcPath\Linkage"

        $snapshot.Add([pscustomobject][ordered]@{
            Name          = $svcName
            RegistryPath  = $svcPath
            Values        = $props
            LinkageValues = $linkageValues
            ImagePath     = $imagePath
            DisplayName   = $displayName
            Type          = $type
            Start         = $start
            Group         = $group
            EnumPath      = $enumPath
            LinkagePath   = $linkagePath
            ParamsPath    = $paramsPath
            InstancesPath = $instancesPath
        })
    }

    return $snapshot.ToArray()
}

function Get-ServiceRegistryMap {
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param(
        [Parameter()]
        [AllowNull()]
        [object[]]$Snapshot
    )

    if (-not $PSBoundParameters.ContainsKey('Snapshot') -or $null -eq $Snapshot) {
        $Snapshot = @(Get-ServiceRegistrySnapshot)
    }

    $map = @{}

    foreach ($entry in $Snapshot) {
        $map[$entry.Name.ToLowerInvariant()] = $entry
    }

    return $map
}

function Get-AdapterRegistryCorrelation {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param()

    $results = New-Object System.Collections.Generic.List[object]
    $classRoot = 'HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}'
    $networkRoot = 'HKLM\SYSTEM\CurrentControlSet\Control\Network\{4d36e972-e325-11ce-bfc1-08002be10318}'
    $tcpipInterfacesRoot = 'HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces'

    foreach ($classSub in @(Get-RegistryChildKeyNamesSafe -RegistryPath $classRoot)) {
        if ($classSub -notmatch '^\d{4}$') { continue }

        $classPath = "$classRoot\$classSub"
        $props = Get-RegistryValuesSafe -RegistryPath $classPath
        if ($null -eq $props) { continue }

        $componentId = Get-NetCleanSafeProperty -InputObject $props -Name 'ComponentId'
        $driverDesc = Get-NetCleanSafeProperty -InputObject $props -Name 'DriverDesc'
        $providerName = Get-NetCleanSafeProperty -InputObject $props -Name 'ProviderName'
        $netCfgInstanceId = Get-NetCleanSafeProperty -InputObject $props -Name 'NetCfgInstanceId'

        $networkPath = $null
        $connectionPath = $null
        $interfacePath = $null
        $guid = $null

        if ($netCfgInstanceId) {
            try {
                $guid = ([guid]$netCfgInstanceId).Guid.ToLowerInvariant()
            }
            catch {
                $guid = $netCfgInstanceId.Trim('{}').ToLowerInvariant()
            }

            $candidateNetwork = "$networkRoot\{$guid}"
            $candidateConnection = "$candidateNetwork\Connection"
            $candidateInterface = "$tcpipInterfacesRoot\{$guid}"

            if (Test-RegistryPathExist -RegistryPath $candidateNetwork) { $networkPath = $candidateNetwork }
            if (Test-RegistryPathExist -RegistryPath $candidateConnection) { $connectionPath = $candidateConnection }
            if (Test-RegistryPathExist -RegistryPath $candidateInterface) { $interfacePath = $candidateInterface }

            $results.Add([pscustomobject]@{
                    InterfaceGuid  = $guid
                    ClassPath      = $classPath
                    NetworkPath    = $networkPath
                    ConnectionPath = $connectionPath
                    TcpipPath      = $interfacePath
                    ComponentId    = $componentId
                    DriverDesc     = $driverDesc
                    ProviderName   = $providerName
                })
        }
    }

    return $results.ToArray()
}


function Invoke-RegExport {
    [CmdletBinding()]
    [OutputType([System.String])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Key,

        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [switch]$DryRun
    )

    if ($DryRun) {
        return $FilePath
    }

    $resolvedKey = Resolve-NetCleanRegistryPath -RegistryPath $Key
    if ($resolvedKey.Contains('"') -or $FilePath.Contains('"')) {
        throw 'Registry export key and output path must not contain double-quote characters.'
    }
    $quote = [char]34
    $regArgs = @('export', "$quote$resolvedKey$quote", "$quote$FilePath$quote", '/y')

    $proc = Start-Process -FilePath 'reg.exe' -ArgumentList $regArgs -NoNewWindow -Wait -PassThru
    if ($null -eq $proc) {
        throw "Failed to start reg.exe export for '$Key'"
    }

    if ($proc.ExitCode -ne 0) {
        throw "reg.exe export failed for '$Key' with exit code $($proc.ExitCode)"
    }

    if (-not (Test-Path -LiteralPath $FilePath)) {
        throw "reg.exe reported success but output file was not created: '$FilePath'"
    }

    return $FilePath
}

<#
.SYNOPSIS
Invoke a native executable and capture its output.
.DESCRIPTION
Executes a native executable with the specified arguments and captures its output, including any errors.
.PARAMETER FilePath
The path to the native executable.
.PARAMETER ArgumentList
The list of arguments to pass to the executable.
.PARAMETER Name
The name to use for the captured output.
.PARAMETER IgnoreExitCode
If specified, ignores the exit code of the executable.
.OUTPUTS
A custom object containing the execution results.
#>
function Invoke-NetCleanNativeCapture {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string]$FilePath,

        [Parameter()]
        [string[]]$ArgumentList = @(),

        [string]$Name = $FilePath,

        [switch]$IgnoreExitCode
    )

    try {
        $output = & $FilePath @ArgumentList 2>&1
        $exitCode = if ($null -ne $LASTEXITCODE) { $LASTEXITCODE } else { 0 }

        if (-not $IgnoreExitCode -and $exitCode -ne 0) {
            return [pscustomobject]@{
                Name      = $Name
                ExitCode  = $exitCode
                Succeeded = $false
                Output    = @($output)
                Error     = (@($output) | Out-String).Trim()
            }
        }

        return [pscustomobject]@{
            Name      = $Name
            ExitCode  = $exitCode
            Succeeded = $true
            Output    = @($output)
            Error     = $null
        }
    }
    catch {
        return [pscustomobject]@{
            Name      = $Name
            ExitCode  = -1
            Succeeded = $false
            Output    = @()
            Error     = $_.Exception.Message
        }
    }
}


# ---------------------------------------------------------------------------
# Workflow orchestration
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
Orchestrates the NetClean workflow across detect, protect, clean, and verify phases.
.DESCRIPTION
Coordinates the execution of the NetClean workflow by invoking each phase in sequence. Accepts parameters to control the mode of operation, backup paths, and which cleaning actions to perform or skip. Returns a context object containing detailed information about each phase's operations and results.
.PARAMETER Mode
Defines the cleaning mode to execute. Supported values are:
- 'Preview': Executes detect and protect phases, then returns context without making changes.
.PARAMETER BackupPath
Specifies the directory path where backups will be stored during the protect phase.
.PARAMETER DryRun
If set, simulates the workflow without performing any destructive actions, allowing for review of intended operations.
.PARAMETER SkipWifi
If set, skips the removal of Wi-Fi profiles during the clean phase.
.PARAMETER SkipDnsFlush
If set, skips flushing the DNS resolver cache during the clean phase.
.PARAMETER SkipEventLogs
If set, skips clearing network-related event logs during the clean phase.
.PARAMETER SkipUserArtifacts
If set, skips removing user artifacts during the clean phase.
.PARAMETER SkipFirewallBackup
If set, skips backing up firewall policies during the protect phase.
.PARAMETER PerformanceProfile
Specifies the validated performance profile used only with PerformanceTune mode.
.EXAMPLE
Invoke-NetCleanWorkflow -Mode 'SafeConferencePrep' -BackupPath 'C:\NetCleanBackups' -DryRun
.OUTPUTS
A context object containing detailed information about the operations performed in each phase of the NetClean workflow, including inventories, backups, cleaning actions, and verification results.
.NOTES
- Ensure that you have appropriate permissions to perform the operations in this workflow.
#>
function Invoke-NetCleanWorkflow {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Preview', 'SafeConferencePrep', 'AdvancedRepair', 'PerformanceTune')]
        [string]$Mode,

        [Parameter(Mandatory = $true)]
        [string]$BackupPath,

        [switch]$DryRun,
        [switch]$SkipWifi,
        [switch]$SkipDnsFlush,
        [switch]$SkipEventLogs,
        [switch]$SkipUserArtifacts,
        [switch]$SkipFirewallBackup,

        [ValidateSet('Conservative', 'Optimal', 'Gaming', 'Default')]
        [string]$PerformanceProfile
    )

    if ($Mode -eq 'PerformanceTune' -and [string]::IsNullOrWhiteSpace($PerformanceProfile)) {
        throw "PerformanceProfile is required when Mode is 'PerformanceTune'."
    }

    if ($Mode -eq 'PerformanceTune') {
        Write-NetCleanLog -Level INFO -Message ('Workflow starting. Mode={0} BackupPath={1} DryRun={2} PerformanceProfile={3}' -f $Mode, $BackupPath, [bool]$DryRun, $PerformanceProfile)
    }
    else {
        Write-NetCleanLog -Level INFO -Message ('Workflow starting. Mode={0} BackupPath={1} DryRun={2}' -f $Mode, $BackupPath, [bool]$DryRun)
    }

    $timings = @{}

    # Phase 1 - Detect
    $t0 = Get-Date
    Write-NetCleanLog -Level INFO -Message ("Phase Detect start: {0}" -f $t0.ToString('s'))

    $ctx = Invoke-NetCleanPhase1Detect

    $t1 = Get-Date
    Write-NetCleanLog -Level INFO -Message ("Phase Detect end: {0} (duration: {1})" -f $t1.ToString('s'), ($t1 - $t0).ToString())

    $timings.Detect = [pscustomobject]@{
        Start    = $t0
        End      = $t1
        Duration = ($t1 - $t0)
    }

    # Phase 2 - Protect
    $t0 = Get-Date
    Write-NetCleanLog -Level INFO -Message ("Phase Protect start: {0}" -f $t0.ToString('s'))

    $ctx = Invoke-NetCleanPhase2Protect `
        -Context $ctx `
        -BackupPath $BackupPath `
        -DryRun:$DryRun `
        -SkipFirewallBackup:$SkipFirewallBackup

    $backupPathFromProtect = $null
    if ($ctx -and $ctx.PSObject.Properties.Name -contains 'BackupPath') {
        $backupPathFromProtect = $ctx.BackupPath
    }

    $t1 = Get-Date
    Write-NetCleanLog -Level INFO -Message ("Phase Protect end: {0} (duration: {1})" -f $t1.ToString('s'), ($t1 - $t0).ToString())

    $timings.Protect = [pscustomobject]@{
        Start    = $t0
        End      = $t1
        Duration = ($t1 - $t0)
    }

    # Populate cached Wi-Fi and network profile lists
    try {
        if ($ctx.PSObject.Properties.Name -contains 'Protect' -and $ctx.Protect.PSObject.Properties.Name -contains 'Manifest') {
            $manifest = $ctx.Protect.Manifest
            $wifiFound = @()
            $netProfiles = @()
            $hasCollectionSnapshot = $ctx.PSObject.Properties.Name -contains 'CollectionSnapshot'

            if ($hasCollectionSnapshot) {
                $wifiFound = @($ctx.CollectionSnapshot.WiFiProfiles | ForEach-Object Name)
                $netProfiles = @($ctx.CollectionSnapshot.NetworkListProfiles | ForEach-Object Name)
            }
            elseif ($manifest -and $manifest.WiFiExports -and $manifest.WiFiExports.Count -gt 0) {
                foreach ($e in $manifest.WiFiExports) {
                    if ($e -is [string] -and $e -like 'PROFILE:*') {
                        $wifiFound += ($e -replace '^PROFILE:', '')
                    }
                    elseif ($e -is [string] -and $e -like '*.xml') {
                        $profileName = [System.IO.Path]::GetFileNameWithoutExtension($e)
                        $wifiFound += ($profileName -replace '^Wi-Fi-', '')
                    }
                }
            }

            if (-not $hasCollectionSnapshot -and $wifiFound.Count -eq 0) {
                $wifiFound = @(Get-WiFiProfileName)
            }

            Add-Member -InputObject $ctx.Protect.Summary -NotePropertyName WiFiProfilesFound -NotePropertyValue @($wifiFound) -Force
            Add-Member -InputObject $ctx.Protect.Summary -NotePropertyName WiFiProfilesFoundCount -NotePropertyValue $wifiFound.Count -Force

            if (-not $hasCollectionSnapshot) {
                $netProfiles = @(Get-NetworkListProfileName)
            }
            Add-Member -InputObject $ctx.Protect.Summary -NotePropertyName NetworkProfilesFound -NotePropertyValue @($netProfiles) -Force
            Add-Member -InputObject $ctx.Protect.Summary -NotePropertyName NetworkProfilesFoundCount -NotePropertyValue $netProfiles.Count -Force
        }
    }
    catch {
        Write-Verbose "Invoke-NetCleanWorkflow cache population: $($_.Exception.Message)"
    }

    if ($Mode -eq 'Preview') {
        Add-Member -InputObject $ctx -NotePropertyName Timings -NotePropertyValue $timings -Force
        return $ctx
    }

    # Phase 3 - Clean
    $t0 = Get-Date
    Write-NetCleanLog -Level INFO -Message ("Phase Clean start: {0}" -f $t0.ToString('s'))

    $cleanParameters = @{
        Context           = $ctx
        Mode              = $Mode
        DryRun            = [bool]$DryRun
        SkipWifi          = [bool]$SkipWifi
        SkipDnsFlush      = [bool]$SkipDnsFlush
        SkipEventLogs     = [bool]$SkipEventLogs
        SkipUserArtifacts = [bool]$SkipUserArtifacts
    }

    if ($Mode -eq 'PerformanceTune') {
        $cleanParameters.PerformanceProfile = $PerformanceProfile
    }

    $ctx = Invoke-NetCleanPhase3Clean @cleanParameters

    if ($backupPathFromProtect -and -not ($ctx.PSObject.Properties.Name -contains 'BackupPath')) {
        Add-Member -InputObject $ctx -NotePropertyName BackupPath -NotePropertyValue $backupPathFromProtect -Force
    }

    if ($Mode -eq 'PerformanceTune' -and $PerformanceProfile) {
        Add-Member -InputObject $ctx -NotePropertyName PerformanceProfile -NotePropertyValue $PerformanceProfile -Force
    }

    $t1 = Get-Date
    Write-NetCleanLog -Level INFO -Message ("Phase Clean end: {0} (duration: {1})" -f $t1.ToString('s'), ($t1 - $t0).ToString())

    $timings.Clean = [pscustomobject]@{
        Start    = $t0
        End      = $t1
        Duration = ($t1 - $t0)
    }

    # Phase 4 - Verify
    $t0 = Get-Date
    Write-NetCleanLog -Level INFO -Message ("Phase Verify start: {0}" -f $t0.ToString('s'))

    $ctx = Invoke-NetCleanPhase4Verify -Context $ctx

    if ($backupPathFromProtect -and -not ($ctx.PSObject.Properties.Name -contains 'BackupPath')) {
        Add-Member -InputObject $ctx -NotePropertyName BackupPath -NotePropertyValue $backupPathFromProtect -Force
    }

    if ($Mode -eq 'PerformanceTune') {
        Add-Member -InputObject $ctx -NotePropertyName PerformanceProfile -NotePropertyValue $PerformanceProfile -Force
    }

    $t1 = Get-Date
    Write-NetCleanLog -Level INFO -Message ("Phase Verify end: {0} (duration: {1})" -f $t1.ToString('s'), ($t1 - $t0).ToString())

    $timings.Verify = [pscustomobject]@{
        Start    = $t0
        End      = $t1
        Duration = ($t1 - $t0)
    }

    Add-Member -InputObject $ctx -NotePropertyName Timings -NotePropertyValue $timings -Force

    Write-NetCleanLog -Level INFO -Message ('Workflow complete. Mode={0} DryRun={1}' -f $Mode, [bool]$DryRun)

    $manifestFile = $null
    if ($ctx.PSObject.Properties.Name -contains 'Protect' -and $ctx.Protect.PSObject.Properties.Name -contains 'ManifestFile') {
        $manifestFile = $ctx.Protect.ManifestFile
    }

    $backupPathVal = $null
    if ($ctx -and $ctx.PSObject.Properties.Name -contains 'BackupPath') {
        $backupPathVal = $ctx.BackupPath
    }

    $backupPathDisplay = if ([string]::IsNullOrWhiteSpace($backupPathVal)) { '(none)' } else { $backupPathVal }

    Write-NetCleanLog -Level INFO -Message ('Final summary: Mode={0} DryRun={1} BackupPath={2} ManifestFile={3}' -f $Mode, [bool]$DryRun, $backupPathDisplay, $manifestFile)

    $wifiProfiles = @()
    if ($ctx.PSObject.Properties.Name -contains 'Clean' -and $ctx.Clean.PSObject.Properties.Name -contains 'WiFi') {
        $wifiProfiles = @($ctx.Clean.WiFi.Profiles)
    }
    Write-NetCleanLog -Level INFO -Message ("Wi-Fi profiles removed/wouldRemove: {0}" -f ($wifiProfiles -join ', '))

    $removedRegs = [System.Collections.Generic.List[string]]::new()
    if ($ctx.PSObject.Properties.Name -contains 'Clean' -and $ctx.Clean.PSObject.Properties.Name -contains 'RegistryArtifacts') {
        $results = @($ctx.Clean.RegistryArtifacts.Results)
        foreach ($r in $results) {
            if ($r.Removed) {
                [void]$removedRegs.Add($r.RegistryPath)
            }
        }
    }

    Write-NetCleanLog -Level INFO -Message ("Registry artifacts removed count: {0}" -f $removedRegs.Count)
    foreach ($rp in $removedRegs) {
        Write-NetCleanLog -Level INFO -Message ("Registry removed: {0}" -f $rp)
    }

    $eventCount = 0
    if ($ctx.PSObject.Properties.Name -contains 'Clean' -and $ctx.Clean.PSObject.Properties.Name -contains 'EventLogs') {
        $eventCount = @($ctx.Clean.EventLogs).Count
    }
    Write-NetCleanLog -Level INFO -Message ("Event logs touched: {0}" -f $eventCount)

    $userTouched = [System.Collections.Generic.List[string]]::new()
    if ($ctx.PSObject.Properties.Name -contains 'Clean' -and $ctx.Clean.PSObject.Properties.Name -contains 'UserArtifacts') {
        foreach ($u in @($ctx.Clean.UserArtifacts)) {
            if ($u.Removed) {
                [void]$userTouched.Add($u.Path)
            }
        }
    }
    Write-NetCleanLog -Level INFO -Message ("User artifacts touched count: {0}" -f $userTouched.Count)

    if ($ctx.PSObject.Properties.Name -contains 'Verify') {
        Write-NetCleanLog -Level INFO -Message ("Verification passed: {0}" -f $ctx.Verify.Summary.Passed)
        Write-NetCleanLog -Level INFO -Message ("Missing vendors: {0}" -f (@($ctx.Verify.VendorComparison.Missing) -join ', '))
        Write-NetCleanLog -Level INFO -Message ("Missing GUIDs: {0}" -f (@($ctx.Verify.GuidComparison.Missing) -join ', '))
        Write-NetCleanLog -Level INFO -Message ("Missing services: {0}" -f (@($ctx.Verify.ServiceComparison.Missing) -join ', '))
    }

    $verifyPassed = $false
    if ($ctx.PSObject.Properties.Name -contains 'Verify') {
        $verifyPassed = [bool]$ctx.Verify.Summary.Passed
    }

    Write-Information ('NetClean final summary: Mode={0} DryRun={1} WiFiRemoved={2} RegistryRemoved={3} VerifyPassed={4}' -f $Mode, [bool]$DryRun, $wifiProfiles.Count, $removedRegs.Count, $verifyPassed) -InformationAction Continue

    return $ctx
}

# ---------------------------------------------------------------------------
# Aliases
# ---------------------------------------------------------------------------

Set-Alias -Name Convert-NormalizeGuid        -Value Convert-Guid -Force
Set-Alias -Name Normalize-Guid               -Value Convert-Guid -Force
Set-Alias -Name Backup-ProtectedRegistryKeys -Value Export-ProtectedRegistryKey -Force
Set-Alias -Name Backup-NetworkList           -Value Export-NetworkList -Force
Set-Alias -Name Backup-WiFiProfiles          -Value Export-WiFiProfile -Force
Set-Alias -Name Export-ProtectedRegistryKeys -Value Export-ProtectedRegistryKey -Force

# ---------------------------------------------------------------------------
# Module exports
# ---------------------------------------------------------------------------

Export-ModuleMember -Function @(
    'Invoke-NetCleanPhase1Detect',
    'Invoke-NetCleanPhase2Protect',
    'Invoke-NetCleanPhase3Clean',
    'Invoke-NetCleanPhase4Verify',
    'Invoke-NetCleanWorkflow',
    'Get-NetCleanLogFile',
    'Start-NetCleanLog',
    'Write-NetCleanLog'
) -Alias @(
    'Backup-NetworkList',
    'Backup-ProtectedRegistryKeys',
    'Backup-WiFiProfiles'
)
