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

. (Join-Path $script:ModuleRoot 'NetCleanPhase1.psm1')
. (Join-Path $script:ModuleRoot 'NetCleanPhase2.psm1')
. (Join-Path $script:ModuleRoot 'NetCleanPhase3.psm1')
. (Join-Path $script:ModuleRoot 'NetCleanPhase4.psm1')

# Returns $true when the runtime supports simple parallelism helpers we use (Start-Job batching)
function Test-ParallelCapability {
    [CmdletBinding()]
    param()

    return $true
}

# Invoke a scriptblock over an input list in parallel using Start-Job with simple throttling.
# Returns an array of results collected from each job's output. This is compatible with Windows PowerShell.
function Invoke-InParallel {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$ScriptBlock,

        [Parameter(Mandatory = $true)]
        [object[]]$InputObjects,

        [int]$ThrottleLimit = ([System.Environment]::ProcessorCount)
    )
    # Prefer PowerShell 7+ runspace parallelism when available for efficiency.
    if ($PSVersionTable.PSVersion -and $PSVersionTable.PSVersion.Major -ge 7) {
        try {
            $ps7Results = @()
            $InputObjects | ForEach-Object -Parallel {
                try {
                    $res = & $using:ScriptBlock $_
                    if ($res) { $res }
                }
                catch { Write-Verbose "Invoke-InParallel (PS7): $($_.Exception.Message)" }
            } -ThrottleLimit $ThrottleLimit -ErrorAction Stop | ForEach-Object { $ps7Results += $_ }

            return , $ps7Results
        }
        catch { Write-Verbose "Invoke-InParallel PS7 fallback: $($_.Exception.Message)" }
    }

    # Fallback: Start-Job batching for Windows PowerShell compatibility
    $jobs = @()
    $results = New-Object System.Collections.Generic.List[object]

    foreach ($item in $InputObjects) {
        while ($jobs.Count -ge $ThrottleLimit) {
            [void](Wait-Job -Job $jobs -Any -Timeout 1)
            $finished = $jobs | Where-Object { $_.State -ne 'Running' }
            foreach ($j in $finished) {
                try {
                    $r = Receive-Job -Job $j -ErrorAction SilentlyContinue
                    if ($r) {
                        foreach ($itemOut in $r) { $results.Add($itemOut) }
                    }
                }
                catch { Write-Verbose "Invoke-InParallel (Receive-Job): $($_.Exception.Message)" }
                Remove-Job -Job $j -Force -ErrorAction SilentlyContinue
            }
            $jobs = $jobs | Where-Object { $_.State -eq 'Running' }
        }

        $jobs += Start-Job -ArgumentList $item -ScriptBlock $ScriptBlock
    }

    # Wait for remaining
    if ($jobs.Count -gt 0) {
        Wait-Job -Job $jobs
        foreach ($j in $jobs) {
            try {
                $r = Receive-Job -Job $j -ErrorAction SilentlyContinue
                if ($r) { foreach ($itemOut in $r) { $results.Add($itemOut) } }
            }
            catch { Write-Verbose "Invoke-InParallel (final Receive-Job): $($_.Exception.Message)" }
            Remove-Job -Job $j -Force -ErrorAction SilentlyContinue
        }
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

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

$script:LogFile = $null
$script:NewLine = [Environment]::NewLine
$script:Utf8NoBom = [System.Text.UTF8Encoding]::new($false)

function Get-NetCleanLogFile {
    [CmdletBinding()]
    param()

    return $script:LogFile
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
        'ERROR' { Write-Error $Message }
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
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )

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
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$RegistryPath
    )

    $p = Convert-RegKeyPath -Path $RegistryPath

    switch -Regex ($p) {
        '^HKLM\\' { return ('Registry::HKEY_LOCAL_MACHINE\' + $p.Substring(5)) }
        '^HKEY_LOCAL_MACHINE\\' { return ('Registry::' + $p) }
        '^HKCU\\' { return ('Registry::HKEY_CURRENT_USER\' + $p.Substring(5)) }
        '^HKEY_CURRENT_USER\\' { return ('Registry::' + $p) }
        '^HKCR\\' { return ('Registry::HKEY_CLASSES_ROOT\' + $p.Substring(5)) }
        '^HKEY_CLASSES_ROOT\\' { return ('Registry::' + $p) }
        '^HKU\\' { return ('Registry::HKEY_USERS\' + $p.Substring(4)) }
        '^HKEY_USERS\\' { return ('Registry::' + $p) }
        '^HKCC\\' { return ('Registry::HKEY_CURRENT_CONFIG\' + $p.Substring(5)) }
        '^HKEY_CURRENT_CONFIG\\' { return ('Registry::' + $p) }
        default { throw "Unsupported registry root in path '$RegistryPath'" }
    }
}

<#
.SYNOPSIS
    Tests if a registry path exists.
.DESCRIPTION
    This function checks if a specified registry path exists.
.PARAMETER RegistryPath
    The registry path to test.
.EXAMPLE
    Test-RegistryPathExist -RegistryPath "HKLM:\SOFTWARE\MyKey"
.OUTPUTS
    System.Boolean - True if the path exists, false otherwise.
.NOTES
    The function uses the Convert-RegToProviderPath function to normalize the input path.
#>
function Test-RegistryPathExist {
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$RegistryPath
    )

    try {
        $providerPath = Convert-RegToProviderPath -RegistryPath $RegistryPath
        return (Test-Path -LiteralPath $providerPath)
    }
    catch {
        return $false
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
.NOTES
    The function uses the Convert-RegToProviderPath function to normalize the input path.
#>
function Get-RegistryValuesSafe {
    [CmdletBinding()]
    [OutputType([System.Object])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$RegistryPath
    )

    try {
        $providerPath = Convert-RegToProviderPath -RegistryPath $RegistryPath
        return Get-ItemProperty -LiteralPath $providerPath -ErrorAction Stop
    }
    catch {
        return $null
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
.NOTES
    The function uses the Convert-RegToProviderPath function to normalize the input path.
#>
function Get-RegistryChildKeyNamesSafe {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$RegistryPath
    )

    try {
        $providerPath = Convert-RegToProviderPath -RegistryPath $RegistryPath
        return @(Get-ChildItem -LiteralPath $providerPath -ErrorAction Stop | Select-Object -ExpandProperty PSChildName)
    }
    catch {
        return @()
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

        [Parameter(Mandatory = $true)]
        [pscustomobject]$Context
    )

    if (-not $Context.PSObject.Properties.Name.Contains('ProtectedRegistryPaths')) {
        return $false
    }

    foreach ($protected in @($Context.ProtectedRegistryPaths)) {
        if ([string]::IsNullOrWhiteSpace($protected)) { continue }

        if ($Path -like "$protected*" -or $protected -like "$Path*") {
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

    $haystackParts = @(
        $Evidence.Name,
        $Evidence.DisplayName,
        $Evidence.Path,
        $Evidence.Publisher,
        $Evidence.InstallPath,
        $Evidence.InterfaceDescription,
        $Evidence.Manufacturer,
        $Evidence.CompanyName,
        $Evidence.FileDescription,
        $Evidence.ProductName,
        $Evidence.SignerSubject
    )

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

function Get-ServiceRegistryMap {
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param()

    $map = @{}
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

        $entry = [ordered]@{
            Name          = $svcName
            RegistryPath  = $svcPath
            ImagePath     = $imagePath
            DisplayName   = $displayName
            Type          = $type
            Start         = $start
            Group         = $group
            EnumPath      = if (Test-RegistryPathExist -RegistryPath "$svcPath\Enum") { "$svcPath\Enum" } else { $null }
            LinkagePath   = if (Test-RegistryPathExist -RegistryPath "$svcPath\Linkage") { "$svcPath\Linkage" } else { $null }
            ParamsPath    = if (Test-RegistryPathExist -RegistryPath "$svcPath\Parameters") { "$svcPath\Parameters" } else { $null }
            InstancesPath = if (Test-RegistryPathExist -RegistryPath "$svcPath\Instances") { "$svcPath\Instances" } else { $null }
        }

        $map[$svcName.ToLowerInvariant()] = [pscustomobject]$entry
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

        $componentId = $props.ComponentId
        $driverDesc = $props.DriverDesc
        $providerName = $props.ProviderName
        $netCfgInstanceId = $props.NetCfgInstanceId

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

    $regArgs = @('export', $Key, $FilePath, '/y')

    if ($DryRun) {
        return $FilePath
    }

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
If set, skips the removal of Wi‑Fi profiles during the clean phase.
.PARAMETER SkipDnsFlush
If set, skips flushing the DNS resolver cache during the clean phase.
.PARAMETER SkipEventLogs
If set, skips clearing network-related event logs during the clean phase.
.PARAMETER SkipUserArtifacts
If set, skips removing user artifacts during the clean phase.
.PARAMETER SkipFirewallBackup
If set, skips backing up firewall policies during the protect phase.
.PARAMETER EnableConservativePerformanceTuning
If set, enables conservative performance tuning options.
.EXAMPLE
Invoke-NetCleanWorkflow -Mode 'SafeConferencePrep' -BackupPath 'C:\NetCleanBackups' -DryRun
.OUTPUTS
A context object containing detailed information about the operations performed in each phase of the NetClean workflow, including inventories, backups, cleaning actions, and verification results.
.NOTES
- Ensure that you have appropriate permissions to perform the operations in this workflow.
#>
function Invoke-NetCleanWorkflow {
    [CmdletBinding(SupportsShouldProcess = $true)]
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

    if ($null -ne (Get-Command Write-NetCleanLog -ErrorAction SilentlyContinue)) {
        if ($Mode -eq 'PerformanceTune') {
            Write-NetCleanLog -Level INFO -Message ('Workflow starting. Mode={0} BackupPath={1} DryRun={2} PerformanceProfile={3}' -f $Mode, $BackupPath, [bool]$DryRun, $PerformanceProfile)
        }
        else {
            Write-NetCleanLog -Level INFO -Message ('Workflow starting. Mode={0} BackupPath={1} DryRun={2}' -f $Mode, $BackupPath, [bool]$DryRun)
        }
    }

    $timings = @{}

    # Phase 1 - Detect
    $t0 = Get-Date
    if ($null -ne (Get-Command Write-NetCleanLog -ErrorAction SilentlyContinue)) {
        Write-NetCleanLog -Level INFO -Message ("Phase Detect start: {0}" -f $t0.ToString('s'))
    }

    $ctx = Invoke-NetCleanPhase1Detect

    $t1 = Get-Date
    if ($null -ne (Get-Command Write-NetCleanLog -ErrorAction SilentlyContinue)) {
        Write-NetCleanLog -Level INFO -Message ("Phase Detect end: {0} (duration: {1})" -f $t1.ToString('s'), ($t1 - $t0).ToString())
    }

    $timings.Detect = [pscustomobject]@{
        Start    = $t0
        End      = $t1
        Duration = ($t1 - $t0)
    }

    # Phase 2 - Protect
    $t0 = Get-Date
    if ($null -ne (Get-Command Write-NetCleanLog -ErrorAction SilentlyContinue)) {
        Write-NetCleanLog -Level INFO -Message ("Phase Protect start: {0}" -f $t0.ToString('s'))
    }

    $ctx = Invoke-NetCleanPhase2Protect `
        -Context $ctx `
        -BackupPath $BackupPath `
        -DryRun:$DryRun `
        -SkipFirewallBackup:$SkipFirewallBackup `
        -WhatIf:$WhatIfPreference

    $backupPathFromProtect = $null
    if ($ctx -and $ctx.PSObject.Properties.Name -contains 'BackupPath') {
        $backupPathFromProtect = $ctx.BackupPath
    }

    $t1 = Get-Date
    if ($null -ne (Get-Command Write-NetCleanLog -ErrorAction SilentlyContinue)) {
        Write-NetCleanLog -Level INFO -Message ("Phase Protect end: {0} (duration: {1})" -f $t1.ToString('s'), ($t1 - $t0).ToString())
    }

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

            if ($manifest -and $manifest.WiFiExports -and $manifest.WiFiExports.Count -gt 0) {
                foreach ($e in $manifest.WiFiExports) {
                    if ($e -is [string] -and $e -like 'PROFILE:*') {
                        $wifiFound += ($e -replace '^PROFILE:', '')
                    }
                    elseif ($e -is [string] -and $e -like '*.xml') {
                        $wifiFound += [System.IO.Path]::GetFileNameWithoutExtension($e)
                    }
                }
            }

            if ($wifiFound.Count -eq 0) {
                $wifiFound = @(Get-WiFiProfileName)
            }

            Add-Member -InputObject $ctx.Protect.Summary -NotePropertyName WiFiProfilesFound -NotePropertyValue @($wifiFound) -Force
            Add-Member -InputObject $ctx.Protect.Summary -NotePropertyName WiFiProfilesFoundCount -NotePropertyValue $wifiFound.Count -Force

            $netProfiles = @(Get-NetworkListProfileName)
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
    if ($null -ne (Get-Command Write-NetCleanLog -ErrorAction SilentlyContinue)) {
        Write-NetCleanLog -Level INFO -Message ("Phase Clean start: {0}" -f $t0.ToString('s'))
    }

    $ctx = Invoke-NetCleanPhase3Clean `
        -Context $ctx `
        -Mode $Mode `
        -DryRun:$DryRun `
        -SkipWifi:$SkipWifi `
        -SkipDnsFlush:$SkipDnsFlush `
        -SkipEventLogs:$SkipEventLogs `
        -SkipUserArtifacts:$SkipUserArtifacts `
        -PerformanceProfile $PerformanceProfile `
        -WhatIf:$WhatIfPreference

    if ($backupPathFromProtect -and -not ($ctx.PSObject.Properties.Name -contains 'BackupPath')) {
        Add-Member -InputObject $ctx -NotePropertyName BackupPath -NotePropertyValue $backupPathFromProtect -Force
    }

    if ($Mode -eq 'PerformanceTune' -and $PerformanceProfile) {
        Add-Member -InputObject $ctx -NotePropertyName PerformanceProfile -NotePropertyValue $PerformanceProfile -Force
    }

    $t1 = Get-Date
    if ($null -ne (Get-Command Write-NetCleanLog -ErrorAction SilentlyContinue)) {
        Write-NetCleanLog -Level INFO -Message ("Phase Clean end: {0} (duration: {1})" -f $t1.ToString('s'), ($t1 - $t0).ToString())
    }

    $timings.Clean = [pscustomobject]@{
        Start    = $t0
        End      = $t1
        Duration = ($t1 - $t0)
    }

    # Phase 4 - Verify
    $t0 = Get-Date
    if ($null -ne (Get-Command Write-NetCleanLog -ErrorAction SilentlyContinue)) {
        Write-NetCleanLog -Level INFO -Message ("Phase Verify start: {0}" -f $t0.ToString('s'))
    }

    $ctx = Invoke-NetCleanPhase4Verify -Context $ctx

    if ($backupPathFromProtect -and -not ($ctx.PSObject.Properties.Name -contains 'BackupPath')) {
        Add-Member -InputObject $ctx -NotePropertyName BackupPath -NotePropertyValue $backupPathFromProtect -Force
    }

    $t1 = Get-Date
    if ($null -ne (Get-Command Write-NetCleanLog -ErrorAction SilentlyContinue)) {
        Write-NetCleanLog -Level INFO -Message ("Phase Verify end: {0} (duration: {1})" -f $t1.ToString('s'), ($t1 - $t0).ToString())
    }

    $timings.Verify = [pscustomobject]@{
        Start    = $t0
        End      = $t1
        Duration = ($t1 - $t0)
    }

    Add-Member -InputObject $ctx -NotePropertyName Timings -NotePropertyValue $timings -Force

    if ($null -ne (Get-Command Write-NetCleanLog -ErrorAction SilentlyContinue)) {
        Write-NetCleanLog -Level INFO -Message ('Workflow complete. Mode={0} DryRun={1}' -f $Mode, [bool]$DryRun)
    }

    if ($null -ne (Get-Command Write-NetCleanLog -ErrorAction SilentlyContinue)) {
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
    }

    return $ctx
}

# ---------------------------------------------------------------------------
# Compatibility wrappers
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
Builds a list of installed AV vendors.
.DESCRIPTION
Aggregates the names of installed antivirus vendors from the protection inventory.
.PARAMETER Inventory
Optionally specify an inventory to build from; if not provided, the current inventory will be retrieved.
.EXAMPLE
Get-InstalledAV
.OUTPUTS
A list of unique, non-empty strings representing installed AV vendors.
#>
function Get-InstalledAV {
    [CmdletBinding()]
    [OutputType([System.String[]])]
    param(
        [Parameter(Mandatory = $false)]
        [object[]]$Inventory
    )

    if ($PSBoundParameters.ContainsKey('Inventory')) { $inventory = @($Inventory) }
    else { $inventory = @(Get-ProtectionInventory) }

    if (@($inventory).Count -eq 0) { return [string[]]@() }

    $securityCategories = @('AV', 'EDR', 'XDR', 'Firewall')

    $results = foreach ($item in $inventory) {
        if (@($item.Categories) | Where-Object { $_ -in $securityCategories }) {
            $item.Vendor
        }
    }

    [string[]]$out = @(Get-UniqueNonEmptyString -InputObject $results)
    if (@($out).Count -eq 0) { return [string[]]@() }
    return $out
}


<#
.SYNOPSIS
Builds a list of service patterns for the specified AV vendors.
.DESCRIPTION
Aggregates service patterns from the protection inventory for the specified AV vendors.
.PARAMETER AvList
List of AV vendor names (case-insensitive, supports partial matches) to derive service patterns for.
.PARAMETER Inventory
Optionally specify an inventory to derive from; if not provided, the current inventory will be retrieved.
.EXAMPLE
Get-AVServicePattern -AvList @('Defender', 'Symantec')
.OUTPUTS
A list of unique, non-empty service patterns associated with the specified AV vendors.
#>
function Get-AVServicePattern {
    [CmdletBinding()]
    [OutputType([System.String[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$AvList,

        [Parameter(Mandatory = $false)]
        [object[]]$Inventory
    )

    if ($PSBoundParameters.ContainsKey('Inventory')) { $inventory = @($Inventory) }
    else { $inventory = @(Get-ProtectionInventory) }

    $patterns = New-Object System.Collections.Generic.List[string]

    foreach ($name in $AvList) {
        $nameLower = $name.ToLowerInvariant()
        foreach ($item in $inventory) {
            $vendorName = if ($null -ne $item.Vendor) { [string]$item.Vendor } else { '' }
            if ($vendorName -eq $name -or ($vendorName.ToLowerInvariant() -like "*$nameLower*")) {
                foreach ($svc in @($item.Services)) {
                    if ($svc) { [void]$patterns.Add($svc) }
                }
            }
        }
    }

    return Get-UniqueNonEmptyString -InputObject $patterns
}


<#
.SYNOPSIS
Builds a comprehensive protection list from the inventory.
.DESCRIPTION
Aggregates services, drivers, adapters and registry keys from the protection inventory into a deduplicated hashtable of lists.
.PARAMETER Inventory
Optionally specify an inventory to build from; if not provided, the current inventory will be retrieved.
.EXAMPLE
Get-ProtectionList
.OuTPUTS
A hashtable with keys 'Services', 'Drivers', 'Adapters' and 'Registry', each containing a list of unique, non-empty strings representing items to protect.
#>
function Get-ProtectionList {
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param(
        [Parameter(Mandatory = $false)]
        [object[]]$Inventory
    )

    if ($PSBoundParameters.ContainsKey('Inventory')) { $inventory = @($Inventory) }
    else { $inventory = @(Get-ProtectionInventory) }

    $services = New-Object System.Collections.Generic.List[string]
    $drivers = New-Object System.Collections.Generic.List[string]
    $adapters = New-Object System.Collections.Generic.List[string]
    $registryPaths = New-Object System.Collections.Generic.List[string]

    foreach ($item in $inventory) {
        foreach ($svc in @($item.Services)) { if ($svc) { [void]$services.Add($svc) } }
        foreach ($drv in @($item.Drivers)) { if ($drv) { [void]$drivers.Add($drv) } }
        foreach ($adp in @($item.Adapters)) { if ($adp) { [void]$adapters.Add($adp) } }
        foreach ($reg in @($item.RegistryKeys)) { if ($reg) { [void]$registryPaths.Add($reg) } }
    }

    return @{
        Services = @(Get-UniqueNonEmptyString -InputObject $services)
        Drivers  = @(Get-UniqueNonEmptyString -InputObject $drivers)
        Adapters = @(Get-UniqueNonEmptyString -InputObject $adapters)
        Registry = @(Get-UniqueNonEmptyString -InputObject $registryPaths)
    }
}

# ---------------------------------------------------------------------------
# Aliases
# ---------------------------------------------------------------------------

Set-Alias -Name Convert-NormalizeGuid        -Value Convert-Guid -Force
Set-Alias -Name Normalize-Guid               -Value Convert-Guid -Force
Set-Alias -Name Derive-AVServicePatterns     -Value Get-AVServicePattern -Force
Set-Alias -Name Build-ProtectionLists        -Value Get-ProtectionList -Force
Set-Alias -Name Backup-ProtectedRegistryKeys -Value Export-ProtectedRegistryKey -Force
Set-Alias -Name Backup-NetworkList           -Value Export-NetworkList -Force
Set-Alias -Name Backup-WiFiProfiles          -Value Export-WiFiProfile -Force
Set-Alias -Name Get-ProtectionLists          -Value Get-ProtectionList -Force
Set-Alias -Name Get-AVServicePatterns        -Value Get-AVServicePattern -Force
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
    'Start-NetCleanLog',
    'Write-NetCleanLog'
) -Alias @(
    'Backup-NetworkList',
    'Backup-ProtectedRegistryKeys',
    'Backup-WiFiProfiles'
)