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
            [Parameter(Mandatory=$true)]
            [scriptblock]$ScriptBlock,

            [Parameter(Mandatory=$true)]
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

                return ,$ps7Results
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

    ## Read human-friendly network profile names directly from the registry.
    function Get-NetworkListProfileNames {
        [CmdletBinding()]
        param()

        $root = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles'
        $names = New-Object System.Collections.Generic.List[string]
        try {
            if (Test-Path -LiteralPath $root) {
                $children = Get-ChildItem -Path $root -ErrorAction SilentlyContinue
                foreach ($c in $children) {
                    try {
                        $pn = Get-ItemProperty -Path $c.PSPath -Name 'ProfileName' -ErrorAction SilentlyContinue
                        if ($pn -and $pn.ProfileName) { [void]$names.Add($pn.ProfileName) }
                    }
                    catch { Write-Verbose "Get-NetworkListProfileNames child: $($_.Exception.Message)" }
                }
            }
        }
        catch { Write-Verbose "Get-NetworkListProfileNames: $($_.Exception.Message)" }

        return $names.ToArray() | Sort-Object -Unique
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
        [ValidateSet('INFO','WARN','ERROR','DEBUG','TRACE')]
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
        'WARN'  { Write-Warning $Message }
        'INFO'  { Write-Information $Message -InformationAction Continue }
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
        '^HKLM\\'               { return ('Registry::HKEY_LOCAL_MACHINE\' + $p.Substring(5)) }
        '^HKEY_LOCAL_MACHINE\\' { return ('Registry::' + $p) }
        '^HKCU\\'               { return ('Registry::HKEY_CURRENT_USER\' + $p.Substring(5)) }
        '^HKEY_CURRENT_USER\\'  { return ('Registry::' + $p) }
        '^HKCR\\'               { return ('Registry::HKEY_CLASSES_ROOT\' + $p.Substring(5)) }
        '^HKEY_CLASSES_ROOT\\'  { return ('Registry::' + $p) }
        '^HKU\\'                { return ('Registry::HKEY_USERS\' + $p.Substring(4)) }
        '^HKEY_USERS\\'         { return ('Registry::' + $p) }
        '^HKCC\\'               { return ('Registry::HKEY_CURRENT_CONFIG\' + $p.Substring(5)) }
        '^HKEY_CURRENT_CONFIG\\'{ return ('Registry::' + $p) }
        default                 { throw "Unsupported registry root in path '$RegistryPath'" }
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
    $afterSet  = @(Get-UniqueNonEmptyString -InputObject $After)

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
        'Microsoft'           = @('microsoft', 'windows defender', 'microsoft corporation', 'hyper-v')
        'VMware'              = @('vmware', 'vmware, inc')
        'VirtualBox'          = @('virtualbox', 'oracle virtualbox')
        'Parallels'           = @('parallels')
        'CrowdStrike'         = @('crowdstrike', 'falcon')
        'SentinelOne'         = @('sentinelone', 'sentinel')
        'Sophos'              = @('sophos')
        'Bitdefender'         = @('bitdefender')
        'Malwarebytes'        = @('malwarebytes', 'mbam')
        'Symantec'            = @('symantec', 'broadcom endpoint', 'sep')
        'Trellix/McAfee'      = @('trellix', 'mcafee', 'mfe')
        'Palo Alto Networks'  = @('palo alto', 'cortex', 'globalprotect', 'traps')
        'Cisco'               = @('cisco', 'anyconnect', 'secure client', 'umbrella', 'amp')
        'Zscaler'             = @('zscaler')
        'ESET'                = @('eset')
        'Trend Micro'         = @('trend micro', 'apex one')
        'Check Point'         = @('check point', 'capsule', 'snx')
        'Fortinet'            = @('fortinet', 'forticlient', 'fortiedr')
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
        'Microsoft' = @{
            Categories = @('AV', 'Firewall', 'Hypervisor', 'VirtualAdapter', 'NetworkFilter', 'EndpointAgent')
            Patterns   = @(
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
        'Bitdefender' = @{
            Categories = @('AV', 'Firewall', 'EndpointAgent', 'NetworkFilter')
            Patterns   = @('bitdefender', 'vsserv', 'bdservice', 'bdredline', 'bdc', 'epsecurityservice')
            RegistryRoots = @('HKLM\SOFTWARE\Bitdefender')
        }
        'Malwarebytes' = @{
            Categories = @('AV', 'EndpointAgent')
            Patterns   = @('malwarebytes', 'mbamservice', 'mbamprotector', 'mbam')
            RegistryRoots = @('HKLM\SOFTWARE\Malwarebytes')
        }
        'CrowdStrike' = @{
            Categories = @('EDR', 'XDR', 'EndpointAgent', 'NetworkFilter')
            Patterns   = @('crowdstrike', 'falcon', 'csfalconservice', 'csagent', 'crowdstrike falcon')
            RegistryRoots = @('HKLM\SOFTWARE\CrowdStrike')
        }
        'SentinelOne' = @{
            Categories = @('EDR', 'XDR', 'EndpointAgent', 'NetworkFilter')
            Patterns   = @('sentinelone', 'sentinelagent', 'sentinelctl', 'sentinel')
            RegistryRoots = @('HKLM\SOFTWARE\SentinelOne')
        }
        'Sophos' = @{
            Categories = @('AV', 'Firewall', 'EndpointAgent', 'NetworkFilter')
            Patterns   = @('sophos', 'savservice', 'sophos endpoint', 'hitmanpro', 'sntp')
            RegistryRoots = @('HKLM\SOFTWARE\Sophos')
        }
        'Symantec' = @{
            Categories = @('AV', 'EndpointAgent', 'Firewall')
            Patterns   = @('symantec', 'broadcom endpoint', 'sep', 'smc', 'symcorpui')
            RegistryRoots = @('HKLM\SOFTWARE\Symantec')
        }
        'Trellix/McAfee' = @{
            Categories = @('AV', 'EDR', 'Firewall', 'EndpointAgent', 'NetworkFilter')
            Patterns   = @('mcafee', 'trellix', 'mfe', 'ens', 'mfefire', 'mfewfpk')
            RegistryRoots = @('HKLM\SOFTWARE\McAfee', 'HKLM\SOFTWARE\Trellix')
        }
        'Palo Alto Networks' = @{
            Categories = @('EDR', 'XDR', 'Firewall', 'VPN', 'EndpointAgent', 'NetworkFilter')
            Patterns   = @('palo alto', 'cortex', 'globalprotect', 'traps', 'pangps', 'pangpd')
            RegistryRoots = @('HKLM\SOFTWARE\Palo Alto Networks')
        }
        'Cisco' = @{
            Categories = @('Firewall', 'VPN', 'EndpointAgent', 'NetworkFilter')
            Patterns   = @('cisco', 'anyconnect', 'secure client', 'amp', 'umbrella', 'ciscosecureclient')
            RegistryRoots = @('HKLM\SOFTWARE\Cisco')
        }
        'Zscaler' = @{
            Categories = @('Firewall', 'VPN', 'EndpointAgent', 'NetworkFilter')
            Patterns   = @('zscaler', 'zsa', 'zsatray', 'zscaler tunnel', 'zcc')
            RegistryRoots = @('HKLM\SOFTWARE\Zscaler')
        }
        'VMware' = @{
            Categories = @('Hypervisor', 'VirtualAdapter')
            Patterns   = @('vmware', 'vmnet', 'vmnat', 'vmwarehostd', 'vmx86', 'vmci', 'vmusb', 'vmware network adapter')
            RegistryRoots = @('HKLM\SOFTWARE\VMware, Inc.')
        }
        'VirtualBox' = @{
            Categories = @('Hypervisor', 'VirtualAdapter')
            Patterns   = @('virtualbox', 'oracle virtualbox', 'vbox', 'vboxnet', 'vboxdrv')
            RegistryRoots = @('HKLM\SOFTWARE\Oracle\VirtualBox')
        }
        'Parallels' = @{
            Categories = @('Hypervisor', 'VirtualAdapter')
            Patterns   = @('parallels', 'prl_', 'prl net', 'prl networking')
            RegistryRoots = @('HKLM\SOFTWARE\Parallels')
        }
        'ESET' = @{
            Categories = @('AV', 'EndpointAgent', 'Firewall', 'NetworkFilter')
            Patterns   = @('eset', 'ekrn', 'epfw', 'epfwlwf')
            RegistryRoots = @('HKLM\SOFTWARE\ESET')
        }
        'Trend Micro' = @{
            Categories = @('AV', 'EDR', 'EndpointAgent', 'NetworkFilter')
            Patterns   = @('trend micro', 'tmlisten', 'ntrtscan', 'ds_agent', 'apex one')
            RegistryRoots = @('HKLM\SOFTWARE\TrendMicro')
        }
        'Check Point' = @{
            Categories = @('Firewall', 'VPN', 'EndpointAgent', 'NetworkFilter')
            Patterns   = @('check point', 'endpoint security', 'tracsrvwrapper', 'snx', 'capsule')
            RegistryRoots = @('HKLM\SOFTWARE\CheckPoint')
        }
        'Fortinet' = @{
            Categories = @('Firewall', 'VPN', 'EndpointAgent', 'NetworkFilter')
            Patterns   = @('fortinet', 'forticlient', 'fortiedr', 'fortishield')
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

# ---------------------------------------------------------------------------
# Phase 1 - Detect helpers
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
Retrieves evidence of WFP (Windows Filtering Platform) state information.
.DESCRIPTION
Scans the WFP state to identify installed filter objects and extracts relevant properties. Attempts to infer the vendor based on known patterns.
.EXAMPLE
Get-WfpStateEvidence
.OUTPUTS
System.Object[] - A collection of custom objects representing WFP filter objects, including properties such as Name, DisplayName, Path, Publisher, and InferredVendor.
.NOTES
- Requires administrative privileges to access WFP state information.
#>
function Get-WfpStateEvidence {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param()

    $results = New-Object System.Collections.Generic.List[object]
    $tempFile = Join-Path $env:TEMP ("netclean_wfp_{0}.xml" -f ([guid]::NewGuid().Guid))

    try {
        & netsh wfp show state file="$tempFile" 2>$null | Out-Null

        if (-not (Test-Path -LiteralPath $tempFile)) {
            return @()
        }

        [xml]$xml = Get-Content -LiteralPath $tempFile -Raw -ErrorAction Stop
        $xmlNodes = @()

        if ($xml -and $xml.DocumentElement) {
                $xmlNodes = $xml.SelectNodes('//*')
        }

        foreach ($node in @($xmlNodes)) {
            $textParts = @()

            foreach ($prop in @('displayData', 'name', 'description', 'serviceName', 'providerKey', 'calloutKey', 'layerKey')) {
                try {
                    $value = $node.$prop
                    if ($value) {
                        $textParts += ($value | Out-String).Trim()
                    }
                }
                catch {
                    Write-Verbose "Failed to extract property '$prop' from WFP XML node: $_"
                }
            }

            $joined = ($textParts | Where-Object { $_ }) -join ' '
            if ([string]::IsNullOrWhiteSpace($joined)) {
                continue
            }

            $vendor = Resolve-VendorFromText -Text @($joined)

            $results.Add([pscustomobject]@{
                Source               = 'WFP'
                ProductClass         = 'WfpObject'
                Name                 = $joined
                DisplayName          = $joined
                Path                 = $null
                Publisher            = $null
                InstallPath          = $null
                InterfaceDescription = $null
                Manufacturer         = $null
                CompanyName          = $null
                FileDescription      = $null
                ProductName          = $null
                SignerSubject        = $null
                InferredVendor       = $vendor
                XmlNodeName          = $node.Name
                Instance             = $node.OuterXml
            })
        }
    }
    catch {
        Write-Verbose "Ignored error: $_"
    }
    finally {
        if (Test-Path -LiteralPath $tempFile) {
            Remove-Item -LiteralPath $tempFile -Force -ErrorAction SilentlyContinue
        }
    }

    return $results.ToArray() | Sort-Object Name -Unique
}

<#
.SYNOPSIS
Retrieves evidence of NDIS filter classes from the registry.
.DESCRIPTION
Scans the registry under the NDIS class keys to identify installed network filter classes. Extracts relevant properties and attempts to infer the vendor based on known patterns.
.EXAMPLE
Get-NdisFilterClassEvidence
.OUTPUTS
A collection of custom objects representing NDIS filter class evidence, including properties such as Name, DisplayName, Publisher, and InferredVendor.
.NOTES
- Requires administrative privileges for full access to registry keys.
#>
function Get-NdisFilterClassEvidence {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param()

    $results = New-Object 'System.Collections.Generic.List[object]'
    $classRoot = 'HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e974-e325-11ce-bfc1-08002be10318}'

    foreach ($child in @(Get-RegistryChildKeyNamesSafe -RegistryPath $classRoot)) {
        if ($child -notmatch '^\d{4}$') { continue }

        $path = "$classRoot\$child"
        $props = Get-RegistryValuesSafe -RegistryPath $path
        if ($null -eq $props) { continue }

        $text = New-Object 'System.Collections.Generic.List[string]'

        foreach ($propertyName in @(
            'ComponentId',
            'DriverDesc',
            'ProviderName',
            'MatchingDeviceId',
            'FilterClass',
            'Characteristic'
        )) {
            if ($props.PSObject.Properties.Name -contains $propertyName) {
                $value = $props.$propertyName
                if ($null -ne $value -and -not [string]::IsNullOrWhiteSpace([string]$value)) {
                    $text.Add([string]$value)
                }
            }
        }

        if ($text.Count -eq 0) { continue }

        $driverDesc   = if ($props.PSObject.Properties.Name -contains 'DriverDesc')   { $props.DriverDesc }   else { $null }
        $providerName = if ($props.PSObject.Properties.Name -contains 'ProviderName') { $props.ProviderName } else { $null }
        $componentId  = if ($props.PSObject.Properties.Name -contains 'ComponentId')  { $props.ComponentId }  else { $null }

        $vendor = Resolve-VendorFromText -Text $text.ToArray()

        $results.Add([pscustomobject]@{
            Source               = 'NDIS'
            ProductClass         = 'NdisFilterClass'
            Name                 = ($text.ToArray() -join ' | ')
            DisplayName          = $driverDesc
            Path                 = $null
            Publisher            = $providerName
            InstallPath          = $null
            InterfaceDescription = $driverDesc
            Manufacturer         = $providerName
            CompanyName          = $providerName
            FileDescription      = $driverDesc
            ProductName          = $componentId
            SignerSubject        = $null
            InferredVendor       = $vendor
            RegistryPath         = $path
            ComponentId          = $componentId
            Instance             = $props
        })
    }

    return $results.ToArray()
}

<#
.SYNOPSIS
Retrieves evidence of NDIS service bindings from the registry.
.DESCRIPTION
Scans the registry under the Services key to identify services that may be related to NDIS bindings. Extracts relevant properties and attempts to infer the vendor based on known patterns.
.EXAMPLE
Get-NdisServiceBindingEvidence
.OUTPUTS
System.Object[] - A collection of custom objects representing NDIS service bindings, including properties such as Name, DisplayName, Path, Publisher, and InferredVendor.
.NOTES
- Requires administrative privileges for full access to registry keys.
#>
function Get-NdisServiceBindingEvidence {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param()

    $results = New-Object System.Collections.Generic.List[object]
    $servicesRoot = 'HKLM\SYSTEM\CurrentControlSet\Services'

    foreach ($svcName in @(Get-RegistryChildKeyNamesSafe -RegistryPath $servicesRoot)) {
        $svcPath = "$servicesRoot\$svcName"
        $linkage = Get-RegistryValuesSafe -RegistryPath "$svcPath\Linkage"
        $props   = Get-RegistryValuesSafe -RegistryPath $svcPath

        $tokens = New-Object System.Collections.Generic.List[string]
        $tokens.Add([string]$svcName)

        $displayName = $null
        $group       = $null
        $imagePath   = $null
        $bindValues  = @()
        $exportValues = @()
        $routeValues  = @()

        if ($null -ne $props) {
            if ($props.PSObject.Properties.Name -contains 'DisplayName') {
                $displayName = $props.DisplayName
                if ($null -ne $displayName -and "$displayName".Trim() -ne '') {
                    $tokens.Add([string]$displayName)
                }
            }

            if ($props.PSObject.Properties.Name -contains 'Group') {
                $group = $props.Group
                if ($null -ne $group -and "$group".Trim() -ne '') {
                    $tokens.Add([string]$group)
                }
            }

            if ($props.PSObject.Properties.Name -contains 'ImagePath') {
                $imagePath = $props.ImagePath
            }
        }

        if ($null -ne $linkage) {
            if ($linkage.PSObject.Properties.Name -contains 'Bind') {
                $bindValues = @($linkage.Bind)
                foreach ($value in $bindValues) {
                    if ($null -ne $value -and "$value".Trim() -ne '') {
                        $tokens.Add([string]$value)
                    }
                }
            }

            if ($linkage.PSObject.Properties.Name -contains 'Export') {
                $exportValues = @($linkage.Export)
                foreach ($value in $exportValues) {
                    if ($null -ne $value -and "$value".Trim() -ne '') {
                        $tokens.Add([string]$value)
                    }
                }
            }

            if ($linkage.PSObject.Properties.Name -contains 'Route') {
                $routeValues = @($linkage.Route)
                foreach ($value in $routeValues) {
                    if ($null -ne $value -and "$value".Trim() -ne '') {
                        $tokens.Add([string]$value)
                    }
                }
            }
        }

        $tokenArray = @($tokens | Where-Object { $null -ne $_ -and "$_".Trim() -ne '' })
        if ($tokenArray.Count -eq 0) { continue }

        $joined = ($tokenArray | ForEach-Object { $_.ToString() }) -join ' '
        $vendor = Resolve-VendorFromText -Text @($joined)

        if ($joined.ToLowerInvariant() -match 'ndis|filter|lwf|wfp|vpn|fw|firewall|net|vmswitch|vmnet|vbox|vethernet|packet|inspect|falcon|sentinel|zscaler|globalprotect|forti|anyconnect') {
            $results.Add([pscustomobject]@{
                Source               = 'NDIS'
                ProductClass         = 'NdisServiceBinding'
                Name                 = $svcName
                DisplayName          = if ($null -ne $displayName -and "$displayName".Trim() -ne '') { $displayName } else { $svcName }
                Path                 = $imagePath
                Publisher            = $null
                InstallPath          = $null
                InterfaceDescription = $null
                Manufacturer         = $null
                CompanyName          = $null
                FileDescription      = $null
                ProductName          = $null
                SignerSubject        = $null
                InferredVendor       = $vendor
                RegistryPath         = $svcPath
                Instance             = [pscustomobject]@{
                    Service = $props
                    Linkage = $linkage
                }
            })
        }
    }

    return $results.ToArray()
}

<#
.SYNOPSIS
Retrieves evidence of installed MSI products from the registry.
.DESCRIPTION
Scans the registry under the MSI product keys to identify installed products. Extracts relevant properties such as DisplayName, Publisher, and InstallLocation. Attempts to infer the vendor based on these properties and known patterns.
.EXAMPLE
Get-MsiRegistryEvidence
.OUTPUTS
System.Object[] - A collection of custom objects representing installed MSI products, including properties such as Name
.NOTES
Requires appropriate permissions to access the registry keys for installed MSI products.
#>
function Get-MsiRegistryEvidence {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param()

    $results = New-Object 'System.Collections.Generic.List[object]'

    foreach ($root in @(
        'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products',
        'HKLM\SOFTWARE\Classes\Installer\Products'
    )) {
        foreach ($child in @(Get-RegistryChildKeyNamesSafe -RegistryPath $root)) {
            $productPath = "$root\$child\InstallProperties"
            $props = Get-RegistryValuesSafe -RegistryPath $productPath
            if ($null -eq $props) { continue }

            $displayName = if ($props.PSObject.Properties.Name -contains 'DisplayName') {
                $props.DisplayName
            } else {
                $null
            }

            if ([string]::IsNullOrWhiteSpace([string]$displayName)) { continue }

            $publisher = if ($props.PSObject.Properties.Name -contains 'Publisher') {
                $props.Publisher
            } else {
                $null
            }

            $installLocation = if ($props.PSObject.Properties.Name -contains 'InstallLocation') {
                $props.InstallLocation
            } else {
                $null
            }

            $uninstallString = if ($props.PSObject.Properties.Name -contains 'UninstallString') {
                $props.UninstallString
            } else {
                $null
            }

            $vendorText = New-Object 'System.Collections.Generic.List[string]'
            foreach ($value in @($displayName, $publisher, $installLocation, $uninstallString)) {
                if ($null -ne $value -and -not [string]::IsNullOrWhiteSpace([string]$value)) {
                    $vendorText.Add([string]$value)
                }
            }

            $vendor = Resolve-VendorFromText -Text $vendorText.ToArray()

            $results.Add([pscustomobject]@{
                Source               = 'MSI'
                ProductClass         = 'MsiProduct'
                Name                 = $displayName
                DisplayName          = $displayName
                Path                 = $null
                Publisher            = $publisher
                InstallPath          = $installLocation
                InterfaceDescription = $null
                Manufacturer         = $publisher
                CompanyName          = $publisher
                FileDescription      = $null
                ProductName          = $displayName
                SignerSubject        = $null
                InferredVendor       = $vendor
                RegistryPath         = $productPath
                Instance             = $props
            })
        }
    }

    return $results.ToArray() | Sort-Object Name -Unique
}


<#
.SYNOPSIS
Retrieves evidence of network-related INF files from the system.
.DESCRIPTION
Scans the Windows INF directory for files matching the pattern 'oem*.inf'. Extracts relevant properties such as Provider, Manufacturer, Class, and ClassGuid. Attempts to infer the vendor based on these properties and known patterns.
.EXAMPLE
Get-InfFileEvidence
.OUTPUTS
System.Object[] - A collection of custom objects representing network-related INF files, including properties such as Name, DisplayName, Path, Publisher, and InferredVendor.
.NOTES
Requires appropriate permissions to access the INF directory and read INF files.
#>
function Get-InfFileEvidence {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param()

    $results = New-Object System.Collections.Generic.List[object]
    $infDirs = @("$env:windir\INF")

    foreach ($dir in $infDirs) {
        if (-not (Test-Path -LiteralPath $dir)) { continue }

        foreach ($file in @(Get-ChildItem -LiteralPath $dir -Filter 'oem*.inf' -File -ErrorAction SilentlyContinue)) {
            try {
                $content = Get-Content -LiteralPath $file.FullName -ErrorAction Stop

                $provider = $null
                $manufacturer = $null
                $class = $null
                $classGuid = $null

                foreach ($line in $content) {
                    $m = [regex]::Match($line, '^\s*Provider\s*=\s*(.+)$')
                    if (-not $provider -and $m.Success) {
                        $provider = $m.Groups[1].Value.Trim().Trim('"').Trim('%')
                    }

                    $m = [regex]::Match($line, '^\s*Manufacturer\s*=\s*(.+)$')
                    if (-not $manufacturer -and $m.Success) {
                        $manufacturer = $m.Groups[1].Value.Trim().Trim('"').Trim('%')
                    }

                    $m = [regex]::Match($line, '^\s*Class\s*=\s*(.+)$')
                    if (-not $class -and $m.Success) {
                        $class = $m.Groups[1].Value.Trim().Trim('"')
                    }

                    $m = [regex]::Match($line, '^\s*ClassGuid\s*=\s*(.+)$')
                    if (-not $classGuid -and $m.Success) {
                        $classGuid = $m.Groups[1].Value.Trim().Trim('"')
                    }

                    if ($provider -and $manufacturer -and $class -and $classGuid) {
                        break
                    }
                }

                $vendor = Resolve-VendorFromText -Text @($provider, $manufacturer, $class, $file.Name)

                if ($vendor -or ($class -and $class -match 'Net|NetService')) {
                    $results.Add([pscustomobject]@{
                        Source               = 'INF'
                        ProductClass         = 'SetupApiInf'
                        Name                 = $file.Name
                        DisplayName          = $file.Name
                        Path                 = $file.FullName
                        Publisher            = $provider
                        InstallPath          = Split-Path -Path $file.FullName -Parent
                        InterfaceDescription = $null
                        Manufacturer         = $manufacturer
                        CompanyName          = $provider
                        FileDescription      = $class
                        ProductName          = $file.Name
                        SignerSubject        = $null
                        InferredVendor       = $vendor
                        Class                = $class
                        ClassGuid            = $classGuid
                        Instance             = $null
                    })
                }
            }
            catch {
                Write-Verbose "Ignored error: $_"
            }
        }
    }

    return $results.ToArray()
}

<#
.SYNOPSIS
Retrieves evidence of scheduled tasks from the system.
.DESCRIPTION
Queries the system for scheduled tasks and extracts relevant properties. Attempts to infer the vendor based on known patterns in task names, paths, and actions.
.EXAMPLE
Get-ScheduledTaskEvidence
.OUTPUTS
System.Object[] - A collection of custom objects representing scheduled tasks, including properties such as Name, DisplayName, Path, Publisher, and InferredVendor.
.NOTES
- Requires appropriate permissions to access scheduled task information.
#>
function Get-ScheduledTaskEvidence {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param()

    $results = New-Object System.Collections.Generic.List[object]

    try {
        $tasks = Get-ScheduledTask -ErrorAction Stop
        foreach ($task in $tasks) {
            $actions = @($task.Actions)
            $actionText = @()

            foreach ($action in $actions) {
                $actionText += $action.Execute
                $actionText += $action.Arguments
                $actionText += $action.WorkingDirectory
            }

            $vendor = Resolve-VendorFromText -Text @(
                $task.TaskName,
                $task.TaskPath,
                $actionText
            )

            if ($vendor) {
                $results.Add([pscustomobject]@{
                    Source               = 'ScheduledTask'
                    ProductClass         = 'ScheduledTask'
                    Name                 = $task.TaskName
                    DisplayName          = $task.TaskName
                    Path                 = ($actionText -join ' ')
                    Publisher            = $null
                    InstallPath          = $null
                    InterfaceDescription = $null
                    Manufacturer         = $null
                    CompanyName          = $null
                    FileDescription      = $null
                    ProductName          = $task.TaskName
                    SignerSubject        = $null
                    InferredVendor       = $vendor
                    TaskPath             = $task.TaskPath
                    Instance             = $task
                })
            }
        }
    }
    catch {
        Write-Verbose "Ignored error: $_"
    }

    return $results.ToArray()
}

<#
.SYNOPSIS
Retrieves evidence of AppX packages from the system.
.DESCRIPTION
Queries the system for installed AppX packages and extracts relevant properties. Attempts to infer the vendor based on known patterns.
.EXAMPLE
Get-AppxPackageEvidence
.OUTPUTS
System.Object[] - A collection of custom objects representing AppX packages, including properties such as Name, DisplayName, Path, Publisher, and InferredVendor.
.NOTES
- Requires appropriate permissions to access AppX package information for all users.
#>
function Get-AppxPackageEvidence {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param()

    $results = New-Object System.Collections.Generic.List[object]

    try {
        $packages = Get-AppxPackage -AllUsers -ErrorAction Stop
        foreach ($pkg in $packages) {
            $vendor = Resolve-VendorFromText -Text @(
                $pkg.Name,
                $pkg.PackageFamilyName,
                $pkg.PublisherDisplayName,
                $pkg.InstallLocation
            )

            if ($vendor) {
                $results.Add([pscustomobject]@{
                    Source               = 'AppX'
                    ProductClass         = 'AppxPackage'
                    Name                 = $pkg.Name
                    DisplayName          = $pkg.Name
                    Path                 = $pkg.InstallLocation
                    Publisher            = $pkg.PublisherDisplayName
                    InstallPath          = $pkg.InstallLocation
                    InterfaceDescription = $null
                    Manufacturer         = $pkg.PublisherDisplayName
                    CompanyName          = $pkg.PublisherDisplayName
                    FileDescription      = $null
                    ProductName          = $pkg.Name
                    SignerSubject        = $pkg.Publisher
                    InferredVendor       = $vendor
                    PackageFamilyName    = $pkg.PackageFamilyName
                    Instance             = $pkg
                })
            }
        }
    }
    catch {
        Write-Verbose "Ignored error: $_"
    }

    return $results.ToArray()
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
                    Path            = $resolvedPath
                    Exists          = $false
                    CompanyName     = $null
                    FileDescription = $null
                    ProductName     = $null
                    OriginalName    = $null
                    FileVersion     = $null
                    SignerSubject   = $null
                    SignerIssuer    = $null
                    SignerThumbprint= $null
                    SignatureStatus = $null
                    InferredVendor  = $null
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

<#
.SYNOPSIS
Retrieves evidence of antivirus and firewall products from the Security Center WMI namespace.
.DESCRIPTION
Queries the 'root/SecurityCenter2' WMI namespace for instances of 'AntivirusProduct' and 'FirewallProduct'. For each product found, extracts relevant properties and attempts to infer the vendor based on known patterns. Also retrieves file metadata for the product executable to enrich the evidence.
.EXAMPLE
Get-ProtectionEvidence
.OUTPUTS
System.Object[] - A collection of custom objects representing antivirus and firewall products, including properties such as Name, DisplayName, Path, Publisher, and InferredVendor.
.NOTES
- Requires administrative privileges to access the 'root/SecurityCenter2' WMI namespace.
#>
function Get-ProtectionEvidence {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param()

    $evidence = New-Object System.Collections.Generic.List[object]

    try {
        $avProducts = Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName 'AntivirusProduct' -ErrorAction Stop
        foreach ($item in $avProducts) {
            $meta = Get-FileMetadatum -Path $item.pathToSignedProductExe
            $evidence.Add([pscustomobject]@{
                Source               = 'SecurityCenter2'
                ProductClass         = 'AntivirusProduct'
                Name                 = $item.displayName
                DisplayName          = $item.displayName
                Path                 = $item.pathToSignedProductExe
                Publisher            = if ($meta) { $meta.CompanyName } else { $null }
                InstallPath          = $null
                InterfaceDescription = $null
                Manufacturer         = $null
                CompanyName          = if ($meta) { $meta.CompanyName } else { $null }
                FileDescription      = if ($meta) { $meta.FileDescription } else { $null }
                ProductName          = if ($meta) { $meta.ProductName } else { $null }
                SignerSubject        = if ($meta) { $meta.SignerSubject } else { $null }
                InferredVendor       = if ($meta) { $meta.InferredVendor } else { (Resolve-VendorFromText -Text @($item.displayName)) }
                Instance             = $item
            })
        }
    }
    catch {
        Write-Verbose "Ignored error: $_"
    }

    try {
        $fwProducts = Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName 'FirewallProduct' -ErrorAction Stop
        foreach ($item in $fwProducts) {
            $meta = Get-FileMetadatum -Path $item.pathToSignedProductExe
            $evidence.Add([pscustomobject]@{
                Source               = 'SecurityCenter2'
                ProductClass         = 'FirewallProduct'
                Name                 = $item.displayName
                DisplayName          = $item.displayName
                Path                 = $item.pathToSignedProductExe
                Publisher            = if ($meta) { $meta.CompanyName } else { $null }
                InstallPath          = $null
                InterfaceDescription = $null
                Manufacturer         = $null
                CompanyName          = if ($meta) { $meta.CompanyName } else { $null }
                FileDescription      = if ($meta) { $meta.FileDescription } else { $null }
                ProductName          = if ($meta) { $meta.ProductName } else { $null }
                SignerSubject        = if ($meta) { $meta.SignerSubject } else { $null }
                InferredVendor       = if ($meta) { $meta.InferredVendor } else { (Resolve-VendorFromText -Text @($item.displayName)) }
                Instance             = $item
            })
        }
    }
    catch {
        Write-Verbose "Ignored error: $_"
    }

    try {
        $services = Get-CimInstance Win32_Service -ErrorAction Stop
        foreach ($svc in $services) {
            $meta = Get-FileMetadatum -Path $svc.PathName
            $evidence.Add([pscustomobject]@{
                Source               = 'Service'
                ProductClass         = 'Service'
                Name                 = $svc.Name
                DisplayName          = $svc.DisplayName
                Path                 = $svc.PathName
                Publisher            = if ($meta) { $meta.CompanyName } else { $null }
                InstallPath          = $null
                InterfaceDescription = $null
                Manufacturer         = $null
                CompanyName          = if ($meta) { $meta.CompanyName } else { $null }
                FileDescription      = if ($meta) { $meta.FileDescription } else { $null }
                ProductName          = if ($meta) { $meta.ProductName } else { $null }
                SignerSubject        = if ($meta) { $meta.SignerSubject } else { $null }
                InferredVendor       = if ($meta) { $meta.InferredVendor } else { (Resolve-VendorFromText -Text @($svc.Name, $svc.DisplayName, $svc.PathName)) }
                State                = $svc.State
                StartMode            = $svc.StartMode
                ServiceType          = $svc.ServiceType
                Instance             = $svc
            })
        }
    }
    catch {
        Write-Verbose "Ignored error: $_"
    }

    try {
        $drivers = Get-CimInstance Win32_SystemDriver -ErrorAction Stop
        foreach ($drv in $drivers) {
            $meta = Get-FileMetadatum -Path $drv.PathName
            $evidence.Add([pscustomobject]@{
                Source               = 'Driver'
                ProductClass         = 'Driver'
                Name                 = $drv.Name
                DisplayName          = $drv.DisplayName
                Path                 = $drv.PathName
                Publisher            = if ($meta) { $meta.CompanyName } else { $null }
                InstallPath          = $null
                InterfaceDescription = $null
                Manufacturer         = $null
                CompanyName          = if ($meta) { $meta.CompanyName } else { $null }
                FileDescription      = if ($meta) { $meta.FileDescription } else { $null }
                ProductName          = if ($meta) { $meta.ProductName } else { $null }
                SignerSubject        = if ($meta) { $meta.SignerSubject } else { $null }
                InferredVendor       = if ($meta) { $meta.InferredVendor } else { (Resolve-VendorFromText -Text @($drv.Name, $drv.DisplayName, $drv.PathName)) }
                State                = $drv.State
                StartMode            = $drv.StartMode
                ServiceType          = $drv.ServiceType
                Instance             = $drv
            })
        }
    }
    catch {
        Write-Verbose "Ignored error: $_"
    }

    foreach ($root in @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )) {
        try {
            Get-ItemProperty -Path $root -ErrorAction SilentlyContinue | ForEach-Object {
                if ($_.DisplayName) {
                    $meta = $null
                    if ($_.DisplayIcon) {
                        $meta = Get-FileMetadatum -Path $_.DisplayIcon
                    }

                    $evidence.Add([pscustomobject]@{
                        Source               = 'Uninstall'
                        ProductClass         = 'InstalledProduct'
                        Name                 = $_.DisplayName
                        DisplayName          = $_.DisplayName
                        Path                 = $_.DisplayIcon
                        Publisher            = $_.Publisher
                        InstallPath          = $_.InstallLocation
                        InterfaceDescription = $null
                        Manufacturer         = $_.Publisher
                        CompanyName          = if ($meta) { $meta.CompanyName } else { $_.Publisher }
                        FileDescription      = if ($meta) { $meta.FileDescription } else { $null }
                        ProductName          = if ($meta) { $meta.ProductName } else { $_.DisplayName }
                        SignerSubject        = if ($meta) { $meta.SignerSubject } else { $null }
                        InferredVendor       = if ($meta -and $meta.InferredVendor) { $meta.InferredVendor } else { (Resolve-VendorFromText -Text @($_.DisplayName, $_.Publisher, $_.InstallLocation, $_.UninstallString)) }
                        UninstallString      = $_.UninstallString
                        Instance             = $_
                    })
                }
            }
        }
        catch {
            Write-Verbose "Ignored error: $_"
        }
    }

    try {
        $adapters = Get-NetAdapter -IncludeHidden -ErrorAction Stop
        foreach ($adapter in $adapters) {
            $vendor = Resolve-VendorFromText -Text @(
                $adapter.Name,
                $adapter.InterfaceDescription,
                $adapter.DriverDescription,
                $adapter.DriverFileName
            )

            $guidValue = $null
            try {
                $guidValue = $adapter.InterfaceGuid.Guid.ToString().ToLowerInvariant()
            }
            catch {
                try {
                    $guidValue = $adapter.InterfaceGuid.ToString().Trim('{}').ToLowerInvariant()
                }
                catch {
                    $guidValue = $null
                }
            }

            $evidence.Add([pscustomobject]@{
                Source               = 'NetAdapter'
                ProductClass         = 'Adapter'
                Name                 = $adapter.Name
                DisplayName          = $adapter.Name
                Path                 = $null
                Publisher            = $null
                InstallPath          = $null
                InterfaceDescription = $adapter.InterfaceDescription
                Manufacturer         = $null
                CompanyName          = $null
                FileDescription      = $null
                ProductName          = $adapter.InterfaceDescription
                SignerSubject        = $null
                InferredVendor       = $vendor
                InterfaceGuid        = $guidValue
                MacAddress           = $adapter.MacAddress
                Status               = $adapter.Status
                Instance             = $adapter
            })
        }
    }
    catch {
        Write-Verbose "Ignored error: $_"
    }

    try {
        $pnpNet = Get-PnpDevice -Class Net -ErrorAction Stop
        foreach ($dev in $pnpNet) {
            $vendor = Resolve-VendorFromText -Text @(
                $dev.FriendlyName,
                $dev.Manufacturer,
                $dev.InstanceId
            )

            $evidence.Add([pscustomobject]@{
                Source               = 'PnpDevice'
                ProductClass         = 'NetDevice'
                Name                 = $dev.FriendlyName
                DisplayName          = $dev.FriendlyName
                Path                 = $null
                Publisher            = $null
                InstallPath          = $null
                InterfaceDescription = $dev.FriendlyName
                Manufacturer         = $dev.Manufacturer
                CompanyName          = $dev.Manufacturer
                FileDescription      = $null
                ProductName          = $dev.FriendlyName
                SignerSubject        = $null
                InferredVendor       = $vendor
                InstanceId           = $dev.InstanceId
                Status               = $dev.Status
                Class                = $dev.Class
                Instance             = $dev
            })
        }
    }
    catch {
        Write-Verbose "Ignored error: $_"
    }

    $servicesRoot = 'HKLM\SYSTEM\CurrentControlSet\Services'
    try {
        foreach ($svcName in @(Get-RegistryChildKeyNamesSafe -RegistryPath $servicesRoot)) {
            $svcRegPath = "$servicesRoot\$svcName"
            $svcProps = Get-RegistryValuesSafe -RegistryPath $svcRegPath
            if ($null -eq $svcProps) { continue }

            $imagePath = $svcProps.ImagePath
            $displayName = $svcProps.DisplayName
            $meta = Get-FileMetadatum -Path $imagePath

            $evidence.Add([pscustomobject]@{
                Source               = 'ServiceRegistry'
                ProductClass         = 'ServiceRegistry'
                Name                 = $svcName
                DisplayName          = $displayName
                Path                 = $imagePath
                Publisher            = if ($meta) { $meta.CompanyName } else { $null }
                InstallPath          = $null
                InterfaceDescription = $null
                Manufacturer         = $null
                CompanyName          = if ($meta) { $meta.CompanyName } else { $null }
                FileDescription      = if ($meta) { $meta.FileDescription } else { $null }
                ProductName          = if ($meta) { $meta.ProductName } else { $null }
                SignerSubject        = if ($meta) { $meta.SignerSubject } else { $null }
                InferredVendor       = if ($meta -and $meta.InferredVendor) { $meta.InferredVendor } else { (Resolve-VendorFromText -Text @($svcName, $displayName, $imagePath)) }
                ServiceRegistryPath  = $svcRegPath
                Start                = $svcProps.Start
                Type                 = $svcProps.Type
                Group                = $svcProps.Group
                Instance             = $svcProps
            })
        }
    }
    catch {
        Write-Verbose "Ignored error: $_"
    }

    foreach ($item in @(Get-WfpStateEvidence))           { $evidence.Add($item) }
    foreach ($item in @(Get-NdisFilterClassEvidence))    { $evidence.Add($item) }
    foreach ($item in @(Get-NdisServiceBindingEvidence)) { $evidence.Add($item) }
    foreach ($item in @(Get-MsiRegistryEvidence))        { $evidence.Add($item) }
    foreach ($item in @(Get-InfFileEvidence))            { $evidence.Add($item) }
    foreach ($item in @(Get-ScheduledTaskEvidence))      { $evidence.Add($item) }
    foreach ($item in @(Get-AppxPackageEvidence))        { $evidence.Add($item) }

    return $evidence.ToArray()
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

            if (Test-RegistryPathExist -RegistryPath $candidateNetwork)   { $networkPath = $candidateNetwork }
            if (Test-RegistryPathExist -RegistryPath $candidateConnection){ $connectionPath = $candidateConnection }
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

<#
.SYNOPSIS
Exports specified registry keys to .reg files in a provider-safe manner.
.DESCRIPTION
For each registry path provided, performs an export using `reg.exe` to ensure provider safety. Exports are saved to the specified destination directory with timestamped filenames. If `-DryRun` is specified, simulates the export process and returns the intended file paths without performing any exports.
.EXAMPLE
Export-RegistryKeys -RegistryPaths @('HKLM\SYSTEM\CurrentControlSet\Services\MyService', 'HKLM\SYSTEM\CurrentControlSet\Services\AnotherService') -DestinationPath 'C:\RegistryExports'
.EXAMPLE
Export-RegistryKeys -RegistryPaths @('HKLM\SYSTEM\CurrentControlSet\Services\MyService') -DestinationPath 'C:\RegistryExports' -DryRun
.OUTPUTS
System.String[]
.NOTES
This function relies on `reg.exe` for exporting registry keys, which ensures that the export process is provider-safe. The exported .reg files can be used for backup, analysis, or transfer to another system.
#>
function Get-ProtectionInventory {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param()

    $evidence = @(Get-ProtectionEvidence)
    $signatures = Get-VendorSignature
    $serviceMap = Get-ServiceRegistryMap
    $adapterCorrelation = @(Get-AdapterRegistryCorrelation)
    $inventory = New-Object System.Collections.Generic.List[object]

    foreach ($vendor in $signatures.Keys) {
        $signature = $signatures[$vendor]
        $matched = New-Object System.Collections.Generic.List[object]

        foreach ($item in $evidence) {
            if (Test-VendorPatternMatch -Vendor $vendor -Signature $signature -Evidence $item) {
                $matched.Add($item)
            }
        }

        if ($matched.Count -eq 0) {
            continue
        }

        $services = New-Object System.Collections.Generic.HashSet[string]
        $drivers = New-Object System.Collections.Generic.HashSet[string]
        $adapters = New-Object System.Collections.Generic.HashSet[string]
        $adapterGuids = New-Object System.Collections.Generic.HashSet[string]
        $registryKeys = New-Object System.Collections.Generic.HashSet[string]
        $evidenceStrings = New-Object System.Collections.Generic.HashSet[string]
        $categories = New-Object System.Collections.Generic.HashSet[string]

        Add-HashSetValue -Set $categories -Values $signature.Categories
        Add-HashSetValue -Set $registryKeys -Values $signature.RegistryRoots

        foreach ($item in $matched) {
            if ($item.Source -in @('Service', 'ServiceRegistry', 'NDIS')) {
                if ($item.Name) {
                    [void]$services.Add($item.Name)
                    [void]$registryKeys.Add("HKLM\SYSTEM\CurrentControlSet\Services\$($item.Name)")
                }
                if ($item.PSObject.Properties.Name -contains 'RegistryPath' -and $item.RegistryPath) {
                    [void]$registryKeys.Add($item.RegistryPath)
                }
            }

            if ($item.Source -eq 'Driver') {
                if ($item.Name) {
                    [void]$drivers.Add($item.Name)
                    [void]$registryKeys.Add("HKLM\SYSTEM\CurrentControlSet\Services\$($item.Name)")
                }
            }

            if ($item.Source -in @('NetAdapter', 'PnpDevice')) {
                if ($item.DisplayName)          { [void]$adapters.Add($item.DisplayName) }
                if ($item.InterfaceDescription) { [void]$adapters.Add($item.InterfaceDescription) }
                if ($item.PSObject.Properties.Name -contains 'InterfaceGuid' -and $item.InterfaceGuid) {
                    [void]$adapterGuids.Add($item.InterfaceGuid)
                }
            }

            if ($item.PSObject.Properties.Name -contains 'InstallPath') {
                Add-HashSetValue -Set $registryKeys -Values (Get-VendorRootsFromInstallPath -InstallPath $item.InstallPath)
            }

            $label = @(
                $item.Source,
                $item.Name,
                $item.DisplayName,
                $item.Path,
                $item.InterfaceDescription,
                $item.CompanyName,
                $item.InferredVendor
            ) | Where-Object { $_ } | Select-Object -First 5

            if ($label.Count -gt 0) {
                [void]$evidenceStrings.Add(($label -join ' | '))
            }
        }

        foreach ($svc in @($services)) {
            $key = $svc.ToLowerInvariant()
            if ($serviceMap.ContainsKey($key)) {
                $svcInfo = $serviceMap[$key]

                foreach ($candidate in @(
                    $svcInfo.RegistryPath,
                    $svcInfo.EnumPath,
                    $svcInfo.LinkagePath,
                    $svcInfo.ParamsPath,
                    $svcInfo.InstancesPath
                )) {
                    if (-not [string]::IsNullOrWhiteSpace($candidate)) {
                        [void]$registryKeys.Add($candidate)
                    }
                }

                $imgMeta = Get-FileMetadatum -Path $svcInfo.ImagePath
                if ($imgMeta -and $imgMeta.Path) {
                    [void]$evidenceStrings.Add("ServiceBinary: $($imgMeta.Path)")
                }
            }
        }

        foreach ($drv in @($drivers)) {
            $key = $drv.ToLowerInvariant()
            if ($serviceMap.ContainsKey($key)) {
                $drvInfo = $serviceMap[$key]
                foreach ($candidate in @(
                    $drvInfo.RegistryPath,
                    $drvInfo.EnumPath,
                    $drvInfo.LinkagePath,
                    $drvInfo.ParamsPath,
                    $drvInfo.InstancesPath
                )) {
                    if (-not [string]::IsNullOrWhiteSpace($candidate)) {
                        [void]$registryKeys.Add($candidate)
                    }
                }
            }
        }

        foreach ($corr in $adapterCorrelation) {
            $adapterText = @(
                $corr.ComponentId,
                $corr.DriverDesc,
                $corr.ProviderName
            ) -join ' '

            $adapterText = $adapterText.ToLowerInvariant()
            $matchedByAdapter = $false

            foreach ($pattern in $signature.Patterns) {
                if ($adapterText -like "*$pattern*") {
                    $matchedByAdapter = $true
                    break
                }
            }

            if ($matchedByAdapter) {
                if ($corr.InterfaceGuid) { [void]$adapterGuids.Add($corr.InterfaceGuid) }

                foreach ($candidate in @($corr.ClassPath, $corr.NetworkPath, $corr.ConnectionPath, $corr.TcpipPath)) {
                    if (-not [string]::IsNullOrWhiteSpace($candidate)) {
                        [void]$registryKeys.Add($candidate)
                    }
                }

                if ($corr.DriverDesc)   { [void]$adapters.Add($corr.DriverDesc) }
                if ($corr.ProviderName) { [void]$evidenceStrings.Add("AdapterProvider: $($corr.ProviderName)") }
            }
        }

        foreach ($svc in @($services)) {
            $svcl = $svc.ToLowerInvariant()
            switch -Wildcard ($svcl) {
                'vm*'         { [void]$categories.Add('VirtualAdapter'); [void]$categories.Add('Hypervisor') }
                '*vbox*'      { [void]$categories.Add('VirtualAdapter'); [void]$categories.Add('Hypervisor') }
                '*falcon*'    { [void]$categories.Add('EDR'); [void]$categories.Add('XDR') }
                '*sentinel*'  { [void]$categories.Add('EDR'); [void]$categories.Add('XDR') }
                '*defend*'    { [void]$categories.Add('AV') }
                '*fire*'      { [void]$categories.Add('Firewall') }
                '*vpn*'       { [void]$categories.Add('VPN') }
            }
        }

        foreach ($adapter in @($adapters)) {
            $al = $adapter.ToLowerInvariant()
            switch -Wildcard ($al) {
                '*vmware*'     { [void]$categories.Add('Hypervisor'); [void]$categories.Add('VirtualAdapter') }
                '*virtualbox*' { [void]$categories.Add('Hypervisor'); [void]$categories.Add('VirtualAdapter') }
                '*vbox*'       { [void]$categories.Add('Hypervisor'); [void]$categories.Add('VirtualAdapter') }
                '*hyper-v*'    { [void]$categories.Add('Hypervisor'); [void]$categories.Add('VirtualAdapter') }
                '*vethernet*'  { [void]$categories.Add('VirtualAdapter') }
                '*vpn*'        { [void]$categories.Add('VPN') }
            }
        }

        $sourceWeights = @{
            'SecurityCenter2' = 12
            'Service'         = 8
            'Driver'          = 10
            'ServiceRegistry' = 8
            'NetAdapter'      = 6
            'PnpDevice'       = 6
            'WFP'             = 10
            'NDIS'            = 9
            'MSI'             = 5
            'INF'             = 5
            'ScheduledTask'   = 4
            'AppX'            = 3
            'Uninstall'       = 4
        }

        $score = 10

        foreach ($m in $matched) {
            if ($sourceWeights.ContainsKey($m.Source)) {
                $score += $sourceWeights[$m.Source]
            }
            else {
                $score += 2
            }
        }

        $score += (@($services).Count * 4)
        $score += (@($drivers).Count * 5)
        $score += (@($adapters).Count * 2)
        $score += (@($adapterGuids).Count * 2)

        if ($matched | Where-Object { $_.Source -eq 'WFP' }) {
            $score += 8
            [void]$categories.Add('NetworkFilter')
        }

        if ($matched | Where-Object { $_.Source -eq 'NDIS' }) {
            $score += 8
            [void]$categories.Add('NetworkFilter')
        }

        $confidence = [Math]::Min(100, $score)

        $inventory.Add([pscustomobject]@{
            Vendor                  = $vendor
            Categories              = @($categories | Sort-Object -Unique)
            Confidence              = $confidence
            Services                = @($services | Sort-Object -Unique)
            Drivers                 = @($drivers | Sort-Object -Unique)
            Adapters                = @($adapters | Sort-Object -Unique)
            ProtectedInterfaceGuids = @($adapterGuids | Sort-Object -Unique)
            RegistryKeys            = @($registryKeys | Where-Object { $_ } | Sort-Object -Unique)
            Evidence                = @($evidenceStrings | Sort-Object -Unique)
            RawEvidenceCount        = $matched.Count
        })
    }

    return $inventory.ToArray() | Sort-Object Vendor
}

<#
.SYNOPSIS
Retrieves metadata for a specified file.
.DESCRIPTION
Gets detailed information about a file, including its version and company details.
.OUTPUTS
A PSCustomObject containing the file's metadata.
#>
<# Duplicate helper removed; canonical function is Get-FileMetadata. #>

<#
.SYNOPSIS
Builds an inventory of protection software from collected evidence.
.DESCRIPTION
Collects vendor signatures and evidence sources to produce a prioritized inventory of detected protection products and related registry keys.
.OUTPUTS
A collection of PSCustomObject inventory entries.
#>
function Get-ProtectionRegistryMap {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param(
        [Parameter()]
        [AllowNull()]
        [object[]]$Inventory
    )

    if ($null -eq $Inventory -or @($Inventory).Count -eq 0) {
        $Inventory = @(Get-ProtectionInventory)
    }

    $result = New-Object System.Collections.Generic.List[object]

    foreach ($item in $Inventory) {
        $keys = New-Object System.Collections.Generic.HashSet[string]
        Add-HashSetValue -Set $keys -Values $item.RegistryKeys

        foreach ($svc in @($item.Services)) {
            [void]$keys.Add("HKLM\SYSTEM\CurrentControlSet\Services\$svc")
            foreach ($suffix in @('Parameters', 'Linkage', 'Enum', 'Instances')) {
                $candidate = "HKLM\SYSTEM\CurrentControlSet\Services\$svc\$suffix"
                if (Test-RegistryPathExist -RegistryPath $candidate) {
                    [void]$keys.Add($candidate)
                }
            }
        }

        foreach ($drv in @($item.Drivers)) {
            [void]$keys.Add("HKLM\SYSTEM\CurrentControlSet\Services\$drv")
            foreach ($suffix in @('Parameters', 'Linkage', 'Enum', 'Instances')) {
                $candidate = "HKLM\SYSTEM\CurrentControlSet\Services\$drv\$suffix"
                if (Test-RegistryPathExist -RegistryPath $candidate) {
                    [void]$keys.Add($candidate)
                }
            }
        }

        foreach ($guid in @($item.ProtectedInterfaceGuids)) {
            if ([string]::IsNullOrWhiteSpace($guid)) { continue }
            $g = $guid.Trim('{}').ToLowerInvariant()

            foreach ($candidate in @(
                "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{$g}",
                "HKLM\SYSTEM\CurrentControlSet\Control\Network\{4d36e972-e325-11ce-bfc1-08002be10318}\{$g}",
                "HKLM\SYSTEM\CurrentControlSet\Control\Network\{4d36e972-e325-11ce-bfc1-08002be10318}\{$g}\Connection"
            )) {
                if (Test-RegistryPathExist -RegistryPath $candidate) {
                    [void]$keys.Add($candidate)
                }
            }
        }

        $result.Add([pscustomobject]@{
            Vendor                  = $item.Vendor
            Categories              = $item.Categories
            Confidence              = $item.Confidence
            Services                = $item.Services
            Drivers                 = $item.Drivers
            Adapters                = $item.Adapters
            ProtectedInterfaceGuids = $item.ProtectedInterfaceGuids
            RegistryKeys            = @($keys | Sort-Object -Unique)
            Evidence                = $item.Evidence
        })
    }

    return $result.ToArray() | Sort-Object Vendor
}

<#
.SYNOPSIS
Returns the set of protected interface GUIDs from inventory.
.DESCRIPTION
Creates a unique set of interface GUIDs marked as protected in an inventory.
.OUTPUTS
A list of GUID strings.
#>
function Get-ProtectedInterfaceGuidSet {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param(
        [Parameter()]
        [AllowNull()]
        [object[]]$Inventory
    )

    if ($null -eq $Inventory -or @($Inventory).Count -eq 0) {
        $Inventory = @(Get-ProtectionInventory)
    }

    $set = New-Object System.Collections.Generic.HashSet[string]

    foreach ($item in $Inventory) {
        foreach ($guid in @($item.ProtectedInterfaceGuids)) {
            if ([string]::IsNullOrWhiteSpace($guid)) { continue }
            [void]$set.Add($guid.Trim('{}').ToLowerInvariant())
        }
    }

    return @($set) | Sort-Object
}

<#
.SYNOPSIS
Enumerates candidate registry artifacts relevant to network history.
.DESCRIPTION
Finds registry locations and interface-specific entries that may contain network history or metadata; marks whether each is protected by inventory.
.OUTPUTS
A collection of artifact candidate PSCustomObjects.
#>
function Get-NetworkPrivacyArtifactCandidate {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param(
        [Parameter()]
        [AllowNull()]
        [object[]]$Inventory
    )

    if ($null -eq $Inventory -or @($Inventory).Count -eq 0) {
        $Inventory = @(Get-ProtectionInventory)
    }

    $protectedGuids = @(Get-ProtectedInterfaceGuidSet -Inventory $Inventory)
    $protectedGuidSet = New-Object System.Collections.Generic.HashSet[string]
    Add-HashSetValue -Set $protectedGuidSet -Values $protectedGuids

    $candidates = New-Object System.Collections.Generic.List[object]

    foreach ($path in @(
        'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles',
        'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures',
        'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed',
        'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged'
    )) {
        if (Test-RegistryPathExist -RegistryPath $path) {
            $candidates.Add([pscustomobject]@{
                ArtifactType  = 'NetworkList'
                RegistryPath  = $path
                InterfaceGuid = $null
                IsProtected   = $false
                Reason        = 'Network profile/signature history'
            })
        }
    }

    $tcpipRoot = 'HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces'
    foreach ($child in @(Get-RegistryChildKeyNamesSafe -RegistryPath $tcpipRoot)) {
        $raw = $child.Trim('{}')
        $guid = $raw.ToLowerInvariant()

        $isGuid = $false
        try {
            [void][guid]$guid
            $isGuid = $true
        }
        catch {
            $isGuid = $false
        }

        if (-not $isGuid) { continue }

        $path = "$tcpipRoot\{$guid}"
        $isProtected = $protectedGuidSet.Contains($guid)

        $candidates.Add([pscustomobject]@{
            ArtifactType  = 'TcpipInterface'
            RegistryPath  = $path
            InterfaceGuid = $guid
            IsProtected   = $isProtected
            Reason        = if ($isProtected) { 'Protected by inventory correlation' } else { 'Non-protected interface-specific network state' }
        })
    }

    $networkRoot = 'HKLM\SYSTEM\CurrentControlSet\Control\Network\{4d36e972-e325-11ce-bfc1-08002be10318}'
    foreach ($child in @(Get-RegistryChildKeyNamesSafe -RegistryPath $networkRoot)) {
        $raw = $child.Trim('{}')
        $guid = $raw.ToLowerInvariant()

        $isGuid = $false
        try {
            [void][guid]$guid
            $isGuid = $true
        }
        catch {
            $isGuid = $false
        }

        if (-not $isGuid) { continue }

        foreach ($path in @(
            "$networkRoot\{$guid}",
            "$networkRoot\{$guid}\Connection"
        )) {
            if (Test-RegistryPathExist -RegistryPath $path) {
                $isProtected = $protectedGuidSet.Contains($guid)
                $candidates.Add([pscustomobject]@{
                    ArtifactType  = 'NetworkControl'
                    RegistryPath  = $path
                    InterfaceGuid = $guid
                    IsProtected   = $isProtected
                    Reason        = if ($isProtected) { 'Protected by inventory correlation' } else { 'Non-protected network connection metadata' }
                })
            }
        }
    }

    return $candidates.ToArray()
}

<#
.SYNOPSIS
Filters artifact candidates to those safe to sanitize.
.DESCRIPTION
Returns artifacts from `Get-NetworkPrivacyArtifactCandidate` that are not marked protected by inventory.
.OUTPUTS
A collection of sanitizable artifact PSCustomObjects.
#>
function Get-SanitizableNetworkArtifact {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param(
        [Parameter()]
        [AllowNull()]
        [object[]]$Inventory
    )

    if ($null -eq $Inventory -or @($Inventory).Count -eq 0) {
        $Inventory = @(Get-ProtectionInventory)
    }

    return @(Get-NetworkPrivacyArtifactCandidate -Inventory $Inventory | Where-Object { -not $_.IsProtected })
}

<#
.SYNOPSIS
Run phase 1 detection to build context for subsequent phases.
.DESCRIPTION
Runs detection routines to assemble Inventory, ProtectionRegistryMap, candidate and sanitizable artifacts and returns a context object used by later phases.
.OUTPUTS
A PSCustomObject containing detection context and summary.
#>
function Invoke-NetCleanPhase1Detect {
    [CmdletBinding()]
    [OutputType([System.Object])]
    param()

    $canLog = $null -ne (Get-Command Write-NetCleanLog -ErrorAction SilentlyContinue)
    if ($canLog) {
        Write-NetCleanLog -Level INFO -Message 'Phase 1 detection started.'
    }

    $inventory = @(Get-ProtectionInventory)
    $protectionMap = @(Get-ProtectionRegistryMap -Inventory $inventory)
    $protectedGuids = @(Get-ProtectedInterfaceGuidSet -Inventory $inventory)
    $candidateArtifacts = @(Get-NetworkPrivacyArtifactCandidate -Inventory $inventory)
    $sanitizableArtifacts = @(Get-SanitizableNetworkArtifact -Inventory $inventory)

    $protectedRegistryPaths = @(
        $protectionMap |
        ForEach-Object { $_.RegistryKeys } |
        Where-Object { $_ } |
        Sort-Object -Unique
    )

    $result = [pscustomobject]@{
        ModuleVersion           = $script:NetCleanModuleVersion
        Phase                   = 'Detect'
        DetectedAt              = Get-Date
        Inventory               = $inventory
        ProtectionRegistryMap   = $protectionMap
        ProtectedInterfaceGuids = $protectedGuids
        CandidateArtifacts      = $candidateArtifacts
        SanitizableArtifacts    = $sanitizableArtifacts
        ProtectedRegistryPaths  = $protectedRegistryPaths
        Summary                 = [pscustomobject]@{
            ProtectedVendorsCount       = @($inventory).Count
            ProtectedInterfaceGuidCount = @($protectedGuids).Count
            CandidateArtifactCount      = @($candidateArtifacts).Count
            SanitizableArtifactCount    = @($sanitizableArtifacts).Count
        }
    }

    if ($canLog) {
        Write-NetCleanLog -Level INFO -Message ("Protected vendors detected: {0}" -f $result.Summary.ProtectedVendorsCount)
        Write-NetCleanLog -Level INFO -Message ("Protected interface GUIDs detected: {0}" -f $result.Summary.ProtectedInterfaceGuidCount)
        Write-NetCleanLog -Level INFO -Message ("Candidate artifacts detected: {0}" -f $result.Summary.CandidateArtifactCount)
        Write-NetCleanLog -Level INFO -Message ("Sanitizable artifacts identified: {0}" -f $result.Summary.SanitizableArtifactCount)

        foreach ($artifact in @($sanitizableArtifacts)) {
            $parts = New-Object System.Collections.Generic.List[string]

            if ($artifact.PSObject.Properties.Name -contains 'ArtifactType' -and $artifact.ArtifactType) {
                [void]$parts.Add("Type=$($artifact.ArtifactType)")
                Write-NetCleanLog -Level DEBUG -Message ("Evaluating artifact of type: {0}" -f $artifact.ArtifactType)
            }
            if ($artifact.PSObject.Properties.Name -contains 'Name' -and $artifact.Name) {
                [void]$parts.Add("Name=$($artifact.Name)")
                Write-NetCleanLog -Level DEBUG -Message ("Evaluating artifact named: {0}" -f $artifact.Name)
            }
            if ($artifact.PSObject.Properties.Name -contains 'RegistryPath' -and $artifact.RegistryPath) {
                [void]$parts.Add("RegistryPath=$($artifact.RegistryPath)")
                Write-NetCleanLog -Level DEBUG -Message ("Evaluating artifact with registry path: {0}" -f $artifact.RegistryPath)
            }
            if ($artifact.PSObject.Properties.Name -contains 'Path' -and $artifact.Path) {
                [void]$parts.Add("Path=$($artifact.Path)")
                Write-NetCleanLog -Level DEBUG -Message ("Evaluating artifact with path: {0}" -f $artifact.Path)
            }

            if ($parts.Count -gt 0) {
                Write-NetCleanLog -Level INFO -Message ("Preview candidate: {0}" -f ($parts.ToArray() -join ' '))
            }
        }

        # Additional detection summary for auditing
        Write-NetCleanLog -Level INFO -Message ("Detected inventory entries: {0}" -f @($inventory).Count)

        $vendors = @($inventory | ForEach-Object { $_.Vendor } | Where-Object { $_ } | Sort-Object -Unique)
        if ($vendors.Count -gt 0) {
            Write-NetCleanLog -Level INFO -Message ("Detected vendors: {0}" -f ($vendors -join ', '))
        }

        if ($protectedRegistryPaths -and $protectedRegistryPaths.Count -gt 0) {
            Write-NetCleanLog -Level INFO -Message ("Protected registry paths count: {0}" -f $protectedRegistryPaths.Count)
            foreach ($p in $protectedRegistryPaths) {
                Write-NetCleanLog -Level INFO -Message ("Protected registry path: {0}" -f $p)
            }
        }

        Write-NetCleanLog -Level INFO -Message ("Candidate artifacts: {0}, Sanitizable artifacts: {1}" -f $candidateArtifacts.Count, $sanitizableArtifacts.Count)

        # Brief console summary
        Write-Information ("Phase 1 detection: Vendors={0} ProtectedPaths={1} SanitizableCandidates={2}" -f (@($vendors).Count), @($protectedRegistryPaths).Count, @($sanitizableArtifacts).Count) -InformationAction Continue

        Write-NetCleanLog -Level INFO -Message 'Phase 1 detection complete.'
    }

    return $result
}

# ---------------------------------------------------------------------------
# Phase 2 - Protect helpers
# ---------------------------------------------------------------------------


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
Export specified registry keys to .reg files in a provider-safe manner.
.DESCRIPTION
For each registry path provided, performs an export using `reg.exe` to ensure provider safety. Exports are saved to the specified destination directory with timestamped filenames. If `-DryRun` is specified, simulates the export process and returns the intended file paths without performing any exports.
.PARAMETER Paths
Array of registry key paths to export.
.PARAMETER Dest
Destination directory for exported files.
.PARAMETER DryRun
If specified, simulates the export process and returns the intended file paths without performing any exports.
.EXAMPLE
Export-ProtectedRegistryKey -Paths @('HKLM\SYSTEM\CurrentControlSet\Services\MyService', 'HKLM\SYSTEM\CurrentControlSet\Services\AnotherService') -Dest "C:\Backups\Registry"
This command exports the specified registry keys to .reg files in the given destination directory.
.OUTPUTS
Array of file paths for the exported .reg files. In dry-run mode, returns the intended file paths without creating any files.
.NOTES
- Ensure that the destination directory exists or can be created.
- The function relies on `reg.exe` for exporting registry keys, which may require appropriate permissions to execute successfully.
#>
function Export-ProtectedRegistryKey {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]]$Paths,

        [Parameter(Mandatory = $true)]
        [string]$Dest,

        [switch]$DryRun
    )

    $exported = New-Object System.Collections.Generic.List[string]
    New-DirectoryIfNotExist -Path $Dest

    foreach ($pathItem in @($Paths)) {
        if ([string]::IsNullOrWhiteSpace($pathItem)) { continue }

        $candidate = $pathItem.Trim()
        if ($candidate -notmatch '^(HKLM|HKEY_LOCAL_MACHINE|HKCU|HKEY_CURRENT_USER|HKCR|HKEY_CLASSES_ROOT|HKU|HKEY_USERS|HKCC|HKEY_CURRENT_CONFIG)(\\|:)?') {
            $candidate = "HKLM\" + $candidate
        }

        try {
            $key = Convert-RegKeyPath -Path $candidate
        }
        catch {
            Write-NetCleanLog -Level WARN -Message ("Skipping invalid registry path for export: {0}" -f $pathItem)
            continue
        }

        $safe = ($key -replace '[^a-zA-Z0-9_.-]', '_')
        $file = Join-Path $Dest ("reg_backup_{0}_{1}.reg" -f $safe, (Get-Date -Format 'yyyyMMdd_HHmmss'))

        $result = Invoke-RegExport -Key $key -FilePath $file -DryRun:$DryRun
        [void]$exported.Add($result)
    }

    return $exported.ToArray()
}

<#
.SYNOPSIS
Export a set of registry keys to .reg files.
.DESCRIPTION
For each provided registry path, performs a provider-safe export to the destination directory. Honors `-DryRun` to simulate exports.
.PARAMETER Paths
Array of registry key paths to export.
.PARAMETER Dest
Destination directory for exported files.
.PARAMETER DryRun
If specified, no external export is performed and simulated results are returned.
.OUTPUTS
Array of exported file paths.
#>
function Export-NetworkList {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Dest,

        [switch]$DryRun
    )

    New-DirectoryIfNotExist -Path $Dest
    $key = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList'
    $file = Join-Path $Dest ("NetworkList_{0}.reg" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))

    return Invoke-RegExport -Key $key -FilePath $file -DryRun:$DryRun
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

<#
.SYNOPSIS
Return Wi‑Fi profile names present on the system.
.DESCRIPTION
Parses `netsh wlan show profiles` output to extract profile names; returns an empty list if none found.
.OUTPUTS
Array of Wi‑Fi profile name strings.
#>
function Get-WiFiProfileNames {
    [CmdletBinding()]
    [OutputType([string[]])]
    param()

    $result = Invoke-NetCleanNativeCapture `
        -FilePath 'netsh.exe' `
        -ArgumentList @('wlan', 'show', 'profiles') `
        -Name 'List Wi-Fi profiles' `
        -IgnoreExitCode

    if (-not $result.Succeeded -or -not $result.Output -or $result.Output.Count -eq 0) {
        Write-NetCleanLog -Level DEBUG -Message 'No Wi-Fi profiles returned by netsh.'
        return @()
    }

    $profiles = [System.Collections.Generic.List[string]]::new()

    foreach ($line in $result.Output) {
        if ($null -eq $line) {
            continue
        }

        $text = [string]$line

        if ($text -match '^\s*All User Profile\s*:\s*(.+?)\s*$') {
            $name = $matches[1].Trim()
            if (-not [string]::IsNullOrWhiteSpace($name)) {
                [void]$profiles.Add($name)
            }
            continue
        }

        if ($text -match '^\s*[^:]+:\s*(.+?)\s*$') {
            $label = ($text -replace ':\s*.+$', '').Trim()
            $name  = $matches[1].Trim()

            if ($label -match 'Profile' -and -not [string]::IsNullOrWhiteSpace($name)) {
                [void]$profiles.Add($name)
            }
        }
    }

    $finalProfiles = @($profiles | Sort-Object -Unique)

    Write-NetCleanLog -Level DEBUG -Message ("Detected Wi-Fi profiles: {0}" -f ($finalProfiles -join ', '))

    return $finalProfiles
}

<#
.SYNOPSIS
Export Wi‑Fi profiles to XML files and write a list of exported items.
.DESCRIPTION
For each Wi‑Fi profile, exports to an XML file using `netsh wlan export profile`. A list file is also created containing the exported file paths. Honors `-DryRun` to simulate exports and return intended file paths without performing actual exports.
.PARAMETER Dest
Destination directory for exported Wi‑Fi profile XML files and list file.
.PARAMETER DryRun
If specified, simulates the export process and returns the list of file paths that would have been created without performing any exports.
.OUTPUTS
Array of file paths for the exported Wi‑Fi profile XML files and the list file. In dry-run mode, returns the intended file paths without creating any files.
.EXAMPLE
Export-WiFiProfile -Dest "C:\Backups\WiFiProfiles"
This command exports all Wi‑Fi profiles to XML files in the specified directory and creates a list file with the exported profile names.
.EXAMPLE
Export-WiFiProfile -Dest "C:\Backups\WiFiProfiles" -DryRun
This command simulates the export process and returns the list of file paths that would have been created without performing any exports.
.NOTES
- Ensure that the destination directory exists or can be created.
- The function relies on `netsh` for exporting Wi‑Fi profiles, which may require appropriate permissions to execute successfully.
#>
function Export-WiFiProfile {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Dest,

        [switch]$DryRun
    )

    $canLog = $null -ne (Get-Command Write-NetCleanLog -ErrorAction SilentlyContinue)
    $exported = [System.Collections.Generic.List[string]]::new()

    $listFile = Join-Path $Dest ("WiFiProfiles_{0}.txt" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
    $profiles = @(Get-WiFiProfileNames)

    if ($profiles.Count -eq 0) {
        if ($canLog) {
            Write-NetCleanLog -Level INFO -Message 'No Wi-Fi profiles detected for backup.'
        }
        return @()
    }

    if ($DryRun) {
        [void]$exported.Add($listFile)

        if ($canLog) {
            Write-NetCleanLog -Level INFO -Message ("Would write Wi-Fi profile list file: {0}" -f $listFile)
        }

        foreach ($wifiProfile in $profiles) {
            [void]$exported.Add("PROFILE:$wifiProfile")

            if ($canLog) {
                Write-NetCleanLog -Level INFO -Message ("Would export Wi-Fi profile: {0}" -f $wifiProfile)
            }
        }

        return $exported.ToArray()
    }

    New-DirectoryIfNotExist -Path $Dest

    [System.IO.File]::WriteAllLines($listFile, $profiles, $script:Utf8NoBom)
    [void]$exported.Add($listFile)

    if ($canLog) {
        Write-NetCleanLog -Level INFO -Message ("Exported Wi-Fi profile list: {0}" -f $listFile)
    }

    $bulkSucceeded = $false

    try {
        $before = @(
            Get-ChildItem -Path $Dest -Filter '*.xml' -File -ErrorAction SilentlyContinue |
                Select-Object -ExpandProperty FullName
        )

        $bulkResult = Invoke-ExternalCommandSafe `
            -Name 'Export Wi-Fi profiles (bulk)' `
            -FilePath 'netsh.exe' `
            -ArgumentList @('wlan', 'export', 'profile', "folder=$Dest", 'key=clear') `
            -IgnoreExitCode

        $after = @(
            Get-ChildItem -Path $Dest -Filter '*.xml' -File -ErrorAction SilentlyContinue |
                Select-Object -ExpandProperty FullName
        )

        $newFiles = @($after | Where-Object { $_ -notin $before })

        if ($newFiles.Count -gt 0) {
            foreach ($newFile in $newFiles) {
                [void]$exported.Add($newFile)
            }

            $bulkSucceeded = $true

            if ($canLog) {
                foreach ($newFile in $newFiles) {
                    Write-NetCleanLog -Level INFO -Message ("Exported Wi-Fi profile to '{0}'" -f $newFile)
                }
            }
        }
        elseif ($canLog) {
            Write-NetCleanLog -Level DEBUG -Message ("Bulk Wi-Fi export returned no new XML files. ExitCode={0}" -f $bulkResult.ExitCode)
        }
    }
    catch {
        $bulkSucceeded = $false

        if ($canLog) {
            Write-NetCleanLog -Level WARN -Message ("Bulk Wi-Fi export failed: {0}" -f $_.Exception.Message)
        }
    }

    if (-not $bulkSucceeded) {
        foreach ($wifiProfile in $profiles) {
            try {
                $before = @(
                    Get-ChildItem -Path $Dest -Filter '*.xml' -File -ErrorAction SilentlyContinue |
                        Select-Object -ExpandProperty FullName
                )

                $profileResult = Invoke-ExternalCommandSafe `
                    -Name ("Export Wi-Fi profile {0}" -f $wifiProfile) `
                    -FilePath 'netsh.exe' `
                    -ArgumentList @('wlan', 'export', 'profile', "name=$wifiProfile", "folder=$Dest", 'key=clear') `
                    -IgnoreExitCode

                $after = @(
                    Get-ChildItem -Path $Dest -Filter '*.xml' -File -ErrorAction SilentlyContinue |
                        Select-Object -ExpandProperty FullName
                )

                $newFiles = @($after | Where-Object { $_ -notin $before })

                if ($newFiles.Count -eq 0) {
                    if ($canLog) {
                        Write-NetCleanLog -Level DEBUG -Message ("No XML exported for Wi-Fi profile '{0}'. ExitCode={1}" -f $wifiProfile, $profileResult.ExitCode)
                    }
                    continue
                }

                foreach ($newFile in $newFiles) {
                    [void]$exported.Add($newFile)

                    if ($canLog) {
                        Write-NetCleanLog -Level INFO -Message ("Exported Wi-Fi profile '{0}' to '{1}'" -f $wifiProfile, $newFile)
                    }
                }
            }
            catch {
                if ($canLog) {
                    Write-NetCleanLog -Level WARN -Message ("Per-profile Wi-Fi export failed for '{0}': {1}" -f $wifiProfile, $_.Exception.Message)
                }
            }
        }
    }

    return $exported.ToArray()
}

<#
.SYNOPSIS
Export Wi‑Fi profiles and write a list file.
.DESCRIPTION
Exports each Wi‑Fi profile to XML using `netsh` and returns a list of exported files. Honors `-DryRun` to simulate exports.
.PARAMETER Dest
Destination folder for exported profiles.
.PARAMETER DryRun
Simulate export operations without calling external commands.
.OUTPUTS
Array of exported file paths and markers for profiles when in dry-run.
#>
function Export-FirewallPolicy {
    [CmdletBinding()]
    [OutputType([System.String])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Dest,

        [switch]$DryRun
    )

    $canLog = $null -ne (Get-Command Write-NetCleanLog -ErrorAction SilentlyContinue)

    New-DirectoryIfNotExist -Path $Dest
    $file = Join-Path $Dest ("FirewallPolicy_{0}.wfw" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))

    if ($canLog) {
        if ($DryRun) {
            Write-NetCleanLog -Level INFO -Message ("Would export firewall policy to: {0}" -f $file)
        }
        else {
            Write-NetCleanLog -Level INFO -Message ("Exporting firewall policy to: {0}" -f $file)
        }
    }

    $result = Invoke-ExternalCommandSafe -Name 'Export firewall policy' -FilePath 'netsh.exe' -ArgumentList @('advfirewall', 'export', "`"$file`"") -DryRun:$DryRun
    if (-not $result.Succeeded) {
        if ($canLog) {
            Write-NetCleanLog -Level ERROR -Message ("Firewall policy export failed: {0}" -f $result.Error)
        }
        throw $result.Error
    }

    if ($canLog -and -not $DryRun) {
        Write-NetCleanLog -Level INFO -Message ("Exported firewall policy: {0}" -f $file)
    }

    return $file
}

<#
.SYNOPSIS
Export firewall policy to a .wfw file.
.DESCRIPTION
Uses `netsh advfirewall export` to export the firewall policy configuration to the destination file. Honors `-DryRun` and returns the intended file path.
.PARAMETER Dest
Destination directory for the exported firewall policy.
.PARAMETER DryRun
Simulate export without running external commands.
.OUTPUTS
Path to the exported firewall policy file.
#>
function Export-ProtectionInventory {
    [CmdletBinding()]
    [OutputType([System.String])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Dest,

        [Parameter()]
        [AllowNull()]
        [object[]]$Inventory,

        [switch]$DryRun
    )

    $canLog = $null -ne (Get-Command Write-NetCleanLog -ErrorAction SilentlyContinue)

    New-DirectoryIfNotExist -Path $Dest

    if ($null -eq $Inventory -or @($Inventory).Count -eq 0) {
        Write-NetCleanLog -Level INFO -Message 'No inventory provided, performing detection to gather current protection inventory.'
        $Inventory = @(Get-ProtectionInventory)
        Write-NetCleanLog -Level INFO -Message ("Detected {0} inventory entries for export." -f @($Inventory).Count)
    }

    $file = Join-Path $Dest ("ProtectionInventory_{0}.json" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))

    if ($DryRun) {
        if ($canLog) {
            Write-NetCleanLog -Level INFO -Message ("Would export protection inventory to: {0}" -f $file)
        }
        return $file
    }

    $Inventory | ConvertTo-Json -Depth 8 | Out-File -FilePath $file -Encoding UTF8

    if ($canLog) {
        Write-NetCleanLog -Level INFO -Message ("Exported protection inventory to: {0}" -f $file)
    }

    return $file
}

<#
.SYNOPSIS
Export protection inventory to JSON.
.DESCRIPTION
Writes the provided protection inventory (or current detected inventory) to a JSON file in the destination directory. Honors `-DryRun` to avoid writing files.
.PARAMETER Dest
Destination directory for the inventory JSON file.
.PARAMETER Inventory
Optional inventory object to serialize; detected inventory is used if omitted.
.PARAMETER DryRun
Simulate writing without creating files.
.OUTPUTS
Path to the JSON file that would be or was written.
#>
function Export-ProtectionRegistryMap {
    [CmdletBinding()]
    [OutputType([System.String])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Dest,

        [Parameter()]
        [AllowNull()]
        [object[]]$Inventory,

        [switch]$DryRun
    )

    $canLog = $null -ne (Get-Command Write-NetCleanLog -ErrorAction SilentlyContinue)

    New-DirectoryIfNotExist -Path $Dest

    $map = @(Get-ProtectionRegistryMap -Inventory $Inventory)
    $file = Join-Path $Dest ("ProtectionRegistryMap_{0}.json" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))

    if ($DryRun) {
        if ($canLog) {
            Write-NetCleanLog -Level INFO -Message ("Would export protection registry map to: {0}" -f $file)
        }
        return $file
    }

    $map | ConvertTo-Json -Depth 8 | Out-File -FilePath $file -Encoding UTF8

    if ($canLog) {
        Write-NetCleanLog -Level INFO -Message ("Exported protection registry map to: {0}" -f $file)
    }

    return $file
}

<#
.SYNOPSIS
Export sanitizable artifact list to JSON.
.DESCRIPTION
Serializes the list of sanitizable network artifacts to JSON in the destination folder. Honors `-DryRun`.
.PARAMETER Dest
Destination directory for the JSON file.
.PARAMETER Inventory
Optional inventory used to derive artifacts.
.PARAMETER DryRun
Simulate writing without creating files.
.OUTPUTS
Path to the JSON file.
#>
function Export-SanitizableNetworkArtifact {
    [CmdletBinding()]
    [OutputType([System.String])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Dest,

        [Parameter()]
        [AllowNull()]
        [object[]]$Inventory,

        [switch]$DryRun
    )

    $canLog = $null -ne (Get-Command Write-NetCleanLog -ErrorAction SilentlyContinue)

    New-DirectoryIfNotExist -Path $Dest

    $artifacts = @(Get-SanitizableNetworkArtifact -Inventory $Inventory)
    $file = Join-Path $Dest ("SanitizableNetworkArtifact_{0}.json" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))

    if ($DryRun) {
        if ($canLog) {
            Write-NetCleanLog -Level INFO -Message ("Would export sanitizable artifact inventory to: {0}" -f $file)
        }
        return $file
    }

    $artifacts | ConvertTo-Json -Depth 8 | Out-File -FilePath $file -Encoding UTF8

    if ($canLog) {
        Write-NetCleanLog -Level INFO -Message ("Exported sanitizable artifact inventory to: {0}" -f $file)
    }

    return $file
}

<#
.SYNOPSIS
Export the NetClean manifest containing backup and summary metadata.
.DESCRIPTION
Serializes the manifest hashtable to JSON in the destination directory. Honors `-DryRun` to avoid filesystem writes.
.PARAMETER Dest
Destination directory for the manifest file.
.PARAMETER Manifest
Hashtable describing backup artifacts and summary information.
.PARAMETER DryRun
If specified, operations are simulated and no files are written.
.EXAMPLE
$manifest = @{
    ExampleKey = 'ExampleValue'
}
.OUTPUTS
Path to the manifest JSON file.
.NOTES
Exports the provided manifest to a JSON file in the specified destination. The manifest should contain relevant metadata about the backup and protection summary. The function returns the path to the manifest file, whether it was actually written or simulated via `-DryRun`.
#>
function Export-NetCleanManifest {
    [CmdletBinding()]
    [OutputType([System.String])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Dest,

        [Parameter(Mandatory = $true)]
        [hashtable]$Manifest,

        [switch]$DryRun
    )

    $canLog = $null -ne (Get-Command Write-NetCleanLog -ErrorAction SilentlyContinue)

    New-DirectoryIfNotExist -Path $Dest
    $file = Join-Path $Dest ("RestoreManifest_{0}.json" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))

    if ($DryRun) {
        if ($canLog) {
            Write-NetCleanLog -Level INFO -Message ("Would export restore manifest to: {0}" -f $file)
        }
        return $file
    }

    $Manifest | ConvertTo-Json -Depth 8 | Out-File -FilePath $file -Encoding UTF8

    if ($canLog) {
        Write-NetCleanLog -Level INFO -Message ("Exported restore manifest to: {0}" -f $file)
    }

    return $file
}

<#
.SYNOPSIS
Export the NetClean manifest containing backup and summary metadata.
.DESCRIPTION
Serializes the manifest hashtable to JSON in the destination directory. Honors `-DryRun` to avoid filesystem writes.
.PARAMETER Dest
Destination directory for the manifest file.
.PARAMETER Manifest
Hashtable describing backup artifacts and summary information.
.PARAMETER DryRun
Simulate writing without creating files.
.OUTPUTS
Path to the manifest JSON file.
#>
function Invoke-NetCleanPhase2Protect {
    [CmdletBinding()]
    [OutputType([System.Object])]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Context,

        [Parameter(Mandatory = $true)]
        [string]$BackupPath,

        [switch]$DryRun,
        [switch]$SkipFirewallBackup
    )

    $canLog = $null -ne (Get-Command Write-NetCleanLog -ErrorAction SilentlyContinue)

    if ($canLog) {
        Write-NetCleanLog -Level INFO -Message ("Phase 2 protect started. BackupPath={0} DryRun={1}" -f $BackupPath, [bool]$DryRun)
    }

    New-DirectoryIfNotExist -Path $BackupPath

    $inventory = @($Context.Inventory)
    $protectedPaths = @($Context.ProtectedRegistryPaths | Sort-Object -Unique)

    $manifest = @{
        ModuleVersion                 = $script:NetCleanModuleVersion
        BackupPath                    = $BackupPath
        CreatedAt                     = (Get-Date).ToString('s')
        ProtectionInventoryJson       = $null
        ProtectionRegistryMapJson     = $null
        SanitizableArtifactsJson      = $null
        FirewallPolicyBackup          = $null
        NetworkListBackup             = $null
        WiFiExports                   = @()
        ProtectedRegistryBackups      = @()
    }

    $manifest.ProtectionInventoryJson   = Export-ProtectionInventory -Dest $BackupPath -Inventory $inventory -DryRun:$DryRun
    $manifest.ProtectionRegistryMapJson = Export-ProtectionRegistryMap -Dest $BackupPath -Inventory $inventory -DryRun:$DryRun
    $manifest.SanitizableArtifactsJson  = Export-SanitizableNetworkArtifact -Dest $BackupPath -Inventory $inventory -DryRun:$DryRun
    $manifest.NetworkListBackup         = Export-NetworkList -Dest $BackupPath -DryRun:$DryRun
    if ($canLog) {
        if ($DryRun) {
            Write-NetCleanLog -Level INFO -Message ("Would export network list to: {0}" -f $manifest.NetworkListBackup)
        }
        else {
            Write-NetCleanLog -Level INFO -Message ("Exported network list to: {0}" -f $manifest.NetworkListBackup)
        }
    }

    $manifest.WiFiExports               = @(Export-WiFiProfile -Dest $BackupPath -DryRun:$DryRun)

    if (-not $SkipFirewallBackup) {
        try {
            $manifest.FirewallPolicyBackup = Export-FirewallPolicy -Dest $BackupPath -DryRun:$DryRun
        }
        catch {
            $manifest.FirewallPolicyBackup = $null
            if ($canLog) {
                Write-NetCleanLog -Level WARN -Message ("Firewall policy backup failed or was skipped due to error: {0}" -f $_.Exception.Message)
            }
        }
    }
    else {
        if ($canLog) {
            Write-NetCleanLog -Level INFO -Message 'Skipping firewall policy backup by option.'
        }
    }

    if ($protectedPaths.Count -gt 0) {
        $manifest.ProtectedRegistryBackups = @(Export-ProtectedRegistryKey -Paths $protectedPaths -Dest $BackupPath -DryRun:$DryRun)

        if ($canLog) {
            if ($DryRun) {
                Write-NetCleanLog -Level INFO -Message ("Would export protected registry backups for {0} paths." -f $protectedPaths.Count)
            }
            else {
                Write-NetCleanLog -Level INFO -Message ("Exported protected registry backups for {0} paths." -f $protectedPaths.Count)
            }
        }
    }
    else {
        if ($canLog) {
            Write-NetCleanLog -Level INFO -Message 'No protected registry paths required backup.'
        }
    }

    $manifestFile = Export-NetCleanManifest -Dest $BackupPath -Manifest $manifest -DryRun:$DryRun

    # Log detailed backup/export results and restoration instructions
    if ($canLog) {
        Write-NetCleanLog -Level INFO -Message ("Protection manifest created: {0}" -f $manifestFile)

        if ($manifest.ProtectionInventoryJson) { Write-NetCleanLog -Level INFO -Message ("Protection inventory file: {0}" -f $manifest.ProtectionInventoryJson) }
        if ($manifest.ProtectionRegistryMapJson) { Write-NetCleanLog -Level INFO -Message ("Protection registry map file: {0}" -f $manifest.ProtectionRegistryMapJson) }
        if ($manifest.SanitizableArtifactsJson) { Write-NetCleanLog -Level INFO -Message ("Sanitizable artifacts file: {0}" -f $manifest.SanitizableArtifactsJson) }
        if ($manifest.NetworkListBackup) { Write-NetCleanLog -Level INFO -Message ("NetworkList backup: {0}" -f $manifest.NetworkListBackup) }

        if ($manifest.WiFiExports -and $manifest.WiFiExports.Count -gt 0) {
            foreach ($e in $manifest.WiFiExports) {
                Write-NetCleanLog -Level INFO -Message ("Wi-Fi export: {0}" -f $e)
            }
            Write-NetCleanLog -Level INFO -Message ('To restore Wi‑Fi profiles, run: netsh wlan add profile filename="<exported-profile.xml>" for each exported XML, or use the provided examples\restore-wifi-profiles.ps1 script.')
        }

        if ($manifest.FirewallPolicyBackup) {
            Write-NetCleanLog -Level INFO -Message ("Firewall policy backup: {0}" -f $manifest.FirewallPolicyBackup)
            Write-NetCleanLog -Level INFO -Message ('To restore firewall policy, run: netsh advfirewall import "<file>.wfw"')
        }

        if ($manifest.ProtectedRegistryBackups -and $manifest.ProtectedRegistryBackups.Count -gt 0) {
            foreach ($reg in $manifest.ProtectedRegistryBackups) {
                if ($reg -is [string] -and $reg.StartsWith('ERROR:')) {
                    Write-NetCleanLog -Level WARN -Message ("Registry backup error: {0}" -f $reg)
                }
                else {
                    Write-NetCleanLog -Level INFO -Message ("Protected registry backup file: {0}" -f $reg)
                }
            }
            Write-NetCleanLog -Level INFO -Message ('To restore registry keys, use: reg.exe import "<regfile>.reg" (run as Administrator).')
        }
    }

    $newContext = [pscustomobject]@{}
    foreach ($p in $Context.PSObject.Properties) {
        Add-Member -InputObject $newContext -NotePropertyName $p.Name -NotePropertyValue $p.Value
    }

    Add-Member -InputObject $newContext -NotePropertyName Phase -NotePropertyValue 'Protect' -Force
    Add-Member -InputObject $newContext -NotePropertyName BackupPath -NotePropertyValue $BackupPath -Force
    Add-Member -InputObject $newContext -NotePropertyName Protect -NotePropertyValue ([pscustomobject]@{
        Manifest     = $manifest
        ManifestFile = $manifestFile
        Summary      = [pscustomobject]@{
            ProtectedRegistryPathCount   = $protectedPaths.Count
            WiFiBackupCount              = @($manifest.WiFiExports).Count
            ProtectedRegistryBackupCount = @($manifest.ProtectedRegistryBackups).Count
        }
    }) -Force

    if ($canLog) {
        Write-NetCleanLog -Level INFO -Message ("Phase 2 protect complete. Manifest={0}" -f $manifestFile)
    }

    return $newContext
}

# ---------------------------------------------------------------------------
# Phase 3 - Clean helpers
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
Removes Wi‑Fi profiles safely (supports -WhatIf).
.DESCRIPTION
Deletes all user Wi‑Fi profiles unless protected; supports `-DryRun`, `-WhatIf` and `-Confirm`.
.PARAMETER DryRun
If specified, operations are simulated and no destructive actions are performed.
.EXAMPLE
Remove-WiFiProfilesSafe -DryRun
#>
function Remove-WiFiProfilesSafe {
    [CmdletBinding(SupportsShouldProcess = $true)]
    [OutputType([System.Object])]
    param(
        [switch]$DryRun,
        [string[]]$Profiles
    )

    $canLog = $null -ne (Get-Command Write-NetCleanLog -ErrorAction SilentlyContinue)

    if ($PSBoundParameters.ContainsKey('Profiles') -and $Profiles) { $profiles = @($Profiles) }
    else { $profiles = @(Get-WiFiProfileNames) }
    $removed = New-Object System.Collections.Generic.List[string]
    $operations = New-Object System.Collections.Generic.List[object]

    if ($DryRun) {
        foreach ($wifiProfile in $profiles) {
            if ($canLog) { Write-NetCleanLog -Level INFO -Message ("Would remove Wi-Fi profile: {0}" -f $wifiProfile) }
            $operations.Add([pscustomobject]@{ Name=$wifiProfile; Succeeded=$true; Skipped=$false; Reason='DryRun' })
            [void]$removed.Add($wifiProfile)
        }
    }
    else {
        $toProcess = @()
        foreach ($wifiProfile in $profiles) {
            if (-not $PSCmdlet.ShouldProcess("Wi-Fi profile '$wifiProfile'", 'Delete')) {
                if ($canLog) { Write-NetCleanLog -Level INFO -Message ("WhatIf/ShouldProcess prevented Wi-Fi profile removal: {0}" -f $wifiProfile) }
                $operations.Add([pscustomobject]@{ Name=$wifiProfile; Succeeded=$false; Skipped=$true; Reason='WhatIf' })
                continue
            }
            $toProcess += $wifiProfile
        }

        if ($toProcess.Count -gt 0) {
            # Use parallel jobs to delete profiles in batches for speed; fallback to sequential if job unavailable
            $sb = {
                param($p)
                & netsh wlan delete profile name="$p" 2>&1 | Out-Null
                if ($LASTEXITCODE -eq 0) { [pscustomobject]@{ Name=$p; Succeeded=$true; Skipped=$false; Reason='Removed' } }
                else { [pscustomobject]@{ Name=$p; Succeeded=$false; Skipped=$false; Reason='Failed' } }
            }

            try {
                $res = Invoke-InParallel -ScriptBlock $sb -InputObjects $toProcess -ThrottleLimit ([System.Math]::Max(1, [System.Environment]::ProcessorCount))
            }
            catch {
                $res = @()
            }

            foreach ($r in $res) {
                if ($r -and $r.Succeeded) { [void]$removed.Add($r.Name) }
                $operations.Add($r)
                if ($canLog) {
                    if ($r.Succeeded) { Write-NetCleanLog -Level INFO -Message ("Removed Wi-Fi profile: {0}" -f $r.Name) }
                    else { Write-NetCleanLog -Level WARN -Message ("Failed to remove Wi-Fi profile '{0}': {1}" -f $r.Name, $r.Reason) }
                }
            }
        }
    }

    return [pscustomobject]@{
        Removed    = $removed.Count
        Profiles   = @($removed)
        Operations = @($operations)
    }
}

<#
.SYNOPSIS
Clears the DNS resolver cache (supports -WhatIf).
.DESCRIPTION
Invokes the platform command to flush the DNS resolver cache. Honors `-DryRun`, `-WhatIf` and `-Confirm`.
.PARAMETER DryRun
Simulate actions without making changes.
.EXAMPLE
Clear-DnsCacheSafe -DryRun
#>
function Clear-DnsCacheSafe {
    [CmdletBinding(SupportsShouldProcess = $true)]
    [OutputType([System.Object])]
    param(
        [switch]$DryRun
    )

    $canLog = $null -ne (Get-Command Write-NetCleanLog -ErrorAction SilentlyContinue)

    if ($DryRun) {
        if ($canLog) {
            Write-NetCleanLog -Level INFO -Message 'Would flush DNS cache.'
        }

        return [pscustomobject]@{
            Name      = 'Flush DNS cache'
            Succeeded = $true
            Skipped   = $false
            Reason    = 'DryRun'
        }
    }

    if (-not $PSCmdlet.ShouldProcess('DNS cache', 'Flush')) {
        if ($canLog) {
            Write-NetCleanLog -Level INFO -Message 'WhatIf/ShouldProcess prevented DNS cache flush.'
        }

        return [pscustomobject]@{
            Name      = 'Flush DNS cache'
            Succeeded = $false
            Skipped   = $true
            Reason    = 'WhatIf'
        }
    }

    $result = Invoke-ExternalCommandSafe -Name 'Flush DNS cache' -FilePath 'ipconfig.exe' -ArgumentList @('/flushdns') -DryRun:$false

    if ($canLog) {
        if ($result.Succeeded) {
            Write-NetCleanLog -Level INFO -Message 'Flushed DNS cache.'
        }
        else {
            Write-NetCleanLog -Level WARN -Message ("Failed to flush DNS cache: {0}" -f $result.Error)
        }
    }

    return $result
}

<#
.SYNOPSIS
Clears the ARP cache (supports -WhatIf).
.DESCRIPTION
Attempts to clear the system ARP cache. Honors `-DryRun`, `-WhatIf` and `-Confirm`.
.PARAMETER DryRun
Simulate actions without making changes.
.EXAMPLE
Clear-ArpCacheSafe
#>
function Clear-ArpCacheSafe {
    [CmdletBinding(SupportsShouldProcess = $true)]
    [OutputType([System.Object])]
    param(
        [switch]$DryRun
    )

    $canLog = $null -ne (Get-Command Write-NetCleanLog -ErrorAction SilentlyContinue)

    if ($DryRun) {
        if ($canLog) {
            Write-NetCleanLog -Level INFO -Message 'Would clear ARP cache.'
        }

        return [pscustomobject]@{
            Name      = 'Clear ARP cache'
            Succeeded = $true
            Skipped   = $false
            Reason    = 'DryRun'
        }
    }

    if (-not $PSCmdlet.ShouldProcess('ARP cache', 'Clear')) {
        if ($canLog) {
            Write-NetCleanLog -Level INFO -Message 'WhatIf/ShouldProcess prevented ARP cache clear.'
        }

        return [pscustomobject]@{
            Name      = 'Clear ARP cache'
            Succeeded = $false
            Skipped   = $true
            Reason    = 'WhatIf'
        }
    }

    $result = Invoke-ExternalCommandSafe -Name 'Clear ARP cache' -FilePath 'arp.exe' -ArgumentList @('-d', '*') -DryRun:$false -IgnoreExitCode

    if ($canLog) {
        if ($result.Succeeded) {
            Write-NetCleanLog -Level INFO -Message 'Cleared ARP cache.'
        }
        else {
            Write-NetCleanLog -Level WARN -Message ("Failed to clear ARP cache: {0}" -f $result.Error)
        }
    }

    return $result
}

<#
.SYNOPSIS
Removes a registry path if allowed (supports -WhatIf).
.DESCRIPTION
Safely removes a registry path unless it is protected. Honors `-DryRun`, `-WhatIf` and `-Confirm`.
.PARAMETER RegistryPath
The registry path to remove.
.PARAMETER Context
Operation context with protection information.
.PARAMETER DryRun
Simulate removal without making changes.
.EXAMPLE
Remove-RegistryPathSafe -RegistryPath 'HKCU:\Software\Foo' -Context $ctx -DryRun
#>
function Remove-RegistryPathSafe {
    [CmdletBinding(SupportsShouldProcess = $true)]
    [OutputType([System.Object])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$RegistryPath,

        [Parameter(Mandatory = $true)]
        [pscustomobject]$Context,

        [switch]$DryRun
    )

    $canLog = $null -ne (Get-Command Write-NetCleanLog -ErrorAction SilentlyContinue)

    if (Test-RegistryPathProtected -Path $RegistryPath -Context $Context) {
        if ($canLog) {
            Write-NetCleanLog -Level INFO -Message ("Skipping protected registry path: {0}" -f $RegistryPath)
        }

        return [pscustomobject]@{
            RegistryPath = $RegistryPath
            Removed      = $false
            Skipped      = $true
            Reason       = 'Protected'
            DryRun       = [bool]$DryRun
        }
    }

    $providerPath = $null
    try {
        $providerPath = Convert-RegToProviderPath -RegistryPath $RegistryPath
    }
    catch {
        if ($canLog) {
            Write-NetCleanLog -Level WARN -Message ("Skipping invalid registry path '{0}'." -f $RegistryPath)
        }

        return [pscustomobject]@{
            RegistryPath = $RegistryPath
            Removed      = $false
            Skipped      = $true
            Reason       = 'InvalidPath'
            DryRun       = [bool]$DryRun
        }
    }

    if (-not (Test-Path -LiteralPath $providerPath)) {
        if ($canLog) {
            Write-NetCleanLog -Level INFO -Message ("Registry path not found, skipping: {0}" -f $RegistryPath)
        }

        return [pscustomobject]@{
            RegistryPath = $RegistryPath
            Removed      = $false
            Skipped      = $true
            Reason       = 'NotFound'
            DryRun       = [bool]$DryRun
        }
    }

    if ($DryRun) {
        if ($canLog) {
            Write-NetCleanLog -Level INFO -Message ("Would remove registry path: {0}" -f $RegistryPath)
        }

        return [pscustomobject]@{
            RegistryPath = $RegistryPath
            Removed      = $true
            Skipped      = $false
            Reason       = 'DryRun'
            DryRun       = $true
        }
    }

    if (-not $PSCmdlet.ShouldProcess($RegistryPath, 'Remove registry path')) {
        if ($canLog) {
            Write-NetCleanLog -Level INFO -Message ("WhatIf/ShouldProcess prevented removal of registry path: {0}" -f $RegistryPath)
        }

        return [pscustomobject]@{
            RegistryPath = $RegistryPath
            Removed      = $false
            Skipped      = $true
            Reason       = 'WhatIf'
            DryRun       = $false
        }
    }

    try {
        Remove-Item -LiteralPath $providerPath -Recurse -Force -ErrorAction Stop

        if ($canLog) {
            Write-NetCleanLog -Level INFO -Message ("Removed registry path: {0}" -f $RegistryPath)
        }

        return [pscustomobject]@{
            RegistryPath = $RegistryPath
            Removed      = $true
            Skipped      = $false
            Reason       = 'Removed'
            DryRun       = $false
        }
    }
    catch {
        if ($canLog) {
            Write-NetCleanLog -Level ERROR -Message ("Failed to remove registry path '{0}': {1}" -f $RegistryPath, $_.Exception.Message)
        }

        return [pscustomobject]@{
            RegistryPath = $RegistryPath
            Removed      = $false
            Skipped      = $true
            Reason       = $_.Exception.Message
            DryRun       = $false
        }
    }
}

<#
.SYNOPSIS
Removes discovered network privacy artifacts.
.DESCRIPTION
Iterates discovered artifacts and removes related registry entries where allowed. Honors `-DryRun`, `-WhatIf` and `-Confirm`.
.PARAMETER Context
The protection/context object produced during detect/protect phases.
.PARAMETER DryRun
Simulate actions without making changes.
.EXAMPLE
Remove-NetworkPrivacyArtifactsSafe -Context $ctx -DryRun
#>
function Remove-NetworkPrivacyArtifactsSafe {
    [CmdletBinding(SupportsShouldProcess = $true)]
    [OutputType([System.Object])]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Context,

        [switch]$DryRun
    )

    $canLog = $null -ne (Get-Command Write-NetCleanLog -ErrorAction SilentlyContinue)

    $artifacts = @($Context.SanitizableArtifacts)
    $results = New-Object System.Collections.Generic.List[object]

    if ($canLog) {
        if ($DryRun) {
            Write-NetCleanLog -Level INFO -Message ("Would process {0} sanitizable registry artifacts." -f $artifacts.Count)
        }
        else {
            Write-NetCleanLog -Level INFO -Message ("Processing {0} sanitizable registry artifacts." -f $artifacts.Count)
        }
    }

    foreach ($artifact in $artifacts) {
        if (-not ($artifact.PSObject.Properties.Name -contains 'RegistryPath') -or [string]::IsNullOrWhiteSpace($artifact.RegistryPath)) {
            continue
        }

        $results.Add((Remove-RegistryPathSafe -RegistryPath $artifact.RegistryPath -Context $Context -DryRun:$DryRun))
    }

    $summary = [pscustomobject]@{
        TotalCandidates = $artifacts.Count
        RemovedCount    = @($results | Where-Object { $_.Removed }).Count
        SkippedCount    = @($results | Where-Object { $_.Skipped }).Count
        Results         = @($results)
    }

    if ($canLog) {
        if ($DryRun) {
            Write-NetCleanLog -Level INFO -Message ("Preview registry artifact cleanup summary: candidates={0} wouldRemove={1} skipped={2}" -f $summary.TotalCandidates, $summary.RemovedCount, $summary.SkippedCount)
        }
        else {
            Write-NetCleanLog -Level INFO -Message ("Registry artifact cleanup summary: candidates={0} removed={1} skipped={2}" -f $summary.TotalCandidates, $summary.RemovedCount, $summary.SkippedCount)
        }
    }

    return $summary
}

<#
.SYNOPSIS
Clears NLA probe state properties.
.DESCRIPTION
Removes NLA internet probe properties to reset network location awareness probes. Honors `-DryRun`, `-WhatIf` and `-Confirm`.
.PARAMETER DryRun
Simulate actions without making changes.
.EXAMPLE
Clear-NlaProbeStateSafe -DryRun
.OUTPUTS
An array of results for each property processed, indicating the property name, whether it was removed, if it was a dry run, if the operation succeeded, and any error messages if applicable.
.NOTES
- Clearing NLA probe state can help reset network location awareness but may have side effects on network connectivity until the system re-probes. Use with caution.
#>
function Clear-NlaProbeStateSafe {
    [CmdletBinding(SupportsShouldProcess = $true)]
    [OutputType([System.Object[]])]
    param(
        [switch]$DryRun
    )

    $canLog = $null -ne (Get-Command Write-NetCleanLog -ErrorAction SilentlyContinue)

    $nlaInternetPath = 'HKLM\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet'
    $properties = @(
        'ActiveDnsProbeContent',
        'ActiveDnsProbeHost',
        'ActiveWebProbeContent',
        'ActiveWebProbeHost'
    )

    $results = New-Object System.Collections.Generic.List[object]
    $providerPath = Convert-RegToProviderPath -RegistryPath $nlaInternetPath

    foreach ($property in $properties) {
        if ($DryRun) {
            if ($canLog) {
                Write-NetCleanLog -Level INFO -Message ("Would remove NLA probe property: {0}\{1}" -f $nlaInternetPath, $property)
            }

            $results.Add([pscustomobject]@{
                Path      = $nlaInternetPath
                Property  = $property
                Removed   = $true
                DryRun    = $true
                Succeeded = $true
            })
            continue
        }

        if (-not $PSCmdlet.ShouldProcess("$nlaInternetPath\$property", 'Remove property')) {
            if ($canLog) {
                Write-NetCleanLog -Level INFO -Message ("WhatIf/ShouldProcess prevented removal of NLA probe property: {0}\{1}" -f $nlaInternetPath, $property)
            }

            $results.Add([pscustomobject]@{
                Path      = $nlaInternetPath
                Property  = $property
                Removed   = $false
                DryRun    = $false
                Succeeded = $false
                Error     = 'WhatIf'
            })
            continue
        }

        try {
            Remove-ItemProperty -LiteralPath $providerPath -Name $property -ErrorAction Stop

            if ($canLog) {
                Write-NetCleanLog -Level INFO -Message ("Removed NLA probe property: {0}\{1}" -f $nlaInternetPath, $property)
            }

            $results.Add([pscustomobject]@{
                Path      = $nlaInternetPath
                Property  = $property
                Removed   = $true
                DryRun    = $false
                Succeeded = $true
            })
        }
        catch {
            if ($canLog) {
                Write-NetCleanLog -Level WARN -Message ("Failed to remove NLA probe property '{0}\{1}': {2}" -f $nlaInternetPath, $property, $_.Exception.Message)
            }

            $results.Add([pscustomobject]@{
                Path      = $nlaInternetPath
                Property  = $property
                Removed   = $false
                DryRun    = $false
                Succeeded = $false
                Error     = $_.Exception.Message
            })
        }
    }

    return $results.ToArray()
}

<#
.SYNOPSIS
Safely clears user network event logs.
.DESCRIPTION
Clears user-specific network event logs such as WLAN AutoConfig, NetworkProfile and DHCP Client operational logs. Honors `-DryRun`, `-WhatIf` and `-Confirm` to allow safe simulation of actions.
.PARAMETER DryRun
If specified, all operations are simulated and no actual changes are made to the system. Results will indicate what would have been done.
.EXAMPLE
Clear-NetworkEventLogsSafe -DryRun
.OUTPUTS
An array of results for each log cleared, indicating the log name, whether it was cleared, if it was a dry run, if the operation succeeded, and any error messages if applicable.
.NOTES
- Clearing event logs can result in loss of historical event data. It is recommended to perform these operations when a backup of important logs has been made or when the logs are not needed for troubleshooting.
#>
function Clear-NetworkEventLogsSafe {
    [CmdletBinding(SupportsShouldProcess = $true)]
    [OutputType([System.Object[]])]
    param(
        [switch]$DryRun
    )

    $canLog = $null -ne (Get-Command Write-NetCleanLog -ErrorAction SilentlyContinue)

    $logs = @(
        'Microsoft-Windows-WLAN-AutoConfig/Operational',
        'Microsoft-Windows-NetworkProfile/Operational',
        'Microsoft-Windows-DHCP-Client/Operational'
    )

    $results = [System.Collections.Generic.List[object]]::new()

    foreach ($log in $logs) {
        if ($DryRun) {
            if ($canLog) {
                Write-NetCleanLog -Level INFO -Message ("Would clear event log: {0}" -f $log)
            }

            $results.Add([pscustomobject]@{
                Name      = "Clear event log $log"
                LogName   = $log
                Succeeded = $true
                Cleared   = $false
                DryRun    = $true
                Skipped   = $false
                Reason    = 'DryRun'
                ExitCode  = 0
                Error     = $null
            })

            continue
        }

        if (-not $PSCmdlet.ShouldProcess($log, 'Clear event log')) {
            if ($canLog) {
                Write-NetCleanLog -Level INFO -Message ("WhatIf prevented clearing event log: {0}" -f $log)
            }

            $results.Add([pscustomobject]@{
                Name      = "Clear event log $log"
                LogName   = $log
                Succeeded = $false
                Cleared   = $false
                DryRun    = $false
                Skipped   = $true
                Reason    = 'WhatIf'
                ExitCode  = $null
                Error     = $null
            })

            continue
        }

        try {
            $result = Invoke-ExternalCommandSafe `
                -Name ("Clear event log {0}" -f $log) `
                -FilePath 'wevtutil.exe' `
                -ArgumentList @('cl', $log) `
                -IgnoreExitCode

            $results.Add([pscustomobject]@{
                Name      = $result.Name
                LogName   = $log
                Succeeded = [bool]$result.Succeeded
                Cleared   = [bool]$result.Succeeded
                DryRun    = $false
                Skipped   = $false
                Reason    = $(if ($result.Succeeded) { $null } else { 'CommandFailed' })
                ExitCode  = $result.ExitCode
                Error     = $result.Error
            })

            if ($canLog) {
                if ($result.Succeeded) {
                    Write-NetCleanLog -Level INFO -Message ("Cleared event log: {0}" -f $log)
                }
                else {
                    Write-NetCleanLog -Level WARN -Message ("Failed to clear event log '{0}': {1}" -f $log, $result.Error)
                }
            }
        }
        catch {
            if ($canLog) {
                Write-NetCleanLog -Level WARN -Message ("Exception clearing event log '{0}': {1}" -f $log, $_.Exception.Message)
            }

            $results.Add([pscustomobject]@{
                Name      = "Clear event log $log"
                LogName   = $log
                Succeeded = $false
                Cleared   = $false
                DryRun    = $false
                Skipped   = $false
                Reason    = 'Exception'
                ExitCode  = -1
                Error     = $_.Exception.Message
            })
        }
    }

    return $results.ToArray()
}

<#
.SYNOPSIS
Safely clears user network artifacts from the registry.
.DESCRIPTION
Removes user-specific network artifacts such as mapped network drive MRU and terminal server client history from the registry. Honors `-DryRun`, `-WhatIf` and `-Confirm` to allow safe simulation of actions.
.PARAMETER DryRun
If specified, all operations are simulated and no actual changes are made to the system. Results will indicate what would have been done.
.EXAMPLE
Clear-UserNetworkArtifactsSafe -DryRun
.OUTPUTS
An array of results for each artifact path processed, indicating the path, whether it was removed, if it was a dry run, if the operation succeeded, and any error messages if applicable.
.NOTES
- This function targets specific user registry paths known to store network-related artifacts. It is designed to be safe and cautious, avoiding any protected paths and providing detailed results for each attempted removal.
#>
function Clear-UserNetworkArtifactsSafe {
    [CmdletBinding(SupportsShouldProcess = $true)]
    [OutputType([System.Object[]])]
    param(
        [switch]$DryRun
    )

    $canLog = $null -ne (Get-Command Write-NetCleanLog -ErrorAction SilentlyContinue)

    $paths = @(
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs'
    )

    $results = [System.Collections.Generic.List[object]]::new()

    foreach ($path in $paths) {

        if ($DryRun) {

            if ($canLog) {
                Write-NetCleanLog -Level INFO -Message ("Would remove user network artifact path: {0}" -f $path)
            }

            $results.Add([pscustomobject]@{
                Path      = $path
                Removed   = $false
                DryRun    = $true
                Succeeded = $true
                Reason    = 'DryRun'
            })

            continue
        }

        if (-not (Test-Path -LiteralPath $path)) {

            $results.Add([pscustomobject]@{
                Path      = $path
                Removed   = $false
                DryRun    = $false
                Succeeded = $true
                Reason    = 'NotFound'
            })

            continue
        }

        if (-not $PSCmdlet.ShouldProcess($path, 'Remove user network artifact path')) {

            if ($canLog) {
                Write-NetCleanLog -Level INFO -Message ("WhatIf prevented clearing user network artifact path: {0}" -f $path)
            }

            $results.Add([pscustomobject]@{
                Path      = $path
                Removed   = $false
                DryRun    = $false
                Succeeded = $false
                Reason    = 'WhatIf'
            })

            continue
        }

        try {

            Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction Stop

            if ($canLog) {
                Write-NetCleanLog -Level INFO -Message ("Removed user network artifact path: {0}" -f $path)
            }

            $results.Add([pscustomobject]@{
                Path      = $path
                Removed   = $true
                DryRun    = $false
                Succeeded = $true
                Reason    = $null
            })
        }
        catch {

            if ($canLog) {
                Write-NetCleanLog -Level WARN -Message ("Failed removing user network artifact path '{0}': {1}" -f $path, $_.Exception.Message)
            }

            $results.Add([pscustomobject]@{
                Path      = $path
                Removed   = $false
                DryRun    = $false
                Succeeded = $false
                Reason    = $_.Exception.Message
            })
        }
    }

    return $results.ToArray()
}

<#
.SYNOPSIS
Performs advanced network repairs by resetting Winsock and TCP/IP stacks.
.DESCRIPTION
Executes a series of commands to reset the Winsock catalog and TCP/IP stacks for both IPv4 and IPv6. These operations can resolve a variety of network issues related to corrupted network configurations. Honors `-DryRun` to simulate actions without making changes.
.PARAMETER DryRun
If specified, all operations are simulated and no actual changes are made to the system. Results will indicate what would have been done.
.EXAMPLE
Invoke-AdvancedNetworkRepair -DryRun
.OUTPUTS
An array of results for each repair command executed, indicating the name of the command, whether it succeeded, if it was a dry run, and any error messages if applicable.
.NOTES
- Resetting Winsock and TCP/IP stacks can disrupt network connectivity until the system is restarted. It is recommended to perform these operations when a restart can be accommodated.
#>
function Invoke-AdvancedNetworkRepair {
    [CmdletBinding(SupportsShouldProcess = $true)]
    [OutputType([System.Object[]])]
    param(
        [switch]$DryRun
    )

    $canLog = $null -ne (Get-Command Write-NetCleanLog -ErrorAction SilentlyContinue)

    $commands = @(
        [pscustomobject]@{
            Name         = 'Reset Winsock'
            FilePath     = 'netsh.exe'
            ArgumentList = @('winsock', 'reset')
        },
        [pscustomobject]@{
            Name         = 'Reset IPv4 stack'
            FilePath     = 'netsh.exe'
            ArgumentList = @('int', 'ip', 'reset')
        },
        [pscustomobject]@{
            Name         = 'Reset IPv6 stack'
            FilePath     = 'netsh.exe'
            ArgumentList = @('int', 'ipv6', 'reset')
        }
    )

    $results = [System.Collections.Generic.List[object]]::new()

    foreach ($cmd in $commands) {
        if ($DryRun) {
            if ($canLog) {
                Write-NetCleanLog -Level INFO -Message ("Would perform advanced network repair action: {0}" -f $cmd.Name)
            }

            $results.Add([pscustomobject]@{
                Name      = $cmd.Name
                FilePath  = $cmd.FilePath
                Arguments = ($cmd.ArgumentList -join ' ')
                Succeeded = $true
                Applied   = $false
                DryRun    = $true
                Skipped   = $false
                Reason    = 'DryRun'
                ExitCode  = 0
                Error     = $null
            })

            continue
        }

        if (-not $PSCmdlet.ShouldProcess($cmd.Name, 'Perform advanced network repair action')) {
            if ($canLog) {
                Write-NetCleanLog -Level INFO -Message ("WhatIf prevented advanced network repair action: {0}" -f $cmd.Name)
            }

            $results.Add([pscustomobject]@{
                Name      = $cmd.Name
                FilePath  = $cmd.FilePath
                Arguments = ($cmd.ArgumentList -join ' ')
                Succeeded = $false
                Applied   = $false
                DryRun    = $false
                Skipped   = $true
                Reason    = 'WhatIf'
                ExitCode  = $null
                Error     = $null
            })

            continue
        }

        try {
            $result = Invoke-ExternalCommandSafe `
                -Name $cmd.Name `
                -FilePath $cmd.FilePath `
                -ArgumentList $cmd.ArgumentList `
                -IgnoreExitCode

            $results.Add([pscustomobject]@{
                Name      = $result.Name
                FilePath  = $cmd.FilePath
                Arguments = ($cmd.ArgumentList -join ' ')
                Succeeded = [bool]$result.Succeeded
                Applied   = [bool]$result.Succeeded
                DryRun    = $false
                Skipped   = $false
                Reason    = $(if ($result.Succeeded) { $null } else { 'CommandFailed' })
                ExitCode  = $result.ExitCode
                Error     = $result.Error
            })

            if ($canLog) {
                if ($result.Succeeded) {
                    Write-NetCleanLog -Level INFO -Message ("Completed advanced network repair action: {0}" -f $cmd.Name)
                }
                else {
                    Write-NetCleanLog -Level WARN -Message ("Failed advanced network repair action '{0}': {1}" -f $cmd.Name, $result.Error)
                }
            }
        }
        catch {
            if ($canLog) {
                Write-NetCleanLog -Level WARN -Message ("Exception during advanced network repair action '{0}': {1}" -f $cmd.Name, $_.Exception.Message)
            }

            $results.Add([pscustomobject]@{
                Name      = $cmd.Name
                FilePath  = $cmd.FilePath
                Arguments = ($cmd.ArgumentList -join ' ')
                Succeeded = $false
                Applied   = $false
                DryRun    = $false
                Skipped   = $false
                Reason    = 'Exception'
                ExitCode  = -1
                Error     = $_.Exception.Message
            })
        }
    }

    return $results.ToArray()
}

<#
    .SYNOPSIS
    Prompts the user to select a network performance tuning profile.
    .DESCRIPTION
    Displays a list of available network performance tuning profiles and allows the user to make a selection.
    .OUTPUTS
    [string] The selected profile name.
#>
function Read-NetCleanPerformanceProfileSelection {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    while ($true) {
        Write-Information '' -InformationAction Continue
        Write-Information 'Network Performance Tuning Profiles' -InformationAction Continue
        Write-Information '-----------------------------------' -InformationAction Continue
        Write-Information '1. Conservative' -InformationAction Continue
        Write-Information '   Safe baseline tuning with minimal change.' -InformationAction Continue
        Write-Information '   Changes:' -InformationAction Continue
        Write-Information '     - TCP autotuning = normal' -InformationAction Continue
        Write-Information '   Why:' -InformationAction Continue
        Write-Information '     - Restores a stable, low-risk TCP setting for most systems.' -InformationAction Continue
        Write-Information '' -InformationAction Continue

        Write-Information '2. Optimal' -InformationAction Continue
        Write-Information '   Balanced general-use broadband tuning.' -InformationAction Continue
        Write-Information '   Changes:' -InformationAction Continue
        Write-Information '     - TCP autotuning = normal' -InformationAction Continue
        Write-Information '     - ECN = enabled' -InformationAction Continue
        Write-Information '     - TCP timestamps = disabled' -InformationAction Continue
        Write-Information '   Why:' -InformationAction Continue
        Write-Information '     - Aims for good general throughput and modern TCP behavior.' -InformationAction Continue
        Write-Information '' -InformationAction Continue

        Write-Information '3. Gaming' -InformationAction Continue
        Write-Information '   Lower-latency focused tuning.' -InformationAction Continue
        Write-Information '   Changes:' -InformationAction Continue
        Write-Information '     - TCP autotuning = normal' -InformationAction Continue
        Write-Information '     - ECN = disabled' -InformationAction Continue
        Write-Information '     - TCP timestamps = disabled' -InformationAction Continue
        Write-Information '   Why:' -InformationAction Continue
        Write-Information '     - Prioritizes simpler, latency-oriented TCP behavior.' -InformationAction Continue
        Write-Information '' -InformationAction Continue

        Write-Information '4. Restore Default' -InformationAction Continue
        Write-Information '   Restore NetClean-supported baseline values.' -InformationAction Continue
        Write-Information '   Changes:' -InformationAction Continue
        Write-Information '     - Reverts tuning changes made by NetClean profiles' -InformationAction Continue
        Write-Information '   Why:' -InformationAction Continue
        Write-Information '     - Gives you a rollback path if tuning does not help.' -InformationAction Continue
        Write-Information '' -InformationAction Continue

        Write-Information '5. Cancel' -InformationAction Continue
        Write-Information '' -InformationAction Continue

        $choice = Read-Host 'Select a profile (1-5)'

        switch ($choice) {
            '1' { return 'Conservative' }
            '2' { return 'Optimal' }
            '3' { return 'Gaming' }
            '4' { return 'Default' }
            '5' { return 'Cancel' }
            default {
                Write-Information '' -InformationAction Continue
                Write-Information 'Invalid selection. Please choose 1 through 5.' -InformationAction Continue
            }
        }
    }
}

<#
.SYNOPSIS
Performs conservative performance tuning by enabling normal autotuning, RSS, and ECN.
.DESCRIPTION
Executes a set of commands to enable normal autotuning, Receive Side Scaling (RSS), and Explicit Congestion Notification (ECN) capability. These settings can improve network performance in many scenarios while maintaining broad compatibility. Honors `-DryRun` to simulate actions without making changes.
.PARAMETER DryRun
If specified, all operations are simulated and no actual changes are made to the system. Results will indicate what would have been done.
.EXAMPLE
Invoke-NetworkPerformanceTune -DryRun
.OUTPUTS
An array of results for each performance tuning command executed, indicating the name of the command, whether it succeeded, if it was a dry run, and any error messages if applicable.
.NOTES
- These performance tuning steps are generally safe and can provide benefits in typical network environments, but results may vary based on specific hardware and drivers.
#>
function Invoke-NetworkPerformanceTune {
    [CmdletBinding(SupportsShouldProcess = $true)]
    [OutputType([System.Object[]])]
    param(
        [ValidateSet('Conservative','Optimal','Gaming','Default')]
        [string]$Profile = 'Conservative',

        [switch]$DryRun
    )

    $canLog = $null -ne (Get-Command Write-NetCleanLog -ErrorAction SilentlyContinue)

    switch ($Profile) {
        'Conservative' {
            $commands = @(
                [pscustomobject]@{
                    Name         = 'Set TCP autotuning to normal'
                    FilePath     = 'netsh.exe'
                    ArgumentList = @('int', 'tcp', 'set', 'global', 'autotuninglevel=normal')
                    Why          = 'Restores stable receive-window scaling behavior.'
                }
            )
        }

        'Optimal' {
            $commands = @(
                [pscustomobject]@{
                    Name         = 'Set TCP autotuning to normal'
                    FilePath     = 'netsh.exe'
                    ArgumentList = @('int', 'tcp', 'set', 'global', 'autotuninglevel=normal')
                    Why          = 'Keeps adaptive receive-window sizing enabled.'
                },
                [pscustomobject]@{
                    Name         = 'Enable ECN capability'
                    FilePath     = 'netsh.exe'
                    ArgumentList = @('int', 'tcp', 'set', 'global', 'ecncapability=enabled')
                    Why          = 'Allows ECN-capable congestion signaling where supported.'
                },
                [pscustomobject]@{
                    Name         = 'Disable TCP timestamps'
                    FilePath     = 'netsh.exe'
                    ArgumentList = @('int', 'tcp', 'set', 'global', 'timestamps=disabled')
                    Why          = 'Reduces header overhead for most common client workloads.'
                }
            )
        }

        'Gaming' {
            $commands = @(
                [pscustomobject]@{
                    Name         = 'Set TCP autotuning to normal'
                    FilePath     = 'netsh.exe'
                    ArgumentList = @('int', 'tcp', 'set', 'global', 'autotuninglevel=normal')
                    Why          = 'Maintains modern TCP scaling without over-constraining throughput.'
                },
                [pscustomobject]@{
                    Name         = 'Disable ECN capability'
                    FilePath     = 'netsh.exe'
                    ArgumentList = @('int', 'tcp', 'set', 'global', 'ecncapability=disabled')
                    Why          = 'Avoids dependency on ECN behavior across network paths.'
                },
                [pscustomobject]@{
                    Name         = 'Disable TCP timestamps'
                    FilePath     = 'netsh.exe'
                    ArgumentList = @('int', 'tcp', 'set', 'global', 'timestamps=disabled')
                    Why          = 'Keeps packet overhead and TCP options simpler.'
                }
            )
        }

        'Default' {
            $commands = @(
                [pscustomobject]@{
                    Name         = 'Set TCP autotuning to normal'
                    FilePath     = 'netsh.exe'
                    ArgumentList = @('int', 'tcp', 'set', 'global', 'autotuninglevel=normal')
                    Why          = 'Restores the NetClean baseline autotuning state.'
                },
                [pscustomobject]@{
                    Name         = 'Disable ECN capability'
                    FilePath     = 'netsh.exe'
                    ArgumentList = @('int', 'tcp', 'set', 'global', 'ecncapability=disabled')
                    Why          = 'Restores the NetClean baseline ECN state.'
                },
                [pscustomobject]@{
                    Name         = 'Disable TCP timestamps'
                    FilePath     = 'netsh.exe'
                    ArgumentList = @('int', 'tcp', 'set', 'global', 'timestamps=disabled')
                    Why          = 'Restores the NetClean baseline timestamp state.'
                }
            )
        }
    }

    $results = [System.Collections.Generic.List[object]]::new()

    foreach ($cmd in $commands) {
        if ($DryRun) {
            if ($canLog) {
                Write-NetCleanLog -Level INFO -Message ("Would apply tuning profile '{0}' action: {1}" -f $Profile, $cmd.Name)
            }

            $results.Add([pscustomobject]@{
                Profile   = $Profile
                Name      = $cmd.Name
                FilePath  = $cmd.FilePath
                Arguments = ($cmd.ArgumentList -join ' ')
                Why       = $cmd.Why
                Succeeded = $true
                Applied   = $false
                DryRun    = $true
                Skipped   = $false
                Reason    = 'DryRun'
                ExitCode  = 0
                Error     = $null
            })

            continue
        }

        if (-not $PSCmdlet.ShouldProcess($cmd.Name, "Apply network tuning profile '$Profile'")) {
            if ($canLog) {
                Write-NetCleanLog -Level INFO -Message ("WhatIf prevented tuning profile '{0}' action: {1}" -f $Profile, $cmd.Name)
            }

            $results.Add([pscustomobject]@{
                Profile   = $Profile
                Name      = $cmd.Name
                FilePath  = $cmd.FilePath
                Arguments = ($cmd.ArgumentList -join ' ')
                Why       = $cmd.Why
                Succeeded = $false
                Applied   = $false
                DryRun    = $false
                Skipped   = $true
                Reason    = 'WhatIf'
                ExitCode  = $null
                Error     = $null
            })

            continue
        }

        try {
            $result = Invoke-ExternalCommandSafe `
                -Name $cmd.Name `
                -FilePath $cmd.FilePath `
                -ArgumentList $cmd.ArgumentList `
                -IgnoreExitCode

            $results.Add([pscustomobject]@{
                Profile   = $Profile
                Name      = $result.Name
                FilePath  = $cmd.FilePath
                Arguments = ($cmd.ArgumentList -join ' ')
                Why       = $cmd.Why
                Succeeded = [bool]$result.Succeeded
                Applied   = [bool]$result.Succeeded
                DryRun    = $false
                Skipped   = $false
                Reason    = $(if ($result.Succeeded) { $null } else { 'CommandFailed' })
                ExitCode  = $result.ExitCode
                Error     = $result.Error
            })

            if ($canLog) {
                if ($result.Succeeded) {
                    Write-NetCleanLog -Level INFO -Message ("Applied tuning profile '{0}' action: {1}" -f $Profile, $cmd.Name)
                }
                else {
                    Write-NetCleanLog -Level WARN -Message ("Failed tuning profile '{0}' action '{1}': {2}" -f $Profile, $cmd.Name, $result.Error)
                }
            }
        }
        catch {
            if ($canLog) {
                Write-NetCleanLog -Level WARN -Message ("Exception applying tuning profile '{0}' action '{1}': {2}" -f $Profile, $cmd.Name, $_.Exception.Message)
            }

            $results.Add([pscustomobject]@{
                Profile   = $Profile
                Name      = $cmd.Name
                FilePath  = $cmd.FilePath
                Arguments = ($cmd.ArgumentList -join ' ')
                Why       = $cmd.Why
                Succeeded = $false
                Applied   = $false
                DryRun    = $false
                Skipped   = $false
                Reason    = 'Exception'
                ExitCode  = -1
                Error     = $_.Exception.Message
            })
        }
    }

    return $results.ToArray()
}

<#
.SYNOPSIS
Performs cleaning operations to remove network privacy artifacts and reset network state.
.DESCRIPTION
Based on the provided context and mode, executes a series of cleaning operations such as removing Wi‑Fi profiles, flushing DNS cache, clearing ARP cache, removing registry artifacts, clearing NLA probe state, and optionally performing advanced repairs and performance tuning. Each operation is performed safely with support for `-DryRun` to simulate actions without making changes. Returns an updated context object containing details of the cleaning operations performed and their results.
.PARAMETER Context
The context object produced during the detect/protect phases, containing inventory and protection information.
.PARAMETER Mode
Determines the cleaning mode and which operations to perform. Supported values are:
- 'Preview': Minimal cleaning for previewing potential changes.
.PARAMETER DryRun
If specified, all operations are simulated and no actual changes are made to the system. Results will indicate what would have been done.
.PARAMETER SkipWifi
If specified, Wi‑Fi profile removal will be skipped.
.PARAMETER SkipDnsFlush
If specified, DNS cache flushing will be skipped.
.PARAMETER SkipEventLogs
If specified, network event log clearing will be skipped.
.PARAMETER SkipUserArtifacts
If specified, user network artifact clearing will be skipped.
.PARAMETER EnableConservativePerformanceTuning
If specified, conservative performance tuning commands will be executed in addition to the standard cleaning operations.
.EXAMPLE
Invoke-NetCleanPhase3Clean -Context $ctx -Mode 'SafeConferencePrep' -DryRun
.OUTPUTS
An updated context object containing the results of the cleaning operations, including which Wi‑Fi profiles were removed, the outcome of DNS cache flushing, ARP cache clearing, registry artifact removal, NLA probe state clearing, event log clearing, user artifact clearing, and any advanced repairs or performance tuning performed based on the selected mode.
.NOTES
- Ensure that the context object provided contains the necessary inventory and protection information for accurate cleaning operations.
#>
function Invoke-NetCleanPhase3Clean {
    [CmdletBinding(SupportsShouldProcess = $true)]
    [OutputType([System.Object])]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Context,

        [ValidateSet('Preview', 'SafeConferencePrep', 'AdvancedRepair', 'PerformanceTune')]
        [string]$Mode = 'SafeConferencePrep',

        [switch]$DryRun,
        [switch]$SkipWifi,
        [switch]$SkipDnsFlush,
        [switch]$SkipEventLogs,
        [switch]$SkipUserArtifacts,
        [switch]$EnableConservativePerformanceTuning
    )

    $canLog = $null -ne (Get-Command Write-NetCleanLog -ErrorAction SilentlyContinue)

    if ($canLog) {
        Write-NetCleanLog -Level INFO -Message ("Phase 3 clean started. Mode={0} DryRun={1}" -f $Mode, [bool]$DryRun)
    }

    $newContext = [pscustomobject]@{}
    foreach ($p in $Context.PSObject.Properties) {
        Add-Member -InputObject $newContext -NotePropertyName $p.Name -NotePropertyValue $p.Value
    }

    if ($SkipWifi) {
        $wifiResult = [pscustomobject]@{
            Removed    = 0
            Profiles   = @()
            Operations = @()
        }

        if ($canLog) {
            Write-NetCleanLog -Level INFO -Message 'Skipping Wi-Fi profile cleanup by option.'
        }
    }
    else {
        $profilesToRemove = $null
        if ($Context -and $Context.PSObject.Properties.Name -contains 'Protect' -and $Context.Protect.PSObject.Properties.Name -contains 'Summary' -and $Context.Protect.Summary.PSObject.Properties.Name -contains 'WiFiProfilesFound') {
            $profilesToRemove = @($Context.Protect.Summary.WiFiProfilesFound)
        }
        if ($profilesToRemove -and $profilesToRemove.Count -gt 0) {
            $wifiResult = Remove-WiFiProfilesSafe -DryRun:$DryRun -Profiles $profilesToRemove
        }
        else {
            $wifiResult = Remove-WiFiProfilesSafe -DryRun:$DryRun
        }
    }

    if ($SkipDnsFlush) {
        $dnsResult = [pscustomobject]@{
            Name      = 'Flush DNS cache'
            Succeeded = $true
            DryRun    = [bool]$DryRun
            Skipped   = $true
            Reason    = 'SkippedByOption'
        }

        if ($canLog) {
            Write-NetCleanLog -Level INFO -Message 'Skipping DNS cache flush by option.'
        }
    }
    else {
        $dnsResult = Clear-DnsCacheSafe -DryRun:$DryRun
    }

    $arpResult = Clear-ArpCacheSafe -DryRun:$DryRun
    $artifacts = Remove-NetworkPrivacyArtifactsSafe -Context $newContext -DryRun:$DryRun
    $nlaResults = Clear-NlaProbeStateSafe -DryRun:$DryRun

    if ($SkipEventLogs) {
        $logResults = @()
        if ($canLog) {
            Write-NetCleanLog -Level INFO -Message 'Skipping network event log cleanup by option.'
        }
    }
    else {
        $logResults = @(Clear-NetworkEventLogsSafe -DryRun:$DryRun)
    }

    if ($SkipUserArtifacts) {
        $userResults = @()
        if ($canLog) {
            Write-NetCleanLog -Level INFO -Message 'Skipping user network artifact cleanup by option.'
        }
    }
    else {
        $userResults = @(Clear-UserNetworkArtifactsSafe -DryRun:$DryRun)
    }

    $advancedRepair = @()
    if ($Mode -eq 'AdvancedRepair') {
        $advancedRepair = @(Invoke-AdvancedNetworkRepair -DryRun:$DryRun)
    }

    $tuningResults = @()
    if ($Mode -eq 'PerformanceTune' -or $EnableConservativePerformanceTuning) {
        $tuningResults = @(Invoke-NetworkPerformanceTune -DryRun:$DryRun)
    }

    Add-Member -InputObject $newContext -NotePropertyName Phase -NotePropertyValue 'Clean' -Force
    Add-Member -InputObject $newContext -NotePropertyName Clean -NotePropertyValue ([pscustomobject]@{
        Mode              = $Mode
        WiFi              = $wifiResult
        Dns               = $dnsResult
        Arp               = $arpResult
        RegistryArtifacts = $artifacts
        Nla               = @($nlaResults)
        EventLogs         = @($logResults)
        UserArtifacts     = @($userResults)
        AdvancedRepair    = @($advancedRepair)
        PerformanceTuning = @($tuningResults)
        Summary           = [pscustomobject]@{
            WiFiProfilesRemoved      = $wifiResult.Removed
            RegistryArtifactsRemoved = $artifacts.RemovedCount
            EventLogsTouched         = @($logResults).Count
            UserArtifactsTouched     = @($userResults | Where-Object { $_.Removed }).Count
            AdvancedRepairActions    = @($advancedRepair).Count
            PerformanceTuningActions = @($tuningResults).Count
        }
    }) -Force

    if ($canLog) {
        if ($DryRun) {
            Write-NetCleanLog -Level INFO -Message ("Preview summary: WiFiWouldRemove={0} RegistryWouldRemove={1} EventLogsTouched={2} UserArtifactsTouched={3} AdvancedRepairActions={4} PerformanceTuningActions={5}" -f `
                $wifiResult.Removed,
                $artifacts.RemovedCount,
                @($logResults).Count,
                @($userResults | Where-Object { $_.Removed }).Count,
                @($advancedRepair).Count,
                @($tuningResults).Count)

            Write-NetCleanLog -Level INFO -Message 'Preview complete. No changes were made.'
        }
        else {
            Write-NetCleanLog -Level INFO -Message ("Phase 3 clean complete. WiFiRemoved={0} RegistryRemoved={1} EventLogsTouched={2} UserArtifactsTouched={3} AdvancedRepairActions={4} PerformanceTuningActions={5}" -f `
                $wifiResult.Removed,
                $artifacts.RemovedCount,
                @($logResults).Count,
                @($userResults | Where-Object { $_.Removed }).Count,
                @($advancedRepair).Count,
                @($tuningResults).Count)
        }
    }

    # Detailed logging of cleaning actions for auditability
    if ($canLog) {
        # Wi‑Fi removals
        if ($wifiResult.Profiles -and $wifiResult.Profiles.Count -gt 0) {
            foreach ($p in $wifiResult.Profiles) {
                Write-NetCleanLog -Level INFO -Message ("Wi‑Fi profile removed or would be removed: {0}" -f $p)
            }
        }

        # Registry artifact removals summary
        if ($artifacts.Results -and $artifacts.Results.Count -gt 0) {
            foreach ($r in $artifacts.Results) {
                $status = if ($r.Removed) { 'Removed' } elseif ($r.Skipped) { "Skipped: $($r.Reason)" } else { "Failed: $($r.Reason)" }
                Write-NetCleanLog -Level INFO -Message ("Registry artifact: {0} => {1}" -f $r.RegistryPath, $status)
            }
        }

        # NLA probe changes
        foreach ($n in @($nlaResults)) {
            Write-NetCleanLog -Level INFO -Message ("NLA probe property processed: {0} {1}" -f $n.Property, (if ($n.Succeeded) { 'OK' } else { "ERR: $($n.Error)" }))
        }

        # Event logs (be defensive: test for properties before accessing them)
        foreach ($l in @($logResults)) {
            $cmd = $null
            if ($l -ne $null) {
                if ($l.PSObject.Properties.Name -contains 'Command') { $cmd = $l.Command }
                elseif ($l.PSObject.Properties.Name -contains 'Name') { $cmd = $l.Name }
                elseif ($l.PSObject.Properties.Name -contains 'LogName') { $cmd = $l.LogName }
            }

            $status = '(unknown)'
            if ($l -and $l.PSObject.Properties.Name -contains 'Succeeded') {
                $status = if ($l.Succeeded) { 'OK' } else { "ERR: $($l.Error)" }
            }

            Write-NetCleanLog -Level INFO -Message ("Event log operation: {0} => {1}" -f ($cmd -or '(unknown)'), $status)
        }

        # User artifacts
        foreach ($u in @($userResults)) {
            Write-NetCleanLog -Level INFO -Message ("User artifact: {0} => {1}" -f $u.Path, (if ($u.Succeeded) { 'OK' } else { "ERR: $($u.Reason)" }))
        }

        # Advanced repair and tuning actions
        foreach ($a in @($advancedRepair)) { Write-NetCleanLog -Level INFO -Message ("Advanced repair action: {0} => ExitCode={1} Succeeded={2}" -f $a.Name, $a.ExitCode, $a.Succeeded) }
        foreach ($t in @($tuningResults)) { Write-NetCleanLog -Level INFO -Message ("Performance tuning action: {0} => ExitCode={1} Succeeded={2}" -f $t.Name, $t.ExitCode, $t.Succeeded) }
    }

    return $newContext
}

# ---------------------------------------------------------------------------
# Phase 4 - Verify helpers
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
Performs post-cleaning state verification by comparing inventories before and after cleaning.
.DESCRIPTION
Compares the pre-cleaning inventory with the post-cleaning inventory to identify any remaining protected items. Evaluates differences in AV vendors, protected interface GUIDs, and associated services. Returns a detailed report of the findings and an overall pass/fail status based on whether any protected items remain.
.PARAMETER Context
The context object containing the pre-cleaning inventory and other relevant information.
.EXAMPLE
Test-NetCleanPostState -Context $ctx
.OUTPUTS
A custom object containing the pre- and post-cleaning inventories, comparisons of vendors, GUIDs, and services, and an overall pass/fail status indicating whether protected items were successfully removed.
.NOTES
- This function assumes that the pre-cleaning inventory was accurately captured during the detect/protect phases. Ensure that those phases completed successfully for reliable verification results.
#>
function Test-NetCleanPostState {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Context
    )

    $canlog = $null -ne (Get-Command Write-NetCleanLog -ErrorAction SilentlyContinue)

    if ($canlog) { Write-NetCleanLog -Level INFO -Message 'Phase 4 verify started.' }

    $preInventory = @($Context.Inventory)
    $postInventory = @(Get-ProtectionInventory)

    $preVendors = @($preInventory | Select-Object -ExpandProperty Vendor -Unique | Sort-Object)
    $postVendors = @($postInventory | Select-Object -ExpandProperty Vendor -Unique | Sort-Object)

    $preGuids = @(Get-ProtectedInterfaceGuidSet -Inventory $preInventory)
    $postGuids = @(Get-ProtectedInterfaceGuidSet -Inventory $postInventory)

    $vendorComparison = Compare-StringSet -Before $preVendors -After $postVendors
    $guidComparison   = Compare-StringSet -Before $preGuids -After $postGuids

    $preServices = @(
        $preInventory |
        ForEach-Object { $_.Services } |
        Where-Object { $_ } |
        Sort-Object -Unique
    )

    foreach ($svc in $preServices) {
         if ($canLog) {
             Write-NetCleanLog -Level INFO -Message ("Pre-cleaning protected service: {0}" -f $svc)
         }
    }

    $postServices = @(
        $postInventory |
        ForEach-Object { $_.Services } |
        Where-Object { $_ } |
        Sort-Object -Unique
    )

    foreach ($svc in $postServices) {
         if ($canLog) {
             Write-NetCleanLog -Level INFO -Message ("Post-cleaning protected service: {0}" -f $svc)
         }
    }

    if ($canlog) { Write-NetCleanLog -Level INFO -Message 'Phase 4 verify completed (inventory gathered).' }

    $serviceComparison = Compare-StringSet -Before $preServices -After $postServices

    return [pscustomobject]@{
        PreInventory        = $preInventory
        PostInventory       = $postInventory
        VendorComparison    = $vendorComparison
        GuidComparison      = $guidComparison
        ServiceComparison   = $serviceComparison
        Passed              = (@($vendorComparison.Missing).Count -eq 0)
    }
}

<#
.SYNOPSIS
Performs verification checks after cleaning to assess the state of the system.
.DESCRIPTION
Compares the post-cleaning inventory against the pre-cleaning inventory to determine if protected items were successfully removed. Evaluates differences in AV vendors, interface GUIDs, and associated services. Returns a detailed report of the comparisons and an overall pass/fail status.
.PARAMETER Context
The context object containing the pre- and post-cleaning inventories.
.EXAMPLE
Invoke-NetCleanPhase4Verify -Context $ctx
.OUTPUTS
A context object enriched with verification results, including comparisons of vendors, GUIDs, and services, and a summary of the verification outcome.
.NOTES
- This function relies on the integrity of the inventories collected during the detect and protect phases. Ensure that those phases completed successfully for accurate verification.
#>
function Invoke-NetCleanPhase4Verify {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Context
    )

    if ($null -ne (Get-Command Write-NetCleanLog -ErrorAction SilentlyContinue)) { Write-NetCleanLog -Level INFO -Message 'Invoke-NetCleanPhase4Verify: starting verification.' }

    $verification = Test-NetCleanPostState -Context $Context

    $newContext = [pscustomobject]@{}
    foreach ($p in $Context.PSObject.Properties) {
        Add-Member -InputObject $newContext -NotePropertyName $p.Name -NotePropertyValue $p.Value
    }

    Add-Member -InputObject $newContext -NotePropertyName Phase -NotePropertyValue 'Verify' -Force
    Add-Member -InputObject $newContext -NotePropertyName Verify -NotePropertyValue ([pscustomobject]@{
        Passed = $verification.Passed
        VendorComparison  = $verification.VendorComparison
        GuidComparison    = $verification.GuidComparison
        ServiceComparison = $verification.ServiceComparison
        Summary = [pscustomobject]@{
            MissingVendorsCount  = @($verification.VendorComparison.Missing).Count
            MissingGuidCount     = @($verification.GuidComparison.Missing).Count
            MissingServiceCount  = @($verification.ServiceComparison.Missing).Count
            Passed               = $verification.Passed
        }
    }) -Force

    if ($null -ne (Get-Command Write-NetCleanLog -ErrorAction SilentlyContinue)) { Write-NetCleanLog -Level INFO -Message ('Invoke-NetCleanPhase4Verify: verification complete. Passed={0}' -f $verification.Passed) }

    # Detailed verification logging
    if ($null -ne (Get-Command Write-NetCleanLog -ErrorAction SilentlyContinue)) {
        if ($verification.VendorComparison -and $verification.VendorComparison.Missing.Count -gt 0) {
            Write-NetCleanLog -Level WARN -Message ("Verification: Missing vendors: {0}" -f ($verification.VendorComparison.Missing -join ', '))
        }
        else {
            Write-NetCleanLog -Level INFO -Message 'Verification: No missing vendors detected.'
        }

        if ($verification.GuidComparison -and $verification.GuidComparison.Missing.Count -gt 0) {
            Write-NetCleanLog -Level WARN -Message ("Verification: Missing GUIDs: {0}" -f ($verification.GuidComparison.Missing -join ', '))
        }
        else {
            Write-NetCleanLog -Level INFO -Message 'Verification: No missing protected GUIDs detected.'
        }

        if ($verification.ServiceComparison -and $verification.ServiceComparison.Missing.Count -gt 0) {
            Write-NetCleanLog -Level WARN -Message ("Verification: Missing services: {0}" -f ($verification.ServiceComparison.Missing -join ', '))
        }
        else {
            Write-NetCleanLog -Level INFO -Message 'Verification: No missing protected services detected.'
        }
    }

    # Console summary for verification
    Write-Information (("Phase 4 verify: Passed={0} MissingVendors={1} MissingGuids={2} MissingServices={3}" -f `
        $verification.Passed, @($verification.VendorComparison.Missing).Count, @($verification.GuidComparison.Missing).Count, @($verification.ServiceComparison.Missing).Count)) -InformationAction Continue

    return $newContext
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
                $wifiFound = @(Get-WiFiProfileNames)
            }

            Add-Member -InputObject $ctx.Protect.Summary -NotePropertyName WiFiProfilesFound -NotePropertyValue @($wifiFound) -Force
            Add-Member -InputObject $ctx.Protect.Summary -NotePropertyName WiFiProfilesFoundCount -NotePropertyValue $wifiFound.Count -Force

            $netProfiles = @(Get-NetworkListProfileNamess)
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
        foreach ($svc in @($item.Services))   { if ($svc) { [void]$services.Add($svc) } }
        foreach ($drv in @($item.Drivers))    { if ($drv) { [void]$drivers.Add($drv) } }
        foreach ($adp in @($item.Adapters))   { if ($adp) { [void]$adapters.Add($adp) } }
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
    'Start-NetCleanLog',
    'Write-NetCleanLog',
    'Invoke-NetCleanPhase1Detect',
    'Invoke-NetCleanPhase2Protect',
    'Invoke-NetCleanPhase3Clean',
    'Invoke-NetCleanPhase4Verify',
    'Invoke-NetCleanWorkflow',
    'Export-ProtectedRegistryKey',
    'Export-NetworkList',
    'Get-WiFiProfileNames',
    'Export-WiFiProfile',
    'Export-FirewallPolicy',
    'Export-ProtectionInventory',
    'Export-ProtectionRegistryMap',
    'Export-SanitizableNetworkArtifact',
    'Export-NetCleanManifest',
    'Remove-WiFiProfilesSafe',
    'Clear-DnsCacheSafe',
    'Clear-ArpCacheSafe',
    'Remove-RegistryPathSafe',
    'Remove-NetworkPrivacyArtifactsSafe',
    'Clear-NlaProbeStateSafe',
    'Clear-NetworkEventLogsSafe',
    'Clear-UserNetworkArtifactsSafe',
    'Invoke-AdvancedNetworkRepair',
    'Invoke-NetworkPerformanceTune',
    'Test-NetCleanPostState',
    'Get-InstalledAV',
    'Get-AVServicePattern',
    'Get-FileMetadatum',
    'Get-ProtectionList'
) -Alias @(
    'Normalize-Guid',
    'Backup-ProtectedRegistryKeys',
    'Backup-NetworkList',
    'Backup-WiFiProfiles',
    'Get-ProtectionLists',
    'Get-AVServicePatterns',
    'Export-ProtectedRegistryKeys',
    'Get-FileMetadata'
)
