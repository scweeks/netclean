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

    return $parsed.Guid.ToLowerInvariant()
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

    return @($list | Sort-Object -Unique)
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
        [Parameter()]
        [AllowNull()]
        [string]$CommandLine
    )

    if ([string]::IsNullOrWhiteSpace($CommandLine)) {
        return $null
    }

    $s = $CommandLine.Trim()

    $m = [regex]::Match($s, '^\s*"([^"]+\.(?:exe|sys|dll))"')
    if ($m.Success) { return $m.Groups[1].Value }

    $m = [regex]::Match($s, '^\s*([^\s]+\.(?:exe|sys|dll))')
    if ($m.Success) { return $m.Groups[1].Value }

    return $null
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
function Get-FileMetadatum {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()]
        [AllowNull()]
        [string]$Path
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return $null
    }

    $candidate = Get-NormalizedFilePathFromCommandLine -CommandLine $Path
    if ([string]::IsNullOrWhiteSpace($candidate)) {
        $candidate = $Path.Trim().Trim('"')
    }

    if (-not (Test-Path -LiteralPath $candidate)) {
        return $null
    }

    try {
        $item = Get-Item -LiteralPath $candidate -ErrorAction Stop
        $ver = $item.VersionInfo
        $sig = Get-AuthenticodeSignature -FilePath $candidate -ErrorAction SilentlyContinue

        $signerSubject = $null
        $signerIssuer = $null
        $signerThumbprint = $null
        $signatureStatus = $null

        if ($sig) {
            $signatureStatus = $sig.Status.ToString()
            if ($sig.SignerCertificate) {
                $signerSubject    = $sig.SignerCertificate.Subject
                $signerIssuer     = $sig.SignerCertificate.Issuer
                $signerThumbprint = $sig.SignerCertificate.Thumbprint
            }
        }

        $inferredVendor = Resolve-VendorFromText -Text @(
            $ver.CompanyName,
            $ver.ProductName,
            $ver.FileDescription,
            $signerSubject,
            $signerIssuer,
            $item.Name
        )

        return [pscustomobject]@{
            Path             = $item.FullName
            CompanyName      = $ver.CompanyName
            FileDescription  = $ver.FileDescription
            ProductName      = $ver.ProductName
            FileVersion      = $ver.FileVersion
            OriginalFilename = $ver.OriginalFilename
            SignerSubject    = $signerSubject
            SignerIssuer     = $signerIssuer
            SignerThumbprint = $signerThumbprint
            SignatureStatus  = $signatureStatus
            InferredVendor   = $inferredVendor
        }
    }
    catch {
        return $null
    }
}

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

    return @($results | Sort-Object Name -Unique)
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

    $results = New-Object System.Collections.Generic.List[object]
    $classRoot = 'HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e974-e325-11ce-bfc1-08002be10318}'

    foreach ($child in @(Get-RegistryChildKeyNamesSafe -RegistryPath $classRoot)) {
        if ($child -notmatch '^\d{4}$') { continue }

        $path = "$classRoot\$child"
        $props = Get-RegistryValuesSafe -RegistryPath $path
        if ($null -eq $props) { continue }

        $text = @(
            $props.ComponentId,
            $props.DriverDesc,
            $props.ProviderName,
            $props.MatchingDeviceId,
            $props.FilterClass,
            $props.Characteristic
        ) | Where-Object { $_ }

        if (@($text).Count -eq 0) { continue }

        $vendor = Resolve-VendorFromText -Text $text

        $results.Add([pscustomobject]@{
            Source               = 'NDIS'
            ProductClass         = 'NdisFilterClass'
            Name                 = ($text -join ' | ')
            DisplayName          = $props.DriverDesc
            Path                 = $null
            Publisher            = $props.ProviderName
            InstallPath          = $null
            InterfaceDescription = $props.DriverDesc
            Manufacturer         = $props.ProviderName
            CompanyName          = $props.ProviderName
            FileDescription      = $props.DriverDesc
            ProductName          = $props.ComponentId
            SignerSubject        = $null
            InferredVendor       = $vendor
            RegistryPath         = $path
            ComponentId          = $props.ComponentId
            Instance             = $props
        })
    }

    return @($results)
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
        $tokens.Add($svcName)

        if ($props) {
            if ($props.DisplayName) { $tokens.Add($props.DisplayName) }
            if ($props.Group)       { $tokens.Add($props.Group) }
        }

        if ($linkage) {
            if ($linkage.Bind)   { $tokens.Add($linkage.Bind) }
            if ($linkage.Export) { $tokens.Add($linkage.Export) }
            if ($linkage.Route)  { $tokens.Add($linkage.Route) }
        }

        $tokens = @($tokens | Where-Object { $_ })

        if (@($tokens).Count -eq 0) { continue }

        $joined = ($tokens | ForEach-Object { $_.ToString() }) -join ' '
        $vendor = Resolve-VendorFromText -Text @($joined)

        if ($joined.ToLowerInvariant() -match 'ndis|filter|lwf|wfp|vpn|fw|firewall|net|vmswitch|vmnet|vbox|vethernet|packet|inspect|falcon|sentinel|zscaler|globalprotect|forti|anyconnect') {
            $results.Add([pscustomobject]@{
                Source               = 'NDIS'
                ProductClass         = 'NdisServiceBinding'
                Name                 = $svcName
                DisplayName          = if ($props) { $props.DisplayName } else { $svcName }
                Path                 = if ($props) { $props.ImagePath } else { $null }
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

    return @($results)
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

    $results = New-Object System.Collections.Generic.List[object]

    foreach ($root in @(
        'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products',
        'HKLM\SOFTWARE\Classes\Installer\Products'
    )) {
        foreach ($child in @(Get-RegistryChildKeyNamesSafe -RegistryPath $root)) {
            $productPath = "$root\$child\InstallProperties"
            $props = Get-RegistryValuesSafe -RegistryPath $productPath
            if ($null -eq $props) { continue }

            if ([string]::IsNullOrWhiteSpace($props.DisplayName)) { continue }

            $vendor = Resolve-VendorFromText -Text @(
                $props.DisplayName,
                $props.Publisher,
                $props.InstallLocation,
                $props.UninstallString
            )

            $results.Add([pscustomobject]@{
                Source               = 'MSI'
                ProductClass         = 'MsiProduct'
                Name                 = $props.DisplayName
                DisplayName          = $props.DisplayName
                Path                 = $null
                Publisher            = $props.Publisher
                InstallPath          = $props.InstallLocation
                InterfaceDescription = $null
                Manufacturer         = $props.Publisher
                CompanyName          = $props.Publisher
                FileDescription      = $null
                ProductName          = $props.DisplayName
                SignerSubject        = $null
                InferredVendor       = $vendor
                RegistryPath         = $productPath
                Instance             = $props
            })
        }
    }

    return @($results | Sort-Object Name -Unique)
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

    return @($results)
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

    return @($results)
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

    return @($results)
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
            $meta = Get-FileMetadata -Path $item.pathToSignedProductExe
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
            $meta = Get-FileMetadata -Path $item.pathToSignedProductExe
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
            $meta = Get-FileMetadata -Path $svc.PathName
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
            $meta = Get-FileMetadata -Path $drv.PathName
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
                        $meta = Get-FileMetadata -Path $_.DisplayIcon
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
            $meta = Get-FileMetadata -Path $imagePath

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

    return @($evidence)
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

        $entry = [ordered]@{
            Name          = $svcName
            RegistryPath  = $svcPath
            ImagePath     = if ($props) { $props.ImagePath } else { $null }
            DisplayName   = if ($props) { $props.DisplayName } else { $null }
            Type          = if ($props) { $props.Type } else { $null }
            Start         = if ($props) { $props.Start } else { $null }
            Group         = if ($props) { $props.Group } else { $null }
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

    return @($results)
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

        Add-HashSetValues -Set $categories -Values $signature.Categories
        Add-HashSetValues -Set $registryKeys -Values $signature.RegistryRoots

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
                Add-HashSetValues -Set $registryKeys -Values (Get-VendorRootsFromInstallPath -InstallPath $item.InstallPath)
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

                $imgMeta = Get-FileMetadata -Path $svcInfo.ImagePath
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

    return @($inventory | Sort-Object Vendor)
}

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
        Add-HashSetValues -Set $keys -Values $item.RegistryKeys

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

    return @($result | Sort-Object Vendor)
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

    return @($set | Sort-Object)
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
    Add-HashSetValues -Set $protectedGuidSet -Values $protectedGuids

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
            if (Test-s -RegistryPath $path) {
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

    return @($candidates)
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
    [OutputType([System.Object[]])]
    param()

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

    return [pscustomobject]@{
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

        $key = Convert-RegKeyPath -Path $pathItem
        $safe = ($key -replace '[^a-zA-Z0-9_.-]', '_')
        $file = Join-Path $Dest ("reg_backup_{0}_{1}.reg" -f $safe, (Get-Date -Format 'yyyyMMdd_HHmmss'))

        $result = Invoke-RegExport -Key $key -FilePath $file -DryRun:$DryRun
        [void]$exported.Add($result)
    }

    return @($exported.ToArray())
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
Return Wi‑Fi profile names present on the system.
.DESCRIPTION
Parses `netsh wlan show profiles` output to extract profile names; returns an empty list if none found.
.OUTPUTS
Array of Wi‑Fi profile name strings.
#>
function Get-WiFiProfileName {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param()

    $lines = netsh wlan show profiles 2>$null
    if (-not $lines) {
        return @()
    }

    $profiles = New-Object System.Collections.Generic.List[string]

    foreach ($line in $lines) {
        $m = [regex]::Match($line, ':\s*(.+)$')
        if ($m.Success) {
            $value = $m.Groups[1].Value.Trim()
            if ([string]::IsNullOrWhiteSpace($value)) { continue }

            $lc = $line.ToLowerInvariant()
            if ($lc -like '*profile*' -or $lc -like '*profil*' -or $lc -like '*perfil*' -or $lc -like '*профил*' -or $lc -like '*配置文件*') {
                [void]$profiles.Add($value)
            }
        }
    }

    return @($profiles | Sort-Object -Unique)
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

    $exported = New-Object System.Collections.Generic.List[string]
    New-DirectoryIfNotExist -Path $Dest

    $listFile = Join-Path $Dest ("WiFiProfiles_{0}.txt" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
    $profiles = @(Get-WiFiProfileName)

    if ($profiles.Count -eq 0) {
        return @()
    }

    if ($DryRun) {
        [void]$exported.Add($listFile)
        foreach ($wifiProfile in $profiles) {
            [void]$exported.Add("PROFILE:$wifiProfile")
        }
        return @($exported)
    }

    $profiles | Out-File -FilePath $listFile -Encoding UTF8
    [void]$exported.Add($listFile)

    foreach ($wifiProfile in $profiles) {
        $before = @(Get-ChildItem -Path $Dest -Filter '*.xml' -File -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName)
        & netsh wlan export profile name="$wifiProfile" folder="$Dest" key=clear 2>&1 | Out-Null
        $after = @(Get-ChildItem -Path $Dest -Filter '*.xml' -File -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName)
        $newFiles = @($after | Where-Object { $_ -notin $before })

        foreach ($newFile in $newFiles) {
            [void]$exported.Add($newFile)
        }
    }

    return @($exported)
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
    [OutputType([System.Object[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Dest,

        [switch]$DryRun
    )

    New-DirectoryIfNotExist -Path $Dest
    $file = Join-Path $Dest ("FirewallPolicy_{0}.wfw" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))

    $result = Invoke-ExternalCommandSafe -Name 'Export firewall policy' -FilePath 'netsh.exe' -ArgumentList @('advfirewall', 'export', "`"$file`"") -DryRun:$DryRun
    if (-not $result.Succeeded) {
        throw $result.Error
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

    New-DirectoryIfNotExist -Path $Dest

    if ($null -eq $Inventory -or @($Inventory).Count -eq 0) {
        $Inventory = @(Get-ProtectionInventory)
    }

    $file = Join-Path $Dest ("ProtectionInventory_{0}.json" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))

    if (-not $DryRun) {
        $Inventory | ConvertTo-Json -Depth 8 | Out-File -FilePath $file -Encoding UTF8
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

    New-DirectoryIfNotExist -Path $Dest

    $map = @(Get-ProtectionRegistryMap -Inventory $Inventory)
    $file = Join-Path $Dest ("ProtectionRegistryMap_{0}.json" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))

    if (-not $DryRun) {
        $map | ConvertTo-Json -Depth 8 | Out-File -FilePath $file -Encoding UTF8
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

    New-DirectoryIfNotExist -Path $Dest

    $artifacts = @(Get-SanitizableNetworkArtifact -Inventory $Inventory)
    $file = Join-Path $Dest ("SanitizableNetworkArtifact_{0}.json" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))

    if (-not $DryRun) {
        $artifacts | ConvertTo-Json -Depth 8 | Out-File -FilePath $file -Encoding UTF8
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

    New-DirectoryIfNotExist -Path $Dest
    $file = Join-Path $Dest ("RestoreManifest_{0}.json" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))

    if (-not $DryRun) {
        $Manifest | ConvertTo-Json -Depth 8 | Out-File -FilePath $file -Encoding UTF8
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
    [OutputType([System.Object[]])]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Context,

        [Parameter(Mandatory = $true)]
        [string]$BackupPath,

        [switch]$DryRun,
        [switch]$SkipFirewallBackup
    )

    New-DirectoryIfNotExist -Path $BackupPath

    $inventory = @($Context.Inventory)
    $protectedPaths = @($Context.ProtectedRegistryPaths | Sort-Object -Unique)

    $manifest = @{
        ModuleVersion               = $script:NetCleanModuleVersion
        BackupPath                  = $BackupPath
        CreatedAt                   = (Get-Date).ToString('s')
        ProtectionInventoryJson     = $null
        ProtectionRegistryMapJson   = $null
        SanitizableArtifactsJson    = $null
        FirewallPolicyBackup        = $null
        NetworkListBackup           = $null
        WiFiExports                 = @()
        ProtectedRegistryBackups    = @()
    }

    $manifest.ProtectionInventoryJson   = Export-ProtectionInventory -Dest $BackupPath -Inventory $inventory -DryRun:$DryRun
    $manifest.ProtectionRegistryMapJson = Export-ProtectionRegistryMap -Dest $BackupPath -Inventory $inventory -DryRun:$DryRun
    $manifest.SanitizableArtifactsJson  = Export-SanitizableNetworkArtifact -Dest $BackupPath -Inventory $inventory -DryRun:$DryRun
    $manifest.NetworkListBackup         = Export-NetworkList -Dest $BackupPath -DryRun:$DryRun
    $manifest.WiFiExports               = @(Export-WiFiProfile -Dest $BackupPath -DryRun:$DryRun)

    if (-not $SkipFirewallBackup) {
        try {
            $manifest.FirewallPolicyBackup = Export-FirewallPolicy -Dest $BackupPath -DryRun:$DryRun
        }
        catch {
            $manifest.FirewallPolicyBackup = $null
        }
    }

    if ($protectedPaths.Count -gt 0) {
        $manifest.ProtectedRegistryBackups = @(Export-ProtectedRegistryKey -Paths $protectedPaths -Dest $BackupPath -DryRun:$DryRun)
    }

    $manifestFile = Export-NetCleanManifest -Dest $BackupPath -Manifest $manifest -DryRun:$DryRun

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
            ProtectedRegistryPathCount = $protectedPaths.Count
            WiFiBackupCount            = @($manifest.WiFiExports).Count
            ProtectedRegistryBackupCount = @($manifest.ProtectedRegistryBackups).Count
        }
    }) -Force

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
    [OutputType([System.Object[]])]
    param(
        [switch]$DryRun
    )

    $profiles = @(Get-WiFiProfileName)
    $removed = New-Object System.Collections.Generic.List[string]
    $operations = New-Object System.Collections.Generic.List[object]

    foreach ($wifiProfile in $profiles) {
        if (-not ($DryRun -or $PSCmdlet.ShouldProcess("Wi-Fi profile '$wifiProfile'", 'Delete'))) {
            $operations.Add([pscustomobject]@{ Name = $wifiProfile; Succeeded = $false; Skipped = $true; Reason = 'WhatIf' })
            continue
        }

        $result = Invoke-ExternalCommandSafe -Name "Delete Wi-Fi profile $wifiProfile" -FilePath 'netsh.exe' -ArgumentList @('wlan', 'delete', 'profile', ('name="' + $wifiProfile + '"')) -DryRun:$DryRun
        $operations.Add($result)

        if ($result.Succeeded) {
            [void]$removed.Add($wifiProfile)
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
    [OutputType([System.Object[]])]
    param(
        [switch]$DryRun
    )

    if (-not ($DryRun -or $PSCmdlet.ShouldProcess('DNS cache', 'Flush'))) {
        return [pscustomobject]@{ Name = 'Flush DNS cache'; Succeeded = $false; Skipped = $true; Reason = 'WhatIf' }
    }

    return Invoke-ExternalCommandSafe -Name 'Flush DNS cache' -FilePath 'ipconfig.exe' -ArgumentList @('/flushdns') -DryRun:$DryRun
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
    [OutputType([System.Object[]])]
    param(
        [switch]$DryRun
    )

    if (-not ($DryRun -or $PSCmdlet.ShouldProcess('ARP cache', 'Clear'))) {
        return [pscustomobject]@{ Name = 'Clear ARP cache'; Succeeded = $false; Skipped = $true; Reason = 'WhatIf' }
    }

    return Invoke-ExternalCommandSafe -Name 'Clear ARP cache' -FilePath 'arp.exe' -ArgumentList @('-d', '*') -DryRun:$DryRun -IgnoreExitCode
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
    [OutputType([System.Object[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$RegistryPath,

        [Parameter(Mandatory = $true)]
        [pscustomobject]$Context,

        [switch]$DryRun
    )

    if (Test-RegistryPathProtected -Path $RegistryPath -Context $Context) {
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
        return [pscustomobject]@{
            RegistryPath = $RegistryPath
            Removed      = $false
            Skipped      = $true
            Reason       = 'InvalidPath'
            DryRun       = [bool]$DryRun
        }
    }

    if (-not (Test-Path -LiteralPath $providerPath)) {
        return [pscustomobject]@{
            RegistryPath = $RegistryPath
            Removed      = $false
            Skipped      = $true
            Reason       = 'NotFound'
            DryRun       = [bool]$DryRun
        }
    }

    if ($DryRun) {
        return [pscustomobject]@{
            RegistryPath = $RegistryPath
            Removed      = $true
            Skipped      = $false
            Reason       = 'DryRun'
            DryRun       = $true
        }
    }

    if (-not $PSCmdlet.ShouldProcess($RegistryPath, 'Remove registry path')) {
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
        return [pscustomobject]@{
            RegistryPath = $RegistryPath
            Removed      = $true
            Skipped      = $false
            Reason       = 'Removed'
            DryRun       = $false
        }
    }
    catch {
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
    [OutputType([System.Object[]])]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Context,

        [switch]$DryRun
    )

    $artifacts = @($Context.SanitizableArtifacts)
    $results = New-Object System.Collections.Generic.List[object]

    foreach ($artifact in $artifacts) {
        if (-not $artifact.RegistryPath) { continue }
        $results.Add((Remove-RegistryPathSafe -RegistryPath $artifact.RegistryPath -Context $Context -DryRun:$DryRun))
    }

    return [pscustomobject]@{
        TotalCandidates = $artifacts.Count
        RemovedCount    = @($results | Where-Object { $_.Removed }).Count
        SkippedCount    = @($results | Where-Object { $_.Skipped }).Count
        Results         = @($results)
    }
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
            $results.Add([pscustomobject]@{
                Path      = $nlaInternetPath
                Property  = $property
                Removed   = $true
                DryRun    = $false
                Succeeded = $true
            })
        }
        catch {
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

    return @($results)
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
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param(
        [switch]$DryRun
    )

    $logs = @(
        'Microsoft-Windows-WLAN-AutoConfig/Operational',
        'Microsoft-Windows-NetworkProfile/Operational',
        'Microsoft-Windows-DHCP-Client/Operational'
    )

    $results = New-Object System.Collections.Generic.List[object]

    foreach ($log in $logs) {
        $results.Add((Invoke-ExternalCommandSafe -Name "Clear event log $log" -FilePath 'wevtutil.exe' -ArgumentList @('cl', $log) -DryRun:$DryRun -IgnoreExitCode))
    }

    return @($results)
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
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param(
        [switch]$DryRun
    )

    $candidatePaths = @(
        'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Map Network Drive MRU',
        'Registry::HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client\Default',
        'Registry::HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client\Servers'
    )

    $results = New-Object System.Collections.Generic.List[object]

    foreach ($path in $candidatePaths) {
        if (-not (Test-Path -LiteralPath $path)) {
            $results.Add([pscustomobject]@{
                Path      = $path
                Removed   = $false
                DryRun    = [bool]$DryRun
                Succeeded = $true
                Reason    = 'NotFound'
            })
            continue
        }

        if ($DryRun) {
            $results.Add([pscustomobject]@{
                Path      = $path
                Removed   = $true
                DryRun    = $true
                Succeeded = $true
                Reason    = 'DryRun'
            })
            continue
        }

        try {
            Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction Stop
            $results.Add([pscustomobject]@{
                Path      = $path
                Removed   = $true
                DryRun    = $false
                Succeeded = $true
                Reason    = 'Removed'
            })
        }
        catch {
            $results.Add([pscustomobject]@{
                Path      = $path
                Removed   = $false
                DryRun    = $false
                Succeeded = $false
                Reason    = $_.Exception.Message
            })
        }
    }

    return @($results)
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
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param(
        [switch]$DryRun
    )

    $commands = @(
        @{ Name = 'Reset Winsock'; File = 'netsh.exe'; Args = @('winsock', 'reset') },
        @{ Name = 'Reset IPv4';    File = 'netsh.exe'; Args = @('int', 'ip', 'reset') },
        @{ Name = 'Reset IPv6';    File = 'netsh.exe'; Args = @('int', 'ipv6', 'reset') }
    )

    $results = New-Object System.Collections.Generic.List[object]

    foreach ($cmd in $commands) {
        $results.Add((Invoke-ExternalCommandSafe -Name $cmd.Name -FilePath $cmd.File -ArgumentList $cmd.Args -DryRun:$DryRun))
    }

    return @($results)
}


<#
.SYNOPSIS
Performs conservative performance tuning by enabling normal autotuning, RSS, and ECN.

.DESCRIPTION
Executes a set of commands to enable normal autotuning, Receive Side Scaling (RSS), and Explicit Congestion Notification (ECN) capability. These settings can improve network performance in many scenarios while maintaining broad compatibility. Honors `-DryRun` to simulate actions without making changes.

.PARAMETER DryRun
If specified, all operations are simulated and no actual changes are made to the system. Results will indicate what would have been done.

.EXAMPLE
Invoke-ConservativePerformanceTune -DryRun

.OUTPUTS
An array of results for each performance tuning command executed, indicating the name of the command, whether it succeeded, if it was a dry run, and any error messages if applicable.

.NOTES
- These performance tuning steps are generally safe and can provide benefits in typical network environments, but results may vary based on specific hardware and drivers.
#>
function Invoke-ConservativePerformanceTune {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param(
        [switch]$DryRun
    )

    $commands = @(
        @{
            Name = 'Enable normal autotuning'
            File = 'netsh.exe'
            Args = @('int', 'tcp', 'set', 'global', 'autotuninglevel=normal')
        },
        @{
            Name = 'Enable RSS'
            File = 'netsh.exe'
            Args = @('int', 'tcp', 'set', 'global', 'rss=enabled')
        },
        @{
            Name = 'Enable ECN capability'
            File = 'netsh.exe'
            Args = @('int', 'tcp', 'set', 'global', 'ecncapability=enabled')
        }
    )

    $results = New-Object System.Collections.Generic.List[object]

    foreach ($cmd in $commands) {
        $results.Add((Invoke-ExternalCommandSafe -Name $cmd.Name -FilePath $cmd.File -ArgumentList $cmd.Args -DryRun:$DryRun -IgnoreExitCode))
    }

    return @($results)
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
    [CmdletBinding()]
    [OutputType([System.Object[]])]
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

    $newContext = [pscustomobject]@{}
    foreach ($p in $Context.PSObject.Properties) {
        Add-Member -InputObject $newContext -NotePropertyName $p.Name -NotePropertyValue $p.Value
    }

    $wifiResult = if ($SkipWifi) { [pscustomobject]@{ Removed = 0; Profiles = @(); Operations = @() } } else { Remove-WiFiProfilesSafe -DryRun:$DryRun }
    $dnsResult  = if ($SkipDnsFlush) { [pscustomobject]@{ Name = 'Flush DNS cache'; Succeeded = $true; DryRun = [bool]$DryRun; Skipped = $true } } else { Clear-DnsCacheSafe -DryRun:$DryRun }
    $arpResult  = Clear-ArpCacheSafe -DryRun:$DryRun
    $artifacts  = Remove-NetworkPrivacyArtifactsSafe -Context $newContext -DryRun:$DryRun
    $nlaResults = Clear-NlaProbeStateSafe -DryRun:$DryRun
    $logResults = if ($SkipEventLogs) { @() } else { @(Clear-NetworkEventLogsSafe -DryRun:$DryRun) }
    $userResults= if ($SkipUserArtifacts) { @() } else { @(Clear-UserNetworkArtifactsSafe -DryRun:$DryRun) }

    $advancedRepair = @()
    if ($Mode -eq 'AdvancedRepair') {
        $advancedRepair = @(Invoke-AdvancedNetworkRepair -DryRun:$DryRun)
    }

    $tuningResults = @()
    if ($Mode -eq 'PerformanceTune' -or $EnableConservativePerformanceTuning) {
        $tuningResults = @(Invoke-ConservativePerformanceTune -DryRun:$DryRun)
    }

    Add-Member -InputObject $newContext -NotePropertyName Phase -NotePropertyValue 'Clean' -Force
    Add-Member -InputObject $newContext -NotePropertyName Clean -NotePropertyValue ([pscustomobject]@{
        Mode                    = $Mode
        WiFi                    = $wifiResult
        Dns                     = $dnsResult
        Arp                     = $arpResult
        RegistryArtifacts       = $artifacts
        Nla                     = @($nlaResults)
        EventLogs               = @($logResults)
        UserArtifacts           = @($userResults)
        AdvancedRepair          = @($advancedRepair)
        PerformanceTuning       = @($tuningResults)
        Summary                 = [pscustomobject]@{
            WiFiProfilesRemoved      = $wifiResult.Removed
            RegistryArtifactsRemoved = $artifacts.RemovedCount
            EventLogsTouched         = @($logResults).Count
            UserArtifactsTouched     = @($userResults | Where-Object { $_.Removed }).Count
            AdvancedRepairActions    = @($advancedRepair).Count
            PerformanceTuningActions = @($tuningResults).Count
        }
    }) -Force

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

    $postServices = @(
        $postInventory |
        ForEach-Object { $_.Services } |
        Where-Object { $_ } |
        Sort-Object -Unique
    )

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
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param(
        [ValidateSet('Preview', 'SafeConferencePrep', 'AdvancedRepair', 'PerformanceTune')]
        [string]$Mode = 'SafeConferencePrep',

        [string]$BackupPath = "$env:ProgramData\NetClean\Backups",

        [switch]$DryRun,
        [switch]$SkipWifi,
        [switch]$SkipDnsFlush,
        [switch]$SkipEventLogs,
        [switch]$SkipUserArtifacts,
        [switch]$SkipFirewallBackup,
        [switch]$EnableConservativePerformanceTuning
    )

    $ctx = Invoke-NetCleanPhase1Detect
    $ctx = Invoke-NetCleanPhase2Protect -Context $ctx -BackupPath $BackupPath -DryRun:$DryRun -SkipFirewallBackup:$SkipFirewallBackup

    if ($Mode -eq 'Preview') {
        return $ctx
    }

    $ctx = Invoke-NetCleanPhase3Clean -Context $ctx -Mode $Mode -DryRun:$DryRun -SkipWifi:$SkipWifi -SkipDnsFlush:$SkipDnsFlush -SkipEventLogs:$SkipEventLogs -SkipUserArtifacts:$SkipUserArtifacts -EnableConservativePerformanceTuning:$EnableConservativePerformanceTuning
    $ctx = Invoke-NetCleanPhase4Verify -Context $ctx
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
    'Convert-RegKeyPath',
    'Convert-Guid',
    'Get-NormalizedFilePathFromCommandLine',
    'Get-UniqueNonEmptyString',
    'Test-RegistryPathExist',
    'Get-RegistryValuesSafe',
    'Get-RegistryChildKeyNamesSafe',
    'Add-HashSetValue',
    'Compare-StringSet',
    'New-DirectoryIfNotExist',
    'Convert-RegToProviderPath',
    'Resolve-VendorFromText',
    'Get-VendorSignature',
    'Get-WfpStateEvidence',
    'Get-NdisFilterClassEvidence',
    'Get-NdisServiceBindingEvidence',
    'Get-MsiRegistryEvidence',
    'Get-InfFileEvidence',
    'Get-ScheduledTaskEvidence',
    'Get-AppxPackageEvidence',
    'Get-ProtectionEvidence',
    'Get-ProtectionInventory',
    'Get-ProtectionRegistryMap',
    'Get-ProtectedInterfaceGuidSet',
    'Get-NetworkPrivacyArtifactCandidate',
    'Get-SanitizableNetworkArtifact',
    'Invoke-NetCleanPhase1Detect',
    'Export-ProtectedRegistryKey',
    'Export-NetworkList',
    'Get-WiFiProfileName',
    'Export-WiFiProfile',
    'Export-FirewallPolicy',
    'Export-ProtectionInventory',
    'Export-ProtectionRegistryMap',
    'Export-SanitizableNetworkArtifact',
    'Export-NetCleanManifest',
    'Invoke-NetCleanPhase2Protect',
    'Remove-WiFiProfilesSafe',
    'Clear-DnsCacheSafe',
    'Clear-ArpCacheSafe',
    'Remove-RegistryPathSafe',
    'Remove-NetworkPrivacyArtifactsSafe',
    'Clear-NlaProbeStateSafe',
    'Clear-NetworkEventLogsSafe',
    'Clear-UserNetworkArtifactsSafe',
    'Invoke-AdvancedNetworkRepair',
    'Invoke-ConservativePerformanceTune',
    'Invoke-NetCleanPhase3Clean',
    'Test-NetCleanPostState',
    'Invoke-NetCleanPhase4Verify',
    'Invoke-NetCleanWorkflow',
    'Get-InstalledAV',
    'Get-AVServicePattern',
    'Get-ProtectionList'
) -Alias @(
    'Convert-NormalizeGuid',
    'Normalize-Guid',
    'Derive-AVServicePatterns',
    'Build-ProtectionLists',
    'Backup-ProtectedRegistryKeys',
    'Backup-NetworkList',
    'Backup-WiFiProfiles',
    'Get-ProtectionLists',
    'Get-AVServicePatterns',
    'Export-ProtectedRegistryKeys'
)