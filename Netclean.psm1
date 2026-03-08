# NetClean PowerShell module
# Phase-oriented engine for:
# - Detect
# - Protect
# - Clean
# - Verify
#
# Goal:
# Remove user/environment-identifying network history and metadata while
# preserving required security, virtualization, firewall, VPN, and network
# infrastructure software.
#
# Notes:
# - Best fidelity requires administrative privileges
# - The default workflow is intentionally conservative
# - Advanced repair and performance tuning are opt-in
# - This module favors explainability, backup, and verification

Set-StrictMode -Version Latest
$script:NetCleanModuleVersion = '1.0.0'

# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

function Convert-RegKeyPath {
    [CmdletBinding()]
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

function Convert-Guid {
    [CmdletBinding()]
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

function Convert-RegToProviderPath {
    [CmdletBinding()]
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

function Test-RegistryPathExists {
    [CmdletBinding()]
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

function Get-RegistryValuesSafe {
    [CmdletBinding()]
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

function Get-RegistryChildKeyNamesSafe {
    [CmdletBinding()]
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

function Get-UniqueNonEmptyStrings {
    [CmdletBinding()]
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

function Add-HashSetValues {
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

function Compare-StringSets {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        [string[]]$Before,

        [Parameter()]
        [AllowNull()]
        [string[]]$After
    )

    $beforeSet = @(Get-UniqueNonEmptyStrings -InputObject $Before)
    $afterSet  = @(Get-UniqueNonEmptyStrings -InputObject $After)

    return [pscustomobject]@{
        Before  = $beforeSet
        After   = $afterSet
        Missing = @($beforeSet | Where-Object { $_ -notin $afterSet })
        Added   = @($afterSet  | Where-Object { $_ -notin $beforeSet })
    }
}

function Ensure-Directory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -Path $Path -ItemType Directory -Force | Out-Null
    }
}

function Get-NormalizedFilePathFromCommandLine {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        [string]$CommandLine
    )

    if ([string]::IsNullOrWhiteSpace($CommandLine)) {
        return $null
    }

    $s = $CommandLine.Trim()

    if ($s -match '^\s*"([^"]+\.(?:exe|sys|dll))"') {
        return $matches[1]
    }

    if ($s -match '^\s*([^\s]+\.(?:exe|sys|dll))') {
        return $matches[1]
    }

    return $null
}

function Resolve-VendorFromText {
    [CmdletBinding()]
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

function Get-FileMetadata {
    [CmdletBinding()]
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

function Get-VendorRootsFromInstallPath {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        [string]$InstallPath
    )

    if ([string]::IsNullOrWhiteSpace($InstallPath)) {
        return @()
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

    return Get-UniqueNonEmptyStrings -InputObject $roots
}

function Invoke-ExternalCommandSafe {
    [CmdletBinding()]
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

function Test-RegistryPathProtected {
    [CmdletBinding()]
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

function Get-VendorSignatures {
    [CmdletBinding()]
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

function Get-WfpStateEvidence {
    [CmdletBinding()]
    param()

    $results = New-Object System.Collections.Generic.List[object]
    $tempFile = Join-Path $env:TEMP ("netclean_wfp_{0}.xml" -f ([guid]::NewGuid().Guid))

    try {
        & netsh wfp show state file="$tempFile" 2>$null | Out-Null

        if (-not (Test-Path -LiteralPath $tempFile)) {
            return @()
        }

        [xml]$xml = Get-Content -LiteralPath $tempFile -Raw -ErrorAction Stop
        $allNodes = @()

        if ($xml -and $xml.DocumentElement) {
            $allNodes = $xml.SelectNodes('//*')
        }

        foreach ($node in @($allNodes)) {
            $textParts = @()

            foreach ($prop in @('displayData', 'name', 'description', 'serviceName', 'providerKey', 'calloutKey', 'layerKey')) {
                try {
                    $value = $node.$prop
                    if ($value) {
                        $textParts += ($value | Out-String).Trim()
                    }
                }
                catch {
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

function Get-NdisFilterClassEvidence {
    [CmdletBinding()]
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

function Get-NdisServiceBindingEvidence {
    [CmdletBinding()]
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

function Get-MsiRegistryEvidence {
    [CmdletBinding()]
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

function Get-InfFileEvidence {
    [CmdletBinding()]
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
                    if (-not $provider -and $line -match '^\s*Provider\s*=\s*(.+)$') {
                        $provider = $matches[1].Trim().Trim('"').Trim('%')
                    }
                    elseif (-not $manufacturer -and $line -match '^\s*Manufacturer\s*=\s*(.+)$') {
                        $manufacturer = $matches[1].Trim().Trim('"').Trim('%')
                    }
                    elseif (-not $class -and $line -match '^\s*Class\s*=\s*(.+)$') {
                        $class = $matches[1].Trim().Trim('"')
                    }
                    elseif (-not $classGuid -and $line -match '^\s*ClassGuid\s*=\s*(.+)$') {
                        $classGuid = $matches[1].Trim().Trim('"')
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
            }
        }
    }

    return @($results)
}

function Get-ScheduledTaskEvidence {
    [CmdletBinding()]
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

function Get-AppxPackageEvidence {
    [CmdletBinding()]
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

function Get-ProtectionEvidence {
    [CmdletBinding()]
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
            EnumPath      = if (Test-RegistryPathExists -RegistryPath "$svcPath\Enum") { "$svcPath\Enum" } else { $null }
            LinkagePath   = if (Test-RegistryPathExists -RegistryPath "$svcPath\Linkage") { "$svcPath\Linkage" } else { $null }
            ParamsPath    = if (Test-RegistryPathExists -RegistryPath "$svcPath\Parameters") { "$svcPath\Parameters" } else { $null }
            InstancesPath = if (Test-RegistryPathExists -RegistryPath "$svcPath\Instances") { "$svcPath\Instances" } else { $null }
        }

        $map[$svcName.ToLowerInvariant()] = [pscustomobject]$entry
    }

    return $map
}

function Get-AdapterRegistryCorrelation {
    [CmdletBinding()]
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

            if (Test-RegistryPathExists -RegistryPath $candidateNetwork)   { $networkPath = $candidateNetwork }
            if (Test-RegistryPathExists -RegistryPath $candidateConnection){ $connectionPath = $candidateConnection }
            if (Test-RegistryPathExists -RegistryPath $candidateInterface) { $interfacePath = $candidateInterface }

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

function Get-ProtectionInventory {
    [CmdletBinding()]
    param()

    $evidence = @(Get-ProtectionEvidence)
    $signatures = Get-VendorSignatures
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

function Get-ProtectionRegistryMap {
    [CmdletBinding()]
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
                if (Test-RegistryPathExists -RegistryPath $candidate) {
                    [void]$keys.Add($candidate)
                }
            }
        }

        foreach ($drv in @($item.Drivers)) {
            [void]$keys.Add("HKLM\SYSTEM\CurrentControlSet\Services\$drv")
            foreach ($suffix in @('Parameters', 'Linkage', 'Enum', 'Instances')) {
                $candidate = "HKLM\SYSTEM\CurrentControlSet\Services\$drv\$suffix"
                if (Test-RegistryPathExists -RegistryPath $candidate) {
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
                if (Test-RegistryPathExists -RegistryPath $candidate) {
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

function Get-ProtectedInterfaceGuidSet {
    [CmdletBinding()]
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

function Get-NetworkPrivacyArtifactCandidates {
    [CmdletBinding()]
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
        if (Test-RegistryPathExists -RegistryPath $path) {
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
            if (Test-RegistryPathExists -RegistryPath $path) {
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

function Get-SanitizableNetworkArtifacts {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        [object[]]$Inventory
    )

    if ($null -eq $Inventory -or @($Inventory).Count -eq 0) {
        $Inventory = @(Get-ProtectionInventory)
    }

    return @(Get-NetworkPrivacyArtifactCandidates -Inventory $Inventory | Where-Object { -not $_.IsProtected })
}

function Invoke-NetCleanPhase1Detect {
    [CmdletBinding()]
    param()

    $inventory = @(Get-ProtectionInventory)
    $protectionMap = @(Get-ProtectionRegistryMap -Inventory $inventory)
    $protectedGuids = @(Get-ProtectedInterfaceGuidSet -Inventory $inventory)
    $candidateArtifacts = @(Get-NetworkPrivacyArtifactCandidates -Inventory $inventory)
    $sanitizableArtifacts = @(Get-SanitizableNetworkArtifacts -Inventory $inventory)

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
    param(
        [Parameter(Mandatory = $true)]
        [string]$Key,

        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [switch]$DryRun
    )

    $args = @('export', $Key, $FilePath, '/y')

    if ($DryRun) {
        return $FilePath
    }

    $proc = Start-Process -FilePath 'reg.exe' -ArgumentList $args -NoNewWindow -Wait -PassThru
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

function Export-ProtectedRegistryKey {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]]$Paths,

        [Parameter(Mandatory = $true)]
        [string]$Dest,

        [switch]$DryRun
    )

    $exported = New-Object System.Collections.Generic.List[string]
    Ensure-Directory -Path $Dest

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

function Export-NetworkList {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Dest,

        [switch]$DryRun
    )

    Ensure-Directory -Path $Dest
    $key = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList'
    $file = Join-Path $Dest ("NetworkList_{0}.reg" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))

    return Invoke-RegExport -Key $key -FilePath $file -DryRun:$DryRun
}

function Get-WiFiProfileNames {
    [CmdletBinding()]
    param()

    $lines = netsh wlan show profiles 2>$null
    if (-not $lines) {
        return @()
    }

    $profiles = New-Object System.Collections.Generic.List[string]

    foreach ($line in $lines) {
        if ($line -match ':\s*(.+)$') {
            $value = $matches[1].Trim()
            if ([string]::IsNullOrWhiteSpace($value)) { continue }

            if ($line -match 'profile' -or $line -match 'profil' -or $line -match 'perfil' -or $line -match 'профил' -or $line -match '配置文件') {
                [void]$profiles.Add($value)
            }
        }
    }

    return @($profiles | Sort-Object -Unique)
}

function Export-WiFiProfile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Dest,

        [switch]$DryRun
    )

    $exported = New-Object System.Collections.Generic.List[string]
    Ensure-Directory -Path $Dest

    $listFile = Join-Path $Dest ("WiFiProfiles_{0}.txt" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
    $profiles = @(Get-WiFiProfileNames)

    if ($profiles.Count -eq 0) {
        return @()
    }

    if ($DryRun) {
        [void]$exported.Add($listFile)
        foreach ($profile in $profiles) {
            [void]$exported.Add("PROFILE:$profile")
        }
        return @($exported)
    }

    $profiles | Out-File -FilePath $listFile -Encoding UTF8
    [void]$exported.Add($listFile)

    foreach ($profile in $profiles) {
        $before = @(Get-ChildItem -Path $Dest -Filter '*.xml' -File -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName)
        & netsh wlan export profile name="$profile" folder="$Dest" key=clear 2>&1 | Out-Null
        $after = @(Get-ChildItem -Path $Dest -Filter '*.xml' -File -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName)
        $newFiles = @($after | Where-Object { $_ -notin $before })

        foreach ($newFile in $newFiles) {
            [void]$exported.Add($newFile)
        }
    }

    return @($exported)
}

function Export-FirewallPolicy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Dest,

        [switch]$DryRun
    )

    Ensure-Directory -Path $Dest
    $file = Join-Path $Dest ("FirewallPolicy_{0}.wfw" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))

    $result = Invoke-ExternalCommandSafe -Name 'Export firewall policy' -FilePath 'netsh.exe' -ArgumentList @('advfirewall', 'export', "`"$file`"") -DryRun:$DryRun
    if (-not $result.Succeeded) {
        throw $result.Error
    }

    return $file
}

function Export-ProtectionInventory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Dest,

        [Parameter()]
        [AllowNull()]
        [object[]]$Inventory,

        [switch]$DryRun
    )

    Ensure-Directory -Path $Dest

    if ($null -eq $Inventory -or @($Inventory).Count -eq 0) {
        $Inventory = @(Get-ProtectionInventory)
    }

    $file = Join-Path $Dest ("ProtectionInventory_{0}.json" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))

    if (-not $DryRun) {
        $Inventory | ConvertTo-Json -Depth 8 | Out-File -FilePath $file -Encoding UTF8
    }

    return $file
}

function Export-ProtectionRegistryMap {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Dest,

        [Parameter()]
        [AllowNull()]
        [object[]]$Inventory,

        [switch]$DryRun
    )

    Ensure-Directory -Path $Dest

    $map = @(Get-ProtectionRegistryMap -Inventory $Inventory)
    $file = Join-Path $Dest ("ProtectionRegistryMap_{0}.json" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))

    if (-not $DryRun) {
        $map | ConvertTo-Json -Depth 8 | Out-File -FilePath $file -Encoding UTF8
    }

    return $file
}

function Export-SanitizableNetworkArtifacts {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Dest,

        [Parameter()]
        [AllowNull()]
        [object[]]$Inventory,

        [switch]$DryRun
    )

    Ensure-Directory -Path $Dest

    $artifacts = @(Get-SanitizableNetworkArtifacts -Inventory $Inventory)
    $file = Join-Path $Dest ("SanitizableNetworkArtifacts_{0}.json" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))

    if (-not $DryRun) {
        $artifacts | ConvertTo-Json -Depth 8 | Out-File -FilePath $file -Encoding UTF8
    }

    return $file
}

function Export-NetCleanManifest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Dest,

        [Parameter(Mandatory = $true)]
        [hashtable]$Manifest,

        [switch]$DryRun
    )

    Ensure-Directory -Path $Dest
    $file = Join-Path $Dest ("RestoreManifest_{0}.json" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))

    if (-not $DryRun) {
        $Manifest | ConvertTo-Json -Depth 8 | Out-File -FilePath $file -Encoding UTF8
    }

    return $file
}

function Invoke-NetCleanPhase2Protect {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Context,

        [Parameter(Mandatory = $true)]
        [string]$BackupPath,

        [switch]$DryRun,
        [switch]$SkipFirewallBackup
    )

    Ensure-Directory -Path $BackupPath

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
    $manifest.SanitizableArtifactsJson  = Export-SanitizableNetworkArtifacts -Dest $BackupPath -Inventory $inventory -DryRun:$DryRun
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

function Remove-WiFiProfilesSafe {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [switch]$DryRun
    )

    $profiles = @(Get-WiFiProfileNames)
    $removed = New-Object System.Collections.Generic.List[string]
    $operations = New-Object System.Collections.Generic.List[object]

    foreach ($profile in $profiles) {
        if (-not ($DryRun -or $PSCmdlet.ShouldProcess("Wi-Fi profile '$profile'", 'Delete'))) {
            $operations.Add([pscustomobject]@{ Name = $profile; Succeeded = $false; Skipped = $true; Reason = 'WhatIf' })
            continue
        }

        $result = Invoke-ExternalCommandSafe -Name "Delete Wi-Fi profile $profile" -FilePath 'netsh.exe' -ArgumentList @('wlan', 'delete', 'profile', ('name="' + $profile + '"')) -DryRun:$DryRun
        $operations.Add($result)

        if ($result.Succeeded) {
            [void]$removed.Add($profile)
        }
    }

    return [pscustomobject]@{
        Removed    = $removed.Count
        Profiles   = @($removed)
        Operations = @($operations)
    }
}

function Clear-DnsCacheSafe {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [switch]$DryRun
    )

    if (-not ($DryRun -or $PSCmdlet.ShouldProcess('DNS cache', 'Flush'))) {
        return [pscustomobject]@{ Name = 'Flush DNS cache'; Succeeded = $false; Skipped = $true; Reason = 'WhatIf' }
    }

    return Invoke-ExternalCommandSafe -Name 'Flush DNS cache' -FilePath 'ipconfig.exe' -ArgumentList @('/flushdns') -DryRun:$DryRun
}

function Clear-ArpCacheSafe {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [switch]$DryRun
    )

    if (-not ($DryRun -or $PSCmdlet.ShouldProcess('ARP cache', 'Clear'))) {
        return [pscustomobject]@{ Name = 'Clear ARP cache'; Succeeded = $false; Skipped = $true; Reason = 'WhatIf' }
    }

    return Invoke-ExternalCommandSafe -Name 'Clear ARP cache' -FilePath 'arp.exe' -ArgumentList @('-d', '*') -DryRun:$DryRun -IgnoreExitCode
}

function Remove-RegistryPathSafe {
    [CmdletBinding(SupportsShouldProcess = $true)]
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

function Remove-NetworkPrivacyArtifactsSafe {
    [CmdletBinding(SupportsShouldProcess = $true)]
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

function Clear-NlaProbeStateSafe {
    [CmdletBinding(SupportsShouldProcess = $true)]
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

function Clear-NetworkEventLogsSafe {
    [CmdletBinding()]
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

function Clear-UserNetworkArtifactsSafe {
    [CmdletBinding()]
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

function Invoke-AdvancedNetworkRepair {
    [CmdletBinding()]
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

function Invoke-ConservativePerformanceTune {
    [CmdletBinding()]
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

function Invoke-NetCleanPhase3Clean {
    [CmdletBinding()]
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

function Test-NetCleanPostState {
    [CmdletBinding()]
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

    $vendorComparison = Compare-StringSets -Before $preVendors -After $postVendors
    $guidComparison   = Compare-StringSets -Before $preGuids -After $postGuids

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

    $serviceComparison = Compare-StringSets -Before $preServices -After $postServices

    return [pscustomobject]@{
        PreInventory        = $preInventory
        PostInventory       = $postInventory
        VendorComparison    = $vendorComparison
        GuidComparison      = $guidComparison
        ServiceComparison   = $serviceComparison
        Passed              = (@($vendorComparison.Missing).Count -eq 0)
    }
}

function Invoke-NetCleanPhase4Verify {
    [CmdletBinding()]
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

function Invoke-NetCleanWorkflow {
    [CmdletBinding()]
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

function Get-InstalledAV {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [object[]]$Inventory
    )

    if ($PSBoundParameters.ContainsKey('Inventory')) { $inventory = @($Inventory) }
    else { $inventory = @(Get-ProtectionInventory) }

    if (@($inventory).Count -eq 0) { return @() }

    $securityCategories = @('AV', 'EDR', 'XDR', 'Firewall')

    $results = foreach ($item in $inventory) {
        if (@($item.Categories) | Where-Object { $_ -in $securityCategories }) {
            $item.Vendor
        }
    }

    $out = @(Get-UniqueNonEmptyStrings -InputObject $results)
    if (@($out).Count -eq 0) { return @() }
    return $out
}

function Get-AVServicePattern {
    [CmdletBinding()]
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

    return Get-UniqueNonEmptyStrings -InputObject $patterns
}

function Get-ProtectionList {
    [CmdletBinding()]
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
        Services = @(Get-UniqueNonEmptyStrings -InputObject $services)
        Drivers  = @(Get-UniqueNonEmptyStrings -InputObject $drivers)
        Adapters = @(Get-UniqueNonEmptyStrings -InputObject $adapters)
        Registry = @(Get-UniqueNonEmptyStrings -InputObject $registryPaths)
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
    'Convert-RegToProviderPath',
    'Resolve-VendorFromText',
    'Get-VendorSignatures',
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
    'Get-NetworkPrivacyArtifactCandidates',
    'Get-SanitizableNetworkArtifacts',
    'Invoke-NetCleanPhase1Detect',
    'Export-ProtectedRegistryKey',
    'Export-NetworkList',
    'Get-WiFiProfileNames',
    'Export-WiFiProfile',
    'Export-FirewallPolicy',
    'Export-ProtectionInventory',
    'Export-ProtectionRegistryMap',
    'Export-SanitizableNetworkArtifacts',
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