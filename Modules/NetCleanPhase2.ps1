# ---------------------------------------------------------------------------
# Phase 2 - Protect helpers
# ---------------------------------------------------------------------------

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
    if (-not $DryRun) {
        New-DirectoryIfNotExist -Path $Dest
    }

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

## Read human-friendly network profile names directly from the registry.
function Get-NetworkListProfileName {
    [CmdletBinding()]
    param()

    $root = Convert-RegToProviderPath -RegistryPath 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles'
    $names = New-Object System.Collections.Generic.List[string]
    try {
        if (Test-Path -LiteralPath $root) {
            $children = Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue
            foreach ($c in $children) {
                try {
                    $pn = Get-ItemProperty -LiteralPath $c.PSPath -Name 'ProfileName' -ErrorAction SilentlyContinue
                    if ($pn -and $pn.ProfileName) { [void]$names.Add($pn.ProfileName) }
                }
                catch { Write-Verbose "Get-NetworkListProfileName child: $($_.Exception.Message)" }
            }
        }
    }
    catch { Write-Verbose "Get-NetworkListProfileName: $($_.Exception.Message)" }

    return $names.ToArray() | Sort-Object -Unique
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

    if (-not $DryRun) {
        New-DirectoryIfNotExist -Path $Dest
    }
    $key = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList'
    $file = Join-Path $Dest ("NetworkList_{0}.reg" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))

    return Invoke-RegExport -Key $key -FilePath $file -DryRun:$DryRun
}

<#
.SYNOPSIS
Return Wi-Fi profile names present on the system.
.DESCRIPTION
Parses `netsh wlan show profiles` output to extract profile names; returns an empty list if none found.
.OUTPUTS
Array of Wi-Fi profile name strings.
#>
function Get-WiFiProfileName {
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
        return [string[]]@()
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
            $name = $matches[1].Trim()

            if ($label -match 'Profile' -and -not [string]::IsNullOrWhiteSpace($name)) {
                [void]$profiles.Add($name)
            }
        }
    }

    [string[]]$finalProfiles = @($profiles | Sort-Object -Unique)

    Write-NetCleanLog -Level DEBUG -Message ("Detected Wi-Fi profiles: {0}" -f ($finalProfiles -join ', '))

    return [string[]]$finalProfiles
}

<#
.SYNOPSIS
Export Wi-Fi profiles to XML files and write a list of exported items.
.DESCRIPTION
For each Wi-Fi profile, exports to an XML file using `netsh wlan export profile`. A list file is also created containing the exported file paths. Honors `-DryRun` to simulate exports and return intended file paths without performing actual exports.
.PARAMETER Dest
Destination directory for exported Wi-Fi profile XML files and list file.
.PARAMETER DryRun
If specified, simulates the export process and returns the list of file paths that would have been created without performing any exports.
.OUTPUTS
Array of file paths for the exported Wi-Fi profile XML files and the list file. In dry-run mode, returns the intended file paths without creating any files.
.EXAMPLE
Export-WiFiProfile -Dest "C:\Backups\WiFiProfiles"
This command exports all Wi-Fi profiles to XML files in the specified directory and creates a list file with the exported profile names.
.EXAMPLE
Export-WiFiProfile -Dest "C:\Backups\WiFiProfiles" -DryRun
This command simulates the export process and returns the list of file paths that would have been created without performing any exports.
.NOTES
- Ensure that the destination directory exists or can be created.
- The function relies on `netsh` for exporting Wi-Fi profiles, which may require appropriate permissions to execute successfully.
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
    $profiles = @(Get-WiFiProfileName)

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

    WriteAllLines -Path $listFile -Contents $profiles -Encoding $script:Utf8NoBom
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
Export the Windows Firewall policy to a .wfw file.
.DESCRIPTION
Uses `netsh advfirewall export` to back up the firewall policy. Honors
`-DryRun` and returns the intended output path.
.PARAMETER Dest
Destination directory for the exported firewall policy.
.PARAMETER DryRun
Simulate export without running the external command.
.OUTPUTS
System.String
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

    if (-not $DryRun) {
        New-DirectoryIfNotExist -Path $Dest
    }
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
Export protection inventory to JSON.
.DESCRIPTION
Writes the supplied inventory, or newly detected inventory when omitted, as
UTF-8 JSON. Honors `-DryRun` without creating directories or files.
.PARAMETER Dest
Destination directory for the inventory JSON file.
.PARAMETER Inventory
Optional inventory to serialize. Current protection inventory is detected when
the argument is omitted or null.
.PARAMETER DryRun
Return the intended output path without writing a file.
.OUTPUTS
System.String
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

    if (-not $DryRun) {
        New-DirectoryIfNotExist -Path $Dest
    }

    if (-not $PSBoundParameters.ContainsKey('Inventory') -or $null -eq $Inventory) {
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

    $json = $Inventory | ConvertTo-Json -Depth 8
    WriteAllText -Path $file -Contents $json -Encoding $script:Utf8NoBom

    if ($canLog) {
        Write-NetCleanLog -Level INFO -Message ("Exported protection inventory to: {0}" -f $file)
    }

    return $file
}

<#
.SYNOPSIS
Export the protection registry map to JSON.
.DESCRIPTION
Derives the protection registry map from the supplied inventory and writes it
as UTF-8 JSON. Honors `-DryRun` without creating directories or files.
.PARAMETER Dest
Destination directory for the registry-map JSON file.
.PARAMETER Inventory
Optional inventory used to derive the registry map.
.PARAMETER DryRun
Return the intended output path without writing a file.
.OUTPUTS
System.String
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

    if (-not $DryRun) {
        New-DirectoryIfNotExist -Path $Dest
    }

    $map = @(Get-ProtectionRegistryMap -Inventory $Inventory)
    $file = Join-Path $Dest ("ProtectionRegistryMap_{0}.json" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))

    if ($DryRun) {
        if ($canLog) {
            Write-NetCleanLog -Level INFO -Message ("Would export protection registry map to: {0}" -f $file)
        }
        return $file
    }

    $json = $map | ConvertTo-Json -Depth 8
    WriteAllText -Path $file -Contents $json -Encoding $script:Utf8NoBom

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

    if (-not $DryRun) {
        New-DirectoryIfNotExist -Path $Dest
    }

    $artifacts = @(Get-SanitizableNetworkArtifact -Inventory $Inventory)
    $file = Join-Path $Dest ("SanitizableNetworkArtifact_{0}.json" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))

    if ($DryRun) {
        if ($canLog) {
            Write-NetCleanLog -Level INFO -Message ("Would export sanitizable artifact inventory to: {0}" -f $file)
        }
        return $file
    }

    $json = $artifacts | ConvertTo-Json -Depth 8
    WriteAllText -Path $file -Contents $json -Encoding $script:Utf8NoBom

    if ($canLog) {
        Write-NetCleanLog -Level INFO -Message ("Exported sanitizable artifact inventory to: {0}" -f $file)
    }

    return $file
}

<#
.SYNOPSIS
Exports the network-adapter configuration that will be reset.
.DESCRIPTION
Writes a compact UTF-8 JSON snapshot of visible adapters, IPv4 DHCP state,
IPv4 addresses and routes, IPv4/IPv6 DNS servers, and the Windows IPv6
DisabledComponents value. The snapshot is informational and is not restored
automatically because conference preparation intentionally returns unmanaged
adapters to DHCP and Quad9 Secure DNS.
.PARAMETER Dest
Private backup directory for the JSON snapshot.
.PARAMETER DryRun
Returns the planned output path without reading configuration or writing a file.
.OUTPUTS
System.String
#>
function Export-NetCleanAdapterConfiguration {
    [CmdletBinding()]
    [OutputType([System.String])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Dest,

        [switch]$DryRun
    )

    $file = Join-Path $Dest ("AdapterConfiguration_{0}.json" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
    if ($DryRun) {
        return $file
    }

    New-DirectoryIfNotExist -Path $Dest

    $adapters = @(
        Get-NetAdapter -ErrorAction Stop |
            Select-Object Name,
                InterfaceDescription,
                InterfaceIndex,
                InterfaceGuid,
                Status,
                MacAddress,
                LinkSpeed,
                Virtual,
                HardwareInterface
    )

    $interfaceIndices = [System.Collections.Generic.HashSet[uint32]]::new()
    foreach ($adapter in $adapters) {
        [void]$interfaceIndices.Add([uint32]$adapter.InterfaceIndex)
    }

    $ipv4Interfaces = @(
        Get-NetIPInterface -AddressFamily IPv4 -ErrorAction Stop |
            Where-Object { $interfaceIndices.Contains([uint32]$_.InterfaceIndex) } |
            Select-Object InterfaceAlias,
                InterfaceIndex,
                Dhcp,
                ConnectionState,
                InterfaceMetric
    )

    $ipv4Addresses = @(
        Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
            Where-Object { $interfaceIndices.Contains([uint32]$_.InterfaceIndex) } |
            Select-Object InterfaceAlias,
                InterfaceIndex,
                IPAddress,
                PrefixLength,
                PrefixOrigin,
                SuffixOrigin,
                AddressState,
                SkipAsSource
    )

    $ipv4Routes = @(
        Get-NetRoute -AddressFamily IPv4 -ErrorAction Stop |
            Where-Object { $interfaceIndices.Contains([uint32]$_.InterfaceIndex) } |
            Select-Object InterfaceAlias,
                InterfaceIndex,
                DestinationPrefix,
                NextHop,
                RouteMetric,
                Protocol,
                PolicyStore
    )

    $dnsServers = @(
        Get-DnsClientServerAddress -ErrorAction Stop |
            Where-Object { $interfaceIndices.Contains([uint32]$_.InterfaceIndex) } |
            Select-Object InterfaceAlias,
                InterfaceIndex,
                AddressFamily,
                ServerAddresses
    )

    $disabledComponents = 0
    $disabledComponentsPresent = $false
    try {
        $preference = Get-ItemProperty `
            -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' `
            -Name 'DisabledComponents' `
            -ErrorAction Stop
        if ($preference.PSObject.Properties.Name -contains 'DisabledComponents') {
            $disabledComponents = [uint32]$preference.DisabledComponents
            $disabledComponentsPresent = $true
        }
    }
    catch {
        Write-Verbose "IPv6 preference was not explicitly configured: $($_.Exception.Message)"
    }

    $snapshot = [ordered]@{
        CapturedAt = (Get-Date).ToString('s')
        Adapters = $adapters
        IPv4Interfaces = $ipv4Interfaces
        IPv4Addresses = $ipv4Addresses
        IPv4Routes = $ipv4Routes
        DnsServers = $dnsServers
        IPv6Preference = [ordered]@{
            DisabledComponentsPresent = $disabledComponentsPresent
            DisabledComponents = $disabledComponents
        }
    }

    $json = $snapshot | ConvertTo-Json -Depth 8
    WriteAllText -Path $file -Contents $json -Encoding $script:Utf8NoBom
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

    if (-not $DryRun) {
        New-DirectoryIfNotExist -Path $Dest
    }
    $file = Join-Path $Dest ("RestoreManifest_{0}.json" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))

    if ($DryRun) {
        if ($canLog) {
            Write-NetCleanLog -Level INFO -Message ("Would export restore manifest to: {0}" -f $file)
        }
        return $file
    }

    $json = $Manifest | ConvertTo-Json -Depth 8
    WriteAllText -Path $file -Contents $json -Encoding $script:Utf8NoBom

    if ($canLog) {
        Write-NetCleanLog -Level INFO -Message ("Exported restore manifest to: {0}" -f $file)
    }

    return $file
}

<#
.SYNOPSIS
Run the Phase 2 protection and backup workflow.
.DESCRIPTION
Creates the requested backups and metadata exports, then returns a new workflow
context containing the protection manifest and summary. Honors `-DryRun`
without creating directories, files, or external-command side effects.
.PARAMETER Context
Detection context returned by Phase 1.
.PARAMETER BackupPath
Destination directory for protection backups and metadata.
.PARAMETER DryRun
Plan backup operations without writing or invoking external commands.
.PARAMETER SkipFirewallBackup
Skip the Windows Firewall policy export.
.OUTPUTS
System.Object
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

    if (-not $DryRun) {
        New-DirectoryIfNotExist -Path $BackupPath
        Set-NetCleanPrivateDirectoryAcl -Path $BackupPath
    }

    $inventory = @($Context.Inventory)
    $protectedPaths = @($Context.ProtectedRegistryPaths | Sort-Object -Unique)

    $manifest = @{
        ModuleVersion             = $script:NetCleanModuleVersion
        BackupPath                = $BackupPath
        CreatedAt                 = (Get-Date).ToString('s')
        ProtectionInventoryJson   = $null
        ProtectionRegistryMapJson = $null
        SanitizableArtifactsJson  = $null
        AdapterConfigurationJson  = $null
        FirewallPolicyBackup      = $null
        NetworkListBackup         = $null
        WiFiExports               = @()
        ProtectedRegistryBackups  = @()
    }

    $manifest.ProtectionInventoryJson = Export-ProtectionInventory -Dest $BackupPath -Inventory $inventory -DryRun:$DryRun
    $manifest.ProtectionRegistryMapJson = Export-ProtectionRegistryMap -Dest $BackupPath -Inventory $inventory -DryRun:$DryRun
    $manifest.SanitizableArtifactsJson = Export-SanitizableNetworkArtifact -Dest $BackupPath -Inventory $inventory -DryRun:$DryRun
    $manifest.AdapterConfigurationJson = Export-NetCleanAdapterConfiguration -Dest $BackupPath -DryRun:$DryRun
    $manifest.NetworkListBackup = Export-NetworkList -Dest $BackupPath -DryRun:$DryRun
    if ($canLog) {
        if ($DryRun) {
            Write-NetCleanLog -Level INFO -Message ("Would export network list to: {0}" -f $manifest.NetworkListBackup)
        }
        else {
            Write-NetCleanLog -Level INFO -Message ("Exported network list to: {0}" -f $manifest.NetworkListBackup)
        }
    }

    $manifest.WiFiExports = @(Export-WiFiProfile -Dest $BackupPath -DryRun:$DryRun)

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
        if ($manifest.AdapterConfigurationJson) { Write-NetCleanLog -Level INFO -Message ("Adapter configuration snapshot: {0}" -f $manifest.AdapterConfigurationJson) }
        if ($manifest.NetworkListBackup) { Write-NetCleanLog -Level INFO -Message ("NetworkList backup: {0}" -f $manifest.NetworkListBackup) }

        if ($manifest.WiFiExports -and $manifest.WiFiExports.Count -gt 0) {
            foreach ($e in $manifest.WiFiExports) {
                Write-NetCleanLog -Level INFO -Message ("Wi-Fi export: {0}" -f $e)
            }
            Write-NetCleanLog -Level INFO -Message ('To restore Wi-Fi profiles, run: netsh wlan add profile filename="<exported-profile.xml>" for each exported XML, or use the provided examples\restore-wifi-profiles.ps1 script.')
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
                AdapterConfigurationBackupCount = @($manifest.AdapterConfigurationJson | Where-Object { $_ }).Count
                WiFiBackupCount              = @($manifest.WiFiExports).Count
                ProtectedRegistryBackupCount = @($manifest.ProtectedRegistryBackups).Count
            }
        }) -Force

    if ($canLog) {
        Write-NetCleanLog -Level INFO -Message ("Phase 2 protect complete. Manifest={0}" -f $manifestFile)
    }

    return $newContext
}

Export-ModuleMember -Function @(
    'Invoke-NetCleanPhase2Protect',
    'Export-ProtectedRegistryKey',
    'Export-NetworkList',
    'Get-WiFiProfileName',
    'Export-WiFiProfile',
    'Export-FirewallPolicy',
    'Export-ProtectionInventory',
    'Export-ProtectionRegistryMap',
    'Export-SanitizableNetworkArtifact',
    'Export-NetCleanManifest'
) -Alias @(
    'Backup-NetworkList',
    'Backup-ProtectedRegistryKeys',
    'Backup-WiFiProfiles'
)
