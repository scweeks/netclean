# ---------------------------------------------------------------------------
# Phase 3 - Clean helpers
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
Removes Wi-Fi profiles safely (supports -WhatIf).
.DESCRIPTION
Deletes all user Wi-Fi profiles unless protected; supports `-DryRun`, `-WhatIf` and `-Confirm`.
.PARAMETER DryRun
If specified, operations are simulated and no destructive actions are performed.
.EXAMPLE
Remove-WiFiProfilesSafe -DryRun
#>
function Remove-WiFiProfilesSafe {
    [CmdletBinding(SupportsShouldProcess = $true)]
    [OutputType([pscustomobject])]
    param(
        [switch]$DryRun,

        [string[]]$WifiProfiles
    )

    $canLog = $null -ne (Get-Command Write-NetCleanLog -ErrorAction SilentlyContinue)

    if ($PSBoundParameters.ContainsKey('WifiProfiles')) {
        $profiles = @($WifiProfiles)
    }
    else {
        $profiles = @(Get-WiFiProfileName)
    }

    $removed = [System.Collections.Generic.List[string]]::new()
    $operations = [System.Collections.Generic.List[object]]::new()

    if ($profiles.Count -eq 0) {
        if ($canLog) {
            Write-NetCleanLog -Level INFO -Message 'No Wi-Fi profiles found to remove.'
        }

        return [pscustomobject]@{
            Removed    = 0
            Profiles   = @()
            Operations = @()
        }
    }

    if ($DryRun) {
        foreach ($wifiProfile in $profiles) {
            if ($canLog) {
                Write-NetCleanLog -Level INFO -Message ("Would remove Wi-Fi profile: {0}" -f $wifiProfile)
            }

            $operations.Add([pscustomobject]@{
                Name      = $wifiProfile
                Succeeded = $true
                Skipped   = $false
                Reason    = 'DryRun'
            })

            [void]$removed.Add($wifiProfile)
        }
    }
    else {
        $toProcess = @()

        foreach ($wifiProfile in $profiles) {
            if (-not (Test-NetCleanSafeIdentifier -Value $wifiProfile)) {
                if ($canLog) {
                    Write-NetCleanLog -Level WARN -Message ("Skipping Wi-Fi profile with unsafe characters in its name: {0}" -f $wifiProfile)
                }

                $operations.Add([pscustomobject]@{
                        Name      = $wifiProfile
                        Succeeded = $false
                        Skipped   = $true
                        Reason    = 'UnsafeName'
                    })

                continue
            }

            if (-not $PSCmdlet.ShouldProcess("Wi-Fi profile '$wifiProfile'", 'Delete')) {
                if ($canLog) {
                    Write-NetCleanLog -Level INFO -Message ("WhatIf/ShouldProcess prevented Wi-Fi profile removal: {0}" -f $wifiProfile)
                }

                $operations.Add([pscustomobject]@{
                    Name      = $wifiProfile
                    Succeeded = $false
                    Skipped   = $true
                    Reason    = 'WhatIf'
                })

                continue
            }

            $toProcess += $wifiProfile
        }

        if ($toProcess.Count -gt 0) {
            $sb = {
                param($p)

                & netsh.exe wlan delete profile name="$p" 2>&1 | Out-Null

                if ($LASTEXITCODE -eq 0) {
                    [pscustomobject]@{
                        Name      = $p
                        Succeeded = $true
                        Skipped   = $false
                        Reason    = 'Removed'
                    }
                }
                else {
                    [pscustomobject]@{
                        Name      = $p
                        Succeeded = $false
                        Skipped   = $false
                        Reason    = 'Failed'
                    }
                }
            }

            try {
                $res = Invoke-InParallel `
                    -ScriptBlock $sb `
                    -InputObjects $toProcess `
                    -ThrottleLimit ([System.Math]::Max(1, [System.Environment]::ProcessorCount))
            }
            catch {
                if ($canLog) {
                    Write-NetCleanLog -Level WARN -Message ("Parallel Wi-Fi profile removal failed, falling back to sequential processing: {0}" -f $_.Exception.Message)
                }

                $res = foreach ($wifiProfile in $toProcess) {
                    & netsh.exe wlan delete profile name="$wifiProfile" 2>&1 | Out-Null

                    if ($LASTEXITCODE -eq 0) {
                        [pscustomobject]@{
                            Name      = $wifiProfile
                            Succeeded = $true
                            Skipped   = $false
                            Reason    = 'Removed'
                        }
                    }
                    else {
                        [pscustomobject]@{
                            Name      = $wifiProfile
                            Succeeded = $false
                            Skipped   = $false
                            Reason    = 'Failed'
                        }
                    }
                }
            }

            foreach ($r in $res) {
                if ($null -eq $r) {
                    continue
                }

                if ($r.Succeeded) {
                    [void]$removed.Add($r.Name)
                }

                $operations.Add($r)

                if ($canLog) {
                    if ($r.Succeeded) {
                        Write-NetCleanLog -Level INFO -Message ("Removed Wi-Fi profile: {0}" -f $r.Name)
                    }
                    else {
                        Write-NetCleanLog -Level WARN -Message ("Failed to remove Wi-Fi profile '{0}': {1}" -f $r.Name, $r.Reason)
                    }
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
Configures the Quad9 Secure resolver set for DNS over HTTPS.
.DESCRIPTION
Adds or updates each Quad9 IPv4 and IPv6 resolver in the Windows encrypted-DNS
table, enabling automatic DoH upgrade without plaintext DNS fallback. Older
Windows versions without the required DNS client commands are reported as
unsupported without preventing static Quad9 DNS configuration.
.PARAMETER ServerAddresses
Quad9 resolver addresses to configure.
#>
function Set-NetCleanQuad9Doh {
    [CmdletBinding(SupportsShouldProcess = $true)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$ServerAddresses
    )

    if (-not $PSCmdlet.ShouldProcess(
            'Windows DNS client',
            'Configure the Quad9 DNS-over-HTTPS resolver table'
        )) {
        return [pscustomobject]@{
            Supported       = $true
            ConfiguredCount = 0
            FailedCount     = 0
            Reason          = 'WhatIf'
            Operations      = @()
        }
    }

    $requiredCommands = @(
        'Get-DnsClientDohServerAddress',
        'Set-DnsClientDohServerAddress',
        'Add-DnsClientDohServerAddress'
    )

    foreach ($commandName in $requiredCommands) {
        if (-not (Get-Command $commandName -ErrorAction SilentlyContinue)) {
            return [pscustomobject]@{
                Supported       = $false
                ConfiguredCount = 0
                FailedCount     = 0
                Reason          = 'UnsupportedWindowsVersion'
                Operations      = @()
            }
        }
    }

    $operations = [System.Collections.Generic.List[object]]::new()
    $template = 'https://dns.quad9.net/dns-query'

    foreach ($serverAddress in $ServerAddresses) {
        try {
            $existing = @(
                Get-DnsClientDohServerAddress `
                    -ServerAddress $serverAddress `
                    -ErrorAction SilentlyContinue
            )

            if ($existing.Count -gt 0) {
                Set-DnsClientDohServerAddress `
                    -ServerAddress $serverAddress `
                    -DohTemplate $template `
                    -AutoUpgrade $true `
                    -AllowFallbackToUdp $false `
                    -ErrorAction Stop
                $action = 'Updated'
            }
            else {
                Add-DnsClientDohServerAddress `
                    -ServerAddress $serverAddress `
                    -DohTemplate $template `
                    -AutoUpgrade $true `
                    -AllowFallbackToUdp $false `
                    -ErrorAction Stop
                $action = 'Added'
            }

            $operations.Add([pscustomobject]@{
                    ServerAddress = $serverAddress
                    Succeeded     = $true
                    Action        = $action
                    Error         = $null
                })
        }
        catch {
            $operations.Add([pscustomobject]@{
                    ServerAddress = $serverAddress
                    Succeeded     = $false
                    Action        = 'Failed'
                    Error         = $_.Exception.Message
                })
        }
    }

    return [pscustomobject]@{
        Supported       = $true
        ConfiguredCount = @($operations | Where-Object Succeeded).Count
        FailedCount     = @($operations | Where-Object { -not $_.Succeeded }).Count
        Reason          = 'Configured'
        Operations      = $operations.ToArray()
    }
}

<#
.SYNOPSIS
Sets the Microsoft-recommended Windows preference for IPv4 over IPv6.
.DESCRIPTION
Sets DisabledComponents to 0x20. IPv6 remains enabled for Windows components
and IPv6-only connectivity; the preference takes full effect after restart.
#>
function Set-NetCleanIPv4Preference {
    [CmdletBinding(SupportsShouldProcess = $true)]
    [OutputType([pscustomobject])]
    param()

    if (-not $PSCmdlet.ShouldProcess(
            'Windows IP stack',
            'Set DisabledComponents to prefer IPv4 while retaining IPv6'
        )) {
        return [pscustomobject]@{
            Succeeded = $false
            Skipped   = $true
            Reason    = 'WhatIf'
            Error     = $null
        }
    }

    try {
        Set-ItemProperty `
            -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' `
            -Name 'DisabledComponents' `
            -Value 32 `
            -Type DWord `
            -Force `
            -ErrorAction Stop

        return [pscustomobject]@{
            Succeeded = $true
            Reason    = 'Configured'
            Error     = $null
        }
    }
    catch {
        return [pscustomobject]@{
            Succeeded = $false
            Reason    = 'Failed'
            Error     = $_.Exception.Message
        }
    }
}

<#
.SYNOPSIS
Resets eligible adapter addressing and DNS for conference preparation.
.DESCRIPTION
Plans or applies IPv4 DHCP and Quad9 Secure DNS to visible adapters while
preserving organization-managed devices and adapter GUIDs associated with
detected VPN, security, and virtualization products. IPv6 remains enabled;
Windows is configured to prefer IPv4 after restart.
.PARAMETER Context
Detection context containing device-management state and protected adapter GUIDs.
.PARAMETER Adapters
Optional adapter inventory. When omitted, visible Windows adapters are enumerated.
.PARAMETER DryRun
Returns the planned changes without modifying the computer.
#>
function Reset-NetCleanAdapterConfigurationSafe {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Context,

        [Parameter()]
        [AllowEmptyCollection()]
        [object[]]$Adapters,

        [switch]$DryRun
    )

    $dnsServers = @(
        '9.9.9.9',
        '149.112.112.112',
        '2620:fe::fe',
        '2620:fe::9'
    )

    if (-not $PSBoundParameters.ContainsKey('Adapters')) {
        try {
            $Adapters = @(Get-NetAdapter -ErrorAction Stop)
        }
        catch {
            return [pscustomobject]@{
                Provider        = 'Quad9 Secure'
                DnsServers      = $dnsServers
                PreferIPv4      = $false
                IPv4Preference  = [pscustomobject]@{
                    Succeeded = $false
                    Skipped   = $true
                    Reason    = 'AdapterDiscoveryFailed'
                    Error     = $_.Exception.Message
                }
                DnsOverHttps    = [pscustomobject]@{
                    Supported       = $true
                    ConfiguredCount = 0
                    FailedCount     = 0
                    Reason          = 'AdapterDiscoveryFailed'
                    Operations      = @()
                }
                RequiresRestart = $false
                ConfiguredCount = 0
                SkippedCount    = 0
                FailedCount     = 0
                Succeeded       = $false
                Operations      = @()
            }
        }
    }

    $isManaged = (
        $Context.PSObject.Properties.Name -contains 'ManagementState' -and
        $Context.ManagementState -and
        $Context.ManagementState.IsManaged
    )

    $protectedGuids = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )

    if ($Context.PSObject.Properties.Name -contains 'ProtectedInterfaceGuids') {
        foreach ($guid in @($Context.ProtectedInterfaceGuids)) {
            if (-not [string]::IsNullOrWhiteSpace($guid)) {
                [void]$protectedGuids.Add($guid.Trim('{}'))
            }
        }
    }

    $adapterPlans = [System.Collections.Generic.List[object]]::new()
    foreach ($adapter in @($Adapters)) {
        $adapterGuid = if ($adapter.InterfaceGuid) {
            ([string]$adapter.InterfaceGuid).Trim('{}')
        }
        else {
            $null
        }

        $skipReason = if ($isManaged) {
            'ManagedDevice'
        }
        elseif ($adapterGuid -and $protectedGuids.Contains($adapterGuid)) {
            'ProtectedAdapter'
        }
        else {
            $null
        }

        $adapterPlans.Add([pscustomobject]@{
                Adapter    = $adapter
                AdapterGuid = $adapterGuid
                SkipReason = $skipReason
            })
    }

    $eligibleCount = @($adapterPlans | Where-Object { -not $_.SkipReason }).Count

    if ($isManaged) {
        $preferenceResult = [pscustomobject]@{
            Succeeded = $true
            Skipped   = $true
            Reason    = 'ManagedDevice'
            Error     = $null
        }
        $dohResult = [pscustomobject]@{
            Supported       = $true
            ConfiguredCount = 0
            FailedCount     = 0
            Reason          = 'ManagedDevice'
            Operations      = @()
        }
    }
    elseif ($DryRun) {
        $preferenceResult = [pscustomobject]@{
            Succeeded = $true
            Skipped   = $false
            Reason    = 'DryRun'
            Error     = $null
        }
        $dohResult = [pscustomobject]@{
            Supported       = $true
            ConfiguredCount = $dnsServers.Count
            FailedCount     = 0
            Reason          = 'DryRun'
            Operations      = @()
        }
    }
    else {
        if ($PSCmdlet.ShouldProcess(
                'Windows IP stack',
                'Prefer IPv4 over IPv6 while keeping IPv6 enabled'
            )) {
            $preferenceResult = Set-NetCleanIPv4Preference -Confirm:$false
            $preferenceResult | Add-Member -NotePropertyName Skipped -NotePropertyValue $false
        }
        else {
            $preferenceResult = [pscustomobject]@{
                Succeeded = $false
                Skipped   = $true
                Reason    = 'WhatIf'
                Error     = $null
            }
        }

        if ($eligibleCount -eq 0) {
            $dohResult = [pscustomobject]@{
                Supported       = $true
                ConfiguredCount = 0
                FailedCount     = 0
                Reason          = 'NoEligibleAdapters'
                Operations      = @()
            }
        }
        elseif ($PSCmdlet.ShouldProcess(
                'Windows DNS client',
                'Configure Quad9 DNS over HTTPS without plaintext fallback'
            )) {
            $dohResult = Set-NetCleanQuad9Doh `
                -ServerAddresses $dnsServers `
                -Confirm:$false
        }
        else {
            $dohResult = [pscustomobject]@{
                Supported       = $true
                ConfiguredCount = 0
                FailedCount     = 0
                Reason          = 'WhatIf'
                Operations      = @()
            }
        }
    }

    $operations = [System.Collections.Generic.List[object]]::new()

    foreach ($plan in $adapterPlans) {
        $adapter = $plan.Adapter
        $adapterGuid = $plan.AdapterGuid
        $skipReason = $plan.SkipReason

        if ($skipReason) {
            $operations.Add([pscustomobject]@{
                    Name           = $adapter.Name
                    InterfaceIndex = $adapter.InterfaceIndex
                    InterfaceGuid  = $adapterGuid
                    DhcpEnabled    = $false
                    DnsServers     = @()
                    Succeeded      = $true
                    Skipped        = $true
                    DryRun         = [bool]$DryRun
                    Reason         = $skipReason
                    Error          = $null
                })
            continue
        }

        if ($DryRun) {
            $operations.Add([pscustomobject]@{
                    Name           = $adapter.Name
                    InterfaceIndex = $adapter.InterfaceIndex
                    InterfaceGuid  = $adapterGuid
                    DhcpEnabled    = $true
                    DnsServers     = $dnsServers
                    Succeeded      = $true
                    Skipped        = $false
                    DryRun         = $true
                    Reason         = 'DryRun'
                    Error          = $null
                })
            continue
        }

        if (-not $PSCmdlet.ShouldProcess(
                "Network adapter '$($adapter.Name)'",
                'Enable IPv4 DHCP and configure Quad9 Secure DNS'
            )) {
            $operations.Add([pscustomobject]@{
                    Name           = $adapter.Name
                    InterfaceIndex = $adapter.InterfaceIndex
                    InterfaceGuid  = $adapterGuid
                    DhcpEnabled    = $false
                    DnsServers     = @()
                    Succeeded      = $false
                    Skipped        = $true
                    DryRun         = $false
                    Reason         = 'WhatIf'
                    Error          = $null
                })
            continue
        }

        $dhcpResult = Invoke-ExternalCommandSafe `
            -Name ("Reset IPv4 address for {0}" -f $adapter.Name) `
            -FilePath 'netsh.exe' `
            -ArgumentList @(
                'interface',
                'ipv4',
                'set',
                'address',
                ("name={0}" -f $adapter.InterfaceIndex),
                'source=dhcp'
            )

        if (-not $dhcpResult.Succeeded) {
            $operations.Add([pscustomobject]@{
                    Name           = $adapter.Name
                    InterfaceIndex = $adapter.InterfaceIndex
                    InterfaceGuid  = $adapterGuid
                    DhcpEnabled    = $false
                    DnsServers     = @()
                    Succeeded      = $false
                    Skipped        = $false
                    DryRun         = $false
                    Reason         = 'DhcpResetFailed'
                    Error          = $dhcpResult.Error
                })
            continue
        }

        try {
            Set-DnsClientServerAddress `
                -InterfaceIndex $adapter.InterfaceIndex `
                -ServerAddresses $dnsServers `
                -ErrorAction Stop

            $operations.Add([pscustomobject]@{
                    Name           = $adapter.Name
                    InterfaceIndex = $adapter.InterfaceIndex
                    InterfaceGuid  = $adapterGuid
                    DhcpEnabled    = $true
                    DnsServers     = $dnsServers
                    Succeeded      = $true
                    Skipped        = $false
                    DryRun         = $false
                    Reason         = 'Configured'
                    Error          = $null
                })
        }
        catch {
            $operations.Add([pscustomobject]@{
                    Name           = $adapter.Name
                    InterfaceIndex = $adapter.InterfaceIndex
                    InterfaceGuid  = $adapterGuid
                    DhcpEnabled    = $true
                    DnsServers     = @()
                    Succeeded      = $false
                    Skipped        = $false
                    DryRun         = $false
                    Reason         = 'DnsConfigurationFailed'
                    Error          = $_.Exception.Message
                })
        }
    }

    return [pscustomobject]@{
        Provider        = 'Quad9 Secure'
        DnsServers      = $dnsServers
        PreferIPv4      = -not [bool]$isManaged
        IPv4Preference  = $preferenceResult
        DnsOverHttps    = $dohResult
        RequiresRestart = (-not $isManaged -and -not $preferenceResult.Skipped)
        ConfiguredCount = @($operations | Where-Object { $_.Succeeded -and -not $_.Skipped }).Count
        SkippedCount    = @($operations | Where-Object Skipped).Count
        FailedCount     = @($operations | Where-Object { -not $_.Succeeded }).Count
        Succeeded       = (
            @($operations | Where-Object { -not $_.Succeeded -and -not $_.Skipped }).Count -eq 0 -and
            $preferenceResult.Succeeded -and
            $dohResult.FailedCount -eq 0
        )
        Operations      = $operations.ToArray()
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
            DryRun    = $true
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
            DryRun    = $true
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
        [Alias('Path')]
        [string]$RegistryPath,

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
            Succeeded    = $true
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
            Succeeded    = $false
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
            Succeeded    = $true
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
            Succeeded    = $true
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
            Succeeded    = $true
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
            Succeeded    = $true
            Reason       = 'Removed'
            DryRun       = $false
        }
    }
    catch {
        if ($canLog) {
            Write-NetCleanLog -Level WARN -Message ("Failed to remove registry path '{0}': {1}" -f $RegistryPath, $_.Exception.Message)
        }

        return [pscustomobject]@{
            RegistryPath = $RegistryPath
            Removed      = $false
            Skipped      = $true
            Succeeded    = $false
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
        Results         = $results.ToArray()
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
        # Deliberately narrow allowlist: identity, account, token, and
        # user-device-registration event logs are outside cleanup scope.
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
                    CompletedAt = $null
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
                    CompletedAt = $null
                })

            continue
        }

        try {
            $result = Invoke-ExternalCommandSafe `
                -Name ("Clear event log {0}" -f $log) `
                -FilePath 'wevtutil.exe' `
                -ArgumentList @('cl', $log)

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
                    CompletedAt = $(if ($result.Succeeded) { Get-Date } else { $null })
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
                    CompletedAt = $null
                })
        }
    }

    return $results.ToArray()
}

<#
.SYNOPSIS
Safely clears user network artifacts from the registry.
.DESCRIPTION
Removes only the explicitly allowed Explorer history keys below. Workplace
registration, Web Account Manager, BrokerPlugin, token, credential, Windows
Hello, and other identity stores are outside cleanup scope. Honors `-DryRun`,
`-WhatIf`, and `-Confirm` to allow safe simulation of actions.
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
        # Deliberately narrow allowlist. Do not add identity, SSO, token,
        # credential, or Workplace registration locations.
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
                -ArgumentList $cmd.ArgumentList

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
        [ValidateSet('Conservative', 'Optimal', 'Gaming', 'Default')]
        [string]$PerformanceProfile = 'Conservative',

        [switch]$DryRun
    )

    $canLog = $null -ne (Get-Command Write-NetCleanLog -ErrorAction SilentlyContinue)

    switch ($PerformanceProfile) {
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
                Write-NetCleanLog -Level INFO -Message ("Would apply tuning profile '{0}' action: {1}" -f $PerformanceProfile, $cmd.Name)
            }

            $results.Add([pscustomobject]@{
                    Profile   = $PerformanceProfile
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

        if (-not $PSCmdlet.ShouldProcess($cmd.Name, "Apply network tuning profile '$PerformanceProfile'")) {
            if ($canLog) {
                Write-NetCleanLog -Level INFO -Message ("WhatIf prevented tuning profile '{0}' action: {1}" -f $PerformanceProfile, $cmd.Name)
            }

            $results.Add([pscustomobject]@{
                    Profile   = $PerformanceProfile
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
                    Profile   = $PerformanceProfile
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
                    Write-NetCleanLog -Level INFO -Message ("Applied tuning profile '{0}' action: {1}" -f $PerformanceProfile, $cmd.Name)
                }
                else {
                    Write-NetCleanLog -Level WARN -Message ("Failed tuning profile '{0}' action '{1}': {2}" -f $PerformanceProfile, $cmd.Name, $result.Error)
                }
            }
        }
        catch {
            if ($canLog) {
                Write-NetCleanLog -Level WARN -Message ("Exception applying tuning profile '{0}' action '{1}': {2}" -f $PerformanceProfile, $cmd.Name, $_.Exception.Message)
            }

            $results.Add([pscustomobject]@{
                    Profile   = $PerformanceProfile
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
Based on the provided context and mode, executes cleaning operations such as removing Wi-Fi profiles, resetting eligible adapters to IPv4 DHCP and Quad9 Secure DNS, flushing DNS and ARP caches, removing registry artifacts, and optionally performing advanced repairs and performance tuning. Each operation supports `-DryRun` to simulate actions without making changes. Returns an updated context object containing details of the operations and their results.
.PARAMETER Context
The context object produced during the detect/protect phases, containing inventory and protection information.
.PARAMETER Mode
Determines the cleaning mode and which operations to perform. Supported values are:
- 'Preview': Minimal cleaning for previewing potential changes.
.PARAMETER DryRun
If specified, all operations are simulated and no actual changes are made to the system. Results will indicate what would have been done.
.PARAMETER SkipWifi
If specified, Wi-Fi profile removal will be skipped.
.PARAMETER SkipDnsFlush
If specified, DNS cache flushing will be skipped.
.PARAMETER SkipEventLogs
If specified, network event log clearing will be skipped.
.PARAMETER SkipUserArtifacts
If specified, user network artifact clearing will be skipped.
.PARAMETER PerformanceProfile
Specifies the validated performance profile used when Mode is PerformanceTune.
.EXAMPLE
Invoke-NetCleanPhase3Clean -Context $ctx -Mode 'SafeConferencePrep' -DryRun
.OUTPUTS
An updated context object containing adapter configuration, Wi-Fi removal, cache clearing, registry artifact removal, event-log clearing, user artifact clearing, and any selected repair or performance-tuning operations.
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
        [ValidateSet('Conservative', 'Optimal', 'Gaming', 'Default')]
        [string]$PerformanceProfile
    )

    $canLog = $null -ne (Get-Command Write-NetCleanLog -ErrorAction SilentlyContinue)

    if ($Mode -eq 'PerformanceTune' -and [string]::IsNullOrWhiteSpace($PerformanceProfile)) {
        throw "PerformanceProfile is required when Mode is 'PerformanceTune'."
    }

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
            Skipped    = $true
            Reason     = 'SkippedByOption'
        }

        if ($canLog) {
            Write-NetCleanLog -Level INFO -Message 'Skipping Wi-Fi profile cleanup by option.'
        }
    }
    else {
        $profilesToRemove = @()
        $hasFreshSnapshot = $false

        if ($Context.PSObject.Properties.Name -contains 'NetworkProfileDecisions') {
            $profilesToRemove += @(
                $Context.NetworkProfileDecisions |
                    Where-Object { $_.ArtifactType -eq 'WiFiProfile' -and $_.Decision -eq 'Remove' } |
                    ForEach-Object Name
            )
            $hasFreshSnapshot = $true
        }
        elseif ($Context.PSObject.Properties.Name -contains 'CollectionSnapshot') {
            $profilesToRemove += @(
                $Context.CollectionSnapshot.WiFiProfiles |
                    Where-Object { -not $_.IsPolicyManaged } |
                    ForEach-Object Name
            )
            $hasFreshSnapshot = $true
        }

        if ($Context.PSObject.Properties.Name -contains 'Protect' -and $Context.Protect.PSObject.Properties.Name -contains 'Summary' -and $Context.Protect.Summary.PSObject.Properties.Name -contains 'WiFiProfilesFound') {
            $profilesToRemove += @($Context.Protect.Summary.WiFiProfilesFound)
        }

        if (-not $hasFreshSnapshot) {
            $profilesToRemove += @(Get-WiFiProfileName)
        }

        $uniqueProfiles = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
        foreach ($profileName in $profilesToRemove) {
            if (-not [string]::IsNullOrWhiteSpace($profileName)) {
                [void]$uniqueProfiles.Add($profileName.Trim())
            }
        }
        $profilesToRemove = @($uniqueProfiles | Sort-Object)
        $wifiResult = Remove-WiFiProfilesSafe -DryRun:$DryRun -WifiProfiles $profilesToRemove
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
    $nlaResults = @()

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

    $adapterResult = Reset-NetCleanAdapterConfigurationSafe `
        -Context $Context `
        -DryRun:$DryRun

    $advancedRepair = @()
    if ($Mode -eq 'AdvancedRepair') {
        $advancedRepair = @(Invoke-AdvancedNetworkRepair -DryRun:$DryRun)
    }

    $tuningResults = @()
    if ($Mode -eq 'PerformanceTune') {
        $tuningResults = @(
            Invoke-NetworkPerformanceTune `
                -PerformanceProfile $PerformanceProfile `
                -DryRun:$DryRun
        )
    }

    Add-Member -InputObject $newContext -NotePropertyName Phase -NotePropertyValue 'Clean' -Force
    Add-Member -InputObject $newContext -NotePropertyName Clean -NotePropertyValue ([pscustomobject]@{
            Mode              = $Mode
            DryRun            = [bool]$DryRun
            WiFi              = $wifiResult
            Dns               = $dnsResult
            Arp               = $arpResult
            AdapterConfiguration = $adapterResult
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
                AdaptersConfigured       = $adapterResult.ConfiguredCount
                AdaptersSkipped          = $adapterResult.SkippedCount
                AdapterFailures          = $adapterResult.FailedCount
                PreferIPv4               = $adapterResult.PreferIPv4
                AdapterRestartRequired   = $adapterResult.RequiresRestart
                AdvancedRepairActions    = @($advancedRepair).Count
                PerformanceTuningActions = @($tuningResults).Count
            }
        }) -Force

    if ($canLog) {
        if ($DryRun) {
            Write-NetCleanLog -Level INFO -Message ("Preview summary: WiFiWouldRemove={0} AdaptersWouldConfigure={1} AdapterFailures={2} RegistryWouldRemove={3} EventLogsTouched={4} UserArtifactsTouched={5} AdvancedRepairActions={6} PerformanceTuningActions={7}" -f `
                    $wifiResult.Removed,
                $adapterResult.ConfiguredCount,
                $adapterResult.FailedCount,
                $artifacts.RemovedCount,
                @($logResults).Count,
                @($userResults | Where-Object { $_.Removed }).Count,
                @($advancedRepair).Count,
                @($tuningResults).Count)

            Write-NetCleanLog -Level INFO -Message 'Preview complete. No changes were made.'
        }
        else {
            Write-NetCleanLog -Level INFO -Message ("Phase 3 clean complete. WiFiRemoved={0} AdaptersConfigured={1} AdapterFailures={2} RegistryRemoved={3} EventLogsTouched={4} UserArtifactsTouched={5} AdvancedRepairActions={6} PerformanceTuningActions={7}" -f `
                    $wifiResult.Removed,
                $adapterResult.ConfiguredCount,
                $adapterResult.FailedCount,
                $artifacts.RemovedCount,
                @($logResults).Count,
                @($userResults | Where-Object { $_.Removed }).Count,
                @($advancedRepair).Count,
                @($tuningResults).Count)
        }
    }

    # Detailed logging of cleaning actions for auditability
    if ($canLog) {
        # Wi-Fi removals
        if ($wifiResult.Profiles -and $wifiResult.Profiles.Count -gt 0) {
            foreach ($p in $wifiResult.Profiles) {
                Write-NetCleanLog -Level INFO -Message ("Wi-Fi profile removed or would be removed: {0}" -f $p)
            }
        }

        # Registry artifact removals summary
        if ($artifacts.Results -and $artifacts.Results.Count -gt 0) {
            foreach ($r in $artifacts.Results) {
                $status = if ($r.Removed) { 'Removed' } elseif ($r.Skipped) { "Skipped: $($r.Reason)" } else { "Failed: $($r.Reason)" }
                Write-NetCleanLog -Level INFO -Message ("Registry artifact: {0} => {1}" -f $r.RegistryPath, $status)
            }
        }

        # Event logs (be defensive: test for properties before accessing them)
        foreach ($l in @($logResults)) {
            $cmd = $null
            if ($null -ne $l) {
                if ($l.PSObject.Properties.Name -contains 'Command') { $cmd = $l.Command }
                elseif ($l.PSObject.Properties.Name -contains 'Name') { $cmd = $l.Name }
                elseif ($l.PSObject.Properties.Name -contains 'LogName') { $cmd = $l.LogName }
            }

            $status = '(unknown)'
            if ($l -and $l.PSObject.Properties.Name -contains 'Succeeded') {
                $status = if ($l.Succeeded) { 'OK' } else { "ERR: $($l.Error)" }
            }

            $commandDisplay = if ([string]::IsNullOrWhiteSpace($cmd)) { '(unknown)' } else { $cmd }
            Write-NetCleanLog -Level INFO -Message ("Event log operation: {0} => {1}" -f $commandDisplay, $status)
        }

        # User artifacts
        foreach ($u in @($userResults)) {
            $userStatus = if ($u.Succeeded) { 'OK' } else { "ERR: $($u.Reason)" }
            Write-NetCleanLog -Level INFO -Message ("User artifact: {0} => {1}" -f $u.Path, $userStatus)
        }

        foreach ($adapterOperation in @($adapterResult.Operations)) {
            $adapterStatus = if ($adapterOperation.Skipped) {
                "Skipped: $($adapterOperation.Reason)"
            }
            elseif ($adapterOperation.Succeeded) {
                'IPv4 DHCP and Quad9 DNS configured'
            }
            else {
                "Failed: $($adapterOperation.Error)"
            }
            Write-NetCleanLog -Level INFO -Message ("Adapter configuration: {0} => {1}" -f $adapterOperation.Name, $adapterStatus)
        }

        # Advanced repair and tuning actions
        foreach ($a in @($advancedRepair)) { Write-NetCleanLog -Level INFO -Message ("Advanced repair action: {0} => ExitCode={1} Succeeded={2}" -f $a.Name, $a.ExitCode, $a.Succeeded) }
        foreach ($t in @($tuningResults)) { Write-NetCleanLog -Level INFO -Message ("Performance tuning action: {0} => ExitCode={1} Succeeded={2}" -f $t.Name, $t.ExitCode, $t.Succeeded) }
    }

    return $newContext
}

Export-ModuleMember -Function @(
    'Invoke-NetCleanPhase3Clean',
    'Remove-WiFiProfilesSafe',
    'Clear-DnsCacheSafe',
    'Clear-ArpCacheSafe',
    'Remove-RegistryPathSafe',
    'Remove-NetworkPrivacyArtifactsSafe',
    'Clear-NetworkEventLogsSafe',
    'Clear-UserNetworkArtifactsSafe',
    'Invoke-AdvancedNetworkRepair',
    'Invoke-NetworkPerformanceTune',
    'Read-NetCleanPerformanceProfileSelection'
)
