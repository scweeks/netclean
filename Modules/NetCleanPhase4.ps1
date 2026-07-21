# ---------------------------------------------------------------------------
# Phase 4 - Verify helpers
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
Independently verifies adapter changes made during conference preparation.
.DESCRIPTION
Re-reads Windows adapter, DNS, encrypted-DNS, and registry state. Verification
requires IPv4 DHCP, the exact Quad9 IPv4/IPv6 resolver set, the Microsoft IPv4
preference value, and DoH auto-upgrade without plaintext fallback whenever the
corresponding change was applied. Dry runs and contexts without adapter changes
are reported as not applicable.
.PARAMETER Context
Clean-phase context containing the adapter operation ledger.
.OUTPUTS
System.Management.Automation.PSCustomObject
#>
function Test-NetCleanAdapterPostState {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Context
    )

    if (
        $Context.PSObject.Properties.Name -notcontains 'Clean' -or
        -not $Context.Clean -or
        $Context.Clean.PSObject.Properties.Name -notcontains 'AdapterConfiguration'
    ) {
        return [pscustomobject]@{
            Applicable = $false
            Passed     = $true
            Reason     = 'NoAdapterChanges'
            Checks     = @()
        }
    }

    if (
        $Context.Clean.PSObject.Properties.Name -contains 'DryRun' -and
        $Context.Clean.DryRun
    ) {
        return [pscustomobject]@{
            Applicable = $false
            Passed     = $true
            Reason     = 'DryRun'
            Checks     = @()
        }
    }

    $configuration = $Context.Clean.AdapterConfiguration
    $expectedDns = @($configuration.DnsServers)
    $checks = [System.Collections.Generic.List[object]]::new()

    foreach ($operation in @($configuration.Operations)) {
        if ($operation.Skipped) {
            continue
        }

        if (-not $operation.Succeeded) {
            $checks.Add([pscustomobject]@{
                    Category = 'AdapterCommand'
                    Target   = $operation.Name
                    Expected = 'Succeeded'
                    Actual   = $operation.Reason
                    Passed   = $false
                    Error    = $operation.Error
                })
            continue
        }

        try {
            $dhcpStates = @(
                Get-NetIPInterface `
                    -InterfaceIndex $operation.InterfaceIndex `
                    -AddressFamily IPv4 `
                    -ErrorAction Stop |
                    ForEach-Object { [string]$_.Dhcp }
            )
            $dhcpPassed = (
                $dhcpStates.Count -gt 0 -and
                @($dhcpStates | Where-Object { $_ -ne 'Enabled' }).Count -eq 0
            )
            $checks.Add([pscustomobject]@{
                    Category = 'IPv4Dhcp'
                    Target   = $operation.Name
                    Expected = 'Enabled'
                    Actual   = ($dhcpStates -join ', ')
                    Passed   = $dhcpPassed
                    Error    = $null
                })
        }
        catch {
            $checks.Add([pscustomobject]@{
                    Category = 'IPv4Dhcp'
                    Target   = $operation.Name
                    Expected = 'Enabled'
                    Actual   = $null
                    Passed   = $false
                    Error    = $_.Exception.Message
                })
        }

        try {
            $actualDns = @(
                Get-DnsClientServerAddress `
                    -InterfaceIndex $operation.InterfaceIndex `
                    -ErrorAction Stop |
                    ForEach-Object { $_.ServerAddresses } |
                    Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
                    Sort-Object -Unique
            )
            $dnsComparison = Compare-StringSet -Before $expectedDns -After $actualDns
            $dnsPassed = (
                @($dnsComparison.Missing).Count -eq 0 -and
                @($dnsComparison.Added).Count -eq 0
            )
            $checks.Add([pscustomobject]@{
                    Category = 'DnsServers'
                    Target   = $operation.Name
                    Expected = @($expectedDns | Sort-Object)
                    Actual   = $actualDns
                    Passed   = $dnsPassed
                    Error    = $null
                })
        }
        catch {
            $checks.Add([pscustomobject]@{
                    Category = 'DnsServers'
                    Target   = $operation.Name
                    Expected = $expectedDns
                    Actual   = @()
                    Passed   = $false
                    Error    = $_.Exception.Message
                })
        }
    }

    $verifyPreference = (
        $configuration.PreferIPv4 -and
        $configuration.PSObject.Properties.Name -contains 'IPv4Preference' -and
        $configuration.IPv4Preference.Succeeded -and
        -not $configuration.IPv4Preference.Skipped
    )
    if ($verifyPreference) {
        try {
            $preference = Get-ItemProperty `
                -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' `
                -Name 'DisabledComponents' `
                -ErrorAction Stop
            $actualPreference = [uint32]$preference.DisabledComponents
            $checks.Add([pscustomobject]@{
                    Category = 'IPv4Preference'
                    Target   = 'Windows IP stack'
                    Expected = 32
                    Actual   = $actualPreference
                    Passed   = ($actualPreference -eq 32)
                    Error    = $null
                })
        }
        catch {
            $checks.Add([pscustomobject]@{
                    Category = 'IPv4Preference'
                    Target   = 'Windows IP stack'
                    Expected = 32
                    Actual   = $null
                    Passed   = $false
                    Error    = $_.Exception.Message
                })
        }
    }

    $verifyDoh = (
        $configuration.PSObject.Properties.Name -contains 'DnsOverHttps' -and
        $configuration.DnsOverHttps.Supported -and
        $configuration.DnsOverHttps.ConfiguredCount -gt 0
    )
    if ($verifyDoh) {
        foreach ($serverAddress in $expectedDns) {
            try {
                $dohEntries = @(
                    Get-DnsClientDohServerAddress `
                        -ServerAddress $serverAddress `
                        -ErrorAction Stop
                )
                $matchingEntry = @(
                    $dohEntries |
                        Where-Object { $_.ServerAddress -eq $serverAddress }
                ) | Select-Object -First 1
                $dohPassed = (
                    $null -ne $matchingEntry -and
                    $matchingEntry.DohTemplate -eq 'https://dns.quad9.net/dns-query' -and
                    [bool]$matchingEntry.AutoUpgrade -and
                    -not [bool]$matchingEntry.AllowFallbackToUdp
                )
                $actualDoh = if ($matchingEntry) {
                    'AutoUpgrade={0}; AllowFallbackToUdp={1}' -f `
                        ([bool]$matchingEntry.AutoUpgrade),
                        ([bool]$matchingEntry.AllowFallbackToUdp)
                }
                else {
                    'Missing'
                }
                $checks.Add([pscustomobject]@{
                        Category = 'DnsOverHttps'
                        Target   = $serverAddress
                        Expected = 'AutoUpgrade=True; AllowFallbackToUdp=False'
                        Actual   = $actualDoh
                        Passed   = $dohPassed
                        Error    = $null
                    })
            }
            catch {
                $checks.Add([pscustomobject]@{
                        Category = 'DnsOverHttps'
                        Target   = $serverAddress
                        Expected = 'AutoUpgrade=True; AllowFallbackToUdp=False'
                        Actual   = $null
                        Passed   = $false
                        Error    = $_.Exception.Message
                    })
            }
        }
    }

    return [pscustomobject]@{
        Applicable = $true
        Passed     = (@($checks | Where-Object { -not $_.Passed }).Count -eq 0)
        Reason     = 'Verified'
        Checks     = $checks.ToArray()
    }
}

<#
.SYNOPSIS
Performs post-cleaning state verification by comparing inventories before and after cleaning.
.DESCRIPTION
Compares protected inventory before and after cleaning and checks that saved
    Wi-Fi and Windows NetworkList profiles no longer remain, and independently
    verifies adapter changes recorded by the clean phase. Verification succeeds
    only when protected inventory was preserved, targeted traces were removed,
    and every applicable adapter post-state check passes.
.PARAMETER Context
The context object containing the pre-cleaning inventory and other relevant information.
.EXAMPLE
Test-NetCleanPostState -Context $ctx
.OUTPUTS
A custom object containing protected-inventory comparisons, remaining privacy
artifacts, and an overall pass/fail status.
.NOTES
- This function assumes that the pre-cleaning inventory was accurately captured during the detect/protect phases. Ensure that those phases completed successfully for reliable verification results.
#>
function Test-NetCleanPostState {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
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
    $guidComparison = Compare-StringSet -Before $preGuids -After $postGuids

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
    $isDryRun = (
        $Context.PSObject.Properties.Name -contains 'Clean' -and
        $Context.Clean -and
        $Context.Clean.PSObject.Properties.Name -contains 'DryRun' -and
        $Context.Clean.DryRun
    )
    $remainingWiFiProfiles = @()
    $remainingNetworkProfiles = @()
    if (-not $isDryRun) {
        $remainingWiFiProfiles = @(Get-WiFiProfileName)
        $remainingNetworkProfiles = @(Get-NetworkListProfileName)
    }
    $adapterVerification = Test-NetCleanAdapterPostState -Context $Context

    return [pscustomobject]@{
        VerificationMode         = if ($isDryRun) { 'Planned' } else { 'Observed' }
        PreInventory             = $preInventory
        PostInventory            = $postInventory
        VendorComparison         = $vendorComparison
        GuidComparison           = $guidComparison
        ServiceComparison        = $serviceComparison
        RemainingWiFiProfiles    = $remainingWiFiProfiles
        RemainingNetworkProfiles = $remainingNetworkProfiles
        AdapterVerification      = $adapterVerification
        Passed                   = (
            @($vendorComparison.Missing).Count -eq 0 -and
            @($guidComparison.Missing).Count -eq 0 -and
            @($serviceComparison.Missing).Count -eq 0 -and
            $remainingWiFiProfiles.Count -eq 0 -and
            $remainingNetworkProfiles.Count -eq 0 -and
            $adapterVerification.Passed
        )
    }
}

<#
.SYNOPSIS
Performs verification checks after cleaning to assess the state of the system.
.DESCRIPTION
Confirms that protected inventory remains intact and that saved Wi-Fi and
Windows NetworkList profiles were removed.
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
    [OutputType([pscustomobject])]
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
            Passed            = $verification.Passed
            VendorComparison  = $verification.VendorComparison
            GuidComparison    = $verification.GuidComparison
            ServiceComparison = $verification.ServiceComparison
            RemainingWiFiProfiles = $verification.RemainingWiFiProfiles
            RemainingNetworkProfiles = $verification.RemainingNetworkProfiles
            AdapterVerification = $verification.AdapterVerification
            Summary           = [pscustomobject]@{
                MissingVendorsCount         = @($verification.VendorComparison.Missing).Count
                MissingGuidCount            = @($verification.GuidComparison.Missing).Count
                MissingServiceCount         = @($verification.ServiceComparison.Missing).Count
                RemainingWiFiProfileCount   = @($verification.RemainingWiFiProfiles).Count
                RemainingNetworkProfileCount = @($verification.RemainingNetworkProfiles).Count
                AdapterCheckFailureCount    = @(
                    $verification.AdapterVerification.Checks |
                        Where-Object { -not $_.Passed }
                ).Count
                Passed                      = $verification.Passed
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

        if (@($verification.RemainingWiFiProfiles).Count -gt 0) {
            Write-NetCleanLog -Level WARN -Message ("Verification: Remaining Wi-Fi profiles: {0}" -f ($verification.RemainingWiFiProfiles -join ', '))
        }

        if (@($verification.RemainingNetworkProfiles).Count -gt 0) {
            Write-NetCleanLog -Level WARN -Message ("Verification: Remaining NetworkList profiles: {0}" -f ($verification.RemainingNetworkProfiles -join ', '))
        }

        foreach ($check in @($verification.AdapterVerification.Checks)) {
            $level = if ($check.Passed) { 'INFO' } else { 'WARN' }
            $message = 'Verification: {0} Target={1} Passed={2} Expected={3} Actual={4}' -f `
                $check.Category,
                $check.Target,
                $check.Passed,
                (@($check.Expected) -join ', '),
                (@($check.Actual) -join ', ')
            if ($check.Error) {
                $message += " Error=$($check.Error)"
            }
            Write-NetCleanLog -Level $level -Message $message
        }
    }

    # Console summary for verification
    Write-Information (("Phase 4 verify: Passed={0} MissingVendors={1} MissingGuids={2} MissingServices={3} RemainingWiFi={4} RemainingNetworkProfiles={5} AdapterCheckFailures={6}" -f `
                $verification.Passed,
                @($verification.VendorComparison.Missing).Count,
                @($verification.GuidComparison.Missing).Count,
                @($verification.ServiceComparison.Missing).Count,
                @($verification.RemainingWiFiProfiles).Count,
                @($verification.RemainingNetworkProfiles).Count,
                @($verification.AdapterVerification.Checks | Where-Object { -not $_.Passed }).Count)) -InformationAction Continue

    return $newContext
}

Export-ModuleMember -Function @(
    'Invoke-NetCleanPhase4Verify',
    'Test-NetCleanPostState'
)
