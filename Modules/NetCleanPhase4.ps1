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
Verifies the non-adapter cleanup work recorded by Phase 3.
.DESCRIPTION
Re-reads persistent registry, user-artifact, and event-log state after cleanup.
DNS and ARP caches can legitimately repopulate immediately, while stack resets
and tuning changes may require a restart, so those volatile or deferred actions
are represented by their command-result ledger instead of a misleading empty-
state assertion. Wi-Fi and NetworkList absence are independently checked by
Test-NetCleanPostState.
.PARAMETER Context
Clean-phase context containing the operation ledger.
.OUTPUTS
System.Management.Automation.PSCustomObject
#>
function Test-NetCleanCleanupPostState {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Context
    )

    if (
        $Context.PSObject.Properties.Name -notcontains 'Clean' -or
        -not $Context.Clean
    ) {
        return [pscustomobject]@{
            Applicable = $false
            Passed     = $true
            Reason     = 'NoCleanupResults'
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

    $checks = [System.Collections.Generic.List[object]]::new()
    foreach ($propertyName in @('Dns', 'Arp')) {
        if ($Context.Clean.PSObject.Properties.Name -notcontains $propertyName) {
            continue
        }

        $operation = $Context.Clean.$propertyName
        if (-not $operation) {
            continue
        }

        $skippedByOption = (
            $operation.PSObject.Properties.Name -contains 'Skipped' -and
            $operation.Skipped -and
            $operation.PSObject.Properties.Name -contains 'Reason' -and
            $operation.Reason -eq 'SkippedByOption'
        )
        $succeeded = (
            $operation.PSObject.Properties.Name -contains 'Succeeded' -and
            [bool]$operation.Succeeded
        )
        $errorMessage = if ($operation.PSObject.Properties.Name -contains 'Error') {
            $operation.Error
        }
        else {
            $null
        }

        $checks.Add([pscustomobject]@{
                Category         = 'VolatileCacheAction'
                Target           = $operation.Name
                VerificationType = 'CommandResult'
                Expected         = 'Succeeded or explicitly skipped'
                Actual           = if ($skippedByOption) { 'SkippedByOption' } elseif ($succeeded) { 'Succeeded' } else { 'Failed' }
                Passed           = ($succeeded -or $skippedByOption)
                Error            = $errorMessage
            })
    }

    if (
        $Context.Clean.PSObject.Properties.Name -contains 'RegistryArtifacts' -and
        $Context.Clean.RegistryArtifacts -and
        $Context.Clean.RegistryArtifacts.PSObject.Properties.Name -contains 'Results'
    ) {
        foreach ($operation in @($Context.Clean.RegistryArtifacts.Results)) {
            if (-not $operation) {
                continue
            }

            $target = $operation.RegistryPath
            $reason = if ($operation.PSObject.Properties.Name -contains 'Reason') {
                $operation.Reason
            }
            else {
                $null
            }
            $succeeded = (
                $operation.PSObject.Properties.Name -contains 'Succeeded' -and
                [bool]$operation.Succeeded
            )
            $protected = (
                $operation.PSObject.Properties.Name -contains 'Skipped' -and
                $operation.Skipped -and
                $reason -eq 'Protected'
            )
            $shouldBeAbsent = (
                $succeeded -and
                (
                    ($operation.PSObject.Properties.Name -contains 'Removed' -and $operation.Removed) -or
                    $reason -eq 'NotFound'
                )
            )

            if ($protected) {
                $checks.Add([pscustomobject]@{
                        Category         = 'RegistryArtifact'
                        Target           = $target
                        VerificationType = 'ProtectionBoundary'
                        Expected         = 'Preserved'
                        Actual           = 'Protected'
                        Passed           = $true
                        Error            = $null
                    })
                continue
            }

            if ($shouldBeAbsent) {
                try {
                    $exists = Test-RegistryPathExist -RegistryPath $target -ThrowOnError
                    $checks.Add([pscustomobject]@{
                            Category         = 'RegistryArtifact'
                            Target           = $target
                            VerificationType = 'IndependentState'
                            Expected         = 'Absent'
                            Actual           = if ($exists) { 'Present' } else { 'Absent' }
                            Passed           = (-not $exists)
                            Error            = $null
                        })
                }
                catch {
                    $checks.Add([pscustomobject]@{
                            Category         = 'RegistryArtifact'
                            Target           = $target
                            VerificationType = 'IndependentState'
                            Expected         = 'Absent'
                            Actual           = 'Unknown'
                            Passed           = $false
                            Error            = $_.Exception.Message
                        })
                }
                continue
            }

            $checks.Add([pscustomobject]@{
                    Category         = 'RegistryArtifact'
                    Target           = $target
                    VerificationType = 'CommandResult'
                    Expected         = 'Removed, absent, or protected'
                    Actual           = if ($reason) { $reason } else { 'Failed' }
                    Passed           = $false
                    Error            = if ($succeeded) { $null } else { $reason }
                })
        }
    }

    if ($Context.Clean.PSObject.Properties.Name -contains 'UserArtifacts') {
        foreach ($operation in @($Context.Clean.UserArtifacts)) {
            if (-not $operation) {
                continue
            }

            $reason = if ($operation.PSObject.Properties.Name -contains 'Reason') {
                $operation.Reason
            }
            else {
                $null
            }
            $succeeded = (
                $operation.PSObject.Properties.Name -contains 'Succeeded' -and
                [bool]$operation.Succeeded
            )
            $shouldBeAbsent = (
                $succeeded -and
                (
                    ($operation.PSObject.Properties.Name -contains 'Removed' -and $operation.Removed) -or
                    $reason -eq 'NotFound'
                )
            )

            if ($shouldBeAbsent) {
                try {
                    $exists = Test-Path -LiteralPath $operation.Path -ErrorAction Stop
                    $checks.Add([pscustomobject]@{
                            Category         = 'UserArtifact'
                            Target           = $operation.Path
                            VerificationType = 'IndependentState'
                            Expected         = 'Absent'
                            Actual           = if ($exists) { 'Present' } else { 'Absent' }
                            Passed           = (-not $exists)
                            Error            = $null
                        })
                }
                catch {
                    $checks.Add([pscustomobject]@{
                            Category         = 'UserArtifact'
                            Target           = $operation.Path
                            VerificationType = 'IndependentState'
                            Expected         = 'Absent'
                            Actual           = 'Unknown'
                            Passed           = $false
                            Error            = $_.Exception.Message
                        })
                }
                continue
            }

            $checks.Add([pscustomobject]@{
                    Category         = 'UserArtifact'
                    Target           = $operation.Path
                    VerificationType = 'CommandResult'
                    Expected         = 'Removed or absent'
                    Actual           = if ($reason) { $reason } else { 'Failed' }
                    Passed           = $false
                    Error            = if ($succeeded) { $null } else { $reason }
                })
        }
    }

    if ($Context.Clean.PSObject.Properties.Name -contains 'EventLogs') {
        foreach ($operation in @($Context.Clean.EventLogs)) {
            if (-not $operation) {
                continue
            }

            $cleared = (
                $operation.PSObject.Properties.Name -contains 'Cleared' -and
                [bool]$operation.Cleared
            )
            $succeeded = (
                $operation.PSObject.Properties.Name -contains 'Succeeded' -and
                [bool]$operation.Succeeded
            )
            $completedAt = if ($operation.PSObject.Properties.Name -contains 'CompletedAt') {
                $operation.CompletedAt
            }
            else {
                $null
            }

            if ($cleared -and $succeeded -and $completedAt) {
                try {
                    $priorEvents = @(
                        Get-WinEvent `
                            -FilterHashtable @{
                                LogName = $operation.LogName
                                EndTime = $completedAt
                            } `
                            -MaxEvents 1 `
                            -ErrorAction Stop
                    )
                    $checks.Add([pscustomobject]@{
                            Category         = 'EventLog'
                            Target           = $operation.LogName
                            VerificationType = 'IndependentState'
                            Expected         = 'No events at or before cleanup completion'
                            Actual           = if ($priorEvents.Count -eq 0) { 'Absent' } else { 'Present' }
                            Passed           = ($priorEvents.Count -eq 0)
                            Error            = $null
                        })
                }
                catch {
                    $noEventsFound = $_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*'
                    $checks.Add([pscustomobject]@{
                            Category         = 'EventLog'
                            Target           = $operation.LogName
                            VerificationType = 'IndependentState'
                            Expected         = 'No events at or before cleanup completion'
                            Actual           = if ($noEventsFound) { 'Absent' } else { 'Unknown' }
                            Passed           = $noEventsFound
                            Error            = if ($noEventsFound) { $null } else { $_.Exception.Message }
                        })
                }
                continue
            }

            $errorMessage = if ($operation.PSObject.Properties.Name -contains 'Error') {
                $operation.Error
            }
            else {
                $null
            }
            $checks.Add([pscustomobject]@{
                    Category         = 'EventLog'
                    Target           = if ($operation.PSObject.Properties.Name -contains 'LogName') { $operation.LogName } else { $operation.Name }
                    VerificationType = 'CommandResult'
                    Expected         = 'Cleared with completion timestamp'
                    Actual           = if (-not $succeeded) { 'Failed' } elseif (-not $cleared) { 'NotCleared' } else { 'MissingCompletionTime' }
                    Passed           = $false
                    Error            = $errorMessage
                })
        }
    }

    foreach ($operationGroup in @(
            [pscustomobject]@{ Property = 'AdvancedRepair'; Category = 'AdvancedRepairAction' },
            [pscustomobject]@{ Property = 'PerformanceTuning'; Category = 'PerformanceTuningAction' }
        )) {
        if ($Context.Clean.PSObject.Properties.Name -notcontains $operationGroup.Property) {
            continue
        }

        foreach ($operation in @($Context.Clean.($operationGroup.Property))) {
            if (-not $operation) {
                continue
            }

            $succeeded = (
                $operation.PSObject.Properties.Name -contains 'Succeeded' -and
                [bool]$operation.Succeeded
            )
            $errorMessage = if ($operation.PSObject.Properties.Name -contains 'Error') {
                $operation.Error
            }
            else {
                $null
            }
            $checks.Add([pscustomobject]@{
                    Category         = $operationGroup.Category
                    Target           = $operation.Name
                    VerificationType = 'CommandResult'
                    Expected         = 'Succeeded'
                    Actual           = if ($succeeded) { 'Succeeded' } else { 'Failed' }
                    Passed           = $succeeded
                    Error            = $errorMessage
            })
        }
    }

    $wifiCleanupExpected = (
        $Context.Clean.PSObject.Properties.Name -contains 'WiFi' -and
        $Context.Clean.WiFi -and
        -not (
            $Context.Clean.WiFi.PSObject.Properties.Name -contains 'Skipped' -and
            $Context.Clean.WiFi.Skipped
        )
    )
    if ($wifiCleanupExpected) {
        try {
            $physicalAdapters = @(Get-NetAdapter -Physical -ErrorAction Stop)
            $wiredAdapters = [System.Collections.Generic.List[object]]::new()
            $wifiAdapters = [System.Collections.Generic.List[object]]::new()

            foreach ($adapter in $physicalAdapters) {
                $mediaTypes = [System.Collections.Generic.List[string]]::new()
                foreach ($propertyName in @('MediaType', 'PhysicalMediaType')) {
                    if (
                        $adapter.PSObject.Properties.Name -contains $propertyName -and
                        -not [string]::IsNullOrWhiteSpace([string]$adapter.$propertyName)
                    ) {
                        $mediaTypes.Add([string]$adapter.$propertyName)
                    }
                }

                $ndisMedium = if ($adapter.PSObject.Properties.Name -contains 'NdisPhysicalMedium') {
                    [int]$adapter.NdisPhysicalMedium
                }
                else {
                    -1
                }
                $isWired = (
                    $mediaTypes -contains '802.3' -or
                    $ndisMedium -eq 14
                )
                $isWifi = (
                    $mediaTypes -contains 'Native 802.11' -or
                    $mediaTypes -contains '802.11' -or
                    $mediaTypes -contains 'Wireless LAN' -or
                    $ndisMedium -in @(1, 9)
                )

                if ($isWired) {
                    $wiredAdapters.Add($adapter)
                }
                elseif ($isWifi) {
                    $wifiAdapters.Add($adapter)
                }
            }

            $connectedWired = @($wiredAdapters | Where-Object { $_.Status -eq 'Up' })
            $connectedWifi = @($wifiAdapters | Where-Object { $_.Status -eq 'Up' })
            $checks.Add([pscustomobject]@{
                    Category         = 'WiFiConnection'
                    Target           = 'Physical Wi-Fi adapters'
                    VerificationType = 'IndependentState'
                    Applicable       = $true
                    Expected         = 'Disconnected'
                    Actual           = if ($connectedWifi.Count -eq 0) { 'Disconnected' } else { @($connectedWifi.Name) }
                    Passed           = ($connectedWifi.Count -eq 0)
                    Error            = $null
                })

            if ($connectedWired.Count -gt 0) {
                foreach ($category in @('DnsCache', 'ArpCache')) {
                    $checks.Add([pscustomobject]@{
                            Category         = $category
                            Target           = 'Local cache'
                            VerificationType = 'ConditionalState'
                            Applicable       = $false
                            Expected         = 'Not evaluated while wired LAN is connected'
                            Actual           = 'WiredLanConnected'
                            Passed           = $true
                            Error            = $null
                        })
                }
            }
            else {
                $dnsWasApplied = (
                    $Context.Clean.PSObject.Properties.Name -contains 'Dns' -and
                    $Context.Clean.Dns -and
                    $Context.Clean.Dns.PSObject.Properties.Name -contains 'Succeeded' -and
                    $Context.Clean.Dns.Succeeded -and
                    -not (
                        $Context.Clean.Dns.PSObject.Properties.Name -contains 'Skipped' -and
                        $Context.Clean.Dns.Skipped
                    )
                )
                if ($dnsWasApplied) {
                    try {
                        $dnsEntries = @(Get-DnsClientCache -ErrorAction Stop)
                        $checks.Add([pscustomobject]@{
                                Category         = 'DnsCache'
                                Target           = 'DNS client cache'
                                VerificationType = 'ConditionalState'
                                Applicable       = $true
                                Expected         = 'Empty when no wired LAN is connected'
                                Actual           = $dnsEntries.Count
                                Passed           = ($dnsEntries.Count -eq 0)
                                Error            = $null
                            })
                    }
                    catch {
                        $checks.Add([pscustomobject]@{
                                Category         = 'DnsCache'
                                Target           = 'DNS client cache'
                                VerificationType = 'ConditionalState'
                                Applicable       = $true
                                Expected         = 'Empty when no wired LAN is connected'
                                Actual           = 'Unknown'
                                Passed           = $false
                                Error            = $_.Exception.Message
                            })
                    }
                }

                $arpWasApplied = (
                    $Context.Clean.PSObject.Properties.Name -contains 'Arp' -and
                    $Context.Clean.Arp -and
                    $Context.Clean.Arp.PSObject.Properties.Name -contains 'Succeeded' -and
                    $Context.Clean.Arp.Succeeded -and
                    -not (
                        $Context.Clean.Arp.PSObject.Properties.Name -contains 'Skipped' -and
                        $Context.Clean.Arp.Skipped
                    )
                )
                if ($arpWasApplied) {
                    try {
                        $physicalInterfaceIndexes = @(
                            $physicalAdapters |
                                Where-Object {
                                    $_.PSObject.Properties.Name -contains 'InterfaceIndex' -and
                                    $null -ne $_.InterfaceIndex
                                } |
                                Select-Object -ExpandProperty InterfaceIndex -Unique
                        )
                        $dynamicNeighbors = if ($physicalInterfaceIndexes.Count -eq 0) {
                            @()
                        }
                        else {
                            @(
                                Get-NetNeighbor `
                                    -InterfaceIndex $physicalInterfaceIndexes `
                                    -AddressFamily IPv4 `
                                    -PolicyStore ActiveStore `
                                    -ErrorAction Stop |
                                    Where-Object { [string]$_.State -ne 'Permanent' }
                            )
                        }
                        $dynamicNeighborCount = @($dynamicNeighbors).Count
                        $checks.Add([pscustomobject]@{
                                Category         = 'ArpCache'
                                Target           = 'Physical-adapter IPv4 neighbor cache'
                                VerificationType = 'ConditionalState'
                                Applicable       = $true
                                Expected         = 'No dynamic entries when no wired LAN is connected'
                                Actual           = @($dynamicNeighbors | ForEach-Object { $_.IPAddress })
                                Passed           = ($dynamicNeighborCount -eq 0)
                                Error            = $null
                            })
                    }
                    catch {
                        $checks.Add([pscustomobject]@{
                                Category         = 'ArpCache'
                                Target           = 'Physical-adapter IPv4 neighbor cache'
                                VerificationType = 'ConditionalState'
                                Applicable       = $true
                                Expected         = 'No dynamic entries when no wired LAN is connected'
                                Actual           = 'Unknown'
                                Passed           = $false
                                Error            = $_.Exception.Message
                            })
                    }
                }
            }
        }
        catch {
            $checks.Add([pscustomobject]@{
                    Category         = 'ConnectivityDetection'
                    Target           = 'Physical network adapters'
                    VerificationType = 'IndependentState'
                    Applicable       = $true
                    Expected         = 'Adapter state available'
                    Actual           = 'Unknown'
                    Passed           = $false
                    Error            = $_.Exception.Message
                })
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
    $cleanupVerification = Test-NetCleanCleanupPostState -Context $Context

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
        CleanupVerification      = $cleanupVerification
        Passed                   = (
            @($vendorComparison.Missing).Count -eq 0 -and
            @($guidComparison.Missing).Count -eq 0 -and
            @($serviceComparison.Missing).Count -eq 0 -and
            $remainingWiFiProfiles.Count -eq 0 -and
            $remainingNetworkProfiles.Count -eq 0 -and
            $adapterVerification.Passed -and
            $cleanupVerification.Passed
        )
    }
}

<#
.SYNOPSIS
Writes a machine-readable post-cleanup verification ledger.
.DESCRIPTION
Serializes the independently observed protection, privacy-artifact, and adapter
checks to UTF-8 JSON in the private backup directory. The report contains no
pre-cleaning inventory beyond missing-item names needed to explain failures.
.PARAMETER Dest
Private backup directory that receives the report.
.PARAMETER Verification
Post-state verification object returned by Test-NetCleanPostState.
.PARAMETER DryRun
Returns the planned path without creating or changing files.
.OUTPUTS
System.String
#>
function Export-NetCleanVerificationReport {
    [CmdletBinding()]
    [OutputType([System.String])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Dest,

        [Parameter(Mandatory = $true)]
        [pscustomobject]$Verification,

        [switch]$DryRun
    )

    $file = Join-Path $Dest ("VerificationReport_{0}.json" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
    if ($DryRun) {
        return $file
    }

    New-DirectoryIfNotExist -Path $Dest
    Set-NetCleanPrivateDirectoryAcl -Path $Dest

    $report = [ordered]@{
        VerifiedAt = (Get-Date).ToString('s')
        VerificationMode = $Verification.VerificationMode
        Passed = [bool]$Verification.Passed
        ProtectedInventory = [ordered]@{
            MissingVendors = @($Verification.VendorComparison.Missing)
            MissingInterfaceGuids = @($Verification.GuidComparison.Missing)
            MissingServices = @($Verification.ServiceComparison.Missing)
        }
        PrivacyArtifacts = [ordered]@{
            RemainingWiFiProfiles = @($Verification.RemainingWiFiProfiles)
            RemainingNetworkProfiles = @($Verification.RemainingNetworkProfiles)
        }
        AdapterVerification = $Verification.AdapterVerification
        CleanupVerification = $Verification.CleanupVerification
    }

    $json = $report | ConvertTo-Json -Depth 10
    WriteAllText -Path $file -Contents $json -Encoding $script:Utf8NoBom
    return $file
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
    $verificationReport = $null
    if (
        $Context.PSObject.Properties.Name -contains 'BackupPath' -and
        -not [string]::IsNullOrWhiteSpace($Context.BackupPath)
    ) {
        $verificationReport = Export-NetCleanVerificationReport `
            -Dest $Context.BackupPath `
            -Verification $verification `
            -DryRun:($verification.VerificationMode -eq 'Planned')
    }

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
            CleanupVerification = $verification.CleanupVerification
            VerificationReport = $verificationReport
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
                CleanupCheckFailureCount    = @(
                    $verification.CleanupVerification.Checks |
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

        foreach ($check in @($verification.CleanupVerification.Checks)) {
            $level = if ($check.Passed) { 'INFO' } else { 'WARN' }
            $applicable = if ($check.PSObject.Properties.Name -contains 'Applicable') {
                [bool]$check.Applicable
            }
            else {
                $true
            }
            $expected = if ($check.PSObject.Properties.Name -contains 'Expected') {
                @($check.Expected) -join ', '
            }
            else {
                $null
            }
            $actual = if ($check.PSObject.Properties.Name -contains 'Actual') {
                @($check.Actual) -join ', '
            }
            else {
                $null
            }
            $errorMessage = if ($check.PSObject.Properties.Name -contains 'Error') {
                $check.Error
            }
            else {
                $null
            }
            $message = 'Verification: {0} Target={1} Applicable={2} Passed={3} Expected={4} Actual={5}' -f `
                $check.Category,
                $check.Target,
                $applicable,
                $check.Passed,
                $expected,
                $actual
            if ($errorMessage) {
                $message += " Error=$errorMessage"
            }
            Write-NetCleanLog -Level $level -Message $message
        }
    }

    # Console summary for verification
    Write-Information (("Phase 4 verify: Passed={0} MissingVendors={1} MissingGuids={2} MissingServices={3} RemainingWiFi={4} RemainingNetworkProfiles={5} AdapterCheckFailures={6} CleanupCheckFailures={7}" -f `
                $verification.Passed,
                @($verification.VendorComparison.Missing).Count,
                @($verification.GuidComparison.Missing).Count,
                @($verification.ServiceComparison.Missing).Count,
                @($verification.RemainingWiFiProfiles).Count,
                @($verification.RemainingNetworkProfiles).Count,
                @($verification.AdapterVerification.Checks | Where-Object { -not $_.Passed }).Count,
                @($verification.CleanupVerification.Checks | Where-Object { -not $_.Passed }).Count)) -InformationAction Continue

    return $newContext
}

Export-ModuleMember -Function @(
    'Invoke-NetCleanPhase4Verify',
    'Test-NetCleanPostState'
)
