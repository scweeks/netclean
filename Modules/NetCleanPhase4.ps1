# ---------------------------------------------------------------------------
# Phase 4 - Verify helpers
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
Performs post-cleaning state verification by comparing inventories before and after cleaning.
.DESCRIPTION
Compares protected inventory before and after cleaning and checks that saved
Wi-Fi and Windows NetworkList profiles no longer remain. Verification succeeds
only when protected vendors, interface GUIDs, and services were preserved and
the targeted network-profile traces were removed.
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
    $remainingWiFiProfiles = @(Get-WiFiProfileName)
    $remainingNetworkProfiles = @(Get-NetworkListProfileName)

    return [pscustomobject]@{
        PreInventory             = $preInventory
        PostInventory            = $postInventory
        VendorComparison         = $vendorComparison
        GuidComparison           = $guidComparison
        ServiceComparison        = $serviceComparison
        RemainingWiFiProfiles    = $remainingWiFiProfiles
        RemainingNetworkProfiles = $remainingNetworkProfiles
        Passed                   = (
            @($vendorComparison.Missing).Count -eq 0 -and
            @($guidComparison.Missing).Count -eq 0 -and
            @($serviceComparison.Missing).Count -eq 0 -and
            $remainingWiFiProfiles.Count -eq 0 -and
            $remainingNetworkProfiles.Count -eq 0
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
            Summary           = [pscustomobject]@{
                MissingVendorsCount         = @($verification.VendorComparison.Missing).Count
                MissingGuidCount            = @($verification.GuidComparison.Missing).Count
                MissingServiceCount         = @($verification.ServiceComparison.Missing).Count
                RemainingWiFiProfileCount   = @($verification.RemainingWiFiProfiles).Count
                RemainingNetworkProfileCount = @($verification.RemainingNetworkProfiles).Count
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
    }

    # Console summary for verification
    Write-Information (("Phase 4 verify: Passed={0} MissingVendors={1} MissingGuids={2} MissingServices={3} RemainingWiFi={4} RemainingNetworkProfiles={5}" -f `
                $verification.Passed,
                @($verification.VendorComparison.Missing).Count,
                @($verification.GuidComparison.Missing).Count,
                @($verification.ServiceComparison.Missing).Count,
                @($verification.RemainingWiFiProfiles).Count,
                @($verification.RemainingNetworkProfiles).Count)) -InformationAction Continue

    return $newContext
}

Export-ModuleMember -Function @(
    'Invoke-NetCleanPhase4Verify',
    'Test-NetCleanPostState'
)
