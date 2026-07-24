<#
.SYNOPSIS
Captures real registry-derived shapes from this machine into a local, git-
ignored fixture for higher-fidelity regression testing.
.DESCRIPTION
Exports the exact output of NetClean's own snapshot-producing functions
(Get-ServiceRegistrySnapshot, Get-NetworkListProfileSnapshot,
Get-AdapterRegistryCorrelation) plus raw Uninstall-registry entries, to JSON
files under tests/LocalFixtures/data/. That directory is git-ignored - the
captured data never leaves this machine or gets committed.

Run this, then run NetClean.RealFixture.Tests.ps1 to replay the captured
shapes through Get-ServiceRegistrySnapshot/Get-NetworkListProfileSnapshot/
Get-AdapterRegistryCorrelation inside an isolated TestRegistry: hive - the
same class of real-world property-shape bug found and fixed this session
(missing DisplayName/Group/LinkageValues/etc.) is exactly what this is meant
to catch going forward, using this machine's actual data instead of hand-
crafted synthetic fixtures. Intentionally scoped to the registry-reading
functions only, not Get-ProtectionEvidence's full evidence collection (that
also queries CIM/WFP/INF/ScheduledTasks/Appx directly against the real
system regardless of any registry fixture, and takes 20-30+ seconds by
design - already covered by this session's live verification separately).
.EXAMPLE
.\tests\LocalFixtures\Export-NetCleanRealFixture.ps1
#>
[CmdletBinding()]
param(
    [string]$OutputPath = (Join-Path $PSScriptRoot 'data')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$manifestPath = Join-Path $PSScriptRoot '..\..\NetClean.psd1'
if (-not (Test-Path -LiteralPath $manifestPath)) {
    throw "NetClean.psd1 not found at path: $manifestPath"
}

if (-not (Test-Path -LiteralPath $OutputPath)) {
    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
}

Remove-Module NetClean -ErrorAction SilentlyContinue
Import-Module $manifestPath -Force

Write-Information 'Capturing service registry snapshot...' -InformationAction Continue
$serviceSnapshot = @(& (Get-Module NetClean) { Get-ServiceRegistrySnapshot })
ConvertTo-Json -InputObject $serviceSnapshot -Depth 6 -AsArray |
    Set-Content -LiteralPath (Join-Path $OutputPath 'ServiceRegistrySnapshot.json') -Encoding utf8
Write-Information "  $($serviceSnapshot.Count) services captured." -InformationAction Continue

Write-Information 'Capturing NetworkList profile snapshot...' -InformationAction Continue
$networkListSnapshot = @(& (Get-Module NetClean) { Get-NetworkListProfileSnapshot })
ConvertTo-Json -InputObject $networkListSnapshot -Depth 6 -AsArray |
    Set-Content -LiteralPath (Join-Path $OutputPath 'NetworkListProfileSnapshot.json') -Encoding utf8
Write-Information "  $($networkListSnapshot.Count) NetworkList profiles captured." -InformationAction Continue

Write-Information 'Capturing adapter registry correlation...' -InformationAction Continue
$adapterCorrelation = @(& (Get-Module NetClean) { Get-AdapterRegistryCorrelation })
ConvertTo-Json -InputObject $adapterCorrelation -Depth 6 -AsArray |
    Set-Content -LiteralPath (Join-Path $OutputPath 'AdapterRegistryCorrelation.json') -Encoding utf8
Write-Information "  $($adapterCorrelation.Count) adapter class entries captured." -InformationAction Continue

Write-Information 'Capturing Uninstall registry entries...' -InformationAction Continue
$uninstallEntries = @(
    @(
        Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue
        Get-ItemProperty -Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue
    ) | ForEach-Object {
        [pscustomobject]@{
            DisplayName     = if ($_.PSObject.Properties.Name -contains 'DisplayName') { $_.DisplayName } else { $null }
            DisplayIcon     = if ($_.PSObject.Properties.Name -contains 'DisplayIcon') { $_.DisplayIcon } else { $null }
            Publisher       = if ($_.PSObject.Properties.Name -contains 'Publisher') { $_.Publisher } else { $null }
            InstallLocation = if ($_.PSObject.Properties.Name -contains 'InstallLocation') { $_.InstallLocation } else { $null }
            UninstallString = if ($_.PSObject.Properties.Name -contains 'UninstallString') { $_.UninstallString } else { $null }
        }
    }
)
ConvertTo-Json -InputObject $uninstallEntries -Depth 6 -AsArray |
    Set-Content -LiteralPath (Join-Path $OutputPath 'UninstallEntries.json') -Encoding utf8
Write-Information "  $($uninstallEntries.Count) Uninstall entries captured." -InformationAction Continue

Write-Information '' -InformationAction Continue
Write-Information "Fixture captured to: $OutputPath" -InformationAction Continue
Write-Information 'This directory is git-ignored (tests/LocalFixtures/data/) and stays local to this machine.' -InformationAction Continue
Write-Information 'Run tests/LocalFixtures/NetClean.RealFixture.Tests.ps1 to replay it.' -InformationAction Continue
