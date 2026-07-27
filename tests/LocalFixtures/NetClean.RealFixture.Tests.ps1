<#
.SYNOPSIS
Replays a locally-captured real-machine fixture (see Export-NetCleanRealFixture.ps1)
through NetClean's detection/evidence functions inside an isolated TestRegistry:
hive.
.DESCRIPTION
Never touches the real registry - everything is written to Pester's ephemeral
TestRegistry: drive and redirected there via Set-NetCleanRegistryRootMap, the
same isolation mechanism used by tests/System/NetClean.Registry.System.Tests.ps1.
Skips entirely (not a failure) when no local fixture has been captured yet,
so this file is safe to run on any machine, including CI, without ever
requiring real machine data to exist.

Runtime note: the TestRegistry: provider has real per-write overhead
(measured ~0.9s per New-ItemProperty call on this machine), so even the
capped sample below (30 services + 30 Uninstall entries + all adapter
entries) takes several minutes end to end - the actual test assertions
run in seconds, the time is all in populating the fixture. This is meant
to be run occasionally as a diagnostic, not as part of the fast day-to-day
test loop; it is intentionally excluded from Run-NetClean-Coverage.ps1's
test discovery for that reason.
#>
$manifestPath = Join-Path $PSScriptRoot '..\..\NetClean.psd1'

if (-not (Test-Path -LiteralPath $manifestPath)) {
    throw "NetClean.psd1 not found at path: $manifestPath"
}

Remove-Module NetClean -ErrorAction SilentlyContinue
Import-Module $manifestPath -Force

Describe 'NetClean real-machine fixture replay' -Tag 'LocalFixture' {

    BeforeAll {
        # Pester v5+ separates Discovery from Run; variables and functions
        # defined at file top level (Discovery) are not visible in Run-phase
        # blocks, so both are (re)established fresh here instead.
        # $PSScriptRoot itself is one of the few things Pester preserves
        # across that boundary.
        $script:FixtureDataPath = Join-Path $PSScriptRoot 'data'
        $script:HasFixture = Test-Path -LiteralPath (Join-Path $script:FixtureDataPath 'ServiceRegistrySnapshot.json')

        function Set-FixtureRegistryValue {
            [CmdletBinding(SupportsShouldProcess = $true)]
            param(
                [Parameter(Mandatory)]
                [string]$Path,
                [Parameter()]
                [AllowNull()]
                [object]$Values
            )

            if ($null -eq $Values) { return }
            if (-not (Test-Path -LiteralPath $Path)) {
                New-Item -Path $Path -Force | Out-Null
            }

            if (-not $PSCmdlet.ShouldProcess($Path, 'Set fixture registry values')) { return }

            foreach ($prop in $Values.PSObject.Properties) {
                $name = $prop.Name
                $value = $prop.Value
                if ($null -eq $value -or $name -eq 'NetCleanNoRegistryValues') { continue }

                if ($value -is [System.Array]) {
                    New-ItemProperty -LiteralPath $Path -Name $name -Value ([string[]]$value) -PropertyType MultiString -Force | Out-Null
                }
                elseif ($value -is [int] -or $value -is [long] -or $value -is [double]) {
                    $longValue = [long]$value
                    $propType = if ($longValue -gt [int]::MaxValue -or $longValue -lt [int]::MinValue) { 'QWord' } else { 'DWord' }
                    New-ItemProperty -LiteralPath $Path -Name $name -Value $longValue -PropertyType $propType -Force | Out-Null
                }
                else {
                    New-ItemProperty -LiteralPath $Path -Name $name -Value ([string]$value) -PropertyType String -Force | Out-Null
                }
            }
        }

        # Populated once here (not per-test): rebuilding ~900+ real services'
        # worth of registry entries is expensive, and every test below only
        # reads this fixture, never mutates it, so one shared build is safe.
        if (-not $script:HasFixture) { return }

        Remove-Item -LiteralPath 'TestRegistry:\Machine' -Recurse -Force -ErrorAction SilentlyContinue
        New-Item -Path 'TestRegistry:\Machine' -Force | Out-Null

        $isolatedRoot = (Get-PSDrive -Name TestRegistry -ErrorAction Stop).Root
        & (Get-Module NetClean) {
            param($RootMap)
            Set-NetCleanRegistryRootMap -RootMap $RootMap
        } @{ HKLM = "$isolatedRoot\Machine" }

        # Capped: the TestRegistry: provider has real per-call overhead, and
        # replaying all ~900+ real services (thousands of individual
        # New-ItemProperty calls) takes several minutes. A capped sample
        # still carries plenty of real-world property-shape diversity - the
        # goal is catching "some real services are missing X" bugs, which
        # doesn't need every single service, just a representative slice.
        $servicesRoot = 'TestRegistry:\Machine\SYSTEM\CurrentControlSet\Services'
        $serviceSampleLimit = 30
        foreach ($svc in (Get-Content -LiteralPath (Join-Path $script:FixtureDataPath 'ServiceRegistrySnapshot.json') -Raw | ConvertFrom-Json | Select-Object -First $serviceSampleLimit)) {
            $svcPath = Join-Path $servicesRoot $svc.Name
            Set-FixtureRegistryValue -Path $svcPath -Values $svc.Values
            if ($svc.LinkageValues) {
                Set-FixtureRegistryValue -Path (Join-Path $svcPath 'Linkage') -Values $svc.LinkageValues
            }
        }

        $networkListRoot = 'TestRegistry:\Machine\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles'
        foreach ($networkListProfile in (Get-Content -LiteralPath (Join-Path $script:FixtureDataPath 'NetworkListProfileSnapshot.json') -Raw | ConvertFrom-Json)) {
            $profilePath = Join-Path $networkListRoot $networkListProfile.ProfileGuid
            New-Item -Path $profilePath -Force | Out-Null
            New-ItemProperty -LiteralPath $profilePath -Name 'ProfileName' -Value $networkListProfile.Name -PropertyType String -Force | Out-Null
        }

        $classRoot = 'TestRegistry:\Machine\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}'
        $i = 0
        foreach ($adapter in (Get-Content -LiteralPath (Join-Path $script:FixtureDataPath 'AdapterRegistryCorrelation.json') -Raw | ConvertFrom-Json)) {
            $subKey = '{0:D4}' -f $i
            $classPath = Join-Path $classRoot $subKey
            $values = [pscustomobject]@{
                ComponentId      = $adapter.ComponentId
                DriverDesc       = $adapter.DriverDesc
                ProviderName     = $adapter.ProviderName
                NetCfgInstanceId = "{$($adapter.InterfaceGuid)}"
            }
            Set-FixtureRegistryValue -Path $classPath -Values $values
            $i++
        }

        $uninstallRoot = 'TestRegistry:\Machine\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
        $j = 0
        foreach ($entry in (Get-Content -LiteralPath (Join-Path $script:FixtureDataPath 'UninstallEntries.json') -Raw | ConvertFrom-Json | Select-Object -First $serviceSampleLimit)) {
            $entryPath = Join-Path $uninstallRoot "FixtureEntry$j"
            Set-FixtureRegistryValue -Path $entryPath -Values $entry
            $j++
        }
    }

    AfterAll {
        if ($script:HasFixture) {
            & (Get-Module NetClean) { Clear-NetCleanRegistryRootMap }
        }
    }

    It 'has a captured fixture to replay (run Export-NetCleanRealFixture.ps1 first if this is skipped)' {
        if (-not $script:HasFixture) {
            Set-ItResult -Skipped -Because 'No local fixture captured yet - run tests/LocalFixtures/Export-NetCleanRealFixture.ps1 on a real machine first.'
            return
        }

        $true | Should -BeTrue
    }

    It 'replays the captured service registry snapshot through Get-ServiceRegistrySnapshot without throwing' {
        if (-not $script:HasFixture) {
            Set-ItResult -Skipped -Because 'No local fixture captured yet.'
            return
        }

        { $script:Result = @(& (Get-Module NetClean) { Get-ServiceRegistrySnapshot }) } | Should -Not -Throw
        $script:Result.Count | Should -BeGreaterThan 0
    }

    It 'replays the captured NetworkList profiles through Get-NetworkListProfileSnapshot without throwing' {
        if (-not $script:HasFixture) {
            Set-ItResult -Skipped -Because 'No local fixture captured yet.'
            return
        }

        { $script:Profiles = @(& (Get-Module NetClean) { Get-NetworkListProfileSnapshot }) } | Should -Not -Throw
    }

    It 'replays the captured adapter correlation through Get-AdapterRegistryCorrelation without throwing' {
        if (-not $script:HasFixture) {
            Set-ItResult -Skipped -Because 'No local fixture captured yet.'
            return
        }

        { $script:Correlation = @(& (Get-Module NetClean) { Get-AdapterRegistryCorrelation }) } | Should -Not -Throw
    }
}
