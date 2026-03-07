# Netclean PowerShell module - core, testable helpers

function Convert-RegKeyPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Path
    )
    if (-not $Path) { return $null }
    $p = $Path.ToString()
    $p = $p -replace 'Microsoft\.PowerShell\.Core\\Registry::',''
    # Remove a colon after HKLM if present and normalize separators
    $p = $p -replace '^HKLM:','HKLM'
    $p = $p -replace '/','\\'
    while ($p -match '\\\\') { $p = $p -replace '\\\\','\\' }
    $p = $p.TrimEnd('\')
    return $p
}

function Convert-Guid {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Guid
    )
    if (-not $Guid) { return $null }
    return ($Guid -replace '[{}]','').ToLower()
}

function Get-InstalledAV {
    [CmdletBinding()]
    param()
    $found = @()
    try {
        $wmi = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct -ErrorAction SilentlyContinue
        if ($wmi) { $found += $wmi.displayName }
    } catch {
        Write-Verbose 'SecurityCenter query failed.'
    }
    $common = @('MsMpSvc','WinDefend','vsserv','BDService','CSFalconService','SentinelAgent','sophos','savservice')
    foreach ($s in $common) {
        try {
            if (Get-Service -Name $s -ErrorAction SilentlyContinue) { $found += $s }
        } catch {
            Write-Verbose ("Service check failed for {0}: {1}" -f $s, $_)
        }
    }
    return ($found | Sort-Object -Unique)
}

function Get-AVServicePattern {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string[]]$AvList
    )
    $patterns = @()
    $map = @{
        'bitdefender' = @('vsserv','BDService')
        'crowdstrike' = @('CSFalconService','csagent','falcon')
        'sentinelone' = @('SentinelAgent','SentinelCtl','Sentinel')
        'carbon'      = @('Cb','cb')
        'symantec'    = @('Symantec','Smc')
        'sophos'      = @('SAVService','Sophos')
        'windows'     = @('WinDefend','MsMpSvc')
    }
    foreach ($a in $AvList) {
        $an = $a.ToString().ToLower()
        foreach ($k in $map.Keys) {
            if ($an -like "*$k*") { $patterns += $map[$k] }
        }
    }
    return ($patterns | Sort-Object -Unique)
}

function Get-ProtectionList {
    [CmdletBinding()]
    param()
    $detected = Get-InstalledAV
    $svcPatterns = @()
    $driverPatterns = @()
    $adapterPatterns = @()
    $registryPaths = @()

    $vendorMap = @{
        'bitdefender' = @{ Services=@('vsserv','bdservice'); Drivers=@('npf','bd*cpt'); Adapters=@('vmware','bd'); Reg=@('SOFTWARE\\Bitdefender') }
        'malwarebytes' = @{ Services=@('MBAMService','MBAMProtector'); Drivers=@('mbam*'); Adapters=@('Malwarebytes'); Reg=@('SOFTWARE\\Malwarebytes') }
        'crowdstrike' = @{ Services=@('CSFalconService'); Drivers=@('cs*'); Adapters=@('CrowdStrike'); Reg=@('') }
        'sentinelone' = @{ Services=@('SentinelAgent'); Drivers=@('Sentinel'); Adapters=@('SentinelOne'); Reg=@('') }
        'sophos' = @{ Services=@('SAVService'); Drivers=@('SAV*'); Adapters=@('Sophos'); Reg=@('SOFTWARE\\SOPHOS') }
        'microsoft' = @{ Services=@('MsMpSvc','WinDefend'); Drivers=@('wd*'); Adapters=@('vEthernet','Hyper-V'); Reg=@('SOFTWARE\\Microsoft\\Windows Defender') }
    }

    foreach ($d in $detected) {
        $dn = $d.ToString().ToLower()
        foreach ($k in $vendorMap.Keys) {
            if ($dn -like "*$k*") {
                $entry = $vendorMap[$k]
                $svcPatterns += $entry.Services
                $driverPatterns += $entry.Drivers
                $adapterPatterns += $entry.Adapters
                $registryPaths += $entry.Reg
            }
        }
    }

    $adapterPatterns += @('VMware','VMnet','vboxnet','vEthernet','Hyper-V','VirtualBox','Parallels')
    $svcPatterns += @('vmnat','vmnetbridge','VMWareHostd','VBoxService')

    return @{ Services=($svcPatterns|Sort-Object -Unique); Drivers=($driverPatterns|Sort-Object -Unique); Adapters=($adapterPatterns|Sort-Object -Unique); Registry=($registryPaths|Sort-Object -Unique) }
}

function Convert-RegKeyPathAlias {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Path
    )
    return Convert-RegKeyPath -Path $Path
}

function Convert-GuidAlias {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Guid
    )
    return Convert-Guid -Guid $Guid
}

function Export-ProtectedRegistryKey {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string[]]$Paths,
        [Parameter(Mandatory=$true)][string]$Dest,
        [switch]$DryRun
    )
    $exported = @()
    if (-not $Paths) { return $exported }
    if (-not (Test-Path $Dest)) { New-Item -Path $Dest -ItemType Directory -Force | Out-Null }
    foreach ($p in $Paths) {
        if (-not $p) { continue }
        $key = Convert-RegKeyPath -Path $p
        if (-not $key) { continue }
        $safe = ($key -replace '[^a-zA-Z0-9_.-]','_')
        $file = Join-Path $Dest ("reg_backup_${safe}_$(Get-Date -Format yyyyMMdd_HHmmss).reg")
        $regArgs = @('export',$key,$file,'/y')
        if ($DryRun) { Write-Verbose "DRYRUN: reg $($regArgs -join ' ')"; $exported += $file }
        else {
            Start-Process -FilePath 'reg' -ArgumentList $regArgs -NoNewWindow -Wait -ErrorAction Stop
            $exported += $file
        }
    }
    Write-Output -InputObject ([object[]]$exported) -NoEnumerate
}

function Export-NetworkList {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Dest,
        [switch]$DryRun
    )
    $key = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList'
    $file = Join-Path $Dest ("NetworkList_$(Get-Date -Format yyyyMMdd_HHmmss).reg")
    $regArgs = @('export',$key,$file,'/y')
    if ($DryRun) { Write-Verbose "DRYRUN: reg $($regArgs -join ' ')" } else { Start-Process -FilePath 'reg' -ArgumentList $regArgs -NoNewWindow -Wait -ErrorAction Stop }
    return $file
}

function Export-WiFiProfile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Dest,
        [switch]$DryRun
    )
    $exported = @()
    $listFile = Join-Path $Dest ("WiFiProfiles_$(Get-Date -Format yyyyMMdd_HHmmss).txt")
    if (-not (Test-Path $Dest)) { New-Item -Path $Dest -ItemType Directory -Force | Out-Null }
    $profiles = (netsh wlan show profiles | Select-String 'All User Profile' | ForEach-Object { ($_ -split ':')[1].Trim() })
    if ($profiles) {
        if ($DryRun) { Write-Verbose "DRYRUN: would write Wi-Fi profile list to $listFile"; $exported += $listFile }
        else { $profiles | Out-File -FilePath $listFile -Encoding UTF8; $exported += $listFile }
        foreach ($p in $profiles) {
            $out = Join-Path $Dest ("WiFiProfile_$([System.Uri]::EscapeDataString($p)).xml")
            if ($DryRun) { Write-Verbose "DRYRUN: netsh wlan export profile name=\"$p\" folder=\"$Dest\""; $exported += $out }
            else { netsh wlan export profile name="$p" folder="$Dest" | Out-Null; $exported += $out }
        }
    }
    Write-Output -InputObject ([object[]]$exported) -NoEnumerate
}

## Create backward-compatible aliases for original names (no new function definitions)
Set-Alias -Name Convert-NormalizeGuid -Value Convert-Guid -Force
Set-Alias -Name Normalize-Guid -Value Convert-Guid -Force
Set-Alias -Name Derive-AVServicePatterns -Value Get-AVServicePattern -Force
Set-Alias -Name Build-ProtectionLists -Value Get-ProtectionList -Force
Set-Alias -Name Backup-ProtectedRegistryKeys -Value Export-ProtectedRegistryKey -Force
Set-Alias -Name Backup-NetworkList -Value Export-NetworkList -Force
Set-Alias -Name Backup-WiFiProfiles -Value Export-WiFiProfile -Force
Set-Alias -Name Get-ProtectionLists -Value Get-ProtectionList -Force
Set-Alias -Name Get-AVServicePatterns -Value Get-AVServicePattern -Force
Set-Alias -Name Export-ProtectedRegistryKeys -Value Export-ProtectedRegistryKey -Force

Export-ModuleMember -Function Convert-RegKeyPath, Convert-Guid, Get-InstalledAV, Get-AVServicePattern, Get-ProtectionList, Export-ProtectedRegistryKey, Export-NetworkList, Export-WiFiProfile -Alias Convert-NormalizeGuid, Normalize-Guid, Derive-AVServicePatterns, Build-ProtectionLists, Backup-ProtectedRegistryKeys, Backup-NetworkList, Backup-WiFiProfiles, Get-ProtectionLists, Get-AVServicePatterns, Export-ProtectedRegistryKeys
