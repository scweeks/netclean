<#
    Aggressive-but-safe Windows 11 network cleanup for conference/CTF.

    - Run as Administrator
    - Does NOT touch:
        * Bitdefender services, drivers, or firewall rules
        * Windows Firewall rules
        * VMware Workstation services or virtual adapters
    - Does:
        * Remove all Wi-Fi profiles
        * Reset Winsock + TCP/IP (IPv4/IPv6)
#>
param(
            [switch]$DryRun,
            [switch]$Force,
            [switch]$OnlyBackup,
            [switch]$CreateLog,
            [string]$BackupPath = "$env:ProgramData\NetworkCleaner\Backups",
            [string]$LogPath = "$env:ProgramData\NetworkCleaner\Logs",
            [switch]$RebootNow
        )

# Reference script parameters in a no-op block to satisfy static analysis for
# tools that report parameters as unused when referenced in nested functions.
if ($false) {
    $null = $DryRun; $null = $Force; $null = $OnlyBackup; $null = $CreateLog; $null = $BackupPath; $null = $LogPath; $null = $RebootNow
}

# Import module with core helpers
Import-Module -Name (Join-Path $PSScriptRoot 'Netclean.psm1') -Force -ErrorAction Stop

        # Logging helpers
        $script:LogFile = $null
        function Start-Log {
            [CmdletBinding(SupportsShouldProcess=$true)]
            param($logDir)
            if (-not $logDir) { $logDir = "$env:ProgramData\NetworkCleaner\Logs" }
            if (-not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null }
            $script:LogFile = Join-Path $logDir "netclean_$(Get-Date -Format yyyyMMdd_HHmmss).log"
            "$((Get-Date).ToString('s')) - INFO - Log started" | Out-File -FilePath $script:LogFile -Encoding UTF8
        }
        function Write-NetcleanLog {
            param(
                [string]$Level = 'INFO',
                [string]$Message
            )
            $line = "$(Get-Date -Format s) - $Level - $Message"
            if ($script:LogFile) { $line | Out-File -FilePath $script:LogFile -Encoding UTF8 -Append }
            # Surface warnings/errors to the host via the appropriate streams
            if ($Level -eq 'ERROR') { Write-Error $Message }
            elseif ($Level -eq 'WARN') { Write-Warning $Message }
            else { Write-Verbose $Message }
        }

        function Test-Administrator {
            $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
                [Security.Principal.WindowsBuiltInRole] "Administrator")
            if (-not $isAdmin) {
                $ans = Read-Host "This script must be run as Administrator. Elevate now? (Y/N)"
                if ($ans -match '^[Yy]') {
                    # Rebuild argument list from supplied bound parameters
                    $scriptPath = $PSCommandPath
                    $argList = "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`""
                    if ($PSBoundParameters) {
                        foreach ($k in $PSBoundParameters.Keys) {
                            $v = $PSBoundParameters[$k]
                            if ($v -is [System.Management.Automation.SwitchParameter]) {
                                if ($v.IsPresent -and $v) { $argList += " -$k" }
                            } else {
                                $escaped = $v.ToString().Replace('"','\"')
                                $argList += " -$k `"$escaped`""
                            }
                        }
                    }
                    Write-NetcleanLog 'INFO' "Relaunching elevated: powershell $argList"
                    Start-Process -FilePath (Get-Command powershell).Source -ArgumentList $argList -Verb RunAs -Wait
                    Exit 0
                } else {
                    Write-NetcleanLog 'ERROR' "This script must be run as Administrator. Exiting."
                    Exit 1
                }
            }
        }

        function New-ProtectedBackupPath {
            [CmdletBinding(SupportsShouldProcess=$true)]
            param($path)
            if (-not (Test-Path $path)) {
                New-Item -Path $path -ItemType Directory -Force | Out-Null
            }
            # Restrict backups to Administrators and SYSTEM
            try {
                $icaclsArgs = @($path,'/inheritance:r','/grant','Administrators:(OI)(CI)F','/grant','SYSTEM:(OI)(CI)F','/C')
                if ($DryRun) { Write-NetcleanLog 'INFO' "DRYRUN: icacls $($icaclsArgs -join ' ')" }
                else {
                    try { Start-Process -FilePath 'icacls' -ArgumentList $icaclsArgs -NoNewWindow -Wait -ErrorAction Stop | Out-Null } catch { throw }
                }
            } catch {
                    Write-NetcleanLog 'WARN' ("Failed to set ACL on backup folder: " + $_.Exception.Message)
            }
            Write-NetcleanLog 'INFO' "Backup folder prepared: $path"
        }

        function Confirm-YesNo($msg, $defaultNo=$true) {
            while ($true) {
                $ans = Read-Host "$msg (Y/N)"
                if ($ans -match '^[Yy]') { return $true }
                if ($ans -match '^[Nn]') { return $false }
                Write-NetcleanLog 'WARN' "Please answer Y or N."
            }
        }

        function Convert-Guid($g) {
            if (-not $g) { return $null }
            return ($g -replace '[{}]','').ToLower()
        }

        function Get-HypervisorGuid {
            # Detect virtual network adapters from common hypervisors and return their normalized Interface GUIDs.
            $guids = @()
            try {
                $adapters = Get-NetAdapter -ErrorAction SilentlyContinue
                foreach ($a in $adapters) {
                    $desc = $a.InterfaceDescription
                    $name = $a.Name
                    if ($desc -match 'VMware|VirtualBox|Hyper-V|HyperV|Parallels|Virtual Adapter|Virtual Ethernet|vEthernet|VirtualBox' -or
                        $name -match 'VMware|VMnet|vbox|VMSwitch|vEthernet') {
                        try {
                            if ($null -ne $a.InterfaceGuid) { $guids += ($a.InterfaceGuid.ToString() -replace '[{}]','').ToLower() }
                        } catch { Write-NetcleanLog 'WARN' "Get-HypervisorGuid adapter item parse failed: $($_.Exception.Message)" }
                    }
                }
            } catch { Write-NetcleanLog 'WARN' "Get-HypervisorGuid adapter lookup failed: $($_.Exception.Message)" }
            return ($guids | Sort-Object -Unique)
        }
        function Get-VMwareGuid { return Get-HypervisorGuid }

        function Get-DetectedHypervisor {
            $found = @()
            # WMI: Hypervisor present
            try {
                $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
                if ($cs -and $cs.HypervisorPresent) { $found += 'HypervisorPresent' }
            } catch { Write-NetcleanLog 'WARN' "Get-DetectedHypervisor WMI lookup failed: $($_.Exception.Message)" }
            # Network adapters
            try {
                $adapters = Get-NetAdapter -ErrorAction SilentlyContinue
                foreach ($a in $adapters) {
                    $d = $a.InterfaceDescription
                    if ($d -match 'VMware') { if (-not ($found -contains 'VMware')) { $found += 'VMware' } }
                    if ($d -match 'VirtualBox') { if (-not ($found -contains 'VirtualBox')) { $found += 'VirtualBox' } }
                    if ($d -match 'Hyper-V|HyperV|vEthernet') { if (-not ($found -contains 'Hyper-V')) { $found += 'Hyper-V' } }
                    if ($d -match 'Parallels') { if (-not ($found -contains 'Parallels')) { $found += 'Parallels' } }
                }
            } catch { Write-NetcleanLog 'WARN' "Get-DetectedHypervisor adapter lookup failed: $($_.Exception.Message)" }
            # Services/processes
            $svcChecks = @{ 'VBoxService'='VirtualBox'; 'vmtools'='VMware'; 'vmware'='VMware'; 'vmms'='Hyper-V'; 'vmcompute'='Hyper-V' }
            foreach ($k in $svcChecks.Keys) {
                try { if (Get-Service -Name $k -ErrorAction SilentlyContinue) { if (-not ($found -contains $svcChecks[$k])) { $found += $svcChecks[$k] } } } catch { Write-NetcleanLog 'WARN' "Get-DetectedHypervisor service check failed for $k: $($_.Exception.Message)" }
            }
            return $found | Sort-Object -Unique
        }

        function Get-InstalledAv {
            $found = @()
            try {
                $wmi = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct -ErrorAction SilentlyContinue
                if ($wmi) { $found += $wmi.displayName }
            } catch {
                    Write-Verbose ("SecurityCenter query failed: " + $_)
            }
            # Fallback: look for common AV services/processes
            $common = @('MsMpSvc','WinDefend','vsserv','BDService','CSFalconService','SentinelAgent','sophos','savservice')
            foreach ($s in $common) {
                try {
                    if (Get-Service -Name $s -ErrorAction SilentlyContinue) { $found += $s }
                    } catch { Write-NetcleanLog 'WARN' "Get-InstalledAv service probe failed for $s: $($_.Exception.Message)" }
            }
            return ($found | Sort-Object -Unique)
        }

        function Get-AVServicePattern($avList) {
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
            foreach ($a in $avList) {
                $an = $a.ToString().ToLower()
                foreach ($k in $map.Keys) {
                    if ($an -like "*$k*") { $patterns += $map[$k] }
                }
            }
            return ($patterns | Sort-Object -Unique)
        }

        function Get-ProtectionList {
            # Returns hashtable with keys: Services, Drivers, Adapters, Registry
            $detected = Get-InstalledAv
            $svcPatterns = @()
            $driverPatterns = @()
            $adapterPatterns = @()
            $registryPaths = @()

            # Per-vendor canonical mappings (services, drivers, adapter name fragments, registry locations)
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

            # Always protect common hypervisor adapters/services
            $adapterPatterns += @('VMware','VMnet','vboxnet','vEthernet','Hyper-V','VirtualBox','Parallels')
            $svcPatterns += @('vmnat','vmnetbridge','VMWareHostd','VBoxService')

            return @{ Services=($svcPatterns|Sort-Object -Unique); Drivers=($driverPatterns|Sort-Object -Unique); Adapters=($adapterPatterns|Sort-Object -Unique); Registry=($registryPaths|Sort-Object -Unique) }
        }

        function Get-ServiceRegistryInfo($svcName) {
            $res = @{}
            $key = "HKLM:\SYSTEM\CurrentControlSet\Services\$svcName"
            if (-not (Test-Path $key)) { return $null }
            try {
                $props = Get-ItemProperty -Path $key -ErrorAction Stop
                $res.Path = $key
                $res.DisplayName = $props.DisplayName
                $res.ImagePath = $props.ImagePath
                $res.DependOnService = $props.DependOnService
                $res.Start = $props.Start
            } catch { return $null }
            return $res
        }

        function Get-ServiceDependency($serviceList) {
            $regPaths = @()
            $driverFiles = @()
            foreach ($s in $serviceList | Sort-Object -Unique) {
                if (-not $s) { continue }
                $info = Get-ServiceRegistryInfo $s
                if ($info) {
                    $regPaths += $info.Path
                    if ($info.ImagePath) {
                        $img = $info.ImagePath -replace '"',''
                        # If it references a .sys driver, capture the filename
                        if ($img -match '\\([^\\]+\.sys)') { $driverFiles += $Matches[1] }
                    }
                    if ($info.DependOnService) {
                        foreach ($d in @($info.DependOnService)) {
                            $regPaths += "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\$d"
                        }
                    }
                }
            }
            return @{ Registry=$regPaths|Sort-Object -Unique; Drivers=$driverFiles|Sort-Object -Unique }
        }

        function Test-RegistryPathProtected($path) {
            if (-not $script:ProtectedRegistryPaths) { return $false }
            foreach ($p in $script:ProtectedRegistryPaths) {
                if (-not $p) { continue }
                if ($path -like "$p*" -or $p -like "$path*") { return $true }
            }
            return $false
        }

        # The registry and Wi-Fi backup helpers are provided by the Netclean module
        # Backup-ProtectedRegistryKeys, Backup-NetworkList, and Backup-WiFiProfiles

        function Remove-WiFiProfileSafe {
            [CmdletBinding(SupportsShouldProcess=$true)]
            param()
            Write-NetcleanLog 'INFO' "Preparing to remove Wi-Fi profiles (preview)..."
            $profiles = (& netsh wlan show profiles) | Select-String 'All User Profile' | ForEach-Object { ($_ -split ':')[1].Trim() }
            if (-not $profiles) { Write-NetcleanLog 'INFO' "No Wi-Fi profiles found."; return }
            $profiles | ForEach-Object { Write-NetcleanLog 'INFO' "Found Wi-Fi profile: $_" }
            if (-not $Force) {
                if (-not (Confirm-YesNo "Delete all above Wi-Fi profiles?")) { Write-NetcleanLog 'WARN' "Skipping Wi-Fi deletion."; return }
            }
            foreach ($p in $profiles) {
                $delArgs = @('wlan','delete','profile','name="' + $p + '"')
                if ($DryRun) { Write-NetcleanLog 'INFO' "DRYRUN: netsh $($delArgs -join ' ')" } else {
                    try {
                        Start-Process -FilePath 'netsh' -ArgumentList $delArgs -NoNewWindow -Wait -ErrorAction Stop
                        Write-NetcleanLog 'INFO' "Deleted Wi-Fi profile: $p"
                    } catch {
                        Write-NetcleanLog 'ERROR' ("Failed to delete Wi-Fi profile: " + $p + " - " + $_.Exception.Message)
                    }
                }
            }
        }

        function Remove-NetworkListProfile {
            [CmdletBinding(SupportsShouldProcess=$true)]
            param($vmwareGuids)
            $base = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList'
            $protection = Get-ProtectionList
            $adapterPatterns = $protection.Adapters
            $profilesPath = Join-Path $base 'Profiles'
            if (-not (Test-Path $profilesPath)) { Write-NetcleanLog 'INFO' "No NetworkList Profiles key found."; return }
            $toRemove = @()
            Get-ChildItem $profilesPath | ForEach-Object {
                $p = $_
                try {
                    $item = Get-ItemProperty -Path $p.PSPath -ErrorAction Stop
                    $profileName = $item.ProfileName
                    $description = $item.Description
                    $isVm = $false
                    if ($description) {
                        foreach ($pat in $adapterPatterns) { if ($description -match $pat) { $isVm = $true; break } }
                    }
                    if (-not $isVm -and $profileName) {
                        foreach ($pat in $adapterPatterns) { if ($profileName -match $pat) { $isVm = $true; break } }
                    }
                    if (-not $isVm) { $toRemove += @{ Path=$p.PSPath; Name=$profileName } }
                    else { Write-NetcleanLog 'INFO' "Preserving VM profile: $profileName" }
                } catch { Write-NetcleanLog 'WARN' ("Failed reading profile key " + $_.Exception.Message) }
            }
            if (-not $toRemove) { Write-NetcleanLog 'INFO' "No non-VM NetworkList profiles to remove."; return }
            Write-NetcleanLog 'INFO' "Profiles to remove:"
            $toRemove | ForEach-Object { Write-NetcleanLog 'INFO' "Planned NetworkList removal: $($_.Name) -> $($_.Path)" }
            if (-not $Force) { if (-not (Confirm-YesNo "Remove listed NetworkList profiles?")) { Write-NetcleanLog 'WARN' "Skipping NetworkList removals."; return } }
            foreach ($r in $toRemove) {
                if (Test-RegistryPathProtected $r.Path) { Write-NetcleanLog 'WARN' "Skipping removal of protected registry path: $($r.Path)"; continue }
                if ($DryRun) { Write-NetcleanLog 'INFO' "DRYRUN: Remove-Item -Path $($r.Path) -Recurse -Force" }
                else { try { Remove-Item -Path $r.Path -Recurse -Force -ErrorAction Stop; Write-NetcleanLog 'INFO' "Removed NetworkList profile: $($r.Name) at $($r.Path)" } catch { Write-NetcleanLog 'ERROR' ("Failed to remove NetworkList profile: " + $($r.Path) + " - " + $_.Exception.Message) } }
            }
            # Signatures removal (map to interface GUIDs) - be conservative
            $sigSubs = @('Signatures\\Unmanaged','Signatures\\Managed')
            foreach ($sub in $sigSubs) {
                $sigPath = Join-Path $base $sub
                if (-not (Test-Path $sigPath)) { continue }
                Get-ChildItem $sigPath | ForEach-Object {
                    $name = $_.PSChildName
                    $norm = Convert-Guid($name)
                    if ($vmwareGuids -contains $norm) { Write-NetcleanLog 'INFO' "Preserving signature $name (VM)"; return }
                    # inspect properties to detect adapter/driver ties
                    try {
                        $sig = Get-ItemProperty -Path $_.PsPath -ErrorAction SilentlyContinue
                        $dnsSuffix = $sig.DnsSuffix
                        $defaultGatewayMac = $sig.DefaultGatewayMac
                        $preserve = $false
                        foreach ($pat in $adapterPatterns) {
                            if ($dnsSuffix -and ($dnsSuffix -match $pat)) { $preserve = $true; break }
                            if ($defaultGatewayMac -and ($defaultGatewayMac -match $pat)) { $preserve = $true; break }
                        }
                        if ($preserve) { Write-NetcleanLog 'INFO' "Preserving signature $name (matches protected adapter/AV)"; return }
                    } catch { Write-NetcleanLog 'WARN' ("Signature inspection failed for $name: " + $_.Exception.Message) }
                    # else remove
                    if ($DryRun) { Write-NetcleanLog 'INFO' "DRYRUN: Remove signature $name" }
                    else { try { Remove-Item -Path $_.PsPath -Recurse -Force -ErrorAction Stop; Write-NetcleanLog 'INFO' "Removed signature: $name" } catch { Write-NetcleanLog 'ERROR' ("Failed remove signature " + ${name} + ": " + $_.Exception.Message) } }
                }
            }
        }

        function Reset-Networking {
            [CmdletBinding(SupportsShouldProcess=$true)]
            param()
            $cmds = @( 
                @{Name='Flush DNS'; Cmd='ipconfig /flushdns'},
                @{Name='Clear ARP'; Cmd='arp -d *'},
                @{Name='Reset Winsock'; Cmd='netsh winsock reset'},
                @{Name='Reset IPv4'; Cmd='netsh int ip reset'},
                @{Name='Reset IPv6'; Cmd='netsh int ipv6 reset'}
            )
            foreach ($c in $cmds) {
                Write-NetcleanLog 'INFO' "$($c.Name) - Command: $($c.Cmd)"
                if ($DryRun) { Write-NetcleanLog 'INFO' "DRYRUN: $($c.Cmd)" } else {
                    try { Start-Process -FilePath 'cmd.exe' -ArgumentList "/c $($c.Cmd)" -NoNewWindow -Wait -ErrorAction Stop | Out-Null; Write-NetcleanLog 'INFO' "$($c.Name) completed" } catch { Write-NetcleanLog 'ERROR' ("$($c.Name) failed: " + $_.Exception.Message) }
                }
            }
        }

        function Clear-NLAProbing {
            [CmdletBinding(SupportsShouldProcess=$true)]
            $nlaInternetPath = 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NlaSvc\\Parameters\\Internet'
            if (Test-Path $nlaInternetPath) {
                $props = 'ActiveDnsProbeContent','ActiveDnsProbeHost','ActiveWebProbeContent','ActiveWebProbeHost'
                foreach ($p in $props) {
                            if ($DryRun) { Write-NetcleanLog 'INFO' "DRYRUN: Remove-ItemProperty $nlaInternetPath -Name $p" }
                            else { try { Remove-ItemProperty -Path $nlaInternetPath -Name $p -ErrorAction Stop; Write-NetcleanLog 'INFO' "Removed NLA property: $p" } catch { Write-NetcleanLog 'WARN' ("NLA property " + $p + " missing or failed: " + $_.Exception.Message) } }
                }
            }
        }

        function Clear-EventLog {
            [CmdletBinding(SupportsShouldProcess=$true)]
            $logs = @("Microsoft-Windows-WLAN-AutoConfig/Operational","Microsoft-Windows-NetworkProfile/Operational","Microsoft-Windows-DHCP-Client/Operational")
            foreach ($l in $logs) {
                Write-NetcleanLog 'INFO' "Clearing event log: $l"
                if ($DryRun) { Write-NetcleanLog 'INFO' "DRYRUN: wevtutil cl `"$l`"" }
                else { try { wevtutil cl "$l" 2>$null; Write-NetcleanLog 'INFO' "Cleared $l" } catch { Write-NetcleanLog 'WARN' ("Failed clearing " + ${l} + ": " + $_.Exception.Message) } }
            }
        }

        function Main {
            [CmdletBinding(SupportsShouldProcess=$true)]
            Write-NetcleanLog 'INFO' "=== Network cleanup starting ==="
            Test-Administrator

            # Detect installed AV/EDR and hypervisors early so user can make an informed choice
            $detectedAV = Get-InstalledAV
            if ($detectedAV -and $detectedAV.Count -gt 0) {
                Write-NetcleanLog 'WARN' "Detected potentially impacted software: $($detectedAV -join ', ')"
            } else { Write-NetcleanLog 'INFO' "No endpoint protection detected by quick checks." }

            $detectedHypervisors = Get-DetectedHypervisor
            if ($detectedHypervisors -and $detectedHypervisors.Count -gt 0) {
                Write-NetcleanLog 'WARN' "Detected hypervisors/virtualization: $($detectedHypervisors -join ', ')"
            } else { Write-NetcleanLog 'INFO' "No hypervisors detected by quick checks." }

            $interactive = ($PSBoundParameters.Count -eq 0)

            if ($interactive) {
                # Interactive prompts when no switches provided
                $DryRun = Confirm-YesNo "Run in DRY RUN mode?"
                $CreateLog = Confirm-YesNo "Create a full log file for this run?"

                # If detection missed AV/EDR, ask the user to confirm and optionally provide product names
                if ((-not $detectedAV) -or ($detectedAV.Count -eq 0)) {
                    $hasAV = Confirm-YesNo "No endpoint protection was detected automatically. Do you have endpoint protection (AV/EDR/XDR) installed?"
                    if ($hasAV) {
                        $entered = Read-Host "If known, enter comma-separated names of installed products (or press Enter to skip)"
                        if ($entered) { $detectedAV = ($entered -split ',') | ForEach-Object { $_.Trim() } }
                    } else { $detectedAV = @() }
                } else { $hasAV = $true }

                # If detection missed hypervisors, ask the user to confirm
                if ((-not $detectedHypervisors) -or ($detectedHypervisors.Count -eq 0)) {
                    $hasVM = Confirm-YesNo "No hypervisor was detected automatically. Do you use VMware/VirtualBox/Hyper-V or other virtualization?"
                    if ($hasVM) { $vmwareGuids = Get-HypervisorGuid } else { $vmwareGuids = @() }
                } else {
                    $hasVM = $true
                    $vmwareGuids = Get-HypervisorGuid
                }

                $performBackups = Confirm-YesNo "Create backups and protected registry exports now?"
                if ($performBackups) { $OnlyBackup = $true }
            } else {
                # Respect provided switches
                $performBackups = [bool]$OnlyBackup
                # Populate vmwareGuids based on detectedHypervisors if not interactive
                $vmwareGuids = Get-HypervisorGuid
                $hasVM = ($vmwareGuids -and $vmwareGuids.Count -gt 0)
                if (-not $detectedAV) { $detectedAV = Get-InstalledAV }
            }

            # If logging requested or backups will be created, initialize the log.
            if ($CreateLog -or $performBackups) { Start-Log $LogPath; Write-NetcleanLog 'INFO' ("Network cleanup starting. DryRun=$DryRun; Force=$Force; OnlyBackup=$OnlyBackup") }
            if ($DryRun) { Write-NetcleanLog 'WARN' "Running in DRY RUN mode. No destructive actions will be performed." }

            # If backups requested, perform them and optionally exit (backup-only)
            if ($performBackups) {
                Write-NetcleanLog 'INFO' "Preparing backup path: $BackupPath"
                New-ProtectedBackupPath $BackupPath
                Backup-NetworkList $BackupPath
                Backup-WiFiProfiles $BackupPath

                # Build protection lists and export protected registry keys
                $protection = Get-ProtectionList
                $deps = Get-ServiceDependency(($protection.Services + $detectedAV) | Sort-Object -Unique)
                $script:ProtectedRegistryPaths = @()
                if ($protection.Registry) { $script:ProtectedRegistryPaths += $protection.Registry }
                if ($deps.Registry) { $script:ProtectedRegistryPaths += $deps.Registry }
                $script:ProtectedRegistryPaths = $script:ProtectedRegistryPaths | Sort-Object -Unique
                if ($script:ProtectedRegistryPaths) { Write-NetcleanLog 'INFO' ("Protected registry paths: " + ($script:ProtectedRegistryPaths -join ', ')) }

                $regBackups = Backup-ProtectedRegistryKeys $script:ProtectedRegistryPaths $BackupPath
                if ($regBackups) { Write-NetcleanLog 'INFO' ("Protected registry keys exported: " + ($regBackups -join ', ')) }

                # Append clear restore instructions at the bottom of the log (always create log for backups)
                Write-NetcleanLog 'INFO' "Backups are located at: $BackupPath"
                $netlist = Get-ChildItem -Path $BackupPath -Filter 'NetworkList_*.reg' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 1
                Write-NetcleanLog 'INFO' "NetworkList registry backup: $netlist"
                Write-NetcleanLog 'INFO' "Exported Wi-Fi profiles (XMLs) are in: $BackupPath"
                if ($regBackups) {
                    Write-NetcleanLog 'INFO' "Protected registry backup files:"
                    foreach ($rb in $regBackups) { Write-NetcleanLog 'INFO' ("  $rb") }
                    Write-NetcleanLog 'INFO' "To restore protected registry keys, run each of the following (as Administrator):"
                    foreach ($rb in $regBackups) { $line = '  reg import "' + $rb + '"'; Write-NetcleanLog 'INFO' $line }
                }
                if ($netlist) { $line = 'To restore NetworkList registry: reg import "' + $netlist + '" (run as Administrator).'; Write-NetcleanLog 'INFO' $line }
                Write-NetcleanLog 'INFO' ("To restore Wi-Fi profiles: for each exported XML in $BackupPath run: netsh wlan add profile filename='<path>'")

                if ($OnlyBackup) { Write-NetcleanLog 'INFO' "Backup-only requested; exiting after backups."; return }
            }

            # Continue with full cleanup
            # Detect hypervisors and prompt only if none detected
            $detectedHypervisors = Get-DetectedHypervisor
            if ($detectedHypervisors -and $detectedHypervisors.Count -gt 0) {
                Write-NetcleanLog 'WARN' "Detected hypervisors/virtualization: $($detectedHypervisors -join ', ')"
                $hasVM = $true
                $vmwareGuids = Get-HypervisorGuid
            } else {
                $hasVM = Prompt-YesNo "Do you use VMware/VirtualBox or other virtualization on this machine?"
                $vmwareGuids = @()
                if ($hasVM) { $vmwareGuids = Get-HypervisorGuid }
            }

            # Stop services where appropriate. Protect AV/EDR services discovered.
            $services = @('WlanSvc','Dnscache','Dhcp','NlaSvc','lmhosts')
            if ($detectedAV) { Write-NetcleanLog 'WARN' ("Detected AV/EDR: " + ($detectedAV -join ', ')) }
            $protection = Get-ProtectionList
            $protectedServices = $protection.Services
            # Inspect service registry dependencies and add to protected registry paths
            $deps = Get-ServiceDependency(($protectedServices + $detectedAV) | Sort-Object -Unique)
            $script:ProtectedRegistryPaths = @()
            if ($protection.Registry) { $script:ProtectedRegistryPaths += $protection.Registry }
            if ($deps.Registry) { $script:ProtectedRegistryPaths += $deps.Registry }
            $script:ProtectedRegistryPaths = $script:ProtectedRegistryPaths | Sort-Object -Unique
            if ($script:ProtectedRegistryPaths) { Write-NetcleanLog 'INFO' ("Protected registry paths: " + ($script:ProtectedRegistryPaths -join ', ')) }
            if ($protectedServices) { Write-NetcleanLog 'INFO' ("Protected service patterns: " + ($protectedServices -join ', ')) }
            # Backup protected registry keys if not already done
            if (-not $regBackups) { $regBackups = Backup-ProtectedRegistryKeys $script:ProtectedRegistryPaths $BackupPath; if ($regBackups) { Write-NetcleanLog 'INFO' ("Protected registry keys exported: " + ($regBackups -join ', ')) } }

            foreach ($s in $services) {
                $skip = $false
                foreach ($pat in $protectedServices) { if ($s.ToLower().Contains($pat.ToLower())) { $skip = $true; break } }
                if ($skip) { Write-NetcleanLog 'INFO' "Preserving service due to protection match: $s"; continue }
                Write-NetcleanLog 'INFO' "Stopping service: $s"
                if ($DryRun) { Write-NetcleanLog 'INFO' "DRYRUN: Stop-Service -Name $s -Force" }
                else { try { Stop-Service -Name $s -Force -ErrorAction Stop; Write-NetcleanLog 'INFO' "Stopped service: $s" } catch { Write-NetcleanLog 'ERROR' ("Failed to stop service " + $s + ": " + $_.Exception.Message) } }
            }

            # Wi-Fi profiles
            Remove-WiFiProfileSafe

            # Reset networking
            Reset-Networking

            # NLA probing
            Clear-NLAProbing

            # NetworkList cleaning
            Remove-NetworkListProfile $vmwareGuids

            # DHCP/WLAN file cleanup - skip if AV present unless forced
            $hasAV = ($detectedAV -and $detectedAV.Count -gt 0)
            if ($hasAV -and -not $Force) { Write-NetcleanLog 'WARN' "Skipping DHCP/WLAN file deletions due to AV presence (use -Force to override)." }
            else {
                $dhcpPath = "$env:SystemRoot\\System32\\dhcp"
                if (Test-Path $dhcpPath) {
                    $files = Get-ChildItem $dhcpPath -File -ErrorAction SilentlyContinue
                    if ($files) {
                        Write-NetcleanLog 'INFO' "DHCP files to remove:"
                        $files | ForEach-Object { Write-NetcleanLog 'INFO' "  - $($_.FullName)" }
                        if ($Force -or (Prompt-YesNo "Delete the above DHCP files?")) {
                            foreach ($f in $files) {
                                if ($DryRun) { Write-NetcleanLog 'INFO' "DRYRUN: Remove-Item $($f.FullName)" } else { try { Remove-Item $f.FullName -Force -ErrorAction Stop; Write-NetcleanLog 'INFO' "Removed $($f.Name)" } catch { Write-NetcleanLog 'ERROR' ("Failed remove " + $($f.FullName) + ": " + $_.Exception.Message) } }
                            }
                        }
                    }
                }
                $wlanLogPath = "$env:ProgramData\\Microsoft\\Wlansvc\\Logs"
                if (Test-Path $wlanLogPath) {
                    if ($Force -or (Prompt-YesNo "Remove WLAN logs under $wlanLogPath?")) {
                        if ($DryRun) { Write-NetcleanLog 'INFO' "DRYRUN: Remove logs under $wlanLogPath" }
                        else { try { Get-ChildItem $wlanLogPath -Recurse -File -ErrorAction Stop | ForEach-Object { Remove-Item $_.FullName -Force -ErrorAction Stop } ; Write-NetcleanLog 'INFO' "Cleared WLAN logs" } catch { Write-NetcleanLog 'ERROR' ("Failed clearing WLAN logs: " + $_.Exception.Message) } }
                    }
                }
            }

            # Event logs
            Clear-EventLog

            # Restart services
            foreach ($s in $services) {
                Write-NetcleanLog 'INFO' "Starting service: $s"
                if ($DryRun) { Write-NetcleanLog 'INFO' "DRYRUN: Start-Service -Name $s" }
                else { try { Start-Service -Name $s -ErrorAction Stop; Write-NetcleanLog 'INFO' "Started service: $s" } catch { Write-NetcleanLog 'ERROR' ("Failed to start service " + $s + ": " + $_.Exception.Message) } }
            }

            Write-NetcleanLog 'INFO' "=== Network cleanup complete ==="
            Write-NetcleanLog 'INFO' "Network cleanup complete"

            # Final summary and restore instructions appended to log bottom
            Write-NetcleanLog 'INFO' "Backups are located at: $BackupPath"
            $netlist = Get-ChildItem -Path $BackupPath -Filter 'NetworkList_*.reg' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 1
            Write-NetcleanLog 'INFO' "NetworkList registry backup: $netlist"
            Write-NetcleanLog 'INFO' "Exported Wi-Fi profiles (XMLs) are in: $BackupPath"
            if ($regBackups) {
                Write-NetcleanLog 'INFO' "Protected registry backup files:"
                foreach ($rb in $regBackups) { Write-NetcleanLog 'INFO' ("  $rb") }
            }
            Write-NetcleanLog 'INFO' "To restore protected registry keys, run each of the following (as Administrator):"
            if ($regBackups) { foreach ($rb in $regBackups) { $line = '  reg import "' + $rb + '"'; Write-NetcleanLog 'INFO' $line } }
            if ($netlist) { $line = 'To restore NetworkList registry: reg import "' + $netlist + '" (run as Administrator).'; Write-NetcleanLog 'INFO' $line }
            Write-NetcleanLog 'INFO' ("To restore Wi-Fi profiles: for each exported XML in $BackupPath run: netsh wlan add profile filename='<path>'")
            Write-NetcleanLog 'INFO' "If you need help restoring drivers or services, review the log and protected registry paths listed above before making changes."

            # Reboot/shutdown options
            if ($RebootNow) {
                if ($DryRun) { Write-NetcleanLog 'INFO' "DRYRUN: Restart-Computer" } else { Restart-Computer -Force }
            } else {
                while ($true) {
                    $choice = Read-Host "Choose post-run action: [R]estart / [S]hutdown / [N]o action"
                    switch ($choice.ToUpper()) {
                        'R' { if ($DryRun) { Write-NetcleanLog 'INFO' "DRYRUN: Restart-Computer" } else { Restart-Computer -Force }; break }
                        'S' { if ($DryRun) { Write-NetcleanLog 'INFO' "DRYRUN: Stop-Computer" } else { Stop-Computer -Force }; break }
                        'N' { Write-NetcleanLog 'INFO' "Please reboot or shutdown later to apply changes."; break }
                        default { Write-NetcleanLog 'WARN' "Enter R, S, or N."; continue }
                    }
                    break
                }
            }
        }

        Main
