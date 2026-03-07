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

# Import module with core helpers
Import-Module -Name (Join-Path $PSScriptRoot 'Netclean.psm1') -Force -ErrorAction Stop

        # Logging helpers
        $script:LogFile = $null
        function Start-Log {
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
            # Also write a short host message for interactive feedback
            # Only show WARN and ERROR on the console to reduce duplicate/info clutter; INFO goes to the log file.
            if ($Level -in @('ERROR','WARN')) {
                switch ($Level) {
                    'ERROR' { Write-Host $Message -ForegroundColor Red }
                    'WARN'  { Write-Host $Message -ForegroundColor Yellow }
                }
            }
        }

        function Ensure-Admin {
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
                    Write-Host "Relaunching elevated: powershell $argList" -ForegroundColor Gray
                    Start-Process -FilePath (Get-Command powershell).Source -ArgumentList $argList -Verb RunAs -Wait
                    Exit 0
                } else {
                    Write-Host "This script must be run as Administrator. Exiting." -ForegroundColor Red
                    Exit 1
                }
            }
        }

        function New-ProtectedBackupPath($path) {
            if (-not (Test-Path $path)) {
                New-Item -Path $path -ItemType Directory -Force | Out-Null
            }
            # Restrict backups to Administrators and SYSTEM
            try {
                $icaclsArgs = @($path,'/inheritance:r','/grant','Administrators:(OI)(CI)F','/grant','SYSTEM:(OI)(CI)F','/C')
                if ($DryRun) { Write-Host "DRYRUN: icacls $($icaclsArgs -join ' ')" -ForegroundColor Gray }
                else {
                    try { Start-Process -FilePath 'icacls' -ArgumentList $icaclsArgs -NoNewWindow -Wait -ErrorAction Stop | Out-Null } catch { throw }
                }
            } catch {
                    Write-Warning ("Failed to set ACL on backup folder: " + $_)
            }
            Write-NetcleanLog 'INFO' "Backup folder prepared: $path"
        }

        function Prompt-YesNo($msg, $defaultNo=$true) {
            while ($true) {
                $ans = Read-Host "$msg (Y/N)"
                if ($ans -match '^[Yy]') { return $true }
                if ($ans -match '^[Nn]') { return $false }
                Write-Host "Please answer Y or N." -ForegroundColor Yellow
            }
        }

        function Normalize-Guid($g) {
            if (-not $g) { return $null }
            return ($g -replace '[{}]','').ToLower()
        }

        function Get-HypervisorGuids {
            # Detect virtual network adapters from common hypervisors and return their normalized GUIDs.
            $adapters = @()
            try {
                $adapters = Get-NetAdapter -ErrorAction SilentlyContinue |
                    Where-Object {
                        ($_.InterfaceDescription -match 'VMware|VirtualBox|Hyper-V|HyperV|Parallels|Virtual Adapter|Virtual Ethernet|vEthernet|VirtualBox') -or
                        ($_.Name -match 'VMware|VMnet|vbox|VMSwitch|vEthernet')
                    }
                $wlanArgs = @('wlan','export','profile','name='+$p,'key=clear','folder='+$dest)
                if ($DryRun) { Write-NetcleanLog 'INFO' "DRYRUN: netsh $($wlanArgs -join ' ')"; $exported += $file }
                else {
                    try {
                        Start-Process -FilePath 'netsh' -ArgumentList $wlanArgs -NoNewWindow -Wait -ErrorAction Stop
                        Write-NetcleanLog 'INFO' "Exported Wi-Fi profile $p -> $file"
                        $exported += $file
                    } catch {
                        Write-NetcleanLog 'WARN' ("Failed to export wifi profile " + $p + ": " + $_)
                    }
                }
        function Get-VMwareGuids { return Get-HypervisorGuids }

        function Get-DetectedHypervisors {
            $found = @()
            # WMI: Hypervisor present
            try {
                $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
                if ($cs -and $cs.HypervisorPresent) { $found += 'HypervisorPresent' }
            } catch {}
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
            } catch {}
            # Services/processes
            $svcChecks = @{ 'VBoxService'='VirtualBox'; 'vmtools'='VMware'; 'vmware'='VMware'; 'vmms'='Hyper-V'; 'vmcompute'='Hyper-V' }
            foreach ($k in $svcChecks.Keys) {
                try { if (Get-Service -Name $k -ErrorAction SilentlyContinue) { if (-not ($found -contains $svcChecks[$k])) { $found += $svcChecks[$k] } } } catch {}
            }
            return $found | Sort-Object -Unique
        }

        function Get-InstalledAV {
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
                } catch {}
            }
            return ($found | Sort-Object -Unique)
        }

        function Derive-AVServicePatterns($avList) {
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

        function Build-ProtectionLists {
            # Returns hashtable with keys: Services, Drivers, Adapters, Registry
            $detected = Get-InstalledAV
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

        function Inspect-ServiceDependencies($serviceList) {
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

        function Is-RegistryPathProtected($path) {
            if (-not $global:ProtectedRegistryPaths) { return $false }
            foreach ($p in $global:ProtectedRegistryPaths) {
                if (-not $p) { continue }
                if ($path -like "$p*" -or $p -like "$path*") { return $true }
            }
            return $false
        }

        # The registry and Wi-Fi backup helpers are provided by the Netclean module
        # Backup-ProtectedRegistryKeys, Backup-NetworkList, and Backup-WiFiProfiles

        function Remove-WiFiProfilesSafe {
            Write-Host "Preparing to remove Wi-Fi profiles (preview)..." -ForegroundColor Yellow
            Write-Log 'INFO' "Preparing to remove Wi-Fi profiles (preview)"
            $profiles = netsh wlan show profiles | Select-String 'All User Profile' | ForEach-Object { ($_ -split ':')[1].Trim() }
            if (-not $profiles) { Write-Host "No Wi-Fi profiles found." -ForegroundColor Gray; return }
            $profiles | ForEach-Object { Write-Host "  - $_" -ForegroundColor DarkGray; Write-Log 'INFO' "Found Wi-Fi profile: $_" }
            if (-not $Force) {
                if (-not (Prompt-YesNo "Delete all above Wi-Fi profiles?")) { Write-Host "Skipping Wi-Fi deletion." -ForegroundColor Yellow; return }
            }
                foreach ($p in $profiles) {
                    $delArgs = @('wlan','delete','profile','name="' + $p + '"')
                    if ($DryRun) { Write-Host "DRYRUN: netsh $($delArgs -join ' ')" } else {
                        try {
                            Start-Process -FilePath 'netsh' -ArgumentList $delArgs -NoNewWindow -Wait -ErrorAction Stop
                            Write-Host "Deleted profile: $p" -ForegroundColor Gray
                            Write-NetcleanLog 'INFO' "Deleted Wi-Fi profile: $p"
                        } catch {
                            Write-Warning ("Failed to delete " + ${p} + ": " + $_)
                            Write-NetcleanLog 'ERROR' ("Failed to delete Wi-Fi profile: " + $p + " - " + $_)
                        }
                    }
                }
        }

        function Safe-RemoveNetworkListProfiles($vmwareGuids, $dest) {
            $base = 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList'
            $protection = Build-ProtectionLists
            $adapterPatterns = $protection.Adapters
            $profilesPath = Join-Path $base 'Profiles'
            if (-not (Test-Path $profilesPath)) { Write-Host "No NetworkList Profiles key found." -ForegroundColor Gray; return }
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
                    else { Write-Host "Preserving VM profile: $profileName" -ForegroundColor DarkGray }
                } catch { Write-Warning ("Failed reading profile key " + $_ + ": " + $_) }
            }
            if (-not $toRemove) { Write-Host "No non-VM NetworkList profiles to remove." -ForegroundColor Gray; return }
            Write-Host "Profiles to remove:" -ForegroundColor Yellow
            $toRemove | ForEach-Object { Write-Host "  - $($_.Name) : $($_.Path)" -ForegroundColor DarkGray; Write-Log 'INFO' "Planned NetworkList removal: $($_.Name) -> $($_.Path)" }
            if (-not $Force) { if (-not (Prompt-YesNo "Remove listed NetworkList profiles?")) { Write-Host "Skipping NetworkList removals." -ForegroundColor Yellow; return } }
            foreach ($r in $toRemove) {
                if (Is-RegistryPathProtected $r.Path) { Write-Host "Skipping removal of protected registry path: $($r.Path)" -ForegroundColor DarkGray; Write-Log 'WARN' "Skipped protected NetworkList profile: $($r.Path)"; continue }
                if ($DryRun) { Write-Host "DRYRUN: Remove-Item -Path $($r.Path) -Recurse -Force" -ForegroundColor Gray; Write-Log 'INFO' "DRYRUN: would remove $($r.Path)" }
                else { try { Remove-Item -Path $r.Path -Recurse -Force -ErrorAction Stop; Write-Host "Removed: $($r.Name)" -ForegroundColor Gray; Write-Log 'INFO' "Removed NetworkList profile: $($r.Name) at $($r.Path)" } catch { Write-Warning ("Failed remove " + $($r.Path) + ": " + $_); Write-Log 'ERROR' ("Failed to remove NetworkList profile: " + $($r.Path) + " - " + $_) } }
            }
            # Signatures removal (map to interface GUIDs) - be conservative
            $sigSubs = @('Signatures\\Unmanaged','Signatures\\Managed')
            foreach ($sub in $sigSubs) {
                $sigPath = Join-Path $base $sub
                if (-not (Test-Path $sigPath)) { continue }
                Get-ChildItem $sigPath | ForEach-Object {
                    $name = $_.PSChildName
                    $norm = Normalize-Guid($name)
                    if ($vmwareGuids -contains $norm) { Write-Host "Preserving signature $name (VM)" -ForegroundColor DarkGray; return }
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
                        if ($preserve) { Write-Host "Preserving signature $name (matches protected adapter/AV)" -ForegroundColor DarkGray; return }
                    } catch {}
                    # else remove
                    if ($DryRun) { Write-Host "DRYRUN: Remove signature $name" -ForegroundColor Gray }
                    else { try { Remove-Item -Path $_.PsPath -Recurse -Force -ErrorAction Stop; Write-Host "Removed signature: $name" -ForegroundColor Gray } catch { Write-Warning ("Failed remove signature " + ${name} + ": " + $_) } }
                }
            }
        }

        function Reset-Networking {
            $cmds = @( 
                @{Name='Flush DNS'; Cmd='ipconfig /flushdns'},
                @{Name='Clear ARP'; Cmd='arp -d *'},
                @{Name='Reset Winsock'; Cmd='netsh winsock reset'},
                @{Name='Reset IPv4'; Cmd='netsh int ip reset'},
                @{Name='Reset IPv6'; Cmd='netsh int ipv6 reset'}
            )
            foreach ($c in $cmds) {
                Write-Host "$($c.Name)..." -ForegroundColor Yellow
                Write-Log 'INFO' "$($c.Name) - Command: $($c.Cmd)"
                if ($DryRun) { Write-Host "DRYRUN: $($c.Cmd)" -ForegroundColor Gray } else {
                    try { iex $c.Cmd | Out-Null; Write-Host "$($c.Name) done" -ForegroundColor Gray; Write-Log 'INFO' "$($c.Name) completed" } catch { Write-Warning ("$($c.Name) failed: " + $_); Write-Log 'ERROR' ("$($c.Name) failed: " + $_) }
                }
            }
        }

        function Clear-NLAProbing {
            $nlaInternetPath = 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NlaSvc\\Parameters\\Internet'
            if (Test-Path $nlaInternetPath) {
                $props = 'ActiveDnsProbeContent','ActiveDnsProbeHost','ActiveWebProbeContent','ActiveWebProbeHost'
                foreach ($p in $props) {
                        if ($DryRun) { Write-Host "DRYRUN: Remove-ItemProperty $nlaInternetPath -Name $p" -ForegroundColor Gray; Write-Log 'INFO' "DRYRUN: would remove NLA property $p" }
                        else { try { Remove-ItemProperty -Path $nlaInternetPath -Name $p -ErrorAction Stop; Write-Host "Removed NLA property: $p" -ForegroundColor Gray; Write-Log 'INFO' "Removed NLA property: $p" } catch { Write-Verbose ("Property " + $p + " not present or failed: " + $_); Write-Log 'WARN' ("NLA property " + $p + " missing or failed: " + $_) } }
                }
            }
        }

        function Clear-EventLogs {
            $logs = @("Microsoft-Windows-WLAN-AutoConfig/Operational","Microsoft-Windows-NetworkProfile/Operational","Microsoft-Windows-DHCP-Client/Operational")
            foreach ($l in $logs) {
                Write-Host "Clearing event log: $l" -ForegroundColor Yellow
                if ($DryRun) { Write-Host "DRYRUN: wevtutil cl `"$l`"" -ForegroundColor Gray }
                else { try { wevtutil cl "$l" 2>$null; Write-Host "Cleared $l" -ForegroundColor Gray } catch { Write-Warning ("Failed clearing " + ${l} + ": " + $_) } }
            }
        }

        function Main {
            Write-Host "=== Network cleanup starting ===" -ForegroundColor Cyan
            Ensure-Admin

            # Detect installed AV/EDR and hypervisors early so user can make an informed choice
            $detectedAV = Get-InstalledAV
            if ($detectedAV -and $detectedAV.Count -gt 0) {
                Write-Host "Detected potentially impacted software:" -ForegroundColor Yellow
                $detectedAV | ForEach-Object { Write-Host "  - $_" -ForegroundColor DarkGray }
            } else { Write-Host "No endpoint protection detected by quick checks." -ForegroundColor DarkGray }

            $detectedHypervisors = Get-DetectedHypervisors
            if ($detectedHypervisors -and $detectedHypervisors.Count -gt 0) {
                Write-Host "Detected hypervisors/virtualization:" -ForegroundColor Yellow
                $detectedHypervisors | ForEach-Object { Write-Host "  - $_" -ForegroundColor DarkGray }
            } else { Write-Host "No hypervisors detected by quick checks." -ForegroundColor DarkGray }

            $interactive = ($PSBoundParameters.Count -eq 0)

            if ($interactive) {
                # Interactive prompts when no switches provided
                $DryRun = Prompt-YesNo "Run in DRY RUN mode?"
                $CreateLog = Prompt-YesNo "Create a full log file for this run?"

                # If detection missed AV/EDR, ask the user to confirm and optionally provide product names
                if ((-not $detectedAV) -or ($detectedAV.Count -eq 0)) {
                    $hasAV = Prompt-YesNo "No endpoint protection was detected automatically. Do you have endpoint protection (AV/EDR/XDR) installed?"
                    if ($hasAV) {
                        $entered = Read-Host "If known, enter comma-separated names of installed products (or press Enter to skip)"
                        if ($entered) { $detectedAV = ($entered -split ',') | ForEach-Object { $_.Trim() } }
                    } else { $detectedAV = @() }
                } else { $hasAV = $true }

                # If detection missed hypervisors, ask the user to confirm
                if ((-not $detectedHypervisors) -or ($detectedHypervisors.Count -eq 0)) {
                    $hasVM = Prompt-YesNo "No hypervisor was detected automatically. Do you use VMware/VirtualBox/Hyper-V or other virtualization?"
                    if ($hasVM) { $vmwareGuids = Get-HypervisorGuids } else { $vmwareGuids = @() }
                } else {
                    $hasVM = $true
                    $vmwareGuids = Get-HypervisorGuids
                }

                $performBackups = Prompt-YesNo "Create backups and protected registry exports now?"
                if ($performBackups) { $OnlyBackup = $true }
            } else {
                # Respect provided switches
                $performBackups = [bool]$OnlyBackup
                # Populate vmwareGuids based on detectedHypervisors if not interactive
                $vmwareGuids = Get-HypervisorGuids
                $hasVM = ($vmwareGuids -and $vmwareGuids.Count -gt 0)
                if (-not $detectedAV) { $detectedAV = Get-InstalledAV }
            }

            # If logging requested or backups will be created, initialize the log.
            if ($CreateLog -or $performBackups) { Start-Log $LogPath; Write-Log 'INFO' ("Network cleanup starting. DryRun=$DryRun; Force=$Force; OnlyBackup=$OnlyBackup") }
            if ($DryRun) { Write-Log 'WARN' "Running in DRY RUN mode. No destructive actions will be performed." }

            # If backups requested, perform them and optionally exit (backup-only)
            if ($performBackups) {
                Write-Host "Preparing backup path: $BackupPath" -ForegroundColor Yellow
                Write-Log 'INFO' "Preparing backup path: $BackupPath"
                New-ProtectedBackupPath $BackupPath
                Backup-NetworkList $BackupPath
                Backup-WiFiProfiles $BackupPath

                # Build protection lists and export protected registry keys
                $protection = Build-ProtectionLists
                $deps = Inspect-ServiceDependencies(($protection.Services + $detectedAV) | Sort-Object -Unique)
                $global:ProtectedRegistryPaths = @()
                if ($protection.Registry) { $global:ProtectedRegistryPaths += $protection.Registry }
                if ($deps.Registry) { $global:ProtectedRegistryPaths += $deps.Registry }
                $global:ProtectedRegistryPaths = $global:ProtectedRegistryPaths | Sort-Object -Unique
                if ($global:ProtectedRegistryPaths) { Write-Host ("Protected registry paths: " + ($global:ProtectedRegistryPaths -join ', ')) -ForegroundColor Gray; Write-Log 'INFO' ("Protected registry paths: " + ($global:ProtectedRegistryPaths -join ', ')) }

                $regBackups = Backup-ProtectedRegistryKeys $global:ProtectedRegistryPaths $BackupPath
                if ($regBackups) { Write-Log 'INFO' ("Protected registry keys exported: " + ($regBackups -join ', ')) }

                # Append clear restore instructions at the bottom of the log (always create log for backups)
                Write-Log 'INFO' "Backups are located at: $BackupPath"
                $netlist = Get-ChildItem -Path $BackupPath -Filter 'NetworkList_*.reg' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 1
                Write-Log 'INFO' "NetworkList registry backup: $netlist"
                Write-Log 'INFO' "Exported Wi-Fi profiles (XMLs) are in: $BackupPath"
                if ($regBackups) {
                    Write-Log 'INFO' "Protected registry backup files:"
                    foreach ($rb in $regBackups) { Write-Log 'INFO' ("  $rb") }
                    Write-Log 'INFO' "To restore protected registry keys, run each of the following (as Administrator):"
                    foreach ($rb in $regBackups) { $line = '  reg import "' + $rb + '"'; Write-Log 'INFO' $line }
                }
                if ($netlist) { $line = 'To restore NetworkList registry: reg import "' + $netlist + '" (run as Administrator).'; Write-Log 'INFO' $line }
                Write-Log 'INFO' ("To restore Wi-Fi profiles: for each exported XML in $BackupPath run: netsh wlan add profile filename='<path>'")

                if ($OnlyBackup) { Write-Host "Backup-only requested; exiting after backups." -ForegroundColor Yellow; return }
            }

            # Continue with full cleanup
            # Detect hypervisors and prompt only if none detected
            $detectedHypervisors = Get-DetectedHypervisors
            if ($detectedHypervisors -and $detectedHypervisors.Count -gt 0) {
                Write-Host "Detected hypervisors/virtualization: " -ForegroundColor Yellow
                $detectedHypervisors | ForEach-Object { Write-Host "  - $_" -ForegroundColor DarkGray }
                $hasVM = $true
                $vmwareGuids = Get-HypervisorGuids
            } else {
                $hasVM = Prompt-YesNo "Do you use VMware/VirtualBox or other virtualization on this machine?"
                $vmwareGuids = @()
                if ($hasVM) { $vmwareGuids = Get-HypervisorGuids }
            }

            # Stop services where appropriate. Protect AV/EDR services discovered.
            $services = @('WlanSvc','Dnscache','Dhcp','NlaSvc','lmhosts')
            if ($detectedAV) { Write-Host ("Detected AV/EDR: " + ($detectedAV -join ', ')) -ForegroundColor Gray; Write-Log 'INFO' ("Detected AV/EDR: " + ($detectedAV -join ', ')) }
            $protection = Build-ProtectionLists
            $protectedServices = $protection.Services
            $protectedAdapters = $protection.Adapters
            # Inspect service registry dependencies and add to protected registry paths
            $deps = Inspect-ServiceDependencies(($protectedServices + $detectedAV) | Sort-Object -Unique)
            $global:ProtectedRegistryPaths = @()
            if ($protection.Registry) { $global:ProtectedRegistryPaths += $protection.Registry }
            if ($deps.Registry) { $global:ProtectedRegistryPaths += $deps.Registry }
            $global:ProtectedRegistryPaths = $global:ProtectedRegistryPaths | Sort-Object -Unique
            if ($global:ProtectedRegistryPaths) { Write-Host ("Protected registry paths: " + ($global:ProtectedRegistryPaths -join ', ')) -ForegroundColor Gray; Write-Log 'INFO' ("Protected registry paths: " + ($global:ProtectedRegistryPaths -join ', ')) }
            if ($protectedServices) { Write-Host ("Protected service patterns: " + ($protectedServices -join ', ')) -ForegroundColor Gray; Write-Log 'INFO' ("Protected service patterns: " + ($protectedServices -join ', ')) }
            # Backup protected registry keys if not already done
            if (-not $regBackups) { $regBackups = Backup-ProtectedRegistryKeys $global:ProtectedRegistryPaths $BackupPath; if ($regBackups) { Write-Log 'INFO' ("Protected registry keys exported: " + ($regBackups -join ', ')) } }

            foreach ($s in $services) {
                $skip = $false
                foreach ($pat in $protectedServices) { if ($s.ToLower().Contains($pat.ToLower())) { $skip = $true; break } }
                if ($skip) { Write-Host "Preserving service due to protection match: $s" -ForegroundColor DarkGray; continue }
                Write-Host "Stopping service: $s" -ForegroundColor Yellow
                Write-Log 'INFO' "Stopping service: $s"
                if ($DryRun) { Write-Host "DRYRUN: Stop-Service -Name $s -Force" -ForegroundColor Gray; Write-Log 'INFO' "DRYRUN: Stop-Service -Name $s -Force" }
                else { try { Stop-Service -Name $s -Force -ErrorAction Stop; Write-Host "Stopped $s" -ForegroundColor Gray; Write-Log 'INFO' "Stopped service: $s" } catch { Write-Warning ("Failed to stop " + ${s} + ": " + $_); Write-Log 'ERROR' ("Failed to stop service " + $s + ": " + $_) } }
            }

            # Wi-Fi profiles
            Remove-WiFiProfilesSafe

            # Reset networking
            Reset-Networking

            # NLA probing
            Clear-NLAProbing

            # NetworkList cleaning
            Safe-RemoveNetworkListProfiles $vmwareGuids $BackupPath

            # DHCP/WLAN file cleanup - skip if AV present unless forced
            $hasAV = ($detectedAV -and $detectedAV.Count -gt 0)
            if ($hasAV -and -not $Force) { Write-Host "Skipping DHCP/WLAN file deletions due to AV presence (use -Force to override)." -ForegroundColor Yellow }
            else {
                $dhcpPath = "$env:SystemRoot\\System32\\dhcp"
                if (Test-Path $dhcpPath) {
                    $files = Get-ChildItem $dhcpPath -File -ErrorAction SilentlyContinue
                    if ($files) {
                        Write-Host "DHCP files to remove:" -ForegroundColor Yellow
                        $files | ForEach-Object { Write-Host "  - $($_.FullName)" -ForegroundColor DarkGray }
                        if ($Force -or (Prompt-YesNo "Delete the above DHCP files?")) {
                            foreach ($f in $files) {
                                if ($DryRun) { Write-Host "DRYRUN: Remove-Item $($f.FullName)" -ForegroundColor Gray } else { try { Remove-Item $f.FullName -Force -ErrorAction Stop; Write-Host "Removed $($f.Name)" -ForegroundColor Gray } catch { Write-Warning ("Failed remove " + $($f.FullName) + ": " + $_) } }
                            }
                        }
                    }
                }
                $wlanLogPath = "$env:ProgramData\\Microsoft\\Wlansvc\\Logs"
                if (Test-Path $wlanLogPath) {
                    if ($Force -or (Prompt-YesNo "Remove WLAN logs under $wlanLogPath?")) {
                        if ($DryRun) { Write-Host "DRYRUN: Remove logs under $wlanLogPath" -ForegroundColor Gray }
                        else { try { Get-ChildItem $wlanLogPath -Recurse -File -ErrorAction Stop | ForEach-Object { Remove-Item $_.FullName -Force -ErrorAction Stop } ; Write-Host "Cleared WLAN logs" -ForegroundColor Gray } catch { Write-Warning ("Failed clearing WLAN logs: " + $_) } }
                    }
                }
            }

            # Event logs
            Clear-EventLogs

            # Restart services
            foreach ($s in $services) {
                Write-Host "Starting service: $s" -ForegroundColor Yellow
                Write-Log 'INFO' "Starting service: $s"
                if ($DryRun) { Write-Host "DRYRUN: Start-Service -Name $s" -ForegroundColor Gray; Write-Log 'INFO' "DRYRUN: Start-Service -Name $s" }
                else { try { Start-Service -Name $s -ErrorAction Stop; Write-Host "Started $s" -ForegroundColor Gray; Write-Log 'INFO' "Started service: $s" } catch { Write-Warning ("Failed to start " + ${s} + ": " + $_); Write-Log 'ERROR' ("Failed to start service " + $s + ": " + $_) } }
            }

            Write-Host "=== Network cleanup complete ===" -ForegroundColor Green
            Write-Log 'INFO' "Network cleanup complete"

            # Final summary and restore instructions appended to log bottom
            Write-Log 'INFO' "Backups are located at: $BackupPath"
            $netlist = Get-ChildItem -Path $BackupPath -Filter 'NetworkList_*.reg' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 1
            Write-Log 'INFO' "NetworkList registry backup: $netlist"
            Write-Log 'INFO' "Exported Wi-Fi profiles (XMLs) are in: $BackupPath"
            if ($regBackups) {
                Write-Log 'INFO' "Protected registry backup files:"
                foreach ($rb in $regBackups) { Write-Log 'INFO' ("  $rb") }
            }
            Write-Log 'INFO' "To restore protected registry keys, run each of the following (as Administrator):"
            if ($regBackups) { foreach ($rb in $regBackups) { $line = '  reg import "' + $rb + '"'; Write-Log 'INFO' $line } }
            if ($netlist) { $line = 'To restore NetworkList registry: reg import "' + $netlist + '" (run as Administrator).'; Write-Log 'INFO' $line }
            Write-Log 'INFO' ("To restore Wi-Fi profiles: for each exported XML in $BackupPath run: netsh wlan add profile filename='<path>'")
            Write-Log 'INFO' "If you need help restoring drivers or services, review the log and protected registry paths listed above before making changes."

            # Reboot/shutdown options
            if ($RebootNow) {
                if ($DryRun) { Write-Host "DRYRUN: Restart-Computer" } else { Restart-Computer -Force }
            } else {
                while ($true) {
                    $choice = Read-Host "Choose post-run action: [R]estart / [S]hutdown / [N]o action"
                    switch ($choice.ToUpper()) {
                        'R' { if ($DryRun) { Write-Host "DRYRUN: Restart-Computer" } else { Restart-Computer -Force }; break }
                        'S' { if ($DryRun) { Write-Host "DRYRUN: Stop-Computer" } else { Stop-Computer -Force }; break }
                        'N' { Write-Host "Please reboot or shutdown later to apply changes." -ForegroundColor Yellow; break }
                        default { Write-Host "Enter R, S, or N." -ForegroundColor Yellow; continue }
                    }
                    break
                }
            }
        }

        Main
