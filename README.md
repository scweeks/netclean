# netclean

[![CI](https://github.com/<owner>/<repo>/actions/workflows/powershell-check.yml/badge.svg)](https://github.com/<owner>/<repo>/actions/workflows/powershell-check.yml) [![License](https://img.shields.io/badge/license-See%20LICENSE-lightgrey.svg)](LICENSE)

netclean is an aggressive-but-safe Windows network and log cleaner designed to prepare a Windows system for attending a conference, workshop, or participating in a Capture The Flag (CTF) event. The script helps remove identifying network traces (Wi‑Fi profiles, NetworkList entries, logs, caches) while providing safe backups and protections for security products and virtual adapters.

> Warning: Run this script only on systems you control. It makes potentially destructive changes to networking state and event logs. Use `-DryRun` first to preview actions.

## Features

- Back up `NetworkList` and Wi‑Fi profiles to a protected folder.
- Remove all Wi‑Fi profiles (optionally exported for restore).
- Reset network state: Winsock, IPv4/IPv6 stacks, flush DNS, clear ARP.
- Clear NLA probing keys and selected networking event logs.
- Detect and preserve common AV/EDR and hypervisor artifacts (services, drivers, registry paths).
- Interactive prompts when run without switches; fully scriptable with command-line switches.

## Summary of actions

- Export the `NetworkList` registry key and Wi‑Fi profiles (XML) to backups.
- Build protection lists for AV/EDR and hypervisor adapters to avoid modifying them.
- Optionally delete DHCP/WLAN cache files and WLAN logs (skipped when endpoint protection detected unless `-Force`).
- Stop and restart a small set of networking services (`WlanSvc`, `Dnscache`, `Dhcp`, `NlaSvc`, etc.).
- Remove non-VM `NetworkList` profiles and signatures, and clear selected event logs.
- Optionally reboot the system when complete.

## What it does NOT do

- Modify Windows Firewall rules.
- Uninstall or remove AV/EDR products.
- Intentionally edit protections for Bitdefender, VMware, or other commonly detected vendor drivers/services.

## Requirements

- Windows 10 / Windows 11 with PowerShell.
- Must be run as Administrator. The script will prompt to relaunch elevated if needed.

## Quick start

Preview what will happen (safe):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File netclean.ps1 -DryRun -CreateLog
```

Run the full cleanup (creates log):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File netclean.ps1 -CreateLog
```

Create backups only and exit:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File netclean.ps1 -OnlyBackup -CreateLog
```

Force deletions that are otherwise skipped due to detected AV/EDR:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File netclean.ps1 -Force -CreateLog
```

Run and reboot automatically:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File netclean.ps1 -RebootNow -CreateLog
```

## Command-line switches

| Switch | Description |
|--------|-------------|
| `-DryRun` | Show what would be done without making destructive changes. |
| `-Force` | Bypass some interactive confirmations and override AV/EDR safety checks for file deletions. Use with caution. |
| `-OnlyBackup` | Perform backups (NetworkList, Wi‑Fi profiles, protected registry keys) then exit. |
| `-CreateLog` | Create a timestamped log file under the log path. |
| `-BackupPath <path>` | Path to store backups (default: `%ProgramData%\NetworkCleaner\Backups`). |
| `-LogPath <path>` | Path to store logs (default: `%ProgramData%\NetworkCleaner\Logs`). |
| `-RebootNow` | Reboot the machine automatically after the script completes. |

## Backups & restore

- Backups are saved to the configured `BackupPath`.

Restore the exported `NetworkList` registry key (as Administrator):

```powershell
reg import "<path-to>/NetworkList_YYYYMMDD_HHMMSS.reg"
```

Restore Wi‑Fi profiles (for each exported XML):

```powershell
netsh wlan add profile filename="<path-to>/WiFiProfile_<name>.xml"
```

Restore protected registry exports:

```powershell
reg import "<path-to>/reg_backup_... .reg"
```

## Tables & outputs

Key directories (defaults):

| Purpose | Default path |
|---------|--------------|
| Backups | `%ProgramData%\NetworkCleaner\Backups` |
| Logs | `%ProgramData%\NetworkCleaner\Logs` |

Log files are timestamped like `netclean_YYYYMMDD_HHMMSS.log` and contain the full sequence of actions and restore instructions for exported registry keys and Wi‑Fi profiles.

## CI / Scheduled task examples

This repository includes a lightweight GitHub Actions workflow that lints PowerShell with `PSScriptAnalyzer` and runs the wrapper in `-DryRun` mode. The workflow file is:

- `.github/workflows/powershell-check.yml`

Example scheduled-task registration script is under `examples/register-scheduledtask.ps1` (creates an idempotent task to run the wrapper at startup).

## Examples: PowerShell wrapper scripts

Below are two example wrappers that make running and restoring easier. They are provided as guidance — you can copy them into `examples/` and customize paths as needed.

1) Simple runner that creates backups, logs, and performs the cleanup non-interactively:

```powershell
# examples/run-netclean.ps1
param(
    [switch]$DryRun,
    [switch]$Force,
    [string]$BackupPath = "$env:ProgramData\NetworkCleaner\Backups",
    [string]$LogPath = "$env:ProgramData\NetworkCleaner\Logs"
)

$script = Join-Path $PSScriptRoot "..\netclean.ps1"
if (-not (Test-Path $script)) { Write-Error "netclean.ps1 not found at $script"; exit 1 }

$args = @('-NoProfile','-ExecutionPolicy','Bypass','-File',$script)
if ($DryRun) { $args += '-DryRun' }
if ($Force) { $args += '-Force' }
$args += '-CreateLog','-BackupPath',$BackupPath,'-LogPath',$LogPath

Write-Host "Launching netclean with args: $($args -join ' ')" -ForegroundColor Cyan
Start-Process -FilePath (Get-Command powershell).Source -ArgumentList $args -NoNewWindow -Wait
Write-Host "netclean run completed. Check logs under $LogPath" -ForegroundColor Green
```

2) Restore Wi‑Fi profiles from a backup folder (imports each XML):

```powershell
# examples/restore-wifi-profiles.ps1
param(
    [string]$BackupPath = "$env:ProgramData\NetworkCleaner\Backups"
)

if (-not (Test-Path $BackupPath)) { Write-Error "Backup path not found: $BackupPath"; exit 1 }

$xmlFiles = Get-ChildItem -Path $BackupPath -Filter 'WiFiProfile_*.xml' -File -ErrorAction SilentlyContinue
if (-not $xmlFiles) { Write-Host "No Wi‑Fi profile exports found in $BackupPath"; exit 0 }

foreach ($f in $xmlFiles) {
    Write-Host "Importing profile: $($f.Name)"
    try { netsh wlan add profile filename="$($f.FullName)" | Out-Null; Write-Host "Imported: $($f.Name)" -ForegroundColor Green } catch { Write-Warning "Failed to import $($f.Name): $_" }
}

Write-Host "Wi‑Fi restore complete." -ForegroundColor Green
```

## Recommended workflow

1. Preview with `-DryRun` and `-CreateLog`.
2. Create backups with `-OnlyBackup` and verify exported files under the backups folder.
3. Run the full cleanup when satisfied.

## Troubleshooting & logs

- Review the timestamped log in `LogPath` for details about protected registry paths, exported files, and skipped actions.
- If the script skips DHCP/WLAN file deletions because AV/EDR was detected, use `-Force` only after confirming backups and understanding risks.

## Contributing & license

- Contributions welcome for improving detection rules, safeguards, or cross-version compatibility; please open a pull request with tests and notes.
- See the `LICENSE` file for license details.

---

If you'd like, I can also commit the workflow and examples to the repository. Tell me to proceed and I'll make a git commit.
