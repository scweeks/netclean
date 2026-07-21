# NetClean

[![CI](https://github.com/scweeks/netclean/actions/workflows/ci.yml/badge.svg)](https://github.com/scweeks/netclean/actions/workflows/ci.yml) [![License](https://img.shields.io/badge/license-GPLv3-blue.svg)](LICENSE)

NetClean is a Windows PowerShell tool for detecting, backing up, cleaning, and verifying selected network-history artifacts before using a system at a conference, workshop, or security event. It uses an inventory of security products, services, drivers, and network adapters to avoid modifying identified protected artifacts.

> [!WARNING]
> Run NetClean only on systems you own or administer. Cleanup modes can remove Wi-Fi profiles, registry data, event logs, and user history. Start with `Preview` or `-DryRun`, review the backup, and keep a separate recovery path.

## Requirements

- Windows 10 or Windows 11.
- Windows PowerShell 5.1 or PowerShell 7.
- Administrator privileges for complete detection, backup, cleanup, and verification.

## Modes

| Mode | Behavior |
|---|---|
| `Menu` | Interactive mode selection. |
| `Preview` | Runs detection and simulated protection/backup planning without cleanup. |
| `SafeConferencePrep` | Detects, backs up, performs the standard cleanup, and verifies protected inventory. |
| `AdvancedRepair` | Adds network-stack repair actions to the standard workflow. |
| `PerformanceTune` | Adds the selected performance profile to the standard workflow. |

## Quick start

Preview without making changes:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\NetClean.ps1 -Mode Preview -CreateLog
```

Run the standard workflow as a dry run:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\NetClean.ps1 -Mode SafeConferencePrep -DryRun -CreateLog
```

Run the standard workflow after reviewing the preview and backup plan:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\NetClean.ps1 -Mode SafeConferencePrep -CreateLog
```

## Launcher parameters

| Parameter | Description |
|---|---|
| `-Mode <name>` | Selects `Menu`, `Preview`, `SafeConferencePrep`, `AdvancedRepair`, or `PerformanceTune`. |
| `-DryRun` | Simulates state-changing operations. `Preview` always behaves as a dry run. |
| `-Force` | Bypasses launcher confirmation prompts. It does not disable protected-artifact checks. |
| `-CreateLog` | Starts a timestamped log in `LogPath`. Explicit non-menu modes also initialize logging. |
| `-BackupPath <path>` | Backup destination. Default: `%ProgramData%\NetClean\Backups`. |
| `-LogPath <path>` | Log destination. Default: `%ProgramData%\NetClean\Logs`. |
| `-SkipWifi` | Skips Wi-Fi profile removal. |
| `-SkipDnsFlush` | Skips DNS cache flushing. |
| `-SkipEventLogs` | Skips network event-log cleanup. |
| `-SkipUserArtifacts` | Skips user-history cleanup. |
| `-SkipFirewallBackup` | Skips firewall-policy export during protection. |
| `-PerformanceProfile <name>` | Selects `Conservative`, `Optimal`, `Gaming`, or `Default` for `PerformanceTune`. |
| `-RebootNow` | Selects restart as the post-run action without prompting. In dry-run mode, the restart is logged but not performed. |

## Workflow and safety model

1. Detect security products, services, drivers, adapters, protected registry paths, and candidate network artifacts.
2. Export the protection inventory, registry map, sanitizable-artifact list, NetworkList data, Wi-Fi profiles, firewall policy, and protected registry keys.
3. Perform only the operations selected by the mode and skip switches. `ShouldProcess`, `-WhatIf`, and `-DryRun` are honored by state-changing helpers.
4. Re-detect protected vendors, interface GUIDs, and services. Verification passes only when none of those baseline items are missing.

Protection detection is best-effort and cannot guarantee recognition of every security or virtual-network product. Review the preview and inventory before cleanup.

### Backup confidentiality

Wi-Fi export uses Windows `netsh` with `key=clear`, so exported XML files can contain plaintext Wi-Fi credentials. Store backups in a location restricted to administrators, avoid syncing them to untrusted services, and securely remove them when they are no longer needed. NetClean does not currently harden custom backup-directory ACLs.

## Restore examples

Restore an exported registry file from an elevated shell:

```powershell
reg.exe import "C:\path\to\backup.reg"
```

Restore a Wi-Fi profile:

```powershell
netsh.exe wlan add profile filename="C:\path\to\Wi-Fi-profile.xml"
```

Restore a firewall policy:

```powershell
netsh.exe advfirewall import "C:\path\to\FirewallPolicy.wfw"
```

The `examples` directory contains reusable launcher, Wi-Fi restore, and scheduled-task examples.

## Development and CI

The project uses Pester v5 and PSScriptAnalyzer. Changes should follow red-green-refactor and add focused regression coverage before production edits.

```powershell
Install-Module Pester -Scope CurrentUser -RequiredVersion 5.9.0 -Force -SkipPublisherCheck
Install-Module PSScriptAnalyzer -Scope CurrentUser -RequiredVersion 1.25.0 -Force
Invoke-Pester -Path .\tests
.\tests\Run-NetClean-Coverage.ps1
```

CI is defined in `.github/workflows/ci.yml`. It validates the module manifest, treats analyzer warnings/errors as failures, runs Pester v5, and enforces 95% overall coverage. Generated output is written under `tests/TestResults` and is ignored by Git.

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution expectations and [LICENSE](LICENSE) for GPLv3 terms.
