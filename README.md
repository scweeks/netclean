# NetClean

## Badges

[![CI](https://github.com/scweeks/netclean/actions/workflows/ci.yml/badge.svg)](https://github.com/scweeks/netclean/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/endpoint?url=https://scweeks.github.io/netclean/coverage.json)](https://scweeks.github.io/netclean/coverage.json)
[![Analyzer](https://img.shields.io/badge/style-PSScriptAnalyzer-00aaff)](https://github.com/scweeks/netclean/actions/workflows/ci.yml)
[![Coverage target](https://img.shields.io/badge/coverage_target-94%25-green)](https://github.com/scweeks/netclean/actions/workflows/ci.yml)
[![PowerShell 5.1 | 7.4](https://img.shields.io/badge/PowerShell-5.1%20%7C%207.4-blue)](https://learn.microsoft.com/powershell/)
[![Windows](https://img.shields.io/badge/platform-Windows-blue)](https://github.com/scweeks/netclean)
[![License](https://img.shields.io/badge/license-GPLv3-blue.svg)](LICENSE)

The coverage badge is served from GitHub Pages at `https://scweeks.github.io/netclean/coverage.json`. It updates from the CI pipeline after a successful push to `main` and requires GitHub Pages to be enabled for the repository.

NetClean is a Windows PowerShell tool for detecting, backing up, cleaning, and verifying selected network-history artifacts before using a system at a conference, workshop, or security event. It uses an inventory of security products, services, drivers, and network adapters to avoid modifying identified protected artifacts.

> [!WARNING]
> Run NetClean only on systems you own or administer. Cleanup modes can remove Wi-Fi profiles, registry data, event logs, and user history. Start with `Preview` or `-DryRun`, review the backup, and keep a separate recovery path.

## Overview

NetClean helps prepare Windows systems for use in semi-public or untrusted environments by:

- Detecting security products, virtual adapters, and protected registry paths.
- Exporting an access-restricted backup of evidence and configuration.
- Performing targeted cleanup of network-history artifacts according to a chosen mode.
- Preserving protected inventory and avoiding modification of protected artifacts.
- Producing a JSON verification ledger and detailed logs for auditability.

The tool is designed to be safe by default, auditable, and reversible when used with the provided backup artifacts.

## Requirements

- Windows 10 or Windows 11.
- Windows PowerShell 5.1 or PowerShell 7.x.
- Administrator privileges are required for full detection, backup, cleanup, and verification.

## Quick Start

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

## Modes

| Mode | Behavior |
|---|---|
| `Menu` | Interactive mode selection. |
| `Preview` | Detects and simulates protection and backup planning without cleanup. |
| `SafeConferencePrep` | Detects, backs up, performs the standard cleanup, and verifies protected inventory. |
| `AdvancedRepair` | Adds network-stack repair actions to the standard workflow. |
| `PerformanceTune` | Direct invocation only; applies a performance profile to the standard workflow. |

Performance tuning is intentionally omitted from the interactive menu while that work is tabled; use `-Mode PerformanceTune` explicitly.

## Launcher Parameters

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

## Workflow and Safety Model

1. Detect security products, services, drivers, adapters, protected registry paths, and candidate network artifacts.
2. Export the protection inventory, adapter IP and DNS state, registry map, sanitizable-artifact list, NetworkList data, Wi-Fi profiles, firewall policy, and protected registry keys into an access-restricted backup directory.
3. Perform only the operations selected by the mode and skip switches. Standard conference preparation removes saved Wi-Fi profiles and network-history artifacts, resets eligible unmanaged adapters to IPv4 DHCP, configures the Quad9 Secure IPv4/IPv6 resolver set and DNS over HTTPS where supported, and keeps IPv6 enabled while preferring IPv4 after restart. `ShouldProcess`, `-WhatIf`, and `-DryRun` are honored by state-changing helpers.
4. Re-read protected inventory, Wi-Fi and NetworkList state, adapter DHCP and DNS state, the IPv4-preference registry value, encrypted-DNS configuration, removed registry and user artifacts, and cleared event logs. A private JSON verification ledger and detailed log record each applicable check.

Protection detection is best effort and cannot guarantee recognition of every security or virtual-network product. Always review the preview and inventory before cleanup.

## Backup Confidentiality

Wi-Fi export uses Windows `netsh` with `key=clear`, so exported XML files can contain plaintext Wi-Fi credentials. NetClean restricts both default and custom backup and log directories to administrators, SYSTEM, and the initiating user, but those principals can still read the files. Avoid syncing backups to untrusted services and securely remove backups when they are no longer needed.

## Verification Limits

Wi-Fi verification requires physical Wi-Fi adapters to be disconnected.

DNS and dynamic IPv4 neighbor or ARP caches require an empty network context for reliable verification; when a wired LAN is connected these checks may be recorded as not applicable.

Stack repair and performance-tuning commands can require a restart or lack an immediate read-back signal; their outcomes are recorded in the evidence ledger.

## Restore Examples

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

Test framework: Pester 6.0.1.

Static analysis: PSScriptAnalyzer 1.25.0.

The authoritative coverage run is intentionally sequential. Pester 6's file-level parallel execution remains experimental, so CI keeps coverage collection on the sequential path. The PowerShell 7 job validates the module manifest, treats analyzer findings as failures, runs Pester with JaCoCo coverage, publishes a GitHub Pages coverage badge payload, and uploads test artifacts. A separate Windows PowerShell 5.1 job runs the full test suite for compatibility.

Run tests locally:

```powershell
Install-Module Pester -Scope CurrentUser -RequiredVersion 6.0.1 -Force -SkipPublisherCheck
Install-Module PSScriptAnalyzer -Scope CurrentUser -RequiredVersion 1.25.0 -Force
Invoke-Pester -Path .\tests
.\tests\Run-NetClean-Coverage.ps1
```

Coverage and gates:

CI enforces an overall coverage gate of 94 percent. Pull-request reporting includes a changed-file target of 95 percent.

The coverage runner rejects source paths beneath `tests/` so test code cannot inflate results. Coverage output is written to `tests/TestResults` or the configured output path and is ignored by Git.

Module cache refresh:

The CI workflow exposes a `workflow_dispatch` input named `force-module-refresh` so maintainers can clear the module cache and force fresh installs from the Actions UI. Use this after merging dependency updates, before a release, or when debugging CI module issues.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines, testing expectations, and the preferred PR workflow.

In brief:

- Follow red-green-refactor: add focused regression coverage for any behavior you change.
- Keep changes small and reviewable.
- Ensure PSScriptAnalyzer passes and Pester tests, including the coverage gate, succeed locally before opening a PR.
- When opening a PR, include a short description of the change, the tests added or updated, and any manual verification steps required.

## License

NetClean is released under the GPLv3. See [LICENSE](LICENSE) for full terms.