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
| `PerformanceTune` | Direct invocation only while network-optimization work is tabled; adds the selected performance profile to the standard workflow. |

The interactive menu currently offers Preview, Safe conference prep, Advanced repair, and Exit. Performance tuning remains available through the explicit `-Mode PerformanceTune` parameter for backward compatibility, but it is intentionally omitted from the menu while that work is tabled.

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
2. Export the protection inventory, adapter IP/DNS state, registry map, sanitizable-artifact list, NetworkList data, Wi-Fi profiles, firewall policy, and protected registry keys into an access-restricted backup directory.
3. Perform only the operations selected by the mode and skip switches. Standard conference preparation removes saved Wi-Fi profiles and network-history artifacts, resets eligible unmanaged adapters to IPv4 DHCP, configures the Quad9 Secure IPv4/IPv6 resolver set and DNS over HTTPS without plaintext fallback where Windows supports it, and keeps IPv6 enabled while preferring IPv4 after restart. `ShouldProcess`, `-WhatIf`, and `-DryRun` are honored by state-changing helpers.
4. Re-read protected inventory, Wi-Fi/NetworkList state, adapter DHCP and DNS state, the IPv4-preference registry value, encrypted-DNS configuration, removed registry/user artifacts, and cleared event logs. A private JSON verification ledger and detailed log record each applicable check.

Protection detection is best-effort and cannot guarantee recognition of every security or virtual-network product. Review the preview and inventory before cleanup.

### Backup confidentiality

Wi-Fi export uses Windows `netsh` with `key=clear`, so exported XML files can contain plaintext Wi-Fi credentials. NetClean restricts both default and custom backup/log directories to administrators, SYSTEM, and the initiating user, but those principals can still read the files. Avoid syncing backups to untrusted services and securely remove them when they are no longer needed.

### Verification limits

When Wi-Fi cleanup was requested, verification requires physical Wi-Fi adapters to be disconnected. DNS and dynamic IPv4 neighbor/ARP caches are also required to be empty when no physical wired LAN is connected. If a wired LAN is connected, cache contents can reflect legitimate live traffic, so those two cache checks are recorded as not applicable and do not affect the result. Permanent neighbor entries are not treated as removable history.

Stack repair and performance-tuning commands can require a restart or lack a reliable immediate read-back signal; their command outcomes are retained in the evidence ledger instead of being presented as independently observed final state.

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

The project uses Pester 6.0.1 and PSScriptAnalyzer. Changes should follow red-green-refactor and add focused regression coverage before production edits. Pester 6 requires Windows PowerShell 5.1 or PowerShell 7.4 and later.

The authoritative coverage run is intentionally sequential. Pester 6 file-level parallel execution remains experimental, and Pester always collects coverage on its sequential path, so CI does not enable parallel execution or use a custom parallel harness.

The System test layer performs real Windows Registry-provider operations against synthetic data in Pester's container-scoped `TestRegistry:` drive. It covers NetworkList discovery and names, native `.reg` backup, protected-path preservation, sanitizable-path removal, adapter-configuration preservation, and independent post-state verification without reading or changing the machine's actual network records. These tests run in CI. They do not replace destructive acceptance testing of real Wi-Fi profiles, adapters, DNS/ARP caches, event logs, restart behavior, or policy-managed systems; those scenarios require a disposable Windows VM or test machine with a restore point or snapshot.

```powershell
Install-Module Pester -Scope CurrentUser -RequiredVersion 6.0.1 -Force -SkipPublisherCheck
Install-Module PSScriptAnalyzer -Scope CurrentUser -RequiredVersion 1.25.0 -Force
Invoke-Pester -Path .\tests
.\tests\Run-NetClean-Coverage.ps1
```

CI is defined in `.github/workflows/ci.yml`. The authoritative PowerShell 7 job validates the module manifest, treats analyzer warnings/errors as failures, and runs Pester 6.0.1 with coverage. An independent Windows PowerShell 5.1 job runs the complete test suite and manifest validation in parallel. Tests execute to exercise production behavior, but the coverage runner rejects source paths beneath `tests/`, so test code cannot inflate the result. Pester 6's profiler-based collector measures the current suite at 95.09% command coverage; the overall gate is ratcheted at 94% to retain regression margin, while pull-request reporting retains a 95% changed-file target. The suite now exceeds the 95% long-term overall target, and the enforced ratchet should only move upward as focused tests add durable margin. Generated output is written under `tests/TestResults` and is ignored by Git.

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution expectations and [LICENSE](LICENSE) for GPLv3 terms.
