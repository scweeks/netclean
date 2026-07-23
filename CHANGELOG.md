# Changelog

All notable changes to this project should be documented in this file.

## Unreleased

- Add conference-preparation adapter reset and verification: IPv4 DHCP, Quad9 IPv4/IPv6 DNS, DNS over HTTPS without plaintext fallback where supported, IPv6 retained with IPv4 preferred, protected/managed-adapter boundaries, private adapter backups, and a machine-readable verification ledger.
- Add conditional post-cleanup evidence for Wi-Fi disconnection and DNS/ARP caches; cache state is evaluated only when no physical wired LAN is connected.
- Upgrade the test toolchain to Pester 6.0.1, make test files discovery-isolated, and fail coverage runs on discovery or container errors.
- Add isolated registry System tests that exercise real Registry-provider detection, native backup, protected-boundary cleanup, and independent verification against synthetic Pester `TestRegistry:` data.
- Fix native registry export argument quoting for keys and output paths containing spaces.
- Raise the overall command-coverage ratchet from 68% to 69% after the isolated System tests increased Pester 6's measured production coverage from 68.43% to 69.42%; retain the 95% changed-file and long-term overall targets.
- Expand fail-closed cleanup verification coverage for registry and user artifacts, event logs, DNS and ARP caches, and physical-adapter discovery; preserve fail-soft registry discovery while allowing verification callers to surface query failures.
- Treat physical adapters without an interface index as having no queryable ARP entries instead of failing under strict mode.
- Raise the overall command-coverage ratchet from 69% to 71% after the verification failure matrix increased measured production coverage from 69.42% to 71.29%, and align Pester's displayed target with the enforced runner and pull-request gates.
- Add source-matrix and correlation tests for Security Center products, services, drivers, uninstall records, adapters, PnP devices, service registry data, file metadata/signatures, and protected service/adapter registry boundaries.
- Allow empty metadata paths to reach the existing fail-soft guard instead of failing during parameter binding.
- Raise the overall command-coverage ratchet from 71% to 80% after protection-discovery tests increased measured production coverage from 71.29% to 80.17%.
- Add functional contracts for menus, confirmation, summaries, previews, safe Preview routing, live backup-directory creation, and mocked dry/live restart or shutdown actions.
- Make launcher-owned settings explicitly script-scoped, allow empty lists to reach their existing summary output, and correct invalid-input feedback that passed an unsupported parameter to `Write-Verbose`.
- Raise the overall command-coverage ratchet from 80% to 85% after launcher and user-facing tests increased measured production coverage from 80.17% to 85.56%.
- Raise the overall command-coverage ratchet from 85% to 90% after failure-path, strict-mode, and active-helper tests increased measured production coverage to 92.05%.
- Expand active-path protection discovery, workflow, registry export, cleanup, and verification tests to 95.09% measured production coverage, and raise the overall command-coverage ratchet from 90% to 94% while retaining the 95% changed-file gate.
- Reject test-directory files as coverage sources so test code cannot inflate reported production coverage.
- Preserve textual vendor inference when executable metadata is present but does not identify a vendor.
- Normalize exported `Wi-Fi-<profile>.xml` filenames before using them as expected profile names during workflow verification.
- Retry a PSScriptAnalyzer target once only when version 1.25.0 raises its intermittent `NullReferenceException`; all repeated null references, other exceptions, and analyzer findings remain fatal.
- Temporarily omit performance tuning from the interactive menu while retaining explicit `-Mode PerformanceTune` compatibility.
- Add a parallel Windows PowerShell 5.1 compatibility job and update workflow actions to immutable Node.js 24 release commits.
- Treat Workplace registration as preserved user-level SSO rather than organization management unless independent domain, Entra join, enterprise join, or MDM evidence exists.
- Preserve identity, account, token, credential, and BrokerPlugin stores through explicit narrow cleanup allowlists and regression tests.
- Capture `netsh` Wi-Fi profile output as UTF-8 while restoring the caller's console encoding so non-ASCII SSID names render correctly.
- Collect the service registry, Wi-Fi profiles, and NetworkList profiles once per run instead of re-querying per phase; cache per-binary file metadata lookups; run read-only supplemental evidence collectors (WFP, NDIS, INF, scheduled tasks, Appx, MSI registry) as two bounded parallel groups with a safe sequential fallback.
- Add `Decision`, `Reason`, and `ProtectionSource` to every network-privacy candidate and Wi-Fi/NetworkList profile decision so each of the ~60+ candidates in a real run states why it will or will not be touched.
- Fix `-Mode PerformanceTune` crashing outright (the profile-selection function was never exported from the module manifest); wire the `-PerformanceProfile` parameter through so an explicitly supplied profile is honored instead of always re-prompting, while still prompting when no profile was explicitly supplied even under `-Force`.
- Wrap every Phase 2 backup export (previously only the firewall-policy export was guarded) in the same try/catch-and-degrade pattern, so one failing backup no longer aborts the entire Protect phase with a raw stack trace.
- Guard `Reset-NetCleanAdapterConfigurationSafe`'s adapter-discovery call so a failure there returns a structured failed result instead of throwing uncaught after Wi-Fi removal, registry cleanup, and event-log/user-artifact clearing have already run for real; align its `-Confirm` wiring with its sibling cleanup steps.
- Redesign Phase 4 verification: fix a false-positive failure on Group-Policy-managed Wi-Fi profiles (previously any remaining profile failed verification regardless of whether it was supposed to be preserved); stop re-running Phase 1's full unoptimized detection a second time by reusing the Phase 1 collection snapshot; add per-artifact verification that joins Phase 1's `Decision` records against Phase 3's own per-item removal ledgers instead of re-detecting state.
- Fix the launcher's Wi-Fi "Found"/"Remaining After Cleanup" summary reporting nothing on real (non-dry-run) runs; it now reads the Phase 1 collection snapshot and Phase 4's own remaining-profile check instead of parsing dry-run-only manifest markers.
- Consolidate the four near-identical Phase 2 JSON-export functions into a shared helper; rename the always-0-or-1 `AdapterConfigurationBackupCount` metric to a boolean `HasAdapterConfigurationBackup`; enable `PSUseApprovedVerbs` (zero violations found).

- Refactor: Make repository PSScriptAnalyzer-clean across all scripts and module functions.
	- Replace `Write-Host` with structured logging and proper streams.
	- Add `CmdletBinding(SupportsShouldProcess=$true)` to state-changing functions.
	- Rename functions to use approved verbs and singular nouns; add backward-compatible aliases.
	- Harden `catch` blocks to surface errors (no empty catches).
	- Remove unsafe `Invoke-Expression` usage and use safer execution patterns.
	- Fix scoping (avoid `global:`), remove unused variables, and avoid assigning to automatic variables in examples/tests.
	- Fix file encoding/BOM for Unicode files and remove non-ASCII artifacts that triggered analyzer warnings.
	- Update examples and tests to be analyzer- and CI-friendly.
	- Add unit tests and ensure Pester tests pass locally.
  
These changes were made to improve safety, testability, and to ensure CI fails fast on analyzer or test regressions.

## 0.1.0 - 2026-03-07

- Initial public release (netclean.ps1) and repository scaffolding.
