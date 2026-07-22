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
