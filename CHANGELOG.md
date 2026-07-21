# Changelog

All notable changes to this project should be documented in this file.

## Unreleased

- Add conference-preparation adapter reset and verification: IPv4 DHCP, Quad9 IPv4/IPv6 DNS, DNS over HTTPS without plaintext fallback where supported, IPv6 retained with IPv4 preferred, protected/managed-adapter boundaries, private adapter backups, and a machine-readable verification ledger.
- Add conditional post-cleanup evidence for Wi-Fi disconnection and DNS/ARP caches; cache state is evaluated only when no physical wired LAN is connected.
- Ratchet CI at the measured 69% overall command-coverage baseline while retaining the 95% changed-file and long-term overall targets.

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
