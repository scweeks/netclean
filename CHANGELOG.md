# Changelog

All notable changes to this project should be documented in this file.

## Unreleased

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
