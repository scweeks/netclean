# AGENTS.md

## Purpose
This document defines mandatory standards for contributors and automation agents working in this repository.

## Core Engineering Standards
- Favor small, focused changes with clear intent and minimal blast radius.
- Keep scripts idempotent where possible and safe by default (`-DryRun` first for destructive operations).
- Use approved PowerShell verbs, descriptive names, and explicit parameter contracts.
- Avoid global state; pass data through parameters and return values.
- Implement robust error handling with actionable messages and non-zero exits on failure paths.
- Update README/CHANGELOG when behavior, interface, or operational guidance changes.

## Architecture Standards
- Enforce modularity: isolate responsibilities into reusable functions/modules (`Netclean.psm1` first, wrapper scripts second).
- Keep orchestration separate from side-effecting operations.
- Design for testability: pure logic should be callable without requiring machine-wide mutation.
- Preserve separation of concerns:
  - detection/inspection
  - decision logic
  - mutation/remediation
  - logging/reporting
- Prefer composable functions over monolithic scripts.

## Security and DevSecOps Standards
- Follow least-privilege and explicit-elevation patterns; require Administrator only when necessary.
- Never commit secrets, credentials, tokens, or sensitive host artifacts.
- Validate all file/registry/network inputs before use.
- Use safe defaults: require explicit flags for destructive or forceful operations.
- Keep AV/EDR and virtual adapter safeguards intact unless a change explicitly requires otherwise.
- Treat CI as a security gate: lint, test, and review findings must be resolved before merge.
- Ensure supply-chain hygiene by pinning or constraining dependency/module versions where practical.

## PowerShell Standards (Microsoft + Community Best Practices)
- Target PowerShell 5.1+ and `pwsh` compatibility where feasible.
- Follow existing `PSScriptAnalyzerSettings.psd1`; do not introduce new warnings/errors.
- Avoid `Invoke-Expression`, aliases, and `Write-Host` for control flow.
- Use `SupportsShouldProcess` for state-changing functions and respect `-WhatIf` semantics where applicable.
- Use structured output objects for automation; reserve console-only output for user guidance.
- Handle external command failures explicitly and preserve exit codes.

## Testing Standards (Pester + TDD)
- Apply TDD for new behavior and bug fixes:
  1. Write or update a failing Pester test.
  2. Implement the minimal code change.
  3. Refactor while keeping tests green.
- Add regression tests for every fixed defect.
- Keep tests deterministic, isolated, and non-destructive.
- Prefer mocking/stubbing for destructive commands and system dependencies.
- Maintain and expand coverage of safety-critical paths (`-DryRun`, backup/restore, protections).

## GitHub Standards
- Use feature branches from `main`; keep commits atomic and descriptive.
- Pull requests must include:
  - problem summary
  - change summary
  - validation evidence (PSScriptAnalyzer + Pester)
  - risk/rollback notes for operational changes
- Ensure GitHub Actions workflows pass before merge.
- Require review for changes affecting cleanup logic, security protections, CI, or release packaging.

## Performance and Efficiency Standards
- Minimize repeated registry, file system, and process queries; cache where safe within a run.
- Prefer bulk operations over repeated shell-outs when equivalent behavior is available.
- Keep logging informative but bounded; avoid excessive noise in normal success paths.
- Maintain predictable runtime and fail fast on unrecoverable prerequisites.

## Definition of Done
A change is complete only when all are true:
- Requirements are met with minimal, modular implementation.
- New/changed behavior is covered by Pester tests (unless documentation-only).
- `PSScriptAnalyzer` reports no blocking findings.
- Security/safety checks are preserved or improved.
- CI workflows pass.