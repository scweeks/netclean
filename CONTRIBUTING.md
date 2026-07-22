# Contributing

Contributions should be small, focused, and based on the latest `main` branch unless a maintainer specifies another base.

## Engineering expectations

- Use red-green-refactor: add or correct a focused Pester 6 test, observe the intended failure, apply the smallest production change, then refactor with the suite green.
- Preserve dry-run, `ShouldProcess`, protected-artifact, and backup behavior for state-changing operations.
- Keep functions compact and single-purpose; isolate native commands and filesystem/registry access behind testable helpers.
- Do not weaken security checks, analyzer rules, test assertions, the 80% overall coverage ratchet, or the 95% changed-file target to make CI pass. Raise the overall ratchet as tests move the project toward 95% total coverage.
- Update public help, README, and CHANGELOG entries when behavior or interfaces change.

## Local validation

```powershell
Install-Module Pester -Scope CurrentUser -RequiredVersion 6.0.1 -Force -SkipPublisherCheck
Install-Module PSScriptAnalyzer -Scope CurrentUser -RequiredVersion 1.25.0 -Force

.\tests\Invoke-NetCleanAnalyzer.ps1

Invoke-Pester -Path .\tests
.\tests\Run-NetClean-Coverage.ps1
```

The repository's registry System tests are safe for normal local and CI runs: Pester creates a random, container-scoped `TestRegistry:` key under HKCU, and the suite populates it only with synthetic data. Run tests that change real adapters, Wi-Fi state, caches, event logs, or restart behavior only on a disposable Windows system you control. Never commit generated test results, coverage reports, logs, exported registry data, Wi-Fi profiles, credentials, or other machine inventory.

## Pull request checklist

- [ ] A focused test demonstrated the defect or missing behavior before the implementation change.
- [ ] Pester 6.0.1 tests pass locally.
- [ ] PSScriptAnalyzer reports no warnings or errors.
- [ ] Documentation and change notes match the implementation.
- [ ] No generated output, secrets, credentials, or host-specific inventory is included.

Contributions are licensed under the repository's GPLv3 license.
