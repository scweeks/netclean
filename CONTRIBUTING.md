# Contributing

Contributions should be small, focused, and based on the latest `main` branch unless a maintainer specifies another base.

## Engineering expectations

- Use red-green-refactor: add or correct a focused Pester v5 test, observe the intended failure, apply the smallest production change, then refactor with the suite green.
- Preserve dry-run, `ShouldProcess`, protected-artifact, and backup behavior for state-changing operations.
- Keep functions compact and single-purpose; isolate native commands and filesystem/registry access behind testable helpers.
- Do not weaken security checks, analyzer rules, test assertions, or the 95% coverage threshold to make CI pass.
- Update public help, README, and CHANGELOG entries when behavior or interfaces change.

## Local validation

```powershell
Install-Module Pester -Scope CurrentUser -MinimumVersion 5.0.0 -MaximumVersion 5.999.999 -Force -SkipPublisherCheck
Install-Module PSScriptAnalyzer -Scope CurrentUser -Force

$settings = Join-Path $PWD 'PSScriptAnalyzerSettings.psd1'
$paths = @('.\NetClean.ps1', '.\NetClean.psd1', '.\Modules', '.\tests')
foreach ($path in $paths) {
    Invoke-ScriptAnalyzer -Path $path -Recurse -Settings $settings
}

Invoke-Pester -Path .\tests
.\tests\Run-NetClean-Coverage.ps1
```

Run state-changing manual tests only on a disposable Windows system you control. Never commit generated test results, coverage reports, logs, exported registry data, Wi-Fi profiles, credentials, or other machine inventory.

## Pull request checklist

- [ ] A focused test demonstrated the defect or missing behavior before the implementation change.
- [ ] Pester v5 tests pass locally.
- [ ] PSScriptAnalyzer reports no warnings or errors.
- [ ] Documentation and change notes match the implementation.
- [ ] No generated output, secrets, credentials, or host-specific inventory is included.

Contributions are licensed under the repository's GPLv3 license.
