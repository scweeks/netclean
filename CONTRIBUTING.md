# Contributing

Thanks for considering contributing to `netclean` — your help improves the tool for everyone.

Please follow these guidelines for a smooth collaboration:

- Fork the repository and open a feature branch from `main`.
- Keep commits small and focused; use clear commit messages.
- Run `PSScriptAnalyzer` locally and fix warnings where practical.

Suggested checks before opening a pull request:

```powershell
Install-Module -Name PSScriptAnalyzer -Scope CurrentUser -Force
Invoke-ScriptAnalyzer -Path . -Recurse
```

Pull request checklist

- [ ] Code changes include tests or verification steps (if applicable).
- [ ] README and CHANGELOG updated if behavior or interface changed.
- [ ] CI passes (GitHub Actions will lint and run safe dry-runs).

Code style and tests

- Use clear, descriptive names for functions and parameters.
- Keep scripts idempotent where possible and add checks for required privileges.

Reporting issues

- Use the repository's Issues to report bugs or request features. Provide reproduction steps and environment details.

License

By contributing you agree that your contributions will be licensed under the project's license.
