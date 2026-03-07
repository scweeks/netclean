Title: Add documentation, CI check, examples, and .gitignore

Description
-----------
This PR gathers several documentation and developer-experience improvements:

- Adds a polished `README.md` with usage, backup/restore instructions, and examples.
- Adds `CHANGELOG.md` and `CONTRIBUTING.md` to document project workflow and contribution expectations.
- Adds a GitHub Actions workflow at `.github/workflows/powershell-check.yml` that runs `PSScriptAnalyzer` and performs a safe `-DryRun` of the example wrapper.
- Adds example scripts in `examples/`:
  - `run-netclean.ps1` - wrapper to run the tool non-interactively (dry-run support)
  - `restore-wifi-profiles.ps1` - imports exported Wi‑Fi profile XMLs
  - `register-scheduledtask.ps1` - idempotent scheduled task registration example
- Adds a repository `.gitignore` to exclude local AI/chat artifacts and assistant session files.
- Adds a PR template to guide future contributors.

Files changed in this branch
----------------------------
- README.md (updated)
- CHANGELOG.md (new)
- CONTRIBUTING.md (new)
- .github/workflows/powershell-check.yml (new)
- .github/PULL_REQUEST_TEMPLATE.md (new)
- examples/register-scheduledtask.ps1 (new)
- examples/run-netclean.ps1 (existing or new)
- examples/restore-wifi-profiles.ps1 (existing or new)
- .gitignore (new)

Testing and verification
------------------------
1. `PSScriptAnalyzer` should run clean or report warnings; run locally with:

```powershell
Install-Module -Name PSScriptAnalyzer -Scope CurrentUser -Force
Invoke-ScriptAnalyzer -Path . -Recurse
```

2. Validate example wrapper dry-run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\examples\run-netclean.ps1 -DryRun
```

3. Review generated logs/backups when running actual script flows (outside CI).

Merge instructions and notes (recommended):
---------------------------------------
1. Review the PR in the GitHub UI and confirm CI passes (`PSScriptAnalyzer` + dry-run).  
2. Merge via the GitHub UI (choose "Create a merge commit" or "Squash and merge" — for documentation-only PRs either is fine).  
3. After merge, ensure the remote does not track local AI/chat artifacts. If the repository has tracked files under `.ai/` (for example `.ai/Database/db.sqlite`), remove them in a follow-up PR that:
   - Removes tracked AI files: `git rm --cached .ai/Database/db.sqlite` (or the specific tracked paths).  
   - Adds `.ai/` or appropriate patterns to `.gitignore` (already added in this PR).  
   - Commit and merge the follow-up PR; this will ensure those files are no longer tracked and won't cause local pull/update failures.

Notes about the locked `.ai/Database/db.sqlite` (if present)
--------------------------------------------------------
- If you see "unlink failed" or similar errors during local `git pull`/`rebase`, it's usually because that file is open by a running process. Close editor windows or assistant background processes that may hold that file, or remove it from tracking via `git rm --cached` before pulling.  
- Optionally, if you prefer, I can prepare and push a separate branch that removes tracked `.ai` files and commits the `.gitignore` change; please confirm and I'll create that follow-up branch and PR text.

Maintainer checklist
--------------------
- [ ] Review changes.
- [ ] Confirm CI passes on PR branch (`docs/add-docs-temp`).
- [ ] Merge PR via GitHub UI.
- [ ] If necessary, remove tracked `.ai` files in a follow-up PR as described above.

