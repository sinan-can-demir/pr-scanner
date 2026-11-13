# Branch protection for this repository

`SCANNER-TAMPER` flags a change that disables, replaces or weakens the scanner, but a flag is only a
warning to a maintainer. These settings make it binding: no change merges without passing the scan (the owner
included), and the scan result itself cannot be faked by another app.

## Settings for `main` (solo maintainer, applied 2026-11-09)

| Setting | Value | Why |
|---|---|---|
| Require a pull request before merging | on, **0 approvals** | every change goes through a PR and its scan; see "Why 0 approvals" |
| Require review from Code Owners | off while solo | the only code owner is the author, who cannot approve their own PR |
| Dismiss stale approvals on new commits | on | takes effect once approvals are required again (T-S13) |
| Require status checks | `PR scanner` and `tests`, **both pinned to the GitHub Actions app (id 15368)** | another app or a hand-made status cannot satisfy it |
| Require branches to be up to date | off | avoids needless re-scans for a small project |
| Block force pushes, block deletion | on | history cannot be rewritten to hide a change |
| Include administrators (`enforce_admins`) | **on** | nobody, the owner included, can merge past the scan |

Only **"PR scanner"** and **"tests"** should be required. `tests` is the job in `.github/workflows/tests.yml`, which runs on every pull request (no path filters), so it cannot hang a PR; if that workflow ever gets path filters, a skipped required check would block merging. The job-level checks `scan` and `report` also appear on each PR
and are implementation details.

## Why 0 approvals while solo

GitHub never lets you approve your own pull request. The first setup (1 code-owner approval, admins may
bypass) could never be satisfied by the only maintainer, so every merge used the admin override, and **the
override skips every rule, including the required scan**. Requiring no approval but enforcing the rules on
admins makes the scan binding for everyone, which is the point of this repository.

Trade-off: if the scanner itself cannot run (for example GitHub's `pull_request_target` brownout on
2026-11-09), nothing can merge. Turning `enforce_admins` off for that one merge is a deliberate, visible
step in Settings > Branches; turn it back on afterwards.

When a second maintainer exists: set approvals to 1, turn Code Owner review back on, and add them to
`CODEOWNERS` in the same change.

## Applying it

```bash
gh api -X PUT repos/OWNER/REPO/branches/main/protection --input - <<'JSON'
{
  "required_status_checks": {"strict": false, "checks": [{"context": "PR scanner", "app_id": 15368}, {"context": "tests", "app_id": 15368}]},
  "enforce_admins": true,
  "required_pull_request_reviews": {
    "required_approving_review_count": 0,
    "require_code_owner_reviews": false,
    "dismiss_stale_reviews": true
  },
  "restrictions": null,
  "allow_force_pushes": false,
  "allow_deletions": false
}
JSON
```

Read it back with `gh api repos/OWNER/REPO/branches/main/protection`. The required check only exists on
repositories that run `.github/workflows/pr-scan.yml`, and a pull request must have run it once for the name
to appear in the UI picker (the API accepts the name regardless).

## Actions policy for `pull_request_target`

GitHub blocks `pull_request_target` in public repositories by default from **2026-12-02**. A brownout on 2026-11-09 made scans fail at startup (`startup_failure`; such runs cannot be re-run, only a new push or reopen starts one). This repository has an Actions policy (Settings > Actions > Policies, id 12534) that allows only `pull_request_target`, only for `.github/workflows/pr-scan.yml`. Every repository that copies the workflow needs the same policy. **Not yet confirmed** that the path format matches and that it suppresses the default block: check the first PR scan after 2026-12-02.

## Known limits

* Until a suppression flow (FR-11) exists, every legitimate edit to the scanner workflow, `.pr-scanner.yml`
  or `CODEOWNERS` shows a warning or block that an owner has to approve by hand.
* CODEOWNERS only protects paths it lists. Keep the catch-all first and every line on the same owner;
  `tests/test_codeowners.py` enforces that.
* Forks and organisations can have rulesets that override or stack with these settings; check them if a
  merge behaves unexpectedly.
