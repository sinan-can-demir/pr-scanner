# Branch protection for this repository

`SCANNER-TAMPER` flags a change that disables, replaces or weakens the scanner, but a flag is only a
warning to a maintainer. These settings make it binding: no change to the scanner's workflow, policy or
ownership files merges without an owner, and the scan result itself cannot be bypassed by another app.

## Recommended settings for `main` (solo maintainer)

| Setting | Value | Why |
|---|---|---|
| Require a pull request before merging | on, **1 approval** | nothing reaches `main` unreviewed |
| Require review from Code Owners | on | `.github/CODEOWNERS` lists the workflow, policy and privileged code paths |
| Dismiss stale approvals on new commits | on | an approval must not survive a push (T-S13) |
| Require status checks | `PR scanner`, **pinned to the GitHub Actions app (id 15368)** | another app or a hand-made status cannot satisfy it |
| Require branches to be up to date | off | avoids needless re-scans for a small project |
| Block force pushes, block deletion | on | history cannot be rewritten to hide a change |
| Include administrators (`enforce_admins`) | **off** | see the trade-off below |

Only **"PR scanner"** should be required. The job-level checks `scan` and `report` also appear on each PR
and are implementation details.

## The trade-off you must choose

GitHub never lets you approve your own pull request. With one maintainer:

* **Admins can bypass (recommended while solo).** You can merge your own work with the admin override, and
  contributors are fully held to the rules. The protection is real for everyone except you, so guard your
  own account (hardware key or passkey, no token with `repo` scope lying around).
* **Admins cannot bypass.** Strongest, but you cannot merge your own pull requests until a second
  maintainer or account exists to approve them. Move here as soon as there is a second owner; add them to
  `CODEOWNERS` in the same change.

## Applying it

```bash
gh api -X PUT repos/OWNER/REPO/branches/main/protection --input - <<'JSON'
{
  "required_status_checks": {"strict": false, "checks": [{"context": "PR scanner", "app_id": 15368}]},
  "enforce_admins": false,
  "required_pull_request_reviews": {
    "required_approving_review_count": 1,
    "require_code_owner_reviews": true,
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

## Known limits

* Until a suppression flow (FR-11) exists, every legitimate edit to the scanner workflow, `.pr-scanner.yml`
  or `CODEOWNERS` shows a warning or block that an owner has to approve by hand.
* CODEOWNERS only protects paths it lists. Keep the catch-all first and every line on the same owner;
  `tests/test_codeowners.py` enforces that.
* Forks and organisations can have rulesets that override or stack with these settings; check them if a
  merge behaves unexpectedly.
