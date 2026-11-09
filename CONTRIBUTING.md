# Contributing

## Adding a rule
1. Identify the threat (`docs/04-threat-model.md`, T-D*) or add a new one.
2. Add **defanged** fixtures: at least one malicious and one benign (FR-16). Never commit live payloads, working endpoints or real credentials.
3. Write failing tests first, then the rule (pure function over a normalised diff).
4. Provide `rationale` and `remediation` text; findings without them fail schema tests.
5. Run the corpus metrics; recall/precision gates must hold (NFR-03). Prefer a real diff (e.g. from a rehearsal) over an imitation when you have one.
6. Update `docs/08-traceability-matrix.md`.

## Performance
Rules run on attacker-controlled text. Avoid regexes with unbounded repetition after a repeated token (`.*`, lazy `[^x]*?`), and do not restart a regex at every quote or bracket. Add a hostile payload to `tests/test_rules_perf.py` for any new pattern shape, and run `pytest -m perf`. Do not "fix" slowness by truncating lines: a payload hidden behind padding must still be found.

## Regular expressions for validation
In Python, `$` also matches just before a trailing newline, so `^[0-9a-f]{40}$` accepts `sha + "\n"`. This slipped through four validators once. Use `\Z` (or `fullmatch`) whenever a regex decides whether a value is acceptable, and add a test with a trailing newline.

## Secrets and logs
Never put a token in argv, a URL, a repr, a request body or an error message. When error text from a server is shown, remove the token from the raw body **before** truncating, otherwise a prefix of it can survive the cut. Tests straddle the cut on purpose.

## Changing the scanner workflow, CODEOWNERS or policy
`.github/`, `.pr-scanner.yml`, `src/pr_scanner/` and `docs/adr/` need owner approval (see `.github/CODEOWNERS`). The workflow pins the scanner by commit SHA; to upgrade it, merge the code first, then change the SHA in its own pull request and check by hand that the commit is on `main`. Never add a checkout of the pull request to a `pull_request_target` workflow; `tests/test_workflow_file.py` fails if one appears, and so does every property of ADR-0005 it guards. Expect `SCANNER-TAMPER` to warn on these edits until a suppression flow exists.

## Measuring on real pull requests
After rule changes, run `pr_scanner.realworld` on a fresh sample (see README). A merged PR from a well-known repository is only *presumed* benign: read every block and warn and label it before calling it a false positive. A sample you tuned a rule on is no longer independent evidence for that rule; say so in the write-up. A clean benign sample says nothing about recall.

## Ground rules
- No code path may execute or import PR-supplied data (ADR-0004).
- Pin dependencies and Actions by hash/SHA.
- Rule or policy changes need review from a second maintainer (enforced once a second owner exists; see `docs/branch-protection.md`).
- Modules that touch PR data or tokens must stay free of `subprocess`, `eval`, `exec`, dynamic import and `pickle`; `tests/test_cli.py` checks this statically.
- Record significant decisions as ADRs.
