# Progress log

Last updated: 2026-11-10, session 5. Resume here.

## Where we are

Runs end to end as a GitHub Action: live on this repository, rehearsed on a throwaway fork. 12 rules, 869 default tests plus 29 `perf`-marked tests (`pytest -m perf`, about 2.5 minutes). Everything is Python standard library only.

| Area | State |
|---|---|
| Docs, threat model, ADRs 0001-0005 | Done and current. ADR-0002 (Python) is still **provisional**. |
| Engine, policy, diff parser, classifier | Done. Fail-safe: errors and partial scans never pass. Caps: 1000 files, 5 MiB added, 1,000,000 chars per line, 60 s. |
| Rules (12) | `EXEC-OBFUSCATED` (new, see `docs/recall-real-attacks.md`), `HOOK-NPM`, `HOOK-PYSETUP`, `HOOK-PYBACKEND`, `EXEC-DROPPER`, `CI-PRT`, `CI-UNPINNED`, `CI-PERMS`, `CI-SECRETS`, `CI-PIPE-SH`, `CI-INJECT`, `SCANNER-TAMPER`. See `docs/rules.md`. |
| In-repo corpus | 28 malicious, 28 benign. Written with the rules, so 100% recall is a sanity check, not evidence. Two cases are real diffs. |
| Fetcher | Done, GET-only. Exercised on 800 real PRs. |
| Reporter, `report_io`, `publisher`, `cli` | Done. Escaping verified against GitHub's real renderer. Trust model in ADR-0005. |
| Action workflow | `.github/workflows/pr-scan.yml`: `pull_request_target`, two jobs, scanner pinned by SHA (currently `4963b36`, main after #7: includes the `EXEC-DROPPER` bundle fix). 18 property tests guard it. |
| Protection of this repo | Branch protection and CODEOWNERS applied (`docs/branch-protection.md`). Since 2026-11-09: 0 approvals, `PR scanner` required, **enforced on admins**, so no merge skips the scan. |
| Real-world runner | `python -m pr_scanner.realworld`, plus data in `realworld/`. |
| CI | `.github/workflows/tests.yml` runs the default suite on every PR and push to `main`, `pytest -m perf` weekly and on demand. Packages pinned by hash. 12 property tests guard it. **Not yet a required check.** |
| Merged 2026-11-09 | #4 (CI), #5 (`EXEC-DROPPER` bundle fix), #6 (real-world runner, plus two resume and summary fixes found in review), #7 (this data and docs). #3 was closed and split into #5-#7 for review (16k lines, 92% JSON). |

## Verified on real systems (2026-11-09)
- **Fetcher and engine** on 800 recent merged PRs from 32 public repos (14,421 files, 0 fetch errors).
- **Reporter** against GitHub's Markdown renderer (mentions, links, issue and commit references, HTML and hidden characters all inert after one fix) and a real check run with 27 annotations.
- **Action** in GitHub Actions on a fork (benign PASS, malicious BLOCK, workflow-tamper BLOCK after `SCANNER-TAMPER`) and on this repo (PR #1 and #2 passed the scan and were held by the code-owner gate).
- **Trust claim:** a PR that rewrites the scan step cannot disable the scan; the base-branch workflow ran and the forged step never did.

## Real-world measurement (800 PRs, scanner at `3a676cf`)
Data and hand labels: `realworld/`. All PRs are benign, so this measures false positives and noise only.

| Outcome | PRs | Rate | 95% CI |
|---|---|---|---|
| Pass | 757 | 94.6% | 92.8 to 96.0% |
| Warn | 16 | 2.0% | 1.2 to 3.2% |
| Block | 15 | 1.9% | 1.1 to 3.1% |
| Incomplete | 12 | 1.5% | 0.9 to 2.6% |

Of the 15 blocks, **14 were false positives** (about 1.75%, CI 1.0 to 2.9%): 12 were `EXEC-DROPPER` on compiled JS-action bundles, 1 was `CI-INJECT` on a `concurrency.group` key, 1 was `CI-SECRETS` on `GITHUB_TOKEN` sent to `api.github.com`. One was rule-correct (`@master` action). The NFR-03 gate (blocked-benign at most 2%) is **not demonstrated**, and the sample over-represents Actions repos (12 of the 14 come from 5 repos that commit bundles). Warn noise is mostly `id-token: write` (9 of 16) and routine CODEOWNERS edits (4).

After the bundle fix (`0e55018`, local), a re-scan of the 27 flagged PRs: the 12 bundle blocks no longer block (`EXEC-DROPPER` is LOW) but become INCOMPLETE because those bundles add 5 to 11 MiB, over the engine's 5 MiB cap. **Do not quote the 1.9% as current**, and do not reuse this sample as independent evidence for `EXEC-DROPPER`.

## Fresh real-world sample (684 PRs from 35 new repos, 2026-11-10, scanner at `e95f51e`)
Data and hand labels: `realworld/*-2026-11-10.json`. None of these repos were in the first sample, and no rule was tuned on them. All PRs are presumed benign, so this measures false positives and noise only, **not recall**. Evidence snippets are not stored. Chosen to cover what the first sample lacked: `setup.py`/packaging, autotools and C (xz, libuv), shell (nvm, pyenv, ohmyzsh, Homebrew), install-script and bundle-heavy JS.

| Outcome | PRs | Rate | 95% CI |
|---|---|---|---|
| Pass | 646 | 94.4% | 92.5 to 95.9% |
| Warn | 16 | 2.3% | 1.4 to 3.8% |
| Block | 3 | 0.4% | 0.2 to 1.3% |
| Incomplete | 19 | 2.8% | 1.8 to 4.3% |

Of the 3 blocks, **2 are false positives** (0.29%, CI 0.08 to 1.1%), both `EXEC-DROPPER` High, in two different repos: a build script that downloads *source* tarballs, runs `configure`/`make` and `chmod +x`'s the libraries it built (psycopg2), and a test that spawns `pnpm next dev` and `fetch()`es the local server (tailwindcss). The third (`actions/download-artifact@main` in upload-artifact's own tests) is rule-correct. **NFR-03 (blocked-benign at most 2%) holds on this sample**, with the first sample's caveat: it is presumed-benign merged PRs from well-known projects, and the upper CI bound (1.1%) is still below 2%, but the sample is not a random draw of all PRs.

- **Warns (16):** 10 are `CI-UNPINNED` Medium on tag-pinned `pypa/cibuildwheel` or `docker/setup-qemu-action` in version-bump PRs (new noise class, 2 repos), 5 are `id-token: write` or a CODEOWNERS edit (already in the backlog), 1 is a `pull_request_target` gated on a label (worth a look).
- **Incomplete (19):** 14 compiled bundles (3.9 to 8.8 MB, `dist/index.cjs`, all from `docker/*` and `actions/*` repos), 1 PR with 1,855 files (over the 1000-file cap), 4 old PRs whose head repository is gone (sampling artifact). The runner does not record *why* a scan was incomplete; checked on one 3.9 MB bundle: incomplete with and without `EXEC-OBFUSCATED`.
- **`EXEC-OBFUSCATED`:** 10 hits, all LOW on `docker/*` `dist/index.cjs` bundles, so **no change to any outcome and 0 hits on any non-bundle file**. It adds about 50% to scan time on bundles (4.6 s to 7.1 s on a 3.9 MB one), far inside the 60 s budget.
- **Transport:** 6 PRs first failed with `URLError` (a flaky connection mid-run) and were re-run once; they are counted with their re-run result.
- **Validation of the package-manager-spawn fix (`d5337cd`), 543 PRs from 28 further new repos:** 537 pass, 6 warn (4 tag-pinned actions, 2 `contents: write` in release jobs), 0 block, 0 incomplete, 0 error (95% upper bound for blocks about 0.7%). No `EXEC-DROPPER` finding at all, so this shows no new false positives but **cannot show the exemption mattered**; a before/after scan with `main`'s code would. Data: `realworld/*-2026-11-10-validation.json`.
- **Limits of this evidence:** 10 of the 14 bundle PRs come from 3 related repos, so bundle numbers are not independent draws; 1 reviewer labelled everything and also wrote the rules.

## Backlog
Priority: **P1** do next, **P2** soon, **P3** later or if wanted.

### A. Detection quality (found by the real-world run)
- **P1 `CI-INJECT` on non-script contexts.** Fires on `concurrency.group: ${{ ... github.head_ref ... }}`. Only flag expansion inside `run:` and `github-script` `script:`.
- **P1 `CI-SECRETS` false positives.** `${{ secrets.GITHUB_TOKEN}}` (no space before `}}`) sent to `api.github.com` is flagged HIGH; recognise the spelling and the host. Secrets to a third-party API (PagerDuty) stay HIGH or drop to MEDIUM: decide.
- **P2 `SCANNER-TAMPER` on CODEOWNERS.** Warn only on removals and on additions that can take over (a catch-all line, `.github/`, scanner paths); last matching pattern wins, so those are the dangerous ones.
- **P2 `CI-PERMS` on `id-token: write`.** The recommended OIDC publishing setup; LOW when it is the only signal.
- **P3 `CI-UNPINNED`.** `slsa-github-generator` must be referenced by tag; consider a documented exception. Tag pins of first-party actions are already LOW.
- **P1 `EXEC-DROPPER` false positives found in the fresh sample (2 of 3 blocks).** (a) **Done 2026-11-10:** a test that spawns a dev server (`spawn('pnpm next dev')`) and `fetch()`es it no longer counts the spawn (narrow package-manager exemption, see `docs/rules.md`); the tailwindcss PR now passes. A "localhost URL" rule was considered and dropped: the URL there is read from the server's stdout, so it never appears as a literal. (b) **Open:** a build script that downloads *source*, runs `configure`/`make` and `chmod +x`'s libraries it built (psycopg2#1755 still blocks). Options: count `chmod` only when its target is a path the script downloaded (my lean), or cap the combination at MEDIUM when `configure`/`make` is present. Needs tests first and validation on repos not yet used.
- **P2 `CI-UNPINNED` Medium on tag-pinned third-party actions** is now 10 of 16 warns in the fresh sample (cibuildwheel bumps). Consider LOW for well-known publishers or when the PR only changes the version string.
- **P2 `EXEC-DROPPER` matches shell tool names as identifiers.** `\bcurl\b` and `\bwget\b` fire on a Python variable named `curl`; in non-shell source, require a call or string context. Found when our own scan flagged `curl = snippet(...)` in a test.
- **P2 `EXEC-DROPPER` limits.** More than 100k code chars of real-looking code between two signals in one new file reduces to LOW (pinned by a test). No cross-file correlation. No "dist changed but source did not" signal. Legitimate binary installers (esbuild, puppeteer, sharp style) are untested: the sample's recent PRs never touched install scripts.
- **P3 Other rule gaps** (`docs/rules.md`): YAML folded scalars, removed `permissions:` blocks, `format()` taint, dynamic lookups, hand-written reports through unusual tools.

### B. Engine and fetcher limits
- **P1 5 MiB added-bytes cap makes bundle PRs INCOMPLETE** (12 of 800). `EXEC-DROPPER` costs about 2.5 s per MB. Plan: optimise the per-line regex pass first (cheap keyword pre-filter), then raise the cap to about 16 MiB inside the 60 s budget. Needs the NFR-02 numbers rechecked.
- **P2 Workflow-context read limit of 50** leaves codeql-action-style PRs INCOMPLETE (6 of 800). Raise, or read only what the rules need.
- **P2 File-count check is two-sided.** Renames appear as delete plus add, so the diff has more files than `changed_files` (Django #22222). Extra files in the diff are not truncation: make the check one-sided.
- **P3 Deleted fork heads** make old merged PRs INCOMPLETE. A sampling artifact; live PRs are unaffected.
- **P2 Time budget is not preemptive** (checked between rules). Planned: per-rule timeout in a worker (T-S03).
- **P3** Huge-PR fallback and the 406/413/422 refusal codes are not confirmed on the real API (the 800-PR run included PRs with thousands of files, but which path they took was not recorded). No ETag or caching. A rate limit aborts instead of waiting. The PR base can move after metadata is read (the diff stays self-consistent).

### C. Action, reporting and operations
- **Done 2026-11-09: GitHub's default `pull_request_target` block.** GitHub will block `pull_request_target` in public repositories by default from **2026-12-02** (a brownout on 2026-11-09 gave `startup_failure` on PRs #3 and #4; failed-at-startup runs cannot be re-run, only a new push or reopen starts one). A repository Actions policy (id 12534, Settings > Actions > Policies) now allows only `pull_request_target`, only for `.github/workflows/pr-scan.yml`. **Not yet confirmed** that the path format matches and that it suppresses the default block: check the first PR scan after 2026-12-02. Adopter docs must tell every adopter to create the same policy.
- **P2 Our own scan flags our own tests.** Attack-like literals in Python test files are, to the scanner, attack-like code; PR #3 was blocked on its first scan. Fixed for the new code by `tests/fixtures/snippets.txt` (data files are not read by `EXEC-DROPPER`); `tests/test_snippets.py` keeps listed files clean when scanned whole. Still inline, so edits near those lines will be flagged: `test_cli.py`, `test_rules_hooks.py`, the older half of `test_rules_dropper.py`, and `src/pr_scanner/rules/dropper.py` (its own regexes). Tests are never exempt from scanning: CI runs them.
- **P1 Make `tests` a required status check** (CI exists since #4; branch protection change, ask first). Pin it to the GitHub Actions app like `PR scanner`.
- **Keep PRs reviewable.** Merge with a plain `gh pr merge N --squash` once the scan passes (`--admin` is blocked, see branch protection). Split by concern, keep generated data separate and mark it `linguist-generated` (`.gitattributes`), and open each PR with a "where to look" guide.
- **P3 Delete merged branches** on GitHub: `ci/run-tests`, `rules/dropper-proximity`, `realworld/runner`, `realworld/data-and-docs`, and `corpus/realworld-runner` (closed #3, kept as a backup). Ask first.
- **P2 Fresh real-world sample** after the next rule fixes (the current one is no longer independent for tuned rules).
- **P2 Visual check of the Checks tab.** Only the API was read. Confirm the summary renders, the `<!-- x -->` annotation path shows as text, and `neutral` (WARN) and `action_required` (INCOMPLETE) look right.
- **P2 Confirm the conclusion mapping:** WARN is `neutral` (passes required checks), INCOMPLETE is `action_required`, BLOCK and ERROR are `failure`.
- **P2 Untested in Actions:** a PR from another account's fork, a genuinely incomplete scan, the missing-artifact fallback, the `report` job after a crashed `scan`.
- **P2 Pin bumps are manual** and a stale pin means the Action runs old code. The bump PR is scanned by the old scanner. Consider a reminder or a check that compares the pin with `main`.
- **P2 Standing warnings** on edits to the scanner workflow, `.pr-scanner.yml` or CODEOWNERS until a suppression flow (FR-11) exists.
- **P3 Package the Action** (composite or Docker, versioned releases, adopter docs) so other repos do not copy the workflow. Later a GitHub App for org-wide installs and an audit store (FR-15).
- **P3 Protection:** when a second maintainer exists, set approvals to 1, turn Code Owner review back on, and add them to CODEOWNERS. Guard the owner account (passkey, no stray `repo` tokens). Check that private vulnerability reporting (SECURITY.md) is switched on.

### D. Features not built
- Suppression flow with authority and audit (FR-11, T-S07); config file read from the base branch (FR-12).
- **Sock-puppet signal (FR-18, from the owner's incident):** new or low-history accounts commenting or approving on a PR with open findings, wording as a signal not an accusation. Findings cannot be cleared by comments (FR-19, already stated in every report).
- Obfuscation rules (FR-06), dependency rules (FR-07: typosquats, new dependencies with install scripts, lockfile-only changes), exfiltration rules (FR-08), author-risk signals (FR-17).
- Optional LLM triage that can only raise severity (FR-13), redacted and opt-in (NFR-05).
- More ecosystems after npm and PyPI (Go, Rust, Maven): open question for the owner.

### E. Evidence still missing
- **Recall on real attacks is unmeasured.** Build a verified, defanged corpus from documented public incidents (candidates: event-stream, tj-actions/changed-files, Ultralytics, nx "s1ngularity", Shai-Hulud, xz). Verify every reference through the API before using it; store references and defanged excerpts, never live payloads.
- An independently authored adversarial set; targeted samples of install-script and workflow changes; a fresh benign sample per tuning round.
- More incident detail from the owner (language, how it detected CI, where the binary went, how it was hidden) so fixtures can be faithful.
- Success-metric targets in `docs/00` are provisional: now there is a baseline to set them from (about 1.75% false-positive block, 2% warn, 1.5% incomplete, all before tuning).
- Mutation testing, coverage numbers, static analysis (bandit/semgrep), dependency audit (none needed: no dependencies).

### F. Housekeeping (outside the repo)
- Throwaway fork `sinan-can-demir/Hello-World`: rehearsal PRs #2-#4 still open, scratch issue #1 with several comments, workflow on `master`. Delete or close when done.
- GitHub App `pr-scanner-sandbox` still exists (private key deleted). Delete it unless it is reused.
- The real-world sample and results were first written to a temporary scratch directory; copies are now in `realworld/` (stripped of evidence text).

## Bugs and lessons worth remembering
1. `||` was read as a pipe (`prebuild-install || node-gyp rebuild`). 2. Rules truncated lines at 4,000 chars, so padding hid payloads (fixed; padding must never help an attacker). 3. Five super-linear regexes (fixed with single-pass algorithms, not length bounds). 4. A fingerprint crash on lone surrogates.
5. **Python `$` also matches before a trailing newline**: `sha + "\n"` passed four validators. Use `\Z`.
6. **Token prefix survived truncation** of an echoed server error; scrub before truncating.
7. Bare 7-40 hex runs in prose autolink to commits on GitHub.
8. A blank added line chosen as evidence crashed a rule, and a rule crash turns the verdict into ERROR.
9. A new module was missing `if __name__ == "__main__"`; tests that call `main()` directly cannot see that. Test the real entry point.
10. The forged-report PR scanned clean until `SCANNER-TAMPER` existed.
11. Whole-file signal correlation fails on bundles; correlate by proximity, with distance in code characters.
12. Fixing a false positive can turn a block into an incomplete (the byte cap): re-scan real PRs after every fix, do not stop at the unit tests.

## Decisions and open questions for the owner
- Decided: rules first, LLM optional; never execute PR code; trust model ADR-0005 (base-branch workflow, two jobs, untrusted artifact); branch protection binding on everyone including the owner (0 approvals while solo, scan required, `enforce_admins` on); scanner pinned by commit SHA from this repo.
- Open: final language (ADR-0002); WARN as `neutral`; which ecosystems next; the original incident's details; whether and when to add a second maintainer; how to treat third-party-API secrets in `CI-SECRETS`.

## Session log
- **Session 1 (2026-11-02):** docs, threat model, engine, parser, 10 rules, corpus.
- **Session 2:** GitHub client and fetcher (fakes only).
- **Session 4 (2026-11-09, evening):** pushed PR #3, opened PR #4 (CI), then split #3 into #5-#7 for review; changed branch protection so the owner cannot skip the scan; reviewed and merged #4-#7 (two runner bugs fixed in review); diagnosed the `pull_request_target` brownout and added the Actions policy; moved attack-like test literals to a fixture file after our own scan blocked PR #3.
- **Session 3 (2026-11-09):** wired incomplete fetches into the verdict; reporter with escaping (verified on real GitHub); ADR-0005; `report_io`, `scan`, `report`, publisher; the workflow, rehearsed on a fork; `SCANNER-TAMPER` (found by the rehearsal); CODEOWNERS and branch protection; first real PRs through this repo; real-world runner and the 800-PR measurement; `EXEC-DROPPER` bundle fix; documentation refresh.

## How to resume
```
cd pr_scanner && git checkout main && git pull
python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'
.venv/bin/python -m pytest                                  # 852 tests
.venv/bin/python -m pytest -m perf                          # 24 slow tests, about 2.5 min
.venv/bin/python -m pr_scanner.corpus corpus                # in-repo corpus metrics
```
Suggested order: make `tests` a required check, fix `CI-INJECT` and `CI-SECRETS` in separate PRs (A), optimise `EXEC-DROPPER` and raise the byte cap (B), take a fresh real-world sample (new repos welcome), then start the real-attack corpus (E).
