# Progress log

## Session 3: reporter and incomplete-fetch wiring

**Bug class found while building `report_io`:** Python's `$` also matches before a trailing newline, so `head_sha + "\n"`, `"owner/repo\n"` and a title with a trailing newline passed validation. Fixed with `\Z` in the fetcher, reporter, report validator and classifier; regression tests added. Two remaining `$` uses run on single, already-split lines.

**Design change (ADR-0005, Proposed):** the earlier plan (`pull_request` plus a `workflow_run` reporter) lets a PR edit the scan workflow and forge the artifact the privileged job trusts. The new plan runs the workflow from the base branch via `pull_request_target`, which is safe only because we never check out or run PR code.

`Engine.scan(..., input_incomplete=fetched.notes)` makes a partial fetch INCOMPLETE. `reporter.build_report` renders verdict, findings and annotations with all PR-derived text escaped (code spans with adaptive fences, hidden/bidi characters shown as markers, no mentions/links/references, no forged headings), caps annotations at 50 and the summary at 65535 bytes, and says when anything was omitted. Tests: 480 default (+135), including a hypothesis property test over arbitrary text.

**First run against real GitHub (2026-11-09):** `scan` on two public `octocat/Hello-World` PRs (fork heads, 1 file each) returned PASS; a deliberately wrong head SHA returned an ERROR report. This is the first real-API exercise of the fetcher, but both PRs were trivial, so it proves the plumbing, not detection quality. The compare endpoint's huge-PR fallback and the 406/413/422 refusal codes are still unexercised.

**Second token-truncation fix:** error text from GitHub is cut at 200 characters, which could leave a prefix of an echoed token that no later scrub recognises. Both clients now remove the token from the body before truncating (tests straddle the cut).

**Workflow notes:** our own scanner reads our workflow as WARN (`CI-PRT` Medium for the `pull_request_target` trigger, `CI-PERMS` Low for `checks: write`), both expected and explained in the file's header; a suppression flow (FR-11) will be needed before this repo can require its own check without a standing warning. The pinned scanner SHA must be bumped by hand after pushing newer code, otherwise the Action runs old code. Check name for branch protection: "PR scanner". Pushed to origin/main on 2026-11-09 (commits up to `0360d1a`).

## Session 2: GitHub fetcher

Added `GitHubClient` (GET-only, token only in the Authorization header and redacted from repr/errors, no redirects, byte-capped reads, bounded retries, rate limits fail closed, remote error text sanitised) and `fetch_pull_request` (PR metadata, then diff by immutable `base...head` SHAs, fills `new_content` for CI workflows from the head repo, falls back to the paged compare file listing for huge PRs without ever splicing attacker filenames into diff text). Tests: 345 default (+75), including a fetcher-to-engine test showing workflow context lifts `CI-PRT` from Medium to Critical.

## Session 1: 2026-11-02

### Where we are
Phase 0 (documentation foundation) is complete. Phase 1 (rule engine and first rules) is about two-thirds done. Nothing runs against a real GitHub PR yet; everything is exercised through tests and a local corpus.

| Area | State |
|---|---|
| Requirements, actors, use cases, threat model, architecture, domain model, test strategy, traceability | Done (`docs/00`-`08`), updated with the owner's real incident |
| ADRs | 0001 records, 0002 language (Python, **provisional**), 0003 rules-first / LLM optional, 0004 never execute PR code |
| Domain models, verdict policy | Done, property-tested |
| Rule engine | Done. Fail-safe: errors and partial scans never pass; limits on files, bytes, time, line length |
| Diff parser, path classifier | Done, hardened against hostile diffs, fuzzed |
| Rules | 10 rules (see `docs/rules.md`) |
| Corpus | 27 malicious (all detected), 27 benign (0 blocked, 5 warned by design) |
| Tests | 270 default + 22 slow performance tests (`pytest -m perf`) |
| GitHub fetcher | Done (session 2): `github_client.py`, `fetcher.py`; tested with fakes and a local server, **never run against real GitHub** |
| Reporter | Done (session 3): `reporter.py`, pure `build_report(ScanResult)` to check-run payload; **never posted to GitHub yet** |
| Action wrapper | In progress (session 3): ADR-0005 (trust model, Accepted) , `report_io.py` (artifact validation) `python -m pr_scanner scan`, `publisher.py` (single-endpoint check-run writer) and `python -m pr_scanner report` (reads the artifact as untrusted, falls back to a fixed failing check) done; `.github/workflows/pr-scan.yml` written (scanner pinned to commit `0360d1a`, actions pinned by SHA, 18 property tests guard the trust model); **a real end-to-end run in GitHub Actions has not happened yet** |

### Rules implemented
`HOOK-NPM`, `HOOK-PYSETUP`, `HOOK-PYBACKEND` (install hooks, FR-04) | `EXEC-DROPPER` (remote binary dropper, CI-aware, FR-20/21) | `CI-PRT`, `CI-UNPINNED`, `CI-PERMS`, `CI-SECRETS`, `CI-PIPE-SH`, `CI-INJECT` (CI workflows, FR-05).

### The reported incident
A real attack the owner stopped shaped two additions (descriptions are approximate and should be refined):
- **T-D15 / T-S14 / FR-18 / FR-19**: the author disputed the review and a second, newly created account backed them up. Design stance: a finding can never be cleared by comments or approvals, only by a code fix or a recorded suppression. Rule for sock-puppet signals (FR-18) is **not yet built**.
- **T-D16 / T-D17 / FR-20 / FR-21**: a process spawner that behaved differently under CI and installed a binary from a remote server. Covered by `EXEC-DROPPER`.

### Bugs found and fixed along the way (worth remembering)
1. `||` was matched as a pipe, which made `prebuild-install || node-gyp rebuild` look malicious.
2. Rules truncated lines at 4,000 characters, so padding hid payloads. Now whole lines are scanned; the engine truncates at 1,000,000 characters and marks the scan `INCOMPLETE`.
3. Five regexes were super-linear on hostile lines (found by the performance suite). Fixed with single-pass algorithms, not length bounds.
4. A fingerprint crash on lone surrogate characters.

### Known gaps and risks
- **Fetcher unverified against the real API.** Tests use fakes and a local HTTP server. Assumptions to confirm against live GitHub: compare endpoint honours `page`/`per_page` and the `application/vnd.github.diff` media type; the head repo of a fork PR serves the head SHA via the contents API; refusal status codes for huge diffs (406/413/422). Record real responses as fixtures once a token is available.
- ~~`FetchResult.incomplete` not wired into the engine~~ done: `Engine.scan(..., input_incomplete=fetched.notes)` makes the verdict INCOMPLETE (never PASS, never hides a BLOCK). The Action wrapper must remember to pass `fetched.notes`.
- **Fetcher residual risks:** reading is pinned to SHAs, but the PR base can move after metadata is read (diff is still self-consistent); no ETag/caching; rate-limit failures abort the scan rather than waiting.
- **Corpus bias.** The corpus was written together with the rules, so 100% recall is a sanity check, not evidence. Need real defanged samples, an independently written adversarial set, and a larger sample of real benign PRs before trusting the metrics in `docs/00`.
- **Dropper blind spots.** Signals in different files are not correlated; dynamic lookups (`getattr`, string building) are not seen; legitimate prebuilt-binary installers (esbuild/puppeteer style) will block until suppressed.
- **Time budget is not preemptive** (checked between rules only). A hard per-rule timeout in a worker is planned for Phase 2 (T-S03).
- **CI must run `pytest -m perf`**; it is excluded from the default run because it takes about 2 minutes.
- Reporter verified against real GitHub (2026-11-09, throwaway fork `sinan-can-demir/Hello-World`, App `pr-scanner-sandbox` with Checks:write only): a check run was accepted (201) with 27 annotations read back, and the summary posted as a real issue comment rendered with only `code h2 li p strong ul`, zero links, mentions, issue refs, hidden characters or timeline cross-references, after one fix: bare 7-40 hex runs in prose autolinked to commits (now wrapped; regression test added). Positive controls confirmed mentions, URLs, `#n`, `GH-n`, `owner/repo#n` and SHAs do link when unescaped. **Still unchecked:** how the Checks tab itself displays the summary and annotations (only the API was read), and that annotation paths which do not exist in the PR display sensibly.
- Annotation paths are shown as-is when they pass `_safe_path` (so a PR file legitimately named `<!-- x -->` is annotated). GitHub accepted it; confirm visually it does not render as HTML.
- Conclusions: WARN is `neutral` (passes required checks), INCOMPLETE is `action_required`, BLOCK/ERROR are `failure`. The owner should confirm WARN and INCOMPLETE mapping.
- Success-metric targets in `docs/00` are provisional; set them from a measured baseline.

### Suggested next steps (in order)
1. ~~GitHub fetcher~~ done; ~~wire `FetchResult.incomplete` into the engine~~ done.
2. ~~Reporter~~ done (payload only). Still to do: the API call that posts it (`POST /check-runs`, batching annotations 50 at a time, needs `checks: write` in the privileged job).
3. GitHub Action wrapper per ADR-0005 (`pull_request_target`, two jobs, untrusted artifact). Done: `report_io`, `scan` command (token from env only, always passes `fetched.notes`, every failure becomes an ERROR report, exit 0 whenever a report is written, 2 for usage problems). Also done: `publisher.py` and the `report` command (symlink/non-regular/oversize files refused, event SHA wins over the file, no blind retry on POST). Workflow done. Next: a rehearsal inside GitHub Actions on the throwaway fork using the built-in `GITHUB_TOKEN` (the sandbox App key was deleted; not needed).
4. Dropper cross-file correlation.
5. Obfuscation rules (FR-06) and dependency rules (FR-07); scanner-config tampering (T-D12 / FR-12).
6. Sock-puppet signal (FR-18) and suppression flow (FR-11).
7. Confirm or change the language decision (ADR-0002) before Phase 2.

### Open questions for the owner
- More details on the original incident (language, how it detected CI, where the binary was put, how it was hidden) so fixtures can be made faithful.
- Which ecosystems after npm and PyPI (Go, Rust, Maven)?
- Final language decision (ADR-0002 is provisional).

### How to resume
```
cd pr_scanner
python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'
.venv/bin/python -m pytest                       # 270 tests
.venv/bin/python -m pytest -m perf               # adversarial performance, slow
.venv/bin/python -m pr_scanner.corpus corpus     # recall / false-positive report
```
Corpus fixtures were generated by a throwaway script that is not in the repo; edit the `corpus/*/*/diff.patch` and `meta.json` files directly from now on (or re-create a generator if many cases are needed).
