# Rule catalog

Each rule maps to a threat in [04](04-threat-model.md) and a requirement in [02](02-requirements.md), and must have malicious and benign corpus fixtures (FR-16, enforced by `tests/test_corpus.py`).

| Rule | Threat | Req | Looks at (added lines only) |
|---|---|---|---|
| `HOOK-NPM` | T-D01, T-D02, T-D07 | FR-04 | `package.json` lifecycle scripts |
| `HOOK-PYSETUP` | T-D01, T-D02 | FR-04 | `setup.py` |
| `HOOK-PYBACKEND` | T-D01 | FR-04 | `pyproject.toml` |
| `EXEC-DROPPER` | T-D16, T-D17 | FR-20, FR-21 | source files, build scripts, `setup.py` |
| `CI-PRT` | T-D03 | FR-05 | `.github/workflows/*`, `.github/actions/*/action.yml` |
| `CI-UNPINNED` | T-D03 | FR-05 | same |
| `CI-PERMS` | T-D03 | FR-05 | same |
| `CI-SECRETS` | T-D03, T-D07 | FR-05 | same |
| `CI-PIPE-SH` | T-D08 | FR-05 | all CI config files (GitHub, GitLab, CircleCI, Jenkins, ...) |
| `CI-INJECT` | T-D03 | FR-05 | GitHub workflows |
| `SCANNER-TAMPER` | T-D12, T-S06 | FR-12 | the scanner workflow, `.pr-scanner.yml`, `CODEOWNERS` (added, removed and renamed lines) |

## HOOK-NPM
Flags `preinstall`, `install`, `postinstall`, `prepare`, `preprepare`, `postprepare`, `prepublish` entries.

| Severity | When |
|---|---|
| Critical | command downloads/pipes to an interpreter, decodes a payload, runs inline code, uses a raw IP/URL, opens a socket, or touches credentials |
| High | hook runs a script file that is added or modified in the same PR |
| Medium | any other install-time hook (`preinstall`/`install`/`postinstall`) |
| Low | any other `prepare`-style hook |
| none | exact match of a small allowlist (`husky install`, `node-gyp rebuild`, `patch-package`, `tsc`, `npm run build`, ...) |

Evasions handled: JSON unicode-escaped keys (`"postinstall"`), shell quote/backslash splitting (`c""url`, `cu\rl`), `${IFS}` as a separator, single-line minified JSON. `||` is treated as logical OR, not a pipe.

Known limits: the hook key is matched on a single line, so a key and value split across lines are not seen; only added lines are inspected, so a malicious script that already existed is not re-reported; the key is not verified to be inside `"scripts"` (over-flags).

## HOOK-PYSETUP
| Severity | When |
|---|---|
| Critical | network access, or decode/deserialise of an embedded payload |
| High | `cmdclass` / subclassing `install`, `develop`, `egg_info`, `build_py`, `build_ext`, `sdist`, `bdist_wheel` |
| Medium | `exec`/`eval`/`compile`/`__import__`, `os.system`, `subprocess` |

Expected false positives: `exec(open("_version.py").read())` and `subprocess` calls to read a git version are common in legitimate `setup.py` files and produce a Medium (warn).

## HOOK-PYBACKEND
High when `build-backend` is not in a short list of well-known backends, or when `backend-path` (in-tree backend) is added. Changes to `requires` are not yet inspected.

## EXEC-DROPPER
Modelled on the reported incident: a process spawner that stayed quiet under CI and installed a binary from a remote server. Correlates signals across all added lines of **one file**; in a *large* added file (bundled or generated output) the signals must also be **close together**.

| Severity | When |
|---|---|
| Critical | download + (spawn or chmod), and either CI-gated or fetched from a raw IP |
| High | download + (spawn or chmod) |
| Medium | CI-environment check + process spawn, no download |
| Low | large added file with download and execution code that are far apart (typical of a compiled bundle); informational, does not change the verdict |
| none | any single signal alone; commented-out code; `regex.exec()` |

Signals: spawn (`subprocess`, `os.system`, `child_process`, `exec.Command`, `Runtime.exec`, `system()`...), download (`urlretrieve`, `requests.get`, `https.get`, `fetch(`, `http.Get`, `curl`, `wget`...), make-executable (`chmod +x`, `os.chmod`, `fs.chmodSync`...), CI check (`CI`, `GITHUB_ACTIONS`, `GITLAB_CI`, `TRAVIS`, `JENKINS_URL`, `is-ci`...).

**Large files (added in session 3, from measuring 800 real merged PRs).** A compiled bundle (for example a JS action's `dist/index.js`) concatenates many unrelated modules, so download code and process-spawn code co-occur by accident; 12 of 800 benign PRs were blocked for this reason. For a file with more than 100,000 added *code characters* the rule now needs the signals within 3,000 code characters of each other. The numbers come from the data: in 8 real bundles the nearest download/execute pair was 6,800 to 1,200,000 characters apart; in the 7 malicious fixtures it was 53 to 129. CI-gating and raw-IP escalation also have to be near the pair. Distance counts code characters only: whitespace, zero-width characters, comment lines and inline `/* */` comments are free, so padding with them cannot separate signals, and a file padded with whitespace still counts as small. Detection never strips comments, so a `"/*"` string cannot hide a call. Small files, which includes any dropper added to an existing file because a diff holds only added lines, keep whole-file correlation (a regression test pins this).

Known limits:
- A new or regenerated file with more than 100,000 code characters of *real-looking code* between two signals reports only LOW (pinned by `test_known_limit_code_padding_inside_a_large_file_separates_signals`). The LOW finding keeps it visible; it needs a reviewer or the obfuscation rules (FR-06) to catch.
- Bundles of 5 MiB or more still end as `INCOMPLETE` because of the engine's added-bytes cap, not because of this rule.
- Signals in *different* files are not correlated (T-D14); dynamic lookups (`getattr(subprocess, ...)`, string building, `eval`) are not seen.
- Only added lines: if the downloader already exists and the PR adds only the spawn, it is missed.
- Expected false positives: legitimate installers that fetch a prebuilt binary and run it (esbuild/puppeteer-style postinstall scripts) will block under the default policy. These need a reviewed suppression (FR-11).
- The description of the original incident is approximate; refine the fixtures when real details are available.

## CI workflow rules (FR-05)
**Primer:** a GitHub Actions workflow runs on GitHub's machines, often with secrets and a write-capable token, so a PR that edits a workflow can be more dangerous than one that edits source code. These rules read only *added* lines, ignore comments, and only treat the repository-root `.github/` as real (a nested `vendor/.github/workflows/` is not executed by GitHub).

**Context from the fetcher.** Some decisions depend on lines the diff does not show, e.g. whether an existing workflow is triggered by `pull_request_target`. The fetcher (`src/pr_scanner/fetcher.py`) reads the file at the head SHA through the API and set `ChangedFile.new_content` (inert text only, ADR-0004). Without it the rules degrade to a lower severity instead of guessing.

| Rule | Severity | When |
|---|---|---|
| `CI-PRT` | Critical | `pull_request_target` workflow checks out PR code (`ref: ...head.sha`, `head_ref`, `refs/pull/...`, `gh pr checkout`, `git fetch ... pull/N/head`, also in flow style) |
| | High | `workflow_run` workflow checks out the triggering run's head |
| | Medium | head checkout but the trigger is unknown (no `new_content`); or the `pull_request_target` trigger was newly added without a PR checkout |
| `CI-UNPINNED` | High | action referenced by a branch (`@main`, `@master`, `@develop`, `@latest`, ...) |
| | Medium | third-party action by tag or short SHA, or a Docker image tag |
| | Low | first-party (`actions/*`, `github/*`) by tag |
| | none | full 40/64-hex SHA, local `./` action, Docker digest |
| `CI-PERMS` | High | `permissions: write-all` |
| | Medium | `write` on `contents`, `actions`, `id-token`, `packages`, `security-events`, `deployments` |
| | Low | other `write` scopes |
| `CI-SECRETS` | Critical | `toJSON(secrets)` |
| | High | secret on a line that also encodes or sends it (`curl`, `wget`, `nc`, `base64`, URL); `printenv \| ...` |
| | Medium | `secrets: inherit` |
| | Low | any other newly referenced secret (the built-in `GITHUB_TOKEN` is not reported) |
| `CI-PIPE-SH` | High (Critical for a raw IP) | download piped into a shell/interpreter, `bash <(curl ...)`, `sh -c "$(curl ...)"`, `iex (iwr ...)`; quote-splitting is normalised |
| `CI-INJECT` | High | attacker-controlled context (`pull_request.title/body/head.ref`, `issue.body`, `comment.body`, `head_ref`, commit messages/author names/emails, ...) expanded directly in a script or `github-script` |
| | none | passing it through `env:`/`with:` as a whole-value assignment (the recommended safe pattern) |

Known limits: line-based, so values split over several lines (YAML folded scalars) are missed; the key under `permissions:` is not verified to be in a `permissions` block; removed restrictions (deleting a `permissions:` block) are not yet reported; GitLab/CircleCI/Jenkins files only get `CI-PIPE-SH`; expression functions that rebuild a tainted value (`format(...)`) are not tracked.

## SCANNER-TAMPER (FR-12, T-D12)
**Primer:** the scan workflow runs from the base branch, so a pull request cannot disable it *before* it merges. But a change that is merged becomes the new base, so a PR that rewrites the scanner's own workflow, policy or ownership file has to be caught as a change and held for an owner. Found in the 2026-11-09 rehearsal (PR #4 scanned clean while replacing the scan step with a hand-written `report.json`); that exact diff is now a corpus case.

"The scanner" means: a root `.github/workflows/` file whose name contains `pr-scan`/`pr_scan` or that calls `pr_scanner`/`pr-scanner` on a non-comment line; `.pr-scanner.yml|yaml`; and `CODEOWNERS`.

| Severity | Condition |
|---|---|
| Critical | scanner workflow deleted, or renamed out of `.github/workflows/`; the number of scanner calls goes down |
| High | a line that writes `report.json` by hand (`>`, `tee`, `cp`, `mv`, `dd`, `install`, `curl`, `open(`, ...); scanner installed from a non-https or non-github.com URL, from a different repository than before, without a full commit SHA, or from a package index; scanner workflow renamed to another workflow name; `.pr-scanner.yml` changed or deleted; `CODEOWNERS` deleted or ownership of `.github`/workflows/the scanner removed |
| Medium | any other change to the scanner workflow (including a legitimate pin bump) or to `CODEOWNERS` |

Comments and blank lines never count. One finding per reason per file. Evidence for removals uses the old-file line number.

Known limits: removing one of several scanner calls in a legitimate refactor reads as Critical (a person decides); a report written through an unusual tool is not seen; a PR cannot be told apart from a real maintainer, so every legitimate change to these files warns until a suppression flow (FR-11) exists, and this only helps if CODEOWNERS plus branch protection require an owner to approve those paths. Changes to the scanner's own source code inside a repository that vendors it are out of scope.

## Performance
Every rule must stay linear on adversarial lines (T-S03). `tests/test_rules_perf.py` feeds 22 hostile payloads (repeated tokens, unterminated strings/expressions, padding) through every rule in a child process with a hard timeout. Writing it found five super-linear patterns in earlier rules (a lazy `.*` after a repeated token, regex restarts on unterminated JSON strings and `${{` expressions); they were replaced with single-pass algorithms (`json_string_pairs`, `_expressions`, `_key_then_value`) rather than length bounds, since a bound is itself an evasion. The suite is slow (~2 minutes) so it is marked `perf` and excluded by default; **CI must run `pytest -m perf`**. Measured cost: `EXEC-DROPPER` is the heaviest at roughly 2 s per MB of text; the engine caps a scan at 5 MB.

## Line-length handling
Rules scan whole lines. The engine truncates lines over 1,000,000 characters and marks the scan `INCOMPLETE` so oversized lines are never skipped silently. (An earlier version truncated at 4,000 characters inside the rules, which let an attacker hide a payload behind padding; fixed with regression tests.)

## Corpus status and honest limits
The in-repo corpus (`corpus/`, 28 malicious, 28 benign) was written together with the rules by the same author, apart from two real diffs (the rehearsal PR that forged a report, and a pin bump). 100% recall and zero blocked benign cases on it show the rules work as designed, **not** that they will perform well on real attacks. Per-rule "FP" counts in the corpus report include *intentional* low-severity or warn-level reports on benign cases, so precision figures look worse than the verdict-level numbers; read the benign blocked/warned rates for user-visible noise. Run it with `python -m pr_scanner.corpus corpus`.

False positives on real code are measured separately with `python -m pr_scanner.realworld` (see `docs/PROGRESS.md` for the latest numbers and for each false positive found). What is still missing: real-world defanged malicious samples (recall), an independently authored adversarial set, and targeted samples of install-script changes (the binary-installer projects legitimately download at install time, which is the dropper rule's known blind spot).
