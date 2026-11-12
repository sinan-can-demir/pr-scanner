# PR Scanner

A GitHub Action that statically scans pull requests for signs of malicious code (supply-chain attacks, CI tampering, obfuscated payloads, credential exfiltration) and reports an explainable verdict on the PR. Python standard library only, no runtime dependencies.

Pull requests are how supply-chain attacks get in: a postinstall hook, a workflow edit, a "test file" that is really a payload. PR Scanner reads the **diff** of each pull request, never runs it, and posts a check with a verdict (pass, warn or block) where every finding has a rule ID, the evidence, why it matters and how to fix it.

## What it catches
| Rule | Flags |
|---|---|
| `HOOK-NPM`, `HOOK-PYSETUP`, `HOOK-PYBACKEND` | install hooks that run code (`postinstall`, `setup.py`, build backends) |
| `EXEC-DROPPER` | download-then-run: fetch, write, `chmod +x` or spawn, in source files and build scripts |
| `EXEC-OBFUSCATED` | decode-then-run: base64, hex, `xz -d` or `openssl enc` next to `eval`, `exec`, `_compile` or a pipe into a shell |
| `CI-PRT`, `CI-INJECT`, `CI-SECRETS`, `CI-PIPE-SH` | risky workflow changes: `pull_request_target` checkouts, script injection, secrets sent out or encoded, `curl \| sh` |
| `CI-UNPINNED`, `CI-PERMS` | actions not pinned to a commit, widened token permissions |
| `SCANNER-TAMPER` | edits to the scanner's own workflow, config or `CODEOWNERS`, so it cannot be quietly switched off |

Details, severities and known limits are in the [rule catalog](docs/rules.md).

## How well does it work?
Measured on real pull requests, with the limits stated.
- **Noise (false positives):** a sample of 684 merged PRs from 35 repositories the rules were not tuned on: 94.4% pass, 2.3% warn, 0.44% block (3 PRs, one of them a correct finding), 2.8% incomplete (too large to scan), measured before two later false-positive fixes. A second sample of 300 PRs from build-script-heavy repositories: 1 block (a correct finding). These PRs are presumed benign, so this measures noise, **not** recall. One reviewer labelled them.
- **Recall on real attacks:** a small corpus of 8 defanged cases from documented incidents (xz, event-stream, tj-actions, nx, Shai-Hulud). The first run caught **4 of 8**. A rule added afterwards catches 2 of the 4 misses, but it was written looking at them, so that is not independent evidence. The other 2 are outside what a diff-only text scanner can see: **binary files** (the xz test files) and **adding an unknown dependency** (event-stream).
- **In-repo corpus:** 100% recall, but it was written together with the rules, so it is a sanity check, not a measurement.

Full tables, labels and caveats: [Progress](docs/PROGRESS.md) and [recall on real attacks](docs/recall-real-attacks.md).

## What it does not do
- It does not run or sandbox code, so it cannot see what a payload does, only what the diff looks like.
- It does not see binaries, tarballs, or a dependency being added (see above).
- Legitimate installers that download a binary and `chmod +x` it are blocked; the plan is reviewed suppressions, not looser rules.
- Very large diffs (over 5 MiB) are reported as incomplete, never as a silent pass.
- Not packaged for other repositories yet, and no suppressions or config file. It is **live on this repository** and was rehearsed on a throwaway fork.

## Quick start
```
python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'
.venv/bin/python -m pytest                          # the default suite
.venv/bin/python -m pytest -m perf                  # adversarial performance, ~2.5 min, run in CI
.venv/bin/python -m pr_scanner.corpus corpus        # recall / false-positive report on the in-repo corpus
```
Scan one pull request (read-only; the token comes from the environment, never from argv):
```
GITHUB_TOKEN=... .venv/bin/python -m pr_scanner scan --repo OWNER/REPO --pr 123 \
    --head-sha <40-hex head commit> --out report.json
```
Measure the scanner on real merged pull requests (references and results only, no third-party code is stored):
```
GITHUB_TOKEN=... .venv/bin/python -m pr_scanner.realworld sample --repos a/b,c/d --per-repo 25 --out manifest.json
GITHUB_TOKEN=... .venv/bin/python -m pr_scanner.realworld run --manifest manifest.json --results results.json
.venv/bin/python -m pr_scanner.realworld summary --results results.json
```

## Using it in a repository
Copy `.github/workflows/pr-scan.yml` (it explains why `pull_request_target` is safe there), pin the scanner to a commit SHA of this repository, then protect the branch as described in [Branch protection](docs/branch-protection.md). Without owner review on the workflow, `.pr-scanner.yml` and `CODEOWNERS`, a merged change could switch the scan off. There is no packaged Action yet.

**GitHub is changing the default for `pull_request_target` on 2026-12-02.** From that date public repositories block it by default, so a copied workflow can fail at startup. This repository handles it with a repository Actions policy (Settings > Actions > Policies) that allows only `pull_request_target`, only for `.github/workflows/pr-scan.yml`; every adopter needs the same policy. That it suppresses the default block is **not yet confirmed**: it will be checked on the first PR scan after 2026-12-02.

## Principles
1. **Never execute PR code.** Analysis is static, on the diff only (ADR-0004).
2. **Rules first, LLM optional.** Deterministic, testable rules decide. An LLM may only add context, never lower a severity (ADR-0003).
3. **Explainable findings.** Every finding has a rule ID, evidence, rationale and remediation.
4. **PR content is hostile input**, including anything we show to an LLM.
5. **Fail loudly.** A scanner error is never a silent pass.

## Documentation map
See also [Progress log](docs/PROGRESS.md) for current status, known gaps and next steps, the [Rule catalog](docs/rules.md), and [Branch protection](docs/branch-protection.md).

| Doc | Purpose |
|---|---|
| [00 Vision & scope](docs/00-vision-and-scope.md) | Why, goals, non-goals, success metrics |
| [01 Actors](docs/01-stakeholders-actors.md) | Who interacts with or attacks the system |
| [02 Requirements](docs/02-requirements.md) | FR/NFR with acceptance criteria |
| [03 Use cases](docs/03-use-cases.md) | Flows per actor goal |
| [04 Threat model](docs/04-threat-model.md) | Attacks we detect and attacks on us |
| [05 Architecture](docs/05-architecture.md) | C4, data flow, trust boundaries |
| [06 Domain model](docs/06-domain-model.md) | Core entities |
| [07 Test strategy](docs/07-test-strategy.md) | Pyramid, corpora, metrics |
| [08 Traceability](docs/08-traceability-matrix.md) | Requirement, use case, threat, test |
| [Rules](docs/rules.md) | What each rule flags, severities, known limits |
| [Branch protection](docs/branch-protection.md) | Settings that make the scan binding |
| [ADRs](docs/adr/) | Recorded decisions, incl. the Action trust model (0005) |

## Roadmap
- **Phase 0 (done):** docs, threat model, skeleton
- **Phase 1 (mostly done):** diff ingestion, rule engine, install-hook, dropper, CI and scanner-tamper rules, corpus. Open: dependency rules (FR-07), a binary-change signal, dropper cross-file correlation
- **Phase 2 (mostly done):** GitHub Action wrapper, check run and annotations, trust model. Open: packaging for other repositories
- **Phase 3 (planned):** suppressions (FR-11), config (FR-12), sock-puppet signal (FR-18), GitHub App, optional LLM triage

## License
Copyright 2026 Sinan Can Demir. Licensed under the Apache License 2.0, see [LICENSE](LICENSE). The code is open for anyone to use, and the project is maintained by its author.
