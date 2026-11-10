# PR Scanner

A GitHub App / Action that statically scans pull requests for signs of malicious code (supply-chain attacks, CI tampering, obfuscated payloads, credential exfiltration) and reports an explainable verdict on the PR.

**Status (2026-11-09):** runs end to end as a GitHub Action, live on this repository and rehearsed on a throwaway fork. 12 rules (install hooks, remote-binary droppers, CI workflow risks, tampering with the scanner itself), a fail-safe engine, a hardened diff parser, a GitHub fetcher, an escaped check-run reporter, and a two-job workflow whose trust model is in [ADR-0005](docs/adr/0005-action-trust-model.md). 809 tests plus 22 slow adversarial-performance tests. **Not built yet:** suppressions, config file, sock-puppet signal, obfuscation and dependency rules, optional LLM triage, packaging for other repositories. **Honest limits:** the in-repo corpus was written together with the rules, so its 100% recall is a sanity check; a real-world false-positive measurement is in [Progress](docs/PROGRESS.md) and recall on real attacks is still unmeasured.

## Quick start
```
python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'
.venv/bin/python -m pytest                          # 809 tests
.venv/bin/python -m pytest -m perf                  # adversarial performance, ~2 min, run in CI
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
- **Phase 1 (mostly done):** diff ingestion, rule engine, install-hook, dropper, CI and scanner-tamper rules, corpus. Open: obfuscation (FR-06) and dependency (FR-07) rules, dropper cross-file correlation
- **Phase 2 (mostly done):** GitHub Action wrapper, check run and annotations, trust model. Open: CI that runs this repository's own tests, packaging for other repositories
- **Phase 3 (planned):** suppressions (FR-11), config (FR-12), sock-puppet signal (FR-18), GitHub App, optional LLM triage
