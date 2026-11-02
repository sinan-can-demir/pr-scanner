# 00 Vision and Scope

## Problem statement
Open-source and internal repositories accept code from many parties. Supply-chain attacks increasingly arrive as ordinary-looking pull requests, or as changes to CI workflows, install scripts or dependencies. Human reviewers miss them because the malicious part is small, obfuscated or placed in files nobody reads (lockfiles, workflow YAML, build scripts).

## Vision
A fast, trustworthy first line of defense that flags the changes in a PR most likely to be malicious, and explains why, so maintainers can focus review where it matters.

## Goals
- G1: Detect high-risk change classes in a PR diff (see threat catalogue T-D*).
- G2: Produce explainable, actionable findings with low false-positive rates.
- G3: Be safe to run on untrusted PRs (it must not become an attack vector itself).
- G4: Be easy to extend: new rules ship with tests and fixtures.
- G5: Be measurable: precision and recall tracked against a labelled corpus.

## Non-goals
- NG1: Not a full SAST or vulnerability scanner (no CVE hunting in the code).
- NG2: Not a malware sandbox; no dynamic execution of PR code.
- NG3: Not a replacement for human review, branch protection or signed commits.
- NG4: Not a post-merge or runtime detector (initially).
- NG5: Not attributing attackers.

## Scope
**In:** diffs of text files, manifests and lockfiles of common ecosystems (npm, PyPI first), GitHub Actions workflows, build/install scripts, PR metadata (author age and history signals).
**Out (v1):** binary analysis beyond flagging unexpected binaries, non-GitHub platforms, historical repository scanning.

## Success metrics
> **Provisional.** These targets are starting hypotheses, not commitments. Phase 1 builds a baseline: run the first rules over a labelled corpus plus a sample of real benign PRs from public repositories, then set the targets from what is measured. The decision rule is that a blocking verdict must be rare and trustworthy, while a warning may be noisier. Review after the baseline.

| ID | Metric | Target |
|---|---|---|
| M1 | Recall on known-malicious corpus (Must rules) | >= 95% |
| M2 | False-positive rate on benign PR corpus | <= 2% of PRs blocked, <= 10% warned |
| M3 | p95 scan latency (diff <= 1000 files / 5 MB) | <= 60 s |
| M4 | Scanner-error-as-pass incidents | 0 |
| M5 | Rules with malicious and benign fixtures | 100% |

## Assumptions and constraints
- Runs in GitHub Actions or as a GitHub App with least-privilege permissions.
- Diffs are obtained through the GitHub API, not by checking out and building PR code.
- Small team; maintainability beats cleverness.

## Open questions
- Q1: Which ecosystems after npm/PyPI (Go, Rust, Maven)?
- Q2: Share anonymised findings or corpus publicly?
- Q3: Final implementation language (ADR-0002 is provisional).
