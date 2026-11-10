# 07 Test Strategy

## Objectives
Prove that the scanner (1) detects what it claims, (2) stays quiet on benign changes, (3) is safe on hostile input, and (4) fails safe.

## Test levels
| Level | Scope | Tools (provisional) | Examples |
|---|---|---|---|
| Unit | Single rule, normaliser, verdict function | pytest | Rule flags `postinstall: curl x \| sh`, ignores `lint` script |
| Property-based | Invariants over generated input | hypothesis | Verdict deterministic; severity monotonic; normaliser idempotent |
| Corpus / regression | Labelled malicious & benign diffs | custom runner | Recall/precision per rule and overall |
| Integration | Fetcher, engine, reporter with mocked GitHub | pytest + recorded fixtures | Event to check run with annotations |
| Adversarial | Evasion, injection, limits | curated suite | Unicode tricks, split strings, prompt-injection text |
| Fuzz | Parsers & diff handling | atheris / hypothesis | No crash, no hang on random diffs |
| Performance | Latency and memory | benchmark in CI | NFR-02 gate |
| Fault injection | API errors, timeouts, bad config | pytest | NFR-08: never success on error |
| Security / static | Ban `eval`/`subprocess` on PR data; secret scan; dep audit | bandit/semgrep, pip-audit | NFR-01, NFR-10 |
| Mutation | Test-suite strength on rules | mutmut | Surviving mutants reviewed |
| End-to-end | Real test repo with sample PRs | GH Actions on a sandbox repo | Done once on a throwaway fork (benign, malicious, workflow-tamper PRs); a PR from another account's fork is not yet tested |
| Static / structure | No process or code execution in modules that touch PR data or tokens; workflow keeps ADR-0005's properties (pull_request_target only, no checkout, SHA pins, no `${{` in scripts, least-privilege per job) | `ast` and text checks in pytest | `tests/test_cli.py`, `tests/test_workflow_file.py`, `tests/test_codeowners.py` |

## Corpora
- `corpus/malicious/`: minimised, **defanged** samples per threat T-D*. Never contains live payloads, working C2 endpoints, or real credentials. Each sample has `meta.json` (threat ID, expected outcome and rule IDs, description). When a real diff exists (e.g. from a rehearsal) it is used instead of an imitation.
- `corpus/benign/`: real-world-style PRs (dependency bumps, workflow tweaks, minified assets, test fixtures with base64) to measure false positives.
- `corpus/adversarial/`: evasion variants of malicious samples.
- Corpora are versioned; adding a rule requires adding to both malicious and benign (FR-16, enforced by `tests/test_corpus.py`).
- **Real-world sample (`pr_scanner.realworld`)**: references (repo, number, head SHA) and results of recent merged PRs from public repositories, scanned through the real fetcher and engine. Nothing third-party is copied. Merged PRs are only *presumed* benign: each block or warn is read and labelled by a person. It measures false positives and noise; it cannot measure recall. Rules tuned on a sample lose that sample as independent evidence.

## Metrics and gates (CI)
- Per-rule and overall precision/recall printed on every run. Real-world rates are reported with 95% Wilson intervals, because zero observed is not zero risk.
- CI (`.github/workflows/tests.yml`) runs the default suite on every pull request and push to `main`, and the `perf` tests weekly and on demand. It is not yet a required status check (see Progress).
- Gate: recall >= 95% on Must-rule malicious corpus; blocked-benign <= 2% (NFR-03).
- Coverage target: 90% line / 80% branch on core; mutation score tracked, not gated initially.
- No test may require network except explicitly marked e2e.

## Safety rules for testing
- Samples are stored as inert data files, never imported or executed.
- Test fixtures containing suspicious strings are marked so repo scanners and editors do not trigger.
- E2E runs only against a dedicated sandbox repo with a throwaway token.

## Test-first workflow for rules
1. Write the threat reference (T-D*) and malicious + benign fixtures.
2. Write failing tests.
3. Implement rule.
4. Run corpus metrics; tune to hit gates.
5. Add adversarial variants; fix gaps.

## Requirement-to-test mapping
See [08 Traceability](08-traceability-matrix.md).
