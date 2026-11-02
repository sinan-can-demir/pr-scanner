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
| End-to-end | Real test repo with sample PRs | GH Actions on a sandbox repo | Full flow incl. fork PR |

## Corpora
- `corpus/malicious/`: minimised, **defanged** samples per threat T-D*. Never contains live payloads, working C2 endpoints, or real credentials. Each sample has `meta.yaml` (threat ID, expected rule IDs, source).
- `corpus/benign/`: real-world-style PRs (dependency bumps, workflow tweaks, minified assets, test fixtures with base64) to measure false positives.
- `corpus/adversarial/`: evasion variants of malicious samples.
- Corpora are versioned; adding a rule requires adding to both malicious and benign (FR-16).

## Metrics and gates (CI)
- Per-rule and overall precision/recall printed on every run.
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
