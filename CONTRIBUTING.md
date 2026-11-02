# Contributing

## Adding a rule
1. Identify the threat (`docs/04-threat-model.md`, T-D*) or add a new one.
2. Add **defanged** fixtures: at least one malicious and one benign (FR-16). Never commit live payloads, working endpoints or real credentials.
3. Write failing tests first, then the rule (pure function over a normalised diff).
4. Provide `rationale` and `remediation` text; findings without them fail schema tests.
5. Run the corpus metrics; recall/precision gates must hold (NFR-03).
6. Update `docs/08-traceability-matrix.md`.

## Performance
Rules run on attacker-controlled text. Avoid regexes with unbounded repetition after a repeated token (`.*`, lazy `[^x]*?`), and do not restart a regex at every quote or bracket. Add a hostile payload to `tests/test_rules_perf.py` for any new pattern shape, and run `pytest -m perf`. Do not "fix" slowness by truncating lines: a payload hidden behind padding must still be found.

## Ground rules
- No code path may execute or import PR-supplied data (ADR-0004).
- Pin dependencies and Actions by hash/SHA.
- Rule or policy changes need review from a second maintainer.
- Record significant decisions as ADRs.
