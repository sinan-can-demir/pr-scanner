# Contributing

## Adding a rule
1. Identify the threat (`docs/04-threat-model.md`, T-D*) or add a new one.
2. Add **defanged** fixtures: at least one malicious and one benign (FR-16). Never commit live payloads, working endpoints or real credentials.
3. Write failing tests first, then the rule (pure function over a normalised diff).
4. Provide `rationale` and `remediation` text; findings without them fail schema tests.
5. Run the corpus metrics; recall/precision gates must hold (NFR-03).
6. Update `docs/08-traceability-matrix.md`.

## Ground rules
- No code path may execute or import PR-supplied data (ADR-0004).
- Pin dependencies and Actions by hash/SHA.
- Rule or policy changes need review from a second maintainer.
- Record significant decisions as ADRs.
