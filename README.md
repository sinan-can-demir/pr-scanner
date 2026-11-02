# PR Scanner

A GitHub App / Action that statically scans pull requests for signs of malicious code (supply-chain attacks, CI tampering, obfuscated payloads, credential exfiltration) and reports an explainable verdict on the PR.

**Status:** Phase 1 in progress. Done: domain models, verdict policy, fail-safe rule engine, hardened unified-diff parser, path classifier. Next: first detection rules (install hooks, CI workflows). No detection rules exist yet.

Development: `python3 -m venv .venv && .venv/bin/pip install -e '.[dev]' && .venv/bin/python -m pytest`

## Principles
1. **Never execute PR code.** Analysis is static, on the diff only (ADR-0004).
2. **Rules first, LLM optional.** Deterministic, testable rules decide. An LLM may only add context, never lower a severity (ADR-0003).
3. **Explainable findings.** Every finding has a rule ID, evidence, rationale and remediation.
4. **PR content is hostile input**, including anything we show to an LLM.
5. **Fail loudly.** A scanner error is never a silent pass.

## Documentation map
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
| [ADRs](docs/adr/) | Recorded decisions |

## Roadmap
- **Phase 0 (now):** docs, threat model, skeleton
- **Phase 1:** diff ingestion, rule engine, 5 Must rules, CLI, corpus
- **Phase 2:** GitHub Action wrapper, check run and annotations
- **Phase 3:** suppressions, config, GitHub App, optional LLM triage
