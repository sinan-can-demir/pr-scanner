# 08 Traceability Matrix

Test types: U unit, P property, C corpus, I integration, A adversarial, F fuzz, Perf, FI fault injection, S static/security, E2E.

| Requirement | Use cases | Threats addressed | Planned tests |
|---|---|---|---|
| FR-01 | UC-01 | T-S08 | I (event fixtures), U |
| FR-02 | UC-01 | T-S04 | S, I |
| FR-03 | UC-01, UC-05 | n/a | U, I |
| FR-04 | UC-01 | T-D01 | U, C, A (implemented: HOOK-NPM, HOOK-PYSETUP, HOOK-PYBACKEND; see rules.md) |
| FR-05 | UC-01 | T-D03, T-D08, T-D12 | U, C, A |
| FR-06 | UC-01 | T-D02, T-D09, T-D10, T-D13 | U, C, A, F |
| FR-07 | UC-01 | T-D04, T-D05, T-D06 | U, C |
| FR-08 | UC-01 | T-D07, T-D13 | U, C |
| FR-09 | UC-01, UC-02 | n/a | I, E2E |
| FR-10 | UC-02, UC-07 | n/a | U (schema), P |
| FR-11 | UC-03 | T-S07 | U, I |
| FR-12 | UC-04 | T-S06, T-D12 | U, FI |
| FR-13 | UC-01 | T-S02 | U, A, P (monotonic) |
| FR-14 | UC-01 | n/a | U (table), P |
| FR-15 | UC-08 | T-S07 | I |
| FR-16 | UC-05 | T-S09 | S (CI check) |
| FR-17 | UC-01 | T-D11 | U |
| FR-18 | UC-01, UC-02 | T-D15, T-S14 | U, C (incident-modelled thread fixture) |
| FR-19 | UC-02, UC-03 | T-S14, T-S07 | U, I |
| FR-20 | UC-01 | T-D16, T-D17 | U, C (7 malicious + 5 benign fixtures), A |
| FR-21 | UC-01 | T-D17 | U, C |
| NFR-01 | UC-01 | T-S04 | S, review |
| NFR-02 | UC-01 | T-S03 | Perf |
| NFR-03 | UC-01, UC-05 | T-S12 | C (gate) |
| NFR-04 | UC-06 | T-S05 | S, review |
| NFR-05 | UC-06 | T-S05, T-S10 | I (egress test) |
| NFR-06 | UC-01 | T-S03 | F, Perf, FI |
| NFR-07 | UC-01 | n/a | P |
| NFR-08 | UC-01 | T-S06 | FI |
| NFR-09 | UC-05 | n/a | Contributor dry run |
| NFR-10 | UC-05 | T-S09 | S |
| NFR-11 | UC-01 | T-S01, T-S02 | A |
| NFR-12 | UC-02, UC-07 | n/a | U (doc links) |
| NFR-13 | UC-08 | n/a | U |

## Threat coverage check (Part A and B)
- Every T-D* maps to at least one FR (T-D14 is explicitly out of scope).
- Every Critical T-S* maps to an NFR plus an ADR or design rule.
- T-S11 and T-S13 are handled by deployment/design rules (05), with test via E2E.

## Maintenance
Update on every requirement, rule or threat change. Later: add a CI script that parses requirement IDs and fails if any is missing from this matrix.
