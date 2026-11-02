# ADR-0003: Rules first, LLM optional

- **Status:** Accepted
- **Date:** 2026-11-02

## Context
LLM judgement is flexible but non-deterministic, costly, privacy-sensitive, and vulnerable to prompt injection from the very content under review.

## Decision
- Deterministic rules produce all findings and the verdict.
- An optional LLM triage step may add explanation and may **raise** severity or confidence, never lower or suppress.
- Off by default; opt-in per repo; sends only redacted, size-capped snippets.
- LLM receives no tools and no secrets; output is validated against a schema.

## Consequences
Verdicts are reproducible and testable (NFR-07). Prompt injection cannot silence a finding (T-S02). Some subtle attacks may be missed without LLM help; accepted for v1.
