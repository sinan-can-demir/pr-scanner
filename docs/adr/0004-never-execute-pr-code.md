# ADR-0004: Never execute PR code; static analysis of the diff only

- **Status:** Accepted
- **Date:** 2026-11-02

## Context
Running PR code (installing deps, building, importing modules, running tests) gives an attacker code execution on the scanner, which often holds tokens. Many real supply-chain compromises came from CI running untrusted PR content with privileges.

## Decision
- Obtain diffs through the GitHub API; do not check out PR head into a privileged context.
- Treat PR content as inert strings; never pass to eval, shell, import, package manager or template engines.
- Read scanner config and rules from the base branch.
- Analysis runs with a read-only token; posting results is a separate, privileged, minimal step handling only sanitised data.
- A static-analysis check in CI forbids `eval`, `exec`, `subprocess`, `os.system` and dynamic import on code paths that touch PR data.

## Consequences
We cannot detect behaviour that only shows on execution (accepted, NG2). Strong containment of T-S04 and T-S05.
