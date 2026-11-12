# ADR-0002: Implementation language

- **Status:** Proposed (provisional, owner to confirm)
- **Date:** 2026-11-02

## Context
The owner has no strong preference. Needs: text/diff processing, good test tooling (property-based, fuzz, mutation), easy GitHub Action packaging, readable rules for contributors.

## Options
| Option | Pros | Cons |
|---|---|---|
| Python | Fast to write, pytest + hypothesis + atheris + mutmut, rich parsing libs (tree-sitter, PyYAML), approachable for rule authors | Slower runtime; packaging in Actions needs Docker or setup-python |
| TypeScript | Native fit for Actions and npm ecosystem; Octokit | Weaker property/mutation tooling; more config overhead |
| Go | Single static binary, fast, strong safety | Slower iteration for heuristics; fewer test-tooling options |

## Decision (provisional)
Python 3.12+ for the engine; ship as a Docker-based GitHub Action. *(Status note 2026-11-11: as built, the workflow installs the package with `pip` from a pinned commit SHA of this repository; there is no Docker image or packaged Action yet.)* Revisit before Phase 2 if performance (NFR-02) or packaging becomes a problem. Keep the core free of GitHub-specific code so a port stays feasible.

## Consequences
- Use `uv`/pip with hash-locked requirements (NFR-10).
- Avoid regex features that allow catastrophic backtracking (T-S03); consider `re2` bindings.
