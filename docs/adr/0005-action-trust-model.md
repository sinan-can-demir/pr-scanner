# ADR-0005: Action trust model: trusted-workflow, two jobs, artifact is untrusted

- **Status:** Proposed (supersedes the "v1" deployment note in `05-architecture.md`)
- **Date:** 2026-11-09

## Context
The architecture note said: run on `pull_request`, give forks a read-only token, and post results from a separate `workflow_run` job. That has a hole that matters for the reported incident (a determined contributor):

* On `pull_request`, GitHub runs the **workflow file from the PR**. An attacker can edit or delete the scan step, or make it upload any artifact they like.
* A `workflow_run` reporter then holds `checks: write` and would publish whatever the artifact says, including a forged "success" under our check name.

So the privileged job would be trusting data produced by attacker-controlled code (T-S06, T-S05).

## Decision
1. Trigger on **`pull_request_target`** (opened, synchronize, reopened). GitHub then runs the workflow file from the **base branch**, which the PR cannot change. This is normally dangerous; it is safe here only because we **never check out, install, build or execute PR code** (ADR-0004): the scanner is installed from a pinned ref of this repository and reads the PR purely through the API.
2. Two jobs, least privilege each:
   * `scan`: `permissions: { contents: read, pull-requests: read }`. Fetches, scans, writes `report.json`. No write access to anything.
   * `report`: `needs: scan`, `permissions: { checks: write }`. No checkout. Downloads `report.json`, **validates it strictly**, posts one check run. Runs `if: always()` so a crashed or missing scan becomes a failing check, never silence (NFR-08).
3. The artifact is **untrusted input** to the reporter. `parse_report` enforces a closed schema, size limits, allowed conclusion/title pairs, the expected head SHA (taken from the event, not the file), and the same Markdown invariants the reporter guarantees. A report that fails validation is replaced by a fixed failing check.
4. Posting uses a separate write-capable client restricted to one endpoint (`POST /repos/{repo}/check-runs`). The read client stays GET-only.
5. Third-party actions are pinned by commit SHA.

## Consequences
* A PR cannot disable or reroute the scan by editing workflows. It can still change the *scanner config* only on the base branch (T-S06).
* A bug in our parser could let attacker diff text influence the `scan` job. The blast radius is a forged report from a job that has no write token; the `report` job's validation limits what a forged report can contain. A forged *clean* report cannot be told apart from a real one, so parser safety (fuzzing, ADR-0004) remains critical.
* `pull_request_target` looks alarming to reviewers and to our own `CI-PRT` rule. The workflow must carry a comment explaining why it is safe, and must never gain a checkout of the PR head.
* Secrets are not exposed to the scan job (no `secrets:` use; token is the default read-only one).
