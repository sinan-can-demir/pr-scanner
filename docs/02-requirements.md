# 02 Requirements

Priority uses MoSCoW (M = Must, S = Should, C = Could). Each requirement has acceptance criteria (AC) that become tests (see 08).

## Functional requirements
| ID | Pri | Requirement | Acceptance criteria |
|---|---|---|---|
| FR-01 | M | Trigger a scan on PR `opened`, `synchronize`, `reopened` | Event fixtures for each trigger start exactly one scan; other events are ignored |
| FR-02 | M | Obtain the PR diff and file metadata via the GitHub API without checking out or executing PR code | No code path imports, runs or builds PR content; verified by test and design review |
| FR-03 | M | Evaluate a pluggable set of rules over the diff, each producing zero or more Findings | A rule registry loads rules; a stub rule's finding appears in output |
| FR-04 | M | Detect changes to install/lifecycle hooks (npm `preinstall/postinstall/prepare`, `setup.py` cmdclass, `pyproject` build backends) | Corpus fixtures for each flagged; benign script edits (e.g. `lint`) are not |
| FR-05 | M | Detect risky CI changes: `pull_request_target` with PR checkout, unpinned third-party actions, new secrets use, `curl \| sh`, permission widening | Workflow fixtures flagged with specific rule IDs (CI-PRT, CI-UNPINNED, CI-PERMS, CI-SECRETS, CI-PIPE-SH, CI-INJECT); safe look-alikes (pull_request checkout, SHA-pinned actions, env-passed values) are not blocked |
| FR-06 | M | Detect obfuscation and encoded payloads: long base64/hex blobs, `eval`/`exec` of decoded data, high-entropy strings, minified code in source dirs | Known obfuscated samples flagged; ordinary test fixtures and assets allow-listed |
| FR-07 | M | Detect dependency risks: new dependency, version swapped for URL/git/tarball, lockfile integrity-hash or registry changes, typosquat similarity | Lockfile-tamper and typosquat fixtures flagged |
| FR-08 | S | Detect credential access and exfiltration patterns: reading env/secrets/`~/.ssh`/cloud creds, outbound HTTP to new hosts | Fixtures flagged; documented false-positive notes |
| FR-09 | M | Publish a GitHub check run with verdict and per-line annotations | Check conclusion and annotations match findings in an integration test |
| FR-10 | M | Every finding includes rule ID, severity, file/line, evidence, rationale, remediation | Schema validation test over all rules |
| FR-11 | S | Suppress a finding only with a written justification, recorded and attributable to an authorised user | Suppression without justification or authority is rejected; audit entry created |
| FR-12 | S | Read policy from a repo config file; changes to the config are themselves scanned and flagged | Config diff yields a finding; invalid config fails closed |
| FR-13 | C | Optional LLM triage adds context to findings | With LLM off, verdict identical; with LLM on, verdict severity never lower than rules' |
| FR-14 | M | Compute verdict (`block` / `warn` / `pass`) from findings with configurable thresholds | Table-driven tests of severity to verdict |
| FR-15 | S | Persist an audit record per scan (inputs hash, rule versions, verdict) | Record present and reproducible |
| FR-16 | M | A new rule is accepted only with at least one malicious and one benign fixture | CI check fails otherwise |
| FR-17 | C | Author-risk signals (account age, first contribution, sudden workflow edits) feed severity | Signals boost, never solely trigger, a block |
| FR-18 | S | Flag suspicious PR-thread behaviour: new or low-history accounts commenting, approving or reacting on a PR that has open findings, and coordinated patterns between author and those accounts | Thread fixture modelled on the reported incident yields a "possible sock-puppet" notice to maintainers; the notice never changes the rule-based verdict and is worded as a signal, not an accusation |
| FR-20 | M | Detect remote binary droppers: within one file's added lines, remote download combined with process execution or `chmod +x`; escalate when CI-gated or when the source is a raw IP | Fixtures in several languages (Python, JS, Go, shell) flagged; download-only, spawn-only, CI-read-only and `regex.exec` cases are not |
| FR-21 | S | Surface CI-environment-conditional behaviour (reads of `CI`, `GITHUB_ACTIONS`, ...) when combined with spawning or downloading | CI-gated spawn without download yields warn; CI read alone yields nothing |
| FR-19 | M | A finding cannot be cleared by comments, reactions or approvals alone; only a recorded suppression (FR-11) or a code change that removes the cause clears it | Test: approval by a new account leaves the verdict unchanged |

## Non-functional requirements
| ID | Pri | Category | Requirement | Acceptance criteria |
|---|---|---|---|---|
| NFR-01 | M | Safety | Never execute, import, install or build PR-supplied code | Static check forbids subprocess/eval on PR data; sandboxed in CI |
| NFR-02 | M | Performance | p95 <= 60 s for diffs up to 1000 files / 5 MB | Benchmark in CI |
| NFR-03 | M | Accuracy | Recall >= 95% on malicious corpus (Must rules); blocked-PR FP <= 2% on benign corpus | Corpus run gate in CI |
| NFR-04 | M | Security | Least-privilege token (read contents/PR, write checks only); no secrets in logs | Permission manifest review; log-scrub test |
| NFR-05 | M | Privacy | No PR content leaves the runner unless LLM triage is explicitly enabled; payload redacted | Network-egress test with LLM off |
| NFR-06 | M | Resilience | Resource limits (file size, count, regex time, memory); oversize input yields `warn: incomplete`, never silent pass | Fuzz and oversize tests |
| NFR-07 | M | Determinism | Same diff + same rules give the same rule-based verdict | Repeat-run test |
| NFR-08 | M | Fail-safe | Internal error yields failed/neutral check with explanation, never success | Fault-injection tests |
| NFR-09 | S | Extensibility | Add a rule by adding one module and fixtures, no core change | Contributor-guide dry run |
| NFR-10 | S | Supply chain | Scanner's own deps pinned and hash-locked; releases signed; Actions pinned by SHA | CI policy check |
| NFR-11 | M | Robustness | Resistant to prompt injection and evasive encodings | Adversarial test suite |
| NFR-12 | S | Usability | Findings readable by non-experts; each links to rule docs | Doc-link test |
| NFR-13 | S | Observability | Structured logs and metrics, per-rule hit counts | Log schema test |
