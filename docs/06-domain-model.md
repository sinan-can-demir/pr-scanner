# 06 Domain Model

```mermaid
classDiagram
  class ScanRequest {
    +repo
    +prNumber
    +headSha
    +baseSha
    +trigger
  }
  class PullRequest {
    +author
    +title
    +body
    +files: ChangedFile[]
  }
  class ChangedFile {
    +path
    +status
    +fileType
    +addedLines
    +removedLines
  }
  class Rule {
    +id
    +version
    +severity
    +category
    +evaluate(ctx) Finding[]
  }
  class Finding {
    +ruleId
    +severity
    +confidence
    +file
    +line
    +evidence
    +rationale
    +remediation
  }
  class Suppression {
    +findingFingerprint
    +justification
    +approvedBy
    +createdAt
  }
  class Policy {
    +blockAt
    +warnAt
    +enabledRules
    +allowlists
  }
  class Verdict {
    +outcome: block|warn|pass|incomplete|error
    +reasons
  }
  class AuditRecord {
    +scanId
    +inputsHash
    +ruleVersions
    +verdict
    +timestamp
  }
  ScanRequest --> PullRequest
  PullRequest "1" --> "*" ChangedFile
  Rule "1" --> "*" Finding : produces
  Finding "0..*" <-- Suppression : silences
  Policy --> Verdict : shapes
  Finding "*" --> "1" Verdict : aggregated into
  Verdict --> AuditRecord
```

## Severity and verdict mapping (default policy)
| Highest unsuppressed severity | Verdict |
|---|---|
| Critical | `block` |
| High | `block` (configurable to `warn`) |
| Medium | `warn` |
| Low / none | `pass` |
| Partial scan (limits hit) | `incomplete` (treated as `warn` minimum) |
| Internal error | `error` (check failure, never success) |

## Invariants
- A Finding always has non-empty rule ID, evidence, rationale, remediation (FR-10).
- A Suppression requires justification and an authorised approver (FR-11).
- Verdict is a pure function of (findings, suppressions, policy): deterministic (NFR-07).
- LLM-derived annotations can raise, never lower, severity (FR-13).
