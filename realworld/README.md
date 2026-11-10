# Real-world measurement data

What the scanner did on **800 recently merged pull requests from 32 public repositories** (25 each,
sampled 2026-11-09 with `python -m pr_scanner.realworld`). References and results only: no third-party
code and no evidence snippets are stored.

| File | Content |
|---|---|
| `sample-2026-11-09.json` | the sample: repo, PR number, head SHA |
| `results-2026-11-09.json` | one record per PR: outcome, rules fired (rule, severity, file, line), fetch notes |
| `labels-2026-11-09.json` | my hand label and cause for every block, warn and incomplete |

The results were produced by the scanner at commit `3a676cf`, before the `EXEC-DROPPER` fix for compiled
bundles (`0e55018`). Merged PRs from well-known projects are only *presumed* benign, which is why every
flag was read and labelled. A rule that was tuned on this sample no longer has independent evidence here;
take a fresh sample (`sample` then `run`) after tuning. Headline numbers and the backlog are in
`docs/PROGRESS.md`.

Reproduce: `GITHUB_TOKEN=... python -m pr_scanner.realworld run --manifest realworld/sample-2026-11-09.json --results out.json`

## Second, fresh sample (2026-11-10)
684 PRs from 35 repositories that were **not** in the first sample, scanned at `e95f51e` (`sample-`, `results-` and `labels-2026-11-10.json`). Evidence snippets are stripped from the results. 6 PRs that first failed with a connection error were re-run once and are recorded with the re-run result. Numbers and caveats: `docs/PROGRESS.md`.
