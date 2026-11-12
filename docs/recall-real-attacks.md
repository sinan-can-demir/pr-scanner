# Recall on real-attack techniques (first run, 2026-11-10)

Set: `corpus_real/` (8 malicious cases, defanged: only `example.invalid`). Run: `PYTHONPATH=src python3 -m pr_scanner.corpus corpus_real`.
**Kept apart from `corpus/` on purpose: do not tune rules on these cases and then quote the number as evidence.** After a fix, add new cases instead of re-scoring these.

Provenance is stated per case in `meta.json`. References were checked through the GitHub API on 2026-11-10 (advisories GHSA-rxwq-x6h5-x525, GHSA-mrrh-fwg8-r2c3, GHSA-9x64-5r7x-2q53, GHSA-cxm3-wv7p-598c, GHSA-qjqf-7j6f-82c4; xz commit 6e636819e8; event-stream issue 116). The tj-actions commit `0e58ed86` is named in issue #2463 but no longer exists (API 422), so that case is reconstructed from public analysis. Ultralytics was **not** used: no reference could be verified.

| Case | Provenance | Result | Why |
|---|---|---|---|
| nx-style postinstall AI-CLI harvest | reconstructed | caught (HOOK-NPM, HIGH) | postinstall runs a new script |
| Shai-Hulud-style token steal + republish | reconstructed | caught (HOOK-NPM + EXEC-DROPPER) | same |
| tj-actions-style fetch+run+dump (`dist/`) | reconstructed | caught (EXEC-DROPPER) | download, write file, execSync |
| tj-actions-style (readable `src/`) | reconstructed | caught (EXEC-DROPPER) | control |
| xz binary test files | real structure | **missed** | diff has no text; no rule looks at binaries |
| xz-style m4 extract and run | reconstructed | **missed** in the first run; **caught since #10** (`EXEC-OBFUSCATED`, block) | `tr`/`xz -d` piped into `/bin/sh` from a file in the tree: no download, so no dropper signals |
| event-stream dependency add | real structure | **missed** | one line adding an unknown package; needs registry reputation, outside diff scope |
| event-stream-style decrypt + `Module._compile` | reconstructed | **missed** in the first run; **caught since #10** (`EXEC-OBFUSCATED`, block) | runtime decrypt-and-compile was not in the rule set |

**First-run recall 4/8 (50%).** Today 6 of 8 block, but `EXEC-OBFUSCATED` was written looking at the 2 it now catches, so 50% remains the only untuned figure. Small n, and the 4 hits are the cases closest to what the rules were built for (install hook or download-and-run); the cases were reconstructed by the same author who knows the rules, so treat 50% as an upper-leaning figure, not a measurement of the real world.

**Runner output differs from the verdicts.** `python -m pr_scanner.corpus corpus_real` still prints `4/8 detected` and FAILs the two cases above, because their `meta.json` expects `EXEC-DROPPER` while `EXEC-OBFUSCATED` fires (outcome `block`). `meta.json` was left as written on purpose, so the first-run expectation is not re-scored after tuning. Read the `fired=` and `outcome=` fields, not the count.

## Gaps found
1. **No obfuscated/in-memory execution rule** (decrypt-then-eval/`_compile`, `... | sh` of a local file). **Done in #10 (`EXEC-OBFUSCATED`).**
2. **Binary files added or changed in test/fixture paths** are invisible. Candidate: INFO/WARN signal for binary changes where no source changed (xz).
3. **New-dependency signal** (event-stream). Needs data outside the diff; relates to FR-18 and the cross-PR ledger idea.
4. Not covered by any case: PR-title / branch-name injection (Ultralytics class), tarball-only payloads (scanner never sees them).
