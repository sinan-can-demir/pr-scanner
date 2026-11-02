# Rule catalog

Each rule maps to a threat in [04](04-threat-model.md) and a requirement in [02](02-requirements.md), and must have malicious and benign corpus fixtures (FR-16, enforced by `tests/test_corpus.py`).

| Rule | Threat | Req | Looks at (added lines only) |
|---|---|---|---|
| `HOOK-NPM` | T-D01, T-D02, T-D07 | FR-04 | `package.json` lifecycle scripts |
| `HOOK-PYSETUP` | T-D01, T-D02 | FR-04 | `setup.py` |
| `HOOK-PYBACKEND` | T-D01 | FR-04 | `pyproject.toml` |
| `EXEC-DROPPER` | T-D16, T-D17 | FR-20, FR-21 | source files, build scripts, `setup.py` |

## HOOK-NPM
Flags `preinstall`, `install`, `postinstall`, `prepare`, `preprepare`, `postprepare`, `prepublish` entries.

| Severity | When |
|---|---|
| Critical | command downloads/pipes to an interpreter, decodes a payload, runs inline code, uses a raw IP/URL, opens a socket, or touches credentials |
| High | hook runs a script file that is added or modified in the same PR |
| Medium | any other install-time hook (`preinstall`/`install`/`postinstall`) |
| Low | any other `prepare`-style hook |
| none | exact match of a small allowlist (`husky install`, `node-gyp rebuild`, `patch-package`, `tsc`, `npm run build`, ...) |

Evasions handled: JSON unicode-escaped keys (`"postinstall"`), shell quote/backslash splitting (`c""url`, `cu\rl`), `${IFS}` as a separator, single-line minified JSON. `||` is treated as logical OR, not a pipe.

Known limits: the hook key is matched on a single line, so a key and value split across lines are not seen; only added lines are inspected, so a malicious script that already existed is not re-reported; the key is not verified to be inside `"scripts"` (over-flags).

## HOOK-PYSETUP
| Severity | When |
|---|---|
| Critical | network access, or decode/deserialise of an embedded payload |
| High | `cmdclass` / subclassing `install`, `develop`, `egg_info`, `build_py`, `build_ext`, `sdist`, `bdist_wheel` |
| Medium | `exec`/`eval`/`compile`/`__import__`, `os.system`, `subprocess` |

Expected false positives: `exec(open("_version.py").read())` and `subprocess` calls to read a git version are common in legitimate `setup.py` files and produce a Medium (warn).

## HOOK-PYBACKEND
High when `build-backend` is not in a short list of well-known backends, or when `backend-path` (in-tree backend) is added. Changes to `requires` are not yet inspected.

## EXEC-DROPPER
Modelled on the reported incident: a process spawner that stayed quiet under CI and installed a binary from a remote server. Correlates signals across all added lines of **one file**.

| Severity | When |
|---|---|
| Critical | download + (spawn or chmod), and either CI-gated or fetched from a raw IP |
| High | download + (spawn or chmod) |
| Medium | CI-environment check + process spawn, no download |
| none | any single signal alone; commented-out code; `regex.exec()` |

Signals: spawn (`subprocess`, `os.system`, `child_process`, `exec.Command`, `Runtime.exec`, `system()`...), download (`urlretrieve`, `requests.get`, `https.get`, `fetch(`, `http.Get`, `curl`, `wget`...), make-executable (`chmod +x`, `os.chmod`, `fs.chmodSync`...), CI check (`CI`, `GITHUB_ACTIONS`, `GITLAB_CI`, `TRAVIS`, `JENKINS_URL`, `is-ci`...).

Known limits:
- Signals in *different* files are not correlated (T-D14); dynamic lookups (`getattr(subprocess, ...)`, string building, `eval`) are not seen.
- Only added lines: if the downloader already exists and the PR adds only the spawn, it is missed.
- Expected false positives: legitimate installers that fetch a prebuilt binary and run it (esbuild/puppeteer-style postinstall scripts) will block under the default policy. These need a reviewed suppression (FR-11).
- The description of the original incident is approximate; refine the fixtures when real details are available.

## Line-length handling
Rules scan whole lines. The engine truncates lines over 1,000,000 characters and marks the scan `INCOMPLETE` so oversized lines are never skipped silently. (An earlier version truncated at 4,000 characters inside the rules, which let an attacker hide a payload behind padding; fixed with regression tests.)

## Corpus status and honest limits
The current corpus (`corpus/`) was written together with the rules by the same author. 100% recall and zero blocked benign cases on it show the rules work as designed, **not** that they will perform well on real attacks. Before trusting any metric in `00-vision-and-scope.md` we need: real-world defanged samples (including the reported incident), an independently authored adversarial set, and a larger sample of real benign PRs. Run the corpus with `python -m pr_scanner.corpus corpus`.
