# Rule catalog

Each rule maps to a threat in [04](04-threat-model.md) and a requirement in [02](02-requirements.md), and must have malicious and benign corpus fixtures (FR-16, enforced by `tests/test_corpus.py`).

| Rule | Threat | Req | Looks at (added lines only) |
|---|---|---|---|
| `HOOK-NPM` | T-D01, T-D02, T-D07 | FR-04 | `package.json` lifecycle scripts |
| `HOOK-PYSETUP` | T-D01, T-D02 | FR-04 | `setup.py` |
| `HOOK-PYBACKEND` | T-D01 | FR-04 | `pyproject.toml` |

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

## Corpus status and honest limits
The current corpus (`corpus/`) was written together with the rules by the same author. 100% recall and zero blocked benign cases on it show the rules work as designed, **not** that they will perform well on real attacks. Before trusting any metric in `00-vision-and-scope.md` we need: real-world defanged samples (including the reported incident), an independently authored adversarial set, and a larger sample of real benign PRs. Run the corpus with `python -m pr_scanner.corpus corpus`.
