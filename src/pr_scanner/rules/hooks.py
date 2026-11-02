"""FR-04 / T-D01: install-time hooks and build-backend changes.

All three rules look only at *added* lines of specific manifest files and
never open, import or execute anything (ADR-0004).
"""

from __future__ import annotations

import json
import posixpath
import re
import shlex
from typing import Sequence

from ..models import Diff, Finding, Severity
from .base import Rule
from ._patterns import cap, evidence, json_string_pairs, suspicious_reasons


def _basename(path: str) -> str:
    return posixpath.basename(path).lower()


# ------------------------------------------------------------------ npm hooks

INSTALL_TIME_HOOKS = {"preinstall", "install", "postinstall"}  # run for every dependent
OTHER_HOOKS = {"prepare", "preprepare", "postprepare", "prepublish"}  # git installs / local installs
_HOOKS = INSTALL_TIME_HOOKS | OTHER_HOOKS

# Whole-command allowlist for ubiquitous, benign hooks. fullmatch, so
# "node-gyp rebuild && curl ... | sh" is NOT allowlisted.
_BENIGN_HOOKS = [
    re.compile(p)
    for p in (
        r"node-gyp rebuild",
        r"node-gyp-build",
        r"prebuild-install(?: \|\| node-gyp rebuild)?",
        r"husky(?: install)?(?: \.husky)?",
        r"(?:is-ci \|\| )?husky(?: install)?",
        r"patch-package",
        r"tsc(?: -p \.| --build)?",
        r"npm run build",
        r"yarn build",
        r"pnpm (?:run )?build",
        r"electron-rebuild",
    )
]
_SEMVER_STRICT = re.compile(r"[\^~<>=v]*\s*\d+(?:\.(?:\d+|x|\*))*")
_SCRIPT_EXT = (".js", ".cjs", ".mjs", ".ts", ".sh", ".bash", ".py", ".ps1", ".bat", ".cmd", ".rb", ".pl")


def _decode_json_string(token: str) -> str | None:
    try:
        value = json.loads(token)  # data parsing only; no code execution
    except ValueError:
        return None
    return value if isinstance(value, str) else None


def _referenced_changed_files(command: str, package_dir: str, changed: set[str]) -> list[str]:
    try:
        tokens = shlex.split(command)
    except ValueError:
        tokens = command.split()
    hits = []
    for tok in tokens:
        if tok.startswith("-") or not ("/" in tok or tok.lower().endswith(_SCRIPT_EXT)):
            continue
        resolved = posixpath.normpath(posixpath.join(package_dir, tok))
        if resolved in changed:
            hits.append(tok)
    return hits


class NpmLifecycleHook(Rule):
    id = "HOOK-NPM"
    version = "1"
    category = "install-hooks"
    description = "npm lifecycle scripts (preinstall/install/postinstall/prepare) added or changed in package.json"

    def evaluate(self, diff: Diff) -> Sequence[Finding]:
        changed = {posixpath.normpath(f.path) for f in diff.files if f.status != "removed"}
        out: list[Finding] = []
        for f in diff.files:
            if f.status == "removed" or f.is_binary or _basename(f.path) != "package.json":
                continue
            pkg_dir = posixpath.dirname(f.path)
            for line_no, raw in f.added_lines:
                for key_tok, val_tok in json_string_pairs(cap(raw)):
                    key, cmd = _decode_json_string(key_tok), _decode_json_string(val_tok)
                    if key not in _HOOKS or cmd is None:
                        continue
                    if _SEMVER_STRICT.fullmatch(cmd.strip()):
                        continue  # a dependency that happens to be named "install"
                    finding = self._classify(f.path, line_no, raw, key, cmd, pkg_dir, changed)
                    if finding:
                        out.append(finding)
        return out

    def _classify(self, path, line_no, raw, key, cmd, pkg_dir, changed) -> Finding | None:
        if any(p.fullmatch(cmd.strip()) for p in _BENIGN_HOOKS):
            return None  # exact, strict allowlist: cannot hide extra commands
        reasons = suspicious_reasons(cmd)
        scripts = _referenced_changed_files(cmd, pkg_dir, changed)
        install_time = key in INSTALL_TIME_HOOKS
        when = "on every install by anyone who depends on this package" if install_time else "on local and git installs"

        if reasons:
            sev = Severity.CRITICAL
            why = f"The '{key}' hook {'; '.join(reasons)}."
        elif scripts:
            sev = Severity.HIGH
            why = f"The '{key}' hook runs {', '.join(scripts)}, which is added or modified in this same PR."
        elif install_time:
            sev, why = Severity.MEDIUM, f"A '{key}' hook was added or changed."
        else:
            sev, why = Severity.LOW, f"A '{key}' hook was added or changed."

        return Finding(
            rule_id=self.id,
            severity=sev,
            file=path,
            line=line_no,
            evidence=evidence(raw),
            rationale=f"{why} npm runs this script {when}, so it is a common supply-chain execution vector.",
            remediation=(
                f"Remove the '{key}' hook, or justify it in the PR description and have a second maintainer "
                "review exactly what it executes. Prefer explicit build steps over install-time scripts."
            ),
            confidence=0.9 if reasons else 0.6,
        )


# --------------------------------------------------------------- setup.py

_I = re.IGNORECASE
_CMDS = r"(?:install|develop|egg_info|build_py|build_ext|sdist|bdist_wheel)"
_PY_OVERRIDE = re.compile(
    rf"\bcmdclass\b|(?:setuptools|distutils)\.command\.{_CMDS}\b|\bclass\s+\w+\s*\(\s*(?:\w+\.)*{_CMDS}\s*\)"
)
_PY_NET = re.compile(r"\b(?:urlopen|urlretrieve|urllib|http\.client|requests\.(?:get|post|put)|socket|ftplib|paramiko)\b")
_PY_DECODE = re.compile(
    r"\b(?:b64decode|b32decode|a85decode|marshal\.loads|pickle\.loads|zlib\.decompress|bytes\.fromhex|binascii\.unhexlify)\b|codecs\.decode|rot_?13"
)
_PY_EXEC = re.compile(r"(?<![.\w])(?:exec|eval|compile)\s*\(|__import__\s*\(")
_PY_PROC = re.compile(r"\bos\.(?:system|popen|exec\w*)\b|\bsubprocess\.\w+|\bpty\.spawn\b")


class PySetupHook(Rule):
    id = "HOOK-PYSETUP"
    version = "1"
    category = "install-hooks"
    description = "setup.py install-command overrides and risky calls (network, decode+exec, subprocess)"

    def evaluate(self, diff: Diff) -> Sequence[Finding]:
        out: list[Finding] = []
        for f in diff.files:
            if f.status == "removed" or f.is_binary or _basename(f.path) != "setup.py":
                continue
            for line_no, raw in f.added_lines:
                s = cap(raw)
                if s.lstrip().startswith("#"):
                    continue
                reasons: list[tuple[Severity, str]] = []
                if _PY_NET.search(s):
                    reasons.append((Severity.CRITICAL, "accesses the network"))
                if _PY_DECODE.search(s):
                    reasons.append((Severity.CRITICAL, "decodes or deserialises an embedded payload"))
                if _PY_OVERRIDE.search(s):
                    reasons.append((Severity.HIGH, "overrides a setuptools install/build command"))
                if _PY_EXEC.search(s):
                    reasons.append((Severity.MEDIUM, "uses exec/eval/compile/__import__"))
                if _PY_PROC.search(s):
                    reasons.append((Severity.MEDIUM, "spawns a process"))
                if not reasons:
                    continue
                sev = max(r[0] for r in reasons)
                out.append(
                    Finding(
                        rule_id=self.id,
                        severity=sev,
                        file=f.path,
                        line=line_no,
                        evidence=evidence(raw),
                        rationale=(
                            "This line in setup.py " + "; ".join(r[1] for r in reasons) + ". "
                            "setup.py executes arbitrary Python at pip install / build time."
                        ),
                        remediation=(
                            "Avoid custom install commands and side effects in setup.py. Use declarative metadata "
                            "(pyproject.toml). If a command override is genuinely needed, have a second maintainer "
                            "review exactly what it runs."
                        ),
                        confidence=0.9 if sev >= Severity.CRITICAL else 0.6,
                    )
                )
        return out


# --------------------------------------------------------- pyproject backend

_KNOWN_BACKENDS = {
    "setuptools.build_meta",
    "setuptools.build_meta:__legacy__",
    "hatchling.build",
    "poetry.core.masonry.api",
    "flit_core.buildapi",
    "maturin",
    "pdm.backend",
    "scikit_build_core.build",
    "mesonpy",
    "uv_build",
}
_BACKEND = re.compile(r"""^\s*["']?build-backend["']?\s*=\s*(["'])(.*?)\1""")
_BACKEND_PATH = re.compile(r"""^\s*["']?backend-path["']?\s*=""")


class PyBuildBackend(Rule):
    id = "HOOK-PYBACKEND"
    version = "1"
    category = "install-hooks"
    description = "pyproject.toml build backend changed to an unknown value, or an in-tree backend added"

    def evaluate(self, diff: Diff) -> Sequence[Finding]:
        out: list[Finding] = []
        for f in diff.files:
            if f.status == "removed" or f.is_binary or _basename(f.path) != "pyproject.toml":
                continue
            for line_no, raw in f.added_lines:
                s = cap(raw)
                m = _BACKEND.match(s)
                if m and m.group(2).strip() not in _KNOWN_BACKENDS:
                    msg = f"The build backend is set to '{m.group(2).strip()[:80]}', which is not a recognised backend."
                elif _BACKEND_PATH.match(s):
                    msg = "An in-tree build backend (backend-path) was added; it runs code from the repository at build time."
                else:
                    continue
                out.append(
                    Finding(
                        rule_id=self.id,
                        severity=Severity.HIGH,
                        file=f.path,
                        line=line_no,
                        evidence=evidence(raw),
                        rationale=f"{msg} The build backend executes whenever the package is built or installed from source.",
                        remediation=(
                            "Use a well-known backend (setuptools, hatchling, poetry-core, flit-core, ...). "
                            "If a custom backend is intended, have a second maintainer review its code."
                        ),
                        confidence=0.8,
                    )
                )
        return out
