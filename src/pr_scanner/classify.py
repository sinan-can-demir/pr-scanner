"""Classify changed paths so rules can target the files that matter.

Pure string logic on the path only; the file is never opened (ADR-0004).
Matching is case-insensitive on purpose: over-flagging a path is safer than
missing one.
"""

from __future__ import annotations

import posixpath
import re
from enum import Enum


class FileKind(str, Enum):
    MANIFEST = "manifest"
    LOCKFILE = "lockfile"
    CI_WORKFLOW = "ci_workflow"
    BUILD_SCRIPT = "build_script"
    SCANNER_CONFIG = "scanner_config"
    SOURCE = "source"
    OTHER = "other"


_MANIFESTS = {
    "package.json", "setup.py", "setup.cfg", "pyproject.toml", "pipfile", "go.mod",
    "cargo.toml", "pom.xml", "gemfile", "build.gradle", "build.gradle.kts", "composer.json",
}
_LOCKFILES = {
    "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
    "pipfile.lock", "cargo.lock", "go.sum", "uv.lock", "gemfile.lock", "composer.lock",
}
_CI_NAMES = {".gitlab-ci.yml", "jenkinsfile", "azure-pipelines.yml", ".travis.yml"}
_SOURCE_EXT = {
    ".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".go", ".rs", ".rb", ".java",
    ".kt", ".c", ".cc", ".cpp", ".h", ".hpp", ".cs", ".php", ".swift",
}
_SCRIPT_EXT = {".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd"}
_REQUIREMENTS = re.compile(r"^requirements.*\.txt\Z")


def _normalise(path: str) -> str:
    p = posixpath.normpath(path.replace("\\", "/").lower())
    return p[2:] if p.startswith("./") else p


def classify(path: str) -> FileKind:
    p = _normalise(path)
    base = posixpath.basename(p)
    ext = posixpath.splitext(base)[1]

    # Only the repository-root .github is executed by GitHub.
    if p.startswith(".github/workflows/") and ext in {".yml", ".yaml"}:
        return FileKind.CI_WORKFLOW
    if p.startswith(".github/actions/") and base in {"action.yml", "action.yaml"}:
        return FileKind.CI_WORKFLOW
    if base in _CI_NAMES or p.startswith(".circleci/"):
        return FileKind.CI_WORKFLOW

    if base in {".pr-scanner.yml", ".pr-scanner.yaml", "codeowners"}:
        return FileKind.SCANNER_CONFIG

    if base in _LOCKFILES:
        return FileKind.LOCKFILE
    if base in _MANIFESTS or _REQUIREMENTS.match(base):
        return FileKind.MANIFEST

    if (
        base == "dockerfile"
        or base.startswith("dockerfile.")
        or base.endswith(".dockerfile")
        or base == "makefile"
        or ext in _SCRIPT_EXT
    ):
        return FileKind.BUILD_SCRIPT

    if ext in _SOURCE_EXT:
        return FileKind.SOURCE
    return FileKind.OTHER
