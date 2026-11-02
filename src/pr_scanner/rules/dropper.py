"""FR-20 / FR-21, T-D16 + T-D17: remote binary dropper, optionally CI-aware.

Origin: a real incident reported by the project owner, a process spawner that
behaved differently under CI and installed a binary from a remote server.

Individually, spawning a process, downloading data and reading CI variables are
all ordinary. The signal is the *combination* inside one file's added lines.
Because this scanner only reads the diff, code that hides itself when it
detects CI cannot evade it (ADR-0004).

Known limits: signals split across different files, or hidden behind dynamic
lookups (getattr, string building, eval), are not correlated (T-D14).
"""

from __future__ import annotations

import posixpath
import re
from typing import Sequence

from ..classify import FileKind, classify
from ..models import ChangedFile, Diff, Finding, Severity
from .base import Rule
from ._patterns import cap, evidence

_CODE_KINDS = {FileKind.SOURCE, FileKind.BUILD_SCRIPT}
_COMMENT_PREFIXES = ("#", "//", "/*", "*", "--")

_SPAWN = re.compile(
    r"\bsubprocess\.\w+|\bos\.(?:system|popen|exec\w*|spawn\w*)\b|\bpty\.spawn\b"
    r"|\bchild_process\b|\b(?:execSync|spawnSync|execFileSync|execFile)\s*\(|(?<![.\w])spawn\s*\("
    r"|\bexec\.Command\w*\s*\(|\bRuntime\.getRuntime\(\)\.exec\b|\bProcessBuilder\b|\bOpen3\b"
    r"|\bsystem\s*\(|\bpopen\s*\(|\bProcess\.Start\s*\("
)
_DOWNLOAD = re.compile(
    r"\b(?:urlopen|urlretrieve|urllib\.request|requests\.(?:get|post)|httpx\.\w+|aiohttp|http\.client)\b"
    r"|\bhttps?\.get\s*\(|\bfetch\s*\(|\baxios\b|\bnode-fetch\b|\bgot\s*\("
    r"|\bhttp\.Get\s*\(|\bwget\b|\bcurl\b|\bInvoke-WebRequest\b|\biwr\b|\bDownloadFile\b|\bDownloadString\b"
    r"|\bNet::HTTP\b|\bURI\.open\b|\bopen-uri\b"
)
_CHMOD = re.compile(
    r"\bchmod\s+(?:\+x|u\+x|a\+x|[0-7]*[1357][0-7]{0,2}\b)|\bos\.chmod\s*\(.*\b0o?[0-7]*[1357]\b"
    r"|\bchmodSync\s*\(|\bfs\.chmod\s*\(|\bos\.Chmod\s*\(|\bS_IXUSR\b|\bsetExecutable\s*\("
)
_CI = re.compile(
    r"\b(?:GITHUB_ACTIONS|GITLAB_CI|TRAVIS|CIRCLECI|JENKINS_URL|BUILDKITE|TF_BUILD|APPVEYOR|CODEBUILD_BUILD_ID)\b"
    r"|environ(?:\.get)?\s*[\[(]\s*[\"']CI[\"']|[\"']CI[\"']\s+(?:not\s+)?in\s+os\.environ"
    r"|process\.env\.CI\b|getenv\s*\(\s*[\"']CI[\"']|\$\{?CI\}?\b|\bis[_-]?ci\b|\bci-info\b",
    re.IGNORECASE,
)
_RAW_IP_URL = re.compile(r"(?:https?|ftp)://\d{1,3}(?:\.\d{1,3}){3}\b|(?:https?|ftp)://\[[0-9a-fA-F:]+\]")


def _is_candidate(f: ChangedFile) -> bool:
    if f.status == "removed" or f.is_binary:
        return False
    return classify(f.path) in _CODE_KINDS or posixpath.basename(f.path).lower() == "setup.py"


class RemoteBinaryExec(Rule):
    id = "EXEC-DROPPER"
    version = "1"
    category = "dropper"
    description = "file adds both remote download and process execution / chmod +x, optionally gated on CI environment"

    def evaluate(self, diff: Diff) -> Sequence[Finding]:
        out: list[Finding] = []
        for f in diff.files:
            if not _is_candidate(f):
                continue
            hits: dict[str, list[int]] = {"spawn": [], "chmod": [], "download": [], "ci": [], "rawip": []}
            first_exec: tuple[int, str] | None = None
            for line_no, raw in f.added_lines:
                if raw.lstrip().startswith(_COMMENT_PREFIXES):
                    continue
                s = cap(raw)
                spawn, chmod = _SPAWN.search(s), _CHMOD.search(s)
                if spawn:
                    hits["spawn"].append(line_no)
                if chmod:
                    hits["chmod"].append(line_no)
                if (spawn or chmod) and first_exec is None:
                    first_exec = (line_no, raw)
                if _DOWNLOAD.search(s):
                    hits["download"].append(line_no)
                if _CI.search(s):
                    hits["ci"].append(line_no)
                if _RAW_IP_URL.search(s):
                    hits["rawip"].append(line_no)

            executes = bool(hits["spawn"] or hits["chmod"])
            downloads = bool(hits["download"])
            ci = bool(hits["ci"])
            if executes and downloads:
                sev = Severity.CRITICAL if (ci or hits["rawip"]) else Severity.HIGH
            elif executes and ci and hits["spawn"]:
                sev = Severity.MEDIUM
            else:
                continue

            assert first_exec is not None
            parts = []
            if downloads:
                parts.append(f"downloads remote content (line {hits['download'][0]})")
            if hits["spawn"]:
                parts.append(f"spawns a process (line {hits['spawn'][0]})")
            if hits["chmod"]:
                parts.append(f"makes a file executable (line {hits['chmod'][0]})")
            if ci:
                parts.append(f"changes behaviour based on the CI environment (line {hits['ci'][0]})")
            if hits["rawip"]:
                parts.append(f"contacts a raw IP address (line {hits['rawip'][0]})")
            why = "This file " + ", ".join(parts) + "."
            if ci:
                why += (
                    " Code that behaves differently under CI can pass automated checks while acting only on"
                    " real users' machines."
                )
            if downloads and executes:
                why += " Downloading and running a binary is the typical pattern of a malware dropper."

            out.append(
                Finding(
                    rule_id=self.id,
                    severity=sev,
                    file=f.path,
                    line=first_exec[0],
                    evidence=evidence(first_exec[1]),
                    rationale=why,
                    remediation=(
                        "Do not download and execute binaries from application code. Vendor the dependency, or "
                        "install it through the package manager with pinned versions and checksum verification. "
                        "If this is intentional, have a second maintainer review the exact source and URL."
                    ),
                    confidence=0.9 if sev >= Severity.CRITICAL else 0.7 if sev == Severity.HIGH else 0.4,
                )
            )
        return out
