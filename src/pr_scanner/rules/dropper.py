"""FR-20 / FR-21, T-D16 + T-D17: remote binary dropper, optionally CI-aware.

Origin: a real incident reported by the project owner, a process spawner that
behaved differently under CI and installed a binary from a remote server.

Individually, spawning a process, downloading data and reading CI variables are
all ordinary. The signal is the *combination* inside one file's added lines.
Because this scanner only reads the diff, code that hides itself when it
detects CI cannot evade it (ADR-0004).

Large generated files (found by measuring 800 real merged PRs): a compiled
bundle concatenates many unrelated modules, so download code and process-spawn
code co-occur by accident. For a file with more than ``LARGE_FILE_CODE_CHARS``
added code characters the signals must therefore be *near each other* (within
``WINDOW_CODE_CHARS``). Distance counts code characters only: whitespace,
zero-width characters, comment lines and inline block comments do not count, so
padding with them cannot separate signals. Detection itself never strips
comments (``"/*"`` inside a string would otherwise hide a call). A diff only
holds *added* lines, so a dropper added to an existing file is small and keeps
whole-file correlation; only new or regenerated files get large. A large file
whose signals are far apart still yields a LOW finding, so it stays visible.

Known limits: signals split across different files, or hidden behind dynamic
lookups (getattr, string building, eval), are not correlated (T-D14); more than
``LARGE_FILE_CODE_CHARS`` of real-looking code between two signals in one file
reduces them to LOW (documented in tests).
"""

from __future__ import annotations

import posixpath
import re
from bisect import bisect_left
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
    r"\bchmod\s+(?:\+x|u\+x|a\+x|[0-7]*[1357][0-7]{0,2}\b)|\bos\.chmod\s*\([^\n]{0,80}?\b0o?[0-7]*[1357]\b"
    r"|\bchmodSync\s*\(|\bfs\.chmod\s*\(|\bos\.Chmod\s*\(|\bS_IXUSR\b|\bsetExecutable\s*\("
)
_CI = re.compile(
    r"\b(?:GITHUB_ACTIONS|GITLAB_CI|TRAVIS|CIRCLECI|JENKINS_URL|BUILDKITE|TF_BUILD|APPVEYOR|CODEBUILD_BUILD_ID)\b"
    r"|environ(?:\.get)?\s*[\[(]\s*[\"']CI[\"']|[\"']CI[\"']\s+(?:not\s+)?in\s+os\.environ"
    r"|process\.env\.CI\b|getenv\s*\(\s*[\"']CI[\"']|\$\{?CI\}?\b|\bis[_-]?ci\b|\bci-info\b",
    re.IGNORECASE,
)
_RAW_IP_URL = re.compile(r"(?:https?|ftp)://\d{1,3}(?:\.\d{1,3}){3}\b|(?:https?|ftp)://\[[0-9a-fA-F:]+\]")


LARGE_FILE_CODE_CHARS = 100_000  # real bundles: 0.7-3.3 MB; real droppers and fixtures: under 1 KB
WINDOW_CODE_CHARS = 3_000  # real bundles: signals 6.8k-1.2M apart; real droppers: under 200

_FILLER = re.compile("[\\s\u00ad\u200b-\u200f\u2060-\u206f\ufeff]+")
_KINDS = (
    ("spawn", _SPAWN),
    ("chmod", _CHMOD),
    ("download", _DOWNLOAD),
    ("ci", _CI),
    ("rawip", _RAW_IP_URL),
)


def _mask_block_comments(s: str) -> str:
    """Blank out inline ``/* ... */`` text (same length) so it does not count as distance.
    Used only for measuring distance, never for finding signals. Linear: each ``find`` moves on."""
    if "/*" not in s:
        return s
    out, pos = [], 0
    while True:
        a = s.find("/*", pos)
        if a < 0:
            break
        b = s.find("*/", a + 2)
        if b < 0:
            break
        out.append(s[pos:a])
        out.append(" " * (b + 2 - a))
        pos = b + 2
    out.append(s[pos:])
    return "".join(out)


def _scan_signals(f: ChangedFile) -> tuple[dict[str, list[tuple[int, int]]], int]:
    """Every signal as (offset in code characters, line number), and the total code characters."""
    sig: dict[str, list[tuple[int, int]]] = {k: [] for k, _ in _KINDS}
    code = 0
    for line_no, raw in f.added_lines:
        if raw.lstrip().startswith(_COMMENT_PREFIXES):
            continue
        s = cap(raw)
        found = [(m.start(), kind) for kind, rx in _KINDS for m in rx.finditer(s)]
        masked = _mask_block_comments(s)
        if not found:
            code += len(_FILLER.sub("", masked))
            continue
        found.sort()
        prev = run = 0
        for start, kind in found:
            if start > prev:
                run += len(_FILLER.sub("", masked[prev:start]))
                prev = start
            sig[kind].append((code + run, line_no))
        run += len(_FILLER.sub("", masked[prev:]))
        code += run
    return sig, code


def _near(entries: list[tuple[int, int]], *centres: int) -> tuple[int, int] | None:
    """First entry within the window of any centre."""
    offsets = [o for o, _ in entries]
    best = None
    for c in centres:
        i = bisect_left(offsets, c - WINDOW_CODE_CHARS)
        if i < len(offsets) and offsets[i] <= c + WINDOW_CODE_CHARS:
            if best is None or entries[i][0] < best[0]:
                best = entries[i]
    return best


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
            sig, code = _scan_signals(f)
            if not (sig["spawn"] or sig["chmod"] or sig["download"] or sig["ci"]):
                continue
            finding = self._large(f, sig) if code > LARGE_FILE_CODE_CHARS else self._whole_file(f, sig)
            if finding is not None:
                out.append(finding)
        return out

    # ---- ordinary files: signals anywhere in the added lines count together -----------------

    def _whole_file(self, f: ChangedFile, sig) -> Finding | None:
        hits = {k: [line for _, line in v] for k, v in sig.items()}
        executes = bool(hits["spawn"] or hits["chmod"])
        downloads = bool(hits["download"])
        ci = bool(hits["ci"])
        if executes and downloads:
            sev = Severity.CRITICAL if (ci or hits["rawip"]) else Severity.HIGH
        elif executes and ci and hits["spawn"]:
            sev = Severity.MEDIUM
        else:
            return None
        first = min(hits["spawn"][:1] + hits["chmod"][:1])
        return self._build(f, sev, first, hits)

    # ---- large generated files: signals must be close together -----------------------------

    def _large(self, f: ChangedFile, sig) -> Finding | None:
        execs = sorted(sig["spawn"] + sig["chmod"])
        downs = sig["download"]
        down_offsets = [o for o, _ in downs]
        for e_off, e_line in execs:
            i = bisect_left(down_offsets, e_off)
            for j in (i - 1, i):
                if 0 <= j < len(downs) and abs(down_offsets[j] - e_off) <= WINDOW_CODE_CHARS:
                    d_off, d_line = downs[j]
                    ci = _near(sig["ci"], e_off, d_off)
                    rawip = _near(sig["rawip"], e_off, d_off)
                    hits = {
                        "spawn": [e_line] if _is_in(sig["spawn"], e_off, e_line) else [],
                        "chmod": [e_line] if _is_in(sig["chmod"], e_off, e_line) else [],
                        "download": [d_line],
                        "ci": [ci[1]] if ci else [],
                        "rawip": [rawip[1]] if rawip else [],
                    }
                    sev = Severity.CRITICAL if (ci or rawip) else Severity.HIGH
                    return self._build(f, sev, e_line, hits)
        for s_off, s_line in sig["spawn"]:
            ci = _near(sig["ci"], s_off)
            if ci:
                return self._build(f, Severity.MEDIUM, s_line, {"spawn": [s_line], "chmod": [], "download": [], "ci": [ci[1]], "rawip": []})
        if execs and downs:
            line = min(execs, key=lambda e: e[1])[1]
            raw = dict(f.added_lines)[line]
            return Finding(
                rule_id=self.id,
                severity=Severity.LOW,
                file=f.path,
                line=line,
                evidence=evidence(raw),
                rationale=(
                    "This is a large added file (typically bundled or generated build output). It contains both "
                    "download code and process-execution code, but they are far apart rather than close together, so "
                    "they are not treated as one dropper. Bundled output cannot be reviewed line by line."
                ),
                remediation=(
                    "Check that the bundle was regenerated from reviewed source and that nothing was edited by hand "
                    "in the generated file."
                ),
                confidence=0.3,
            )
        return None

    # ---- shared ---------------------------------------------------------------------------

    def _build(self, f: ChangedFile, sev: Severity, first_exec_line: int, hits: dict[str, list[int]]) -> Finding:
        downloads, ci = bool(hits["download"]), bool(hits["ci"])
        executes = bool(hits["spawn"] or hits["chmod"])
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
        raw = dict(f.added_lines)[first_exec_line]
        return Finding(
            rule_id=self.id,
            severity=sev,
            file=f.path,
            line=first_exec_line,
            evidence=evidence(raw),
            rationale=why,
            remediation=(
                "Do not download and execute binaries from application code. Vendor the dependency, or "
                "install it through the package manager with pinned versions and checksum verification. "
                "If this is intentional, have a second maintainer review the exact source and URL."
            ),
            confidence=0.9 if sev >= Severity.CRITICAL else 0.7 if sev == Severity.HIGH else 0.4,
        )


def _is_in(entries: list[tuple[int, int]], offset: int, line: int) -> bool:
    return (offset, line) in entries
