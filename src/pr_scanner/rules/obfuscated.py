"""EXEC-OBFUSCATED: decode-then-run, and a decoded stream piped into a shell.

Origin: the first real-attack recall run (docs/recall-real-attacks.md) missed two
techniques seen in the xz backdoor and in event-stream: a payload hidden in data
that is decoded or decrypted and then executed *from memory* or through a shell,
with no download and no process-spawn call that ``EXEC-DROPPER`` looks for.

Signal: in one file's added lines, a *decode* primitive (base64, hex, zlib, xz,
a cipher) close to a *dynamic execution* primitive (``eval``/``exec``,
``new Function``, ``Module._compile``, ``vm.run*``, shell ``eval``, a pipe into
a shell). Each alone is common. Distance is counted in code lines (blank and
comment lines are free, so padding cannot separate the signals).

Severity: same line or within 5 code lines is HIGH; within 12 is MEDIUM; a CI
check anywhere in the file makes a HIGH finding CRITICAL (ADR-0004: code that
hides under CI cannot hide from a diff). A file with more than 100,000 code
characters (bundled or generated output, where both primitives co-occur by
accident) is capped at LOW so it stays visible without blocking.

``exec(open("_version.py").read())`` (running a file that is itself in the repo, the common
setup.py version idiom) is not a hidden payload and is excluded.

Known limits: only added lines; decoding or execution built from strings or
looked up dynamically is not seen; the same file only; payloads that live in
binary files or in release tarballs outside git are invisible to any diff rule.
"""

from __future__ import annotations

import posixpath
import re
from typing import Sequence

from ..classify import FileKind, classify
from ..models import ChangedFile, Diff, Finding, Severity
from ._patterns import cap, evidence
from .base import Rule
from .dropper import _CI, _COMMENT_PREFIXES, _FILLER, LARGE_FILE_CODE_CHARS

_DECODE = re.compile(
    r"\bbase64\b|\batob\s*\(|\bb64decode\b|\bfromhex\b|\bunhexlify\b|\bcreateDecipher(?:iv)?\b"
    r"|\bzlib\.(?:decompress|inflate|gunzip|unzip)\w*|\b(?:gunzip|inflate|unzip)Sync\b|\bmarshal\.loads\b"
    r"|\bcodecs\.decode\b|\brot13\b|\b(?:xz|gzip|bzip2|lzma)\s+-d\b|\b(?:unxz|xzcat|zcat|bzcat|lzcat)\b"
    r"|\bopenssl\s+enc\b|\bxxd\s+-r\b"
)
_EXEC = re.compile(
    r"(?<![.\w])(?:eval|exec)\s*\((?!\s*(?:compile\s*\(\s*)?open\s*\()|\bnew\s+Function\s*\(|\bvm\.(?:runIn\w+|Script)\b|\brunIn(?:This|New)Context\b"
    r"|\._compile\s*\(|(?<![\w.-])eval\s+[\"'$`(]|\bsource\s+<\(|(?<![|])\|\s*(?:sudo\s+)?(?:/(?:usr/)?bin/)?(?:ba|z|da|k)?sh\b"
)

# Cheap C-speed substring checks so ordinary lines skip the regexes (the regexes decide; these only filter).
_DECODE_KW = ("base64", "atob", "b64decode", "fromhex", "unhexlify", "Decipher", "zlib", "Sync", "marshal",
              "codecs", "rot13", "xz", "gzip", "bzip2", "lzma", "zcat", "bzcat", "lzcat", "openssl", "xxd")
_EXEC_KW = ("eval", "exec", "Function", "vm.", "runIn", "_compile", "source", "|")

_EXTRA_EXT = {".m4", ".ac", ".am", ".in", ".cmake", ".mk", ".gradle", ".rake", ".pl", ".lua"}
_CODE_KINDS = {FileKind.SOURCE, FileKind.BUILD_SCRIPT}
HIGH_LINES = 5
MEDIUM_LINES = 12


def _is_candidate(f: ChangedFile) -> bool:
    if f.status == "removed" or f.is_binary:
        return False
    base = posixpath.basename(f.path.lower())
    return classify(f.path) in _CODE_KINDS or base == "setup.py" or posixpath.splitext(base)[1] in _EXTRA_EXT


class ObfuscatedExec(Rule):
    id = "EXEC-OBFUSCATED"
    version = "1"
    category = "obfuscation"
    description = "file decodes or decrypts data and runs it from memory or through a shell"

    def evaluate(self, diff: Diff) -> Sequence[Finding]:
        return [x for f in diff.files if _is_candidate(f) for x in [self._file(f)] if x is not None]

    def _file(self, f: ChangedFile) -> Finding | None:
        decodes: list[tuple[int, int]] = []  # (code-line index, line number)
        execs: list[tuple[int, int, str]] = []
        ci_line = 0
        code_chars = idx = 0
        for line_no, raw in f.added_lines:
            if not raw.strip() or raw.lstrip().startswith(_COMMENT_PREFIXES):
                continue
            idx += 1
            s = cap(raw)
            code_chars += len(_FILLER.sub("", s))
            if any(k in s for k in _DECODE_KW) and _DECODE.search(s):
                decodes.append((idx, line_no))
            if any(k in s for k in _EXEC_KW) and _EXEC.search(s):
                execs.append((idx, line_no, raw))
            if not ci_line and _CI.search(s):
                ci_line = line_no
        if not decodes or not execs:
            return None
        best = min(
            ((abs(ei - di), el, raw, dl) for ei, el, raw in execs for di, dl in decodes),
            key=lambda t: (t[0], t[1]),
        )
        gap, exec_line, raw, decode_line = best
        if gap > MEDIUM_LINES:
            return None
        sev = Severity.HIGH if gap <= HIGH_LINES else Severity.MEDIUM
        if sev == Severity.HIGH and ci_line:
            sev = Severity.CRITICAL
        if code_chars > LARGE_FILE_CODE_CHARS:
            sev = Severity.LOW
        why = (
            f"This file decodes or decrypts data (line {decode_line}) and runs the result through eval/exec, "
            f"a dynamic code loader or a shell (line {exec_line}). Hiding a payload in encoded data that is "
            "executed from memory defeats code review and is typical of a backdoor or dropper."
        )
        if ci_line:
            why += (
                f" It also checks the CI environment (line {ci_line}); code that behaves differently under CI can"
                " pass automated checks while acting only on real users' machines."
            )
        if sev == Severity.LOW:
            why += " The file is large (bundled or generated output), so this is informational."
        return Finding(
            rule_id=self.id,
            severity=sev,
            file=f.path,
            line=exec_line,
            evidence=evidence(raw),
            rationale=why,
            remediation=(
                "Do not execute decoded or decrypted data. Commit the readable source, or load a pinned, "
                "checksum-verified dependency. If this is intentional, have a second maintainer review the "
                "decoded content, not just the code that loads it."
            ),
            confidence=0.9 if sev >= Severity.CRITICAL else 0.7 if sev == Severity.HIGH else 0.4,
        )
