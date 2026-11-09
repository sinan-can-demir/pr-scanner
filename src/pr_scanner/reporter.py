"""Turn a scan result into a GitHub check-run payload (FR-09, FR-10, T-S05, NFR-08).

This module is pure: it builds data and never calls GitHub, so it can be tested exhaustively.

Everything in a finding may be attacker-controlled (file names, matched evidence, and even
error messages that quote them), and GitHub renders the summary as Markdown. So every string is
passed through one of two renderers before it reaches the output:

* :func:`_code` puts text in a code span whose fence is longer than any backtick run inside it.
  Nothing in a code span is rendered, linked or turned into a mention.
* :func:`_plain` escapes Markdown and HTML, and wraps the characters GitHub auto-links
  (``@``, ``#``, ``://``, ``www.``, ``GH-<n>``) in code spans so they cannot ping, link or reference.

Both first replace control, bidirectional and invisible characters with a visible ``⟦U+XXXX⟧``
marker, so hidden text is shown to the reviewer instead of acting on them (Trojan Source).
Newlines are collapsed, so a value can never start a heading, table, quote or fence of its own.

Conclusion mapping fails closed: only a complete, clean scan is ``success``. ``neutral`` (WARN)
passes required checks by design; INCOMPLETE is ``action_required`` so it can never read as green.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .engine import ScanResult
from .models import Finding, Severity
from .policy import Outcome

MAX_ANNOTATIONS = 50  # GitHub accepts at most 50 annotations per request
MAX_SUMMARY_CHARS = 65535  # GitHub's limit for output.summary (also enforced in bytes)
_TITLE_LIMIT = 255
_EVIDENCE_LIMIT = 300
_TEXT_LIMIT = 600
_MAX_PATH = 1024
_SHA = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")

_CONCLUSIONS = {
    Outcome.PASS: "success",
    Outcome.WARN: "neutral",
    Outcome.BLOCK: "failure",
    Outcome.ERROR: "failure",
    Outcome.INCOMPLETE: "action_required",
}
_LEVELS = {
    Severity.CRITICAL: "failure",
    Severity.HIGH: "failure",
    Severity.MEDIUM: "warning",
    Severity.LOW: "notice",
}

# C0/C1 controls, soft hyphen, Arabic letter mark, Hangul fillers, Mongolian selectors,
# zero-width and bidi controls, line/paragraph separators, invisible operators, BOM,
# interlinear annotation, tag characters, and lone surrogates.
_INVISIBLE = re.compile(
    "[\x00-\x1f\x7f-\x9f­͏؜ᅟᅠ឴឵᠋-᠎"
    "​-‏ -‮⁠-⁯ㅤ﻿ﾠ￰-￻"
    "\U000e0000-\U000e0fff\ud800-\udfff]"
)
_LINEBREAKS = "\n\r\t"
_AUTOLINK = re.compile(r"(@|#|GH-(?=\d)|://|www\.)", re.IGNORECASE)
_MD_ESCAPES = {ord(c): "\\" + c for c in "\\`*_~[]()!|#"}
_MD_ESCAPES.update({ord("&"): "&amp;", ord("<"): "&lt;", ord(">"): "&gt;"})


@dataclass(frozen=True)
class CheckRunReport:
    head_sha: str
    conclusion: str  # success | neutral | failure | action_required
    title: str
    summary: str  # Markdown, every untrusted string escaped
    annotations: tuple[dict[str, object], ...]


def build_report(result: ScanResult) -> CheckRunReport:
    if not _SHA.match(result.head_sha):
        raise ValueError("head_sha is not a full lowercase hex commit id")
    ordered = sorted(result.findings, key=lambda f: (-f.severity, f.file, f.line, f.rule_id))
    annotations = tuple(a for a in (_annotation(f) for f in ordered) if a is not None)[:MAX_ANNOTATIONS]
    skipped = len(ordered) - len(annotations)
    return CheckRunReport(
        head_sha=result.head_sha,
        conclusion=_CONCLUSIONS[result.verdict.outcome],
        title=_title(result, len(ordered)),
        summary=_summary(result, ordered, skipped),
        annotations=annotations,
    )


# ---- sanitising ----------------------------------------------------------------------------


def _clean(text: str, limit: int | None = None) -> str:
    """Make text visible and single-line: hidden characters become ⟦U+XXXX⟧ markers."""

    def mark(m: re.Match[str]) -> str:
        ch = m.group(0)
        return " " if ch in _LINEBREAKS else f"⟦U+{ord(ch):04X}⟧"

    text = _INVISIBLE.sub(mark, text)
    if limit is not None and len(text) > limit:
        text = text[:limit] + "…"
    return text


def _code(text: str, limit: int = _EVIDENCE_LIMIT) -> str:
    """Inline code span that the text cannot escape from."""
    text = _clean(text, limit)
    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    fence = "`" * (longest + 1)
    return f"{fence} {text} {fence}"


def _plain(text: str, limit: int = _TEXT_LIMIT) -> str:
    """Prose that GitHub renders as text only: no HTML, links, pings or references."""
    parts = _AUTOLINK.split(_clean(text, limit))
    return "".join(
        f"`{part}`" if i % 2 else part.translate(_MD_ESCAPES) for i, part in enumerate(parts)
    )


def _safe_path(path: str) -> bool:
    segments = path.split("/")
    return (
        0 < len(path) <= _MAX_PATH
        and _clean(path) == path
        and not path.startswith("/")
        and ".." not in segments
        and "" not in segments
    )


# ---- annotations ---------------------------------------------------------------------------


def _annotation(f: Finding) -> dict[str, object] | None:
    if not _safe_path(f.file):  # an annotation on a path that is not a real repo path is noise
        return None
    line = max(f.line, 1)
    message = "\n".join(
        [
            _clean(f.rationale, _TEXT_LIMIT),
            "Evidence: " + _clean(f.evidence, _EVIDENCE_LIMIT),
            "Fix: " + _clean(f.remediation, _TEXT_LIMIT),
        ]
    )
    return {
        "path": f.file,
        "start_line": line,
        "end_line": line,
        "annotation_level": _LEVELS[f.severity],
        "title": _clean(f"{f.rule_id} ({f.severity.name})", _TITLE_LIMIT - 1),
        "message": message,
    }


# ---- summary -------------------------------------------------------------------------------


def _title(result: ScanResult, count: int) -> str:
    # Built only from our own constants and numbers: no PR text.
    return f"PR scanner: {result.verdict.outcome.name} ({count} finding(s))"


def _summary(result: ScanResult, findings: list[Finding], not_annotated: int) -> str:
    outcome = result.verdict.outcome
    head = ["## Verdict", "", f"**{outcome.name}**"]
    if outcome is Outcome.INCOMPLETE or result.incomplete:
        head += [
            "",
            "**This pull request was not fully scanned.** Parts of it could not be read or "
            "analysed, so this result must not be treated as clean.",
        ]
    head += [""] + [f"- {_plain(r)}" for r in result.verdict.reasons]

    if result.errors:
        head += ["", "## Scan problems", ""] + [f"- {_plain(e)}" for e in result.errors]

    tail = [
        "",
        "## About this report",
        "",
        "This is a static scan of the diff; no pull request code was executed. A scan with no "
        "findings means no rule matched, which is not a guarantee about the code. Findings are "
        "not cleared by comments, reactions or approvals; only a code change that removes the "
        "cause or a recorded suppression clears them.",
    ]
    if not_annotated:
        tail.append("")
        tail.append(
            f"{not_annotated} finding(s) are not annotated inline (annotation limit or unusable "
            "file path) and are listed above only."
            if len(findings) <= MAX_ANNOTATIONS
            else f"{not_annotated} finding(s) are not annotated inline (limit of {MAX_ANNOTATIONS})."
        )

    body = ["", "## Findings", ""]
    blocks = [_finding_block(f) for f in findings]
    if not findings:
        body.append("No findings.")

    fixed = "\n".join(head + body + tail)
    budget = MAX_SUMMARY_CHARS - len(fixed.encode("utf-8")) - 200  # room for the omitted note
    kept: list[str] = []
    for block in blocks:
        size = len(block.encode("utf-8")) + 1
        if size > budget:
            break
        kept.append(block)
        budget -= size
    if len(kept) < len(blocks):
        kept.append(f"\n{len(blocks) - len(kept)} more finding(s) omitted to fit GitHub's size limit.")

    return "\n".join(head + body + kept + tail)


def _finding_block(f: Finding) -> str:
    return "\n".join(
        [
            f"- **{f.severity.name}** {_code(f.rule_id, 80)} in {_code(f'{f.file}:{f.line}', 260)}",
            f"  - Evidence: {_code(f.evidence)}",
            f"  - Why: {_plain(f.rationale)}",
            f"  - Fix: {_plain(f.remediation)}",
        ]
    )
