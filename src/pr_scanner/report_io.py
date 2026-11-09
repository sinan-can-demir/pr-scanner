"""Serialise a report for hand-over between jobs, and validate it on the other side (ADR-0005).

The ``scan`` job runs with no write access and produces ``report.json``. The privileged ``report``
job reads it. That file was produced by a process that parsed attacker-controlled input, so
:func:`parse_report` treats it as untrusted: closed schema, hard limits, the head SHA the *event*
says (not the file), and the same Markdown guarantees :mod:`pr_scanner.reporter` makes. A report
that does not satisfy all of it raises :class:`ReportRejected` and must never be posted.

What this cannot do: tell a genuine clean report from a forged clean one. That is why the workflow
that runs the scan must come from the base branch (``pull_request_target``), not from the PR.
"""

from __future__ import annotations

import json
import re
from typing import Any

from .reporter import (
    _CONCLUSIONS,
    _INVISIBLE,
    _LEVELS,
    _SHA,
    CheckRunReport,
    MAX_ANNOTATIONS,
    MAX_SUMMARY_CHARS,
    _safe_path,
)

VERSION = 1
MAX_REPORT_BYTES = 2 * 1024 * 1024
_TITLE_LIMIT = 255
_MESSAGE_LIMIT = 4096
_MAX_LINE = 10_000_000
_TITLE = re.compile(r"^PR scanner: (PASS|WARN|BLOCK|ERROR|INCOMPLETE) \((\d{1,6}) finding\(s\)\)\Z")
_OUR_HEADINGS = ("## Verdict", "## Scan problems", "## Findings", "## About this report")
_OUTCOME_CONCLUSION = {o.name: c for o, c in _CONCLUSIONS.items()}
_ANNOTATION_KEYS = {"path", "start_line", "end_line", "annotation_level", "title", "message"}
_TOP_KEYS = {"version", "head_sha", "conclusion", "title", "summary", "annotations"}
# Things GitHub would turn into pings, links, references or HTML if they appeared as live text.
_LIVE_MARKUP = re.compile(
    r"<|@|://|www\.|GH-\d|#|\]\(|!\[|\b[0-9a-f]{7,40}\b", re.IGNORECASE
)


class ReportRejected(ValueError):
    """The report failed validation and must not be posted."""


def report_to_json(report: CheckRunReport) -> str:
    return json.dumps(
        {
            "version": VERSION,
            "head_sha": report.head_sha,
            "conclusion": report.conclusion,
            "title": report.title,
            "summary": report.summary,
            "annotations": list(report.annotations),
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def parse_report(text: str, *, expected_head_sha: str | None = None) -> CheckRunReport:
    if not isinstance(text, str) or len(text.encode("utf-8", "surrogatepass")) > MAX_REPORT_BYTES:
        raise ReportRejected("report missing or too large")
    doc = _load(text)
    if set(doc) != _TOP_KEYS:
        raise ReportRejected("report has unexpected or missing fields")
    if type(doc["version"]) is not int or doc["version"] != VERSION:
        raise ReportRejected("unsupported report version")

    head_sha, conclusion, title, summary, annotations = (
        doc["head_sha"], doc["conclusion"], doc["title"], doc["summary"], doc["annotations"],
    )
    for name, value in (("head_sha", head_sha), ("conclusion", conclusion), ("title", title), ("summary", summary)):
        if not isinstance(value, str):
            raise ReportRejected(f"{name} must be a string")
    if not _SHA.match(head_sha):
        raise ReportRejected("head_sha is not a full lowercase hex commit id")
    if expected_head_sha is not None and head_sha != expected_head_sha:
        raise ReportRejected("report is for a different commit than the event")

    outcome = _check_title(title)
    if conclusion != _OUTCOME_CONCLUSION[outcome]:
        raise ReportRejected("conclusion does not match the verdict in the title")
    _check_summary(summary, outcome)

    if not isinstance(annotations, list) or len(annotations) > MAX_ANNOTATIONS:
        raise ReportRejected("annotations must be a list of at most %d" % MAX_ANNOTATIONS)
    checked = tuple(_check_annotation(a) for a in annotations)
    return CheckRunReport(
        head_sha=head_sha, conclusion=conclusion, title=title, summary=summary, annotations=checked
    )


# ---- parsing -------------------------------------------------------------------------------


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError("duplicate key")
    return dict(pairs)


def _reject_constant(name: str) -> Any:
    raise ValueError(f"non-finite number {name}")


def _load(text: str) -> dict[str, Any]:
    try:
        doc = json.loads(text, object_pairs_hook=_no_duplicates, parse_constant=_reject_constant)
    except (ValueError, RecursionError):
        raise ReportRejected("report is not valid JSON") from None
    if not isinstance(doc, dict):
        raise ReportRejected("report must be a JSON object")
    return doc


# ---- title and summary ---------------------------------------------------------------------


def _check_title(title: str) -> str:
    m = _TITLE.match(title)
    if not m or len(title) > _TITLE_LIMIT:
        raise ReportRejected("title does not have the fixed format")
    return m.group(1)


def _outside_code_spans(text: str) -> str | None:
    """Text with CommonMark code spans replaced by a space; None if a span is left open.

    A run of N backticks opens a span that only a run of exactly N closes. Outside a span, a
    backslash escapes the first backtick of a run."""
    out: list[str] = []
    pos, opener = 0, None
    for m in re.finditer(r"`+", text):
        start, n = m.start(), len(m.group(0))
        if opener is None:
            before = text[:start]
            if (len(before) - len(before.rstrip("\\"))) % 2 == 1:
                start, n = start + 1, n - 1
            if n == 0:
                continue
            out.append(text[pos:start])
            opener, pos = n, m.end()
        elif n == opener:
            out.append(" ")
            opener, pos = None, m.end()
    if opener is not None:
        return None
    out.append(text[pos:])
    return "".join(out)


def _check_summary(summary: str, outcome: str) -> None:
    if len(summary) > MAX_SUMMARY_CHARS or len(summary.encode("utf-8")) > MAX_SUMMARY_CHARS:
        raise ReportRejected("summary is too large")
    if _INVISIBLE.search(summary.replace("\n", "")):
        raise ReportRejected("summary contains control or invisible characters")
    lines = summary.split("\n")
    if lines[:3] != ["## Verdict", "", f"**{outcome}**"]:
        raise ReportRejected("summary does not start with our verdict")

    outside = _outside_code_spans(summary)
    if outside is None:
        raise ReportRejected("summary has an unterminated code span")

    seen: set[str] = set()
    for line in outside.split("\n"):
        if line.startswith("#"):
            if line not in _OUR_HEADINGS or line in seen:
                raise ReportRejected("summary contains a forged heading")
            seen.add(line)
            continue
        if line.startswith((">", "|", "---", "===", "```", "~~~")):
            raise ReportRejected("summary contains a forged block")
        if _LIVE_MARKUP.search(line):
            raise ReportRejected("summary contains live markup outside a code span")


# ---- annotations ---------------------------------------------------------------------------


def _is_int(value: Any) -> bool:
    return type(value) is int


def _check_annotation(a: Any) -> dict[str, object]:
    if not isinstance(a, dict) or set(a) != _ANNOTATION_KEYS:
        raise ReportRejected("annotation has unexpected or missing fields")
    path, start, end = a["path"], a["start_line"], a["end_line"]
    title, message, level = a["title"], a["message"], a["annotation_level"]
    if not isinstance(path, str) or not _safe_path(path):
        raise ReportRejected("annotation path is not a safe repository path")
    if not (_is_int(start) and _is_int(end)) or start != end or not 1 <= start <= _MAX_LINE:
        raise ReportRejected("annotation line numbers are invalid")
    if level not in set(_LEVELS.values()):
        raise ReportRejected("annotation level is invalid")
    if not isinstance(title, str) or not 0 < len(title) <= _TITLE_LIMIT or _INVISIBLE.search(title):
        raise ReportRejected("annotation title is invalid")
    if (
        not isinstance(message, str)
        or not 0 < len(message) <= _MESSAGE_LIMIT
        or _INVISIBLE.search(message.replace("\n", ""))
    ):
        raise ReportRejected("annotation message is invalid")
    return dict(a)
