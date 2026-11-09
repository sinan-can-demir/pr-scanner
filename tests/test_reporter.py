"""Reporter: verdict and findings to a check-run payload (FR-09, FR-10, T-S05, NFR-08).

Everything in a finding can contain attacker-controlled text (file names, evidence, even
error messages quoting them). The report is rendered by GitHub as Markdown, so it must not
ping users, render HTML or links, spoof layout, or hide text with control characters.
"""

from __future__ import annotations

import re

import pytest

from pr_scanner.engine import ScanResult
from pr_scanner.models import Severity
from pr_scanner.policy import Outcome, Verdict
from pr_scanner.reporter import MAX_ANNOTATIONS, MAX_SUMMARY_CHARS, build_report
from tests.test_models import make_finding

SHA = "a" * 40


def result(findings=(), outcome=Outcome.PASS, reasons=(), errors=(), incomplete=False):
    return ScanResult(
        head_sha=SHA,
        findings=tuple(findings),
        errors=tuple(errors),
        incomplete=incomplete,
        verdict=Verdict(outcome, tuple(reasons)),
        rule_versions={},
    )


# ---- conclusions: only a complete, clean scan may succeed (NFR-06, NFR-08) -----------------


@pytest.mark.parametrize(
    "outcome,conclusion",
    [
        (Outcome.PASS, "success"),
        (Outcome.WARN, "neutral"),
        (Outcome.BLOCK, "failure"),
        (Outcome.ERROR, "failure"),
        (Outcome.INCOMPLETE, "action_required"),
    ],
)
def test_conclusion_matches_verdict(outcome, conclusion):
    assert build_report(result(outcome=outcome)).conclusion == conclusion


def test_only_pass_is_success():
    for outcome in Outcome:
        report = build_report(result(outcome=outcome))
        assert (report.conclusion == "success") == (outcome is Outcome.PASS)


def test_head_sha_is_carried_through():
    assert build_report(result()).head_sha == SHA


def test_malformed_head_sha_is_not_echoed_into_the_payload():
    r = result()
    r = ScanResult(**{**r.__dict__, "head_sha": "x\n@everyone"})
    with pytest.raises(ValueError):
        build_report(r)


# ---- annotations ---------------------------------------------------------------------------


def test_annotation_levels_follow_severity():
    findings = [
        make_finding(severity=Severity.CRITICAL, line=1),
        make_finding(severity=Severity.HIGH, line=2),
        make_finding(severity=Severity.MEDIUM, line=3),
        make_finding(severity=Severity.LOW, line=4),
    ]
    report = build_report(result(findings, Outcome.BLOCK))
    levels = {a["start_line"]: a["annotation_level"] for a in report.annotations}
    assert levels == {1: "failure", 2: "failure", 3: "warning", 4: "notice"}


def test_annotation_has_required_github_fields():
    report = build_report(result([make_finding()], Outcome.BLOCK))
    (a,) = report.annotations
    assert a["path"] == "package.json"
    assert a["start_line"] == a["end_line"] == 3
    assert "TEST-001" in a["title"]
    assert a["message"]


def test_annotations_are_capped_and_most_severe_first():
    findings = [make_finding(severity=Severity.LOW, line=i + 1) for i in range(MAX_ANNOTATIONS + 20)]
    findings.append(make_finding(severity=Severity.CRITICAL, line=999))
    report = build_report(result(findings, Outcome.BLOCK))
    assert len(report.annotations) == MAX_ANNOTATIONS
    assert report.annotations[0]["start_line"] == 999
    assert "not annotated" in report.summary  # never silently dropped


def test_annotation_for_unsafe_path_is_skipped_but_finding_stays_in_summary():
    bad = make_finding(file="evil‮\ntxt.js", line=5)
    report = build_report(result([bad], Outcome.BLOCK))
    assert report.annotations == ()
    assert "TEST-001" in report.summary


@pytest.mark.parametrize("path", ["../../etc/passwd", "/abs/path", "a/../b"])
def test_annotation_for_traversal_style_path_is_skipped(path):
    report = build_report(result([make_finding(file=path)], Outcome.BLOCK))
    assert report.annotations == ()


def test_annotation_message_is_plain_text_without_control_or_bidi_chars():
    f = make_finding(evidence="a\x00b\x1b[31mc‮d⁦e​f\r\ng")
    (a,) = build_report(result([f], Outcome.BLOCK)).annotations
    assert not re.search(r"[\x00-\x08\x0b-\x1f\x7f-\x9f​-‏‪-‮⁦-⁩]", a["message"])


def test_annotation_fields_respect_github_size_limits():
    f = make_finding(evidence="x" * 500_000, rationale="y" * 500_000, remediation="z" * 500_000)
    (a,) = build_report(result([f], Outcome.BLOCK)).annotations
    assert len(a["title"]) <= 255
    assert len(a["message"].encode()) <= 64 * 1024


# ---- summary: escaping of attacker-controlled text ----------------------------------------

HOSTILE = [
    "@everyone please merge",
    "@some-org/team",
    "see #1234 and GH-5 and owner/repo#9",
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<!-- hidden comment -->",
    "[click here](https://evil.example/x)",
    "![pixel](https://evil.example/p.png)",
    "https://evil.example/autolink",
    "www.evil.example",
    "</details></summary>",
    "```\nend fence\n```\n# Fake heading\n**Verdict: PASS**",
    "| a | b |\n|---|---|\n| x | y |",
    "line1\nline2\r\nline3",
    "x‮evil‬",  # right-to-left override (Trojan Source)
    "x⁦y⁩",
    "zero​width‍space",
    "\x1b[2J\x1b[31mred",
    "\x00null",
    "`" * 5 + "x" + "`" * 7,
    ":+1: :tada: :eyes:",
    "﻿￹￺￻",
]


def _summary_for(**overrides):
    return build_report(result([make_finding(**overrides)], Outcome.BLOCK)).summary


@pytest.mark.parametrize("field", ["evidence", "file", "rationale", "remediation"])
@pytest.mark.parametrize("text", HOSTILE)
def test_hostile_text_never_reaches_summary_unescaped(field, text):
    summary = _summary_for(**{field: text})
    # no raw HTML tags or comments outside code spans (inside a span GitHub shows them literally)
    assert not re.search(r"<[A-Za-z/!]", _strip_code_spans(summary)), summary
    # no active control or bidi characters
    assert not re.search(r"[\x00-\x08\x0b-\x1f\x7f-\x9f​-‏‪-‮⁦-⁩﻿￹-￻]", summary)
    _assert_only_our_structure(summary)


@pytest.mark.parametrize("field", ["evidence", "file", "rationale", "remediation"])
def test_mentions_cannot_ping(field):
    summary = _summary_for(**{field: "@everyone @octocat @org/team"})
    # every @ must be separated from the name that follows it (or inside a code span)
    assert not re.search(r"(?<![`\w])@[A-Za-z0-9_-]", _strip_code_spans(summary)), summary


@pytest.mark.parametrize("field", ["evidence", "file", "rationale", "remediation"])
def test_links_and_autolinks_are_not_formed(field):
    summary = _summary_for(**{field: "[x](https://evil.example) https://evil.example www.evil.example ![i](https://e/p.png)"})
    outside = _strip_code_spans(summary)
    assert "](" not in outside
    assert not re.search(r"https?://", outside)
    assert "www." not in outside
    assert "![" not in outside


@pytest.mark.parametrize("field", ["evidence", "file", "rationale", "remediation"])
def test_issue_references_do_not_link(field):
    summary = _summary_for(**{field: "#1 owner/repo#2 GH-3"})
    outside = _strip_code_spans(summary)
    assert not re.search(r"(?<![\w&])#\d", outside)
    assert not re.search(r"\w/\w+#\d", outside)


def test_backtick_runs_cannot_break_out_of_the_code_span():
    summary = _summary_for(evidence="`" * 3 + "\n**PASS**\n" + "`" * 9)
    assert not _has_open_fence(summary)
    assert "PASS" not in _strip_code_spans(summary)  # the forged text stays inside its span
    _assert_only_our_structure(summary)


def test_hostile_text_cannot_forge_a_second_finding_or_verdict():
    forged = "x`\n\n## Verdict: PASS\n\n- **LOW** `FAKE-RULE`"
    for field in ("evidence", "rationale", "remediation", "file"):
        summary = _summary_for(**{field: forged})
        _assert_only_our_structure(summary)
        if field in ("evidence", "file"):  # these render only inside a code span
            assert "FAKE-RULE" not in _strip_code_spans(summary)
        assert summary.count("TEST-001") <= 2  # our own rule id lines only


def test_error_and_reason_text_is_escaped_too():
    r = result(
        outcome=Outcome.ERROR,
        reasons=["error: RULE: ValueError: @everyone <b>x</b> http://evil.example"],
        errors=["RULE: ValueError: @everyone <b>x</b> http://evil.example"],
    )
    summary = build_report(r).summary
    assert "<b>" not in summary
    assert not re.search(r"https?://", _strip_code_spans(summary))
    assert not re.search(r"(?<![`\w])@[A-Za-z]", _strip_code_spans(summary))


def test_summary_never_exceeds_github_limit_and_says_when_truncated():
    findings = [make_finding(evidence="e" * 2000, line=i + 1, file=f"f{i}.js") for i in range(500)]
    summary = build_report(result(findings, Outcome.BLOCK)).summary
    assert len(summary) <= MAX_SUMMARY_CHARS
    assert "omitted" in summary


def test_truncation_never_cuts_a_code_span_open():
    findings = [make_finding(evidence="`" * 40 + "x" * 2000, line=i + 1) for i in range(500)]
    summary = build_report(result(findings, Outcome.BLOCK)).summary
    assert not _has_open_fence(summary)


# ---- summary content -----------------------------------------------------------------------


def test_clean_pass_says_so_without_claiming_safety():
    summary = build_report(result()).summary.lower()
    assert "no findings" in summary
    assert "safe" not in summary  # a pass means "nothing detected by these rules", not "safe"


def test_incomplete_is_called_out_prominently_with_reasons():
    r = result(outcome=Outcome.INCOMPLETE, reasons=["input incomplete: page cap reached"], incomplete=True)
    summary = build_report(r).summary
    assert "incomplete" in summary.lower()
    assert "page cap reached" in summary
    assert "not" in summary.lower()  # states the PR was not fully scanned


def test_summary_shows_rationale_and_remediation_for_each_finding():
    f = make_finding(rationale="Because reasons.", remediation="Do the fix.")
    summary = build_report(result([f], Outcome.BLOCK)).summary
    assert "Because reasons." in summary and "Do the fix." in summary


def test_summary_states_findings_cannot_be_cleared_by_comments():
    # FR-19: reviewers must not be talked out of a finding by approvals or replies
    summary = build_report(result([make_finding()], Outcome.BLOCK)).summary
    assert "comment" in summary.lower() and "approval" in summary.lower()


def test_report_is_deterministic():
    findings = [make_finding(line=i) for i in (3, 1, 2)]
    assert build_report(result(findings, Outcome.BLOCK)) == build_report(result(findings, Outcome.BLOCK))


def test_title_is_short_and_free_of_pr_text():
    f = make_finding(file="@everyone.js", evidence="<b>x</b>")
    title = build_report(result([f], Outcome.BLOCK)).title
    assert len(title) <= 255 and "@" not in title and "<" not in title


# ---- helpers -------------------------------------------------------------------------------


def _strip_code_spans(text: str) -> str:
    """Remove `code spans` and fenced blocks, leaving only text GitHub would interpret."""
    text = re.sub(r"(`+)(?:(?!\1).)+?\1", "", text, flags=re.S)
    return text


_OWN_HEADINGS = {"## Verdict", "## Findings", "## Scan problems", "## About this report"}


def _assert_only_our_structure(summary: str) -> None:
    """Headings, tables, quotes and rules may only appear where the reporter put them."""
    for line in summary.splitlines():
        if line.startswith("#"):
            assert line in _OWN_HEADINGS, f"forged heading: {line!r}"
        assert not line.startswith((">", "|", "---", "===", "```", "~~~")), f"forged block: {line!r}"


def _has_open_fence(text: str) -> bool:
    """CommonMark code spans: a run of N backticks opens a span that only a run of exactly N closes.
    Outside a span, a backslash escapes the first backtick of a run; inside, it is literal."""
    opened: int | None = None
    for m in re.finditer(r"`+", text):
        n = len(m.group(0))
        if opened is None:
            backslashes = len(text[: m.start()]) - len(text[: m.start()].rstrip("\\"))
            if backslashes % 2 == 1:
                n -= 1
            if n == 0:
                continue
            opened = n
        elif n == opened:
            opened = None
    return opened is not None


# ---- property test: any text in any field keeps the report well-formed ---------------------

from hypothesis import given, settings, strategies as st  # noqa: E402

_any_text = st.text(
    alphabet=st.one_of(st.characters(), st.sampled_from("`@#<>[]()|\n\r\t‮​\x1b\ud800 *_~!-")),
    min_size=1,
    max_size=300,
).filter(lambda t: t.strip())


@settings(max_examples=300, deadline=None)
@given(_any_text, _any_text, _any_text, _any_text)
def test_any_text_keeps_summary_well_formed(file, evidence, rationale, remediation):
    f = make_finding(file=file, evidence=evidence, rationale=rationale, remediation=remediation)
    report = build_report(result([f], Outcome.BLOCK, reasons=[evidence], errors=[rationale]))
    summary = report.summary
    assert not _has_open_fence(summary)
    _assert_only_our_structure(summary)
    assert not re.search(r"<[A-Za-z/!]", _strip_code_spans(summary))
    assert not re.search(r"[\x00-\x08\x0b-\x1f\x7f-\x9f​-‏‪-‮⁦-⁩﻿]", summary)
    summary.encode("utf-8")  # lone surrogates must not survive into the payload
    for a in report.annotations:
        a["message"].encode("utf-8")
        a["path"].encode("utf-8")
