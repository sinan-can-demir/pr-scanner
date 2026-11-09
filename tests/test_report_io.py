"""Report serialisation and the trust boundary between the scan job and the report job (ADR-0005).

The artifact the privileged job reads was produced by a process that parsed hostile input,
so ``parse_report`` treats it as untrusted: closed schema, hard limits, expected head SHA,
and the same Markdown invariants the reporter guarantees.
"""

from __future__ import annotations

import json

import pytest
from hypothesis import given, settings

from pr_scanner.models import Severity
from pr_scanner.policy import Outcome
from pr_scanner.report_io import MAX_REPORT_BYTES, ReportRejected, parse_report, report_to_json
from pr_scanner.reporter import MAX_ANNOTATIONS, build_report
from tests.test_models import make_finding
from tests.test_reporter import SHA, _any_text, result

# ---- helpers -------------------------------------------------------------------------------


def good_report(findings=None, outcome=Outcome.BLOCK):
    findings = [make_finding()] if findings is None else findings
    return build_report(result(findings, outcome))


def good_doc(**overrides):
    doc = json.loads(report_to_json(good_report()))
    doc.update(overrides)
    return doc


def reject(doc, **kw):
    text = doc if isinstance(doc, str) else json.dumps(doc)
    with pytest.raises(ReportRejected):
        parse_report(text, **kw)


# ---- round trip ----------------------------------------------------------------------------


@pytest.mark.parametrize("outcome", list(Outcome))
def test_round_trip_for_every_outcome(outcome):
    findings = [] if outcome is Outcome.PASS else [make_finding(severity=Severity.HIGH)]
    report = good_report(findings, outcome)
    assert parse_report(report_to_json(report)) == report


def test_round_trip_with_many_findings_and_annotations():
    findings = [make_finding(line=i + 1, file=f"f{i}.js") for i in range(MAX_ANNOTATIONS + 10)]
    report = good_report(findings)
    assert parse_report(report_to_json(report)) == report


@settings(max_examples=200, deadline=None)
@given(_any_text, _any_text, _any_text, _any_text)
def test_anything_the_reporter_emits_passes_validation(file, evidence, rationale, remediation):
    f = make_finding(file=file, evidence=evidence, rationale=rationale, remediation=remediation)
    report = build_report(result([f], Outcome.BLOCK, reasons=[evidence], errors=[rationale]))
    assert parse_report(report_to_json(report)) == report


def test_serialisation_is_deterministic():
    assert report_to_json(good_report()) == report_to_json(good_report())


# ---- envelope ------------------------------------------------------------------------------


def test_expected_head_sha_must_match_the_event_not_the_file():
    parse_report(report_to_json(good_report()), expected_head_sha=SHA)
    reject(good_doc(), expected_head_sha="b" * 40)


def test_oversize_input_is_rejected_before_parsing():
    reject("x" * (MAX_REPORT_BYTES + 1))


@pytest.mark.parametrize("text", ["", "not json", "[]", "null", "42", '"s"', "{"])
def test_non_object_or_invalid_json_is_rejected(text):
    reject(text)


def test_json_with_duplicate_or_odd_constants_is_rejected():
    reject('{"version": 1, "version": 1}')
    reject('{"version": NaN}')


def test_wrong_version_is_rejected():
    reject(good_doc(version=2))
    reject(good_doc(version="1"))
    reject(good_doc(version=True))


def test_extra_and_missing_keys_are_rejected():
    reject(good_doc(extra="x"))
    doc = good_doc()
    del doc["summary"]
    reject(doc)


@pytest.mark.parametrize("key,value", [("head_sha", 1), ("conclusion", None), ("title", []), ("summary", {}), ("annotations", "x")])
def test_wrong_types_are_rejected(key, value):
    reject(good_doc(**{key: value}))


@pytest.mark.parametrize("sha", ["", "A" * 40, "g" * 40, "a" * 39, "a" * 40 + "\n", "a" * 41])
def test_malformed_head_sha_is_rejected(sha):
    reject(good_doc(head_sha=sha))


# ---- conclusion and title ------------------------------------------------------------------


def test_conclusion_must_be_a_known_value():
    reject(good_doc(conclusion="cancelled"))
    reject(good_doc(conclusion="SUCCESS"))


def test_title_must_match_the_fixed_format():
    reject(good_doc(title="PR scanner: BLOCK (1 finding(s)) @everyone"))
    reject(good_doc(title="Looks fine"))
    reject(good_doc(title="PR scanner: BLOCK (-1 finding(s))"))


def test_title_with_trailing_newline_is_rejected():
    reject(good_doc(title=good_doc()["title"] + "\n"))


def test_title_and_conclusion_must_agree():
    # a BLOCK title can not carry a success conclusion, and vice versa
    reject(good_doc(conclusion="success"))
    pass_doc = json.loads(report_to_json(good_report([], Outcome.PASS)))
    pass_doc["conclusion"] = "failure"
    reject(pass_doc)


def test_summary_verdict_must_agree_with_title():
    doc = good_doc()
    doc["summary"] = doc["summary"].replace("**BLOCK**", "**PASS**", 1)
    reject(doc)


# ---- summary invariants (the reporter's promises, re-checked) ------------------------------


def _with_summary(extra: str):
    doc = good_doc()
    doc["summary"] = doc["summary"] + "\n\n" + extra
    return doc


@pytest.mark.parametrize(
    "extra",
    [
        "# Forged heading",
        "## Verdict",  # a second copy of our own heading is still a forgery
        "<script>alert(1)</script>",
        "<!-- hidden -->",
        "<img src=x>",
        "ping @everyone",
        "see https://evil.example",
        "www.evil.example",
        "[click](https://evil.example)",
        "ref #123",
        "GH-5",
        "commit 7fd1a60b01f9",
        "> quoted block",
        "| a | b |",
        "---",
        "```",
        "bidi ‮ text",
        "zero​width",
        "nul \x00",
    ],
)
def test_summary_with_unescaped_attacker_markup_is_rejected(extra):
    reject(_with_summary(extra))


def test_summary_is_allowed_to_hold_the_same_things_inside_code_spans():
    doc = _with_summary("- evidence: `` <script>@everyone https://x #1 7fd1a60b01f9 ``")
    parse_report(json.dumps(doc))


def test_summary_over_the_github_limit_is_rejected():
    doc = good_doc()
    doc["summary"] = doc["summary"] + "a" * 70_000
    reject(doc)


def test_unterminated_code_span_is_rejected():
    reject(_with_summary("`never closed @everyone"))


# ---- annotations ---------------------------------------------------------------------------


def _ann(**overrides):
    a = dict(
        path="README",
        start_line=1,
        end_line=1,
        annotation_level="failure",
        title="TEST-001 (HIGH)",
        message="m",
    )
    a.update(overrides)
    return a


def _doc_with(annotations):
    return good_doc(annotations=annotations)


def test_valid_annotation_is_accepted():
    parse_report(json.dumps(_doc_with([_ann()])))


def test_too_many_annotations_rejected():
    reject(_doc_with([_ann()] * (MAX_ANNOTATIONS + 1)))


@pytest.mark.parametrize(
    "bad",
    [
        {"path": "../../etc/passwd"},
        {"path": "/abs"},
        {"path": ""},
        {"path": "a\nb"},
        {"path": "a‮b"},
        {"start_line": 0},
        {"start_line": -3},
        {"start_line": 10**9, "end_line": 10**9},
        {"start_line": True, "end_line": True},
        {"start_line": 1.5, "end_line": 1.5},
        {"end_line": 2},
        {"annotation_level": "critical"},
        {"title": "x" * 256},
        {"title": "bad\x00"},
        {"message": "x" * 5000},
        {"message": "bad\x1b[31m"},
        {"message": "bad‮"},
        {"message": 5},
    ],
)
def test_bad_annotation_fields_are_rejected(bad):
    reject(_doc_with([_ann(**bad)]))


def test_annotation_with_extra_or_missing_keys_is_rejected():
    reject(_doc_with([_ann(raw_details="x")]))
    a = _ann()
    del a["message"]
    reject(_doc_with([a]))


def test_annotation_message_may_contain_newlines():
    parse_report(json.dumps(_doc_with([_ann(message="line one\nline two")])))


def test_non_dict_annotation_is_rejected():
    reject(_doc_with(["x"]))
    reject(_doc_with([None]))
