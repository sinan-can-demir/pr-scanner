"""Check-run publisher: the only write path, one endpoint, validated input only (ADR-0005)."""

from __future__ import annotations

import json

import pytest

from pr_scanner.github_client import HttpResponse
from pr_scanner.models import Severity
from pr_scanner.policy import Outcome
from pr_scanner.publisher import CHECK_NAME, CheckRunPublisher, PublishError
from pr_scanner.report_io import ReportRejected
from pr_scanner.reporter import CheckRunReport, build_report
from tests.test_models import make_finding
from tests.test_reporter import SHA, result

TOKEN = "ghs_SECRETSECRETSECRET1234567890"
OK_BODY = json.dumps({"id": 42, "html_url": "https://github.com/owner/repo/runs/42"}).encode()


class FakeTransport:
    def __init__(self, response=None, error=None):
        self.response = response or HttpResponse(201, {}, OK_BODY)
        self.error = error
        self.calls: list[tuple[str, str, dict, bytes, int]] = []

    def __call__(self, method, url, headers, body, max_bytes):
        self.calls.append((method, url, dict(headers), body, max_bytes))
        if self.error:
            raise self.error
        return self.response


def report(outcome=Outcome.BLOCK, findings=None):
    findings = [make_finding()] if findings is None else findings
    return build_report(result(findings, outcome))


def publisher(transport, **kw):
    return CheckRunPublisher(TOKEN, transport=transport, **kw)


# ---- the request ---------------------------------------------------------------------------


def test_posts_one_request_to_the_check_runs_endpoint_only():
    t = FakeTransport()
    publisher(t).publish("owner/repo", report())
    assert len(t.calls) == 1
    method, url, *_ = t.calls[0]
    assert method == "POST" and url == "https://api.github.com/repos/owner/repo/check-runs"


def test_body_has_exactly_the_expected_fields():
    t = FakeTransport()
    rep = report()
    publisher(t).publish("owner/repo", rep)
    body = json.loads(t.calls[0][3])
    assert set(body) == {"name", "head_sha", "status", "conclusion", "output"}
    assert body["name"] == CHECK_NAME and body["status"] == "completed"
    assert body["head_sha"] == rep.head_sha and body["conclusion"] == rep.conclusion
    assert set(body["output"]) == {"title", "summary", "annotations"}
    assert body["output"]["summary"] == rep.summary
    assert body["output"]["annotations"] == list(rep.annotations)


def test_headers_carry_the_token_only_as_authorization():
    t = FakeTransport()
    publisher(t).publish("owner/repo", report())
    _, url, headers, body, _ = t.calls[0]
    assert headers["Authorization"] == f"Bearer {TOKEN}"
    assert headers["Content-Type"] == "application/json"
    assert headers["Accept"] == "application/vnd.github+json"
    assert "X-GitHub-Api-Version" in headers
    assert TOKEN not in url and TOKEN.encode() not in body


def test_response_is_capped():
    t = FakeTransport()
    publisher(t).publish("owner/repo", report())
    assert 0 < t.calls[0][4] <= 1024 * 1024


def test_returns_id_and_url():
    run = publisher(FakeTransport()).publish("owner/repo", report())
    assert run.id == 42 and run.url == "https://github.com/owner/repo/runs/42"


def test_a_created_run_with_an_unreadable_body_is_still_a_success():
    t = FakeTransport(HttpResponse(201, {}, b"<html>"))
    run = publisher(t).publish("owner/repo", report())
    assert run.id is None and run.url is None


def test_a_url_that_is_not_github_is_not_returned():
    body = json.dumps({"id": 1, "html_url": "https://evil.example/x"}).encode()
    run = publisher(FakeTransport(HttpResponse(201, {}, body))).publish("owner/repo", report())
    assert run.url is None


def test_custom_check_name_is_used_and_validated():
    t = FakeTransport()
    publisher(t, check_name="Supply chain scan").publish("owner/repo", report())
    assert json.loads(t.calls[0][3])["name"] == "Supply chain scan"
    for bad in ("", "x" * 65, "a\nb", "@everyone", "<b>"):
        with pytest.raises(ValueError):
            publisher(FakeTransport(), check_name=bad)


# ---- nothing unvalidated is ever sent ------------------------------------------------------


def test_a_report_that_fails_validation_is_not_sent():
    t = FakeTransport()
    forged = CheckRunReport(SHA, "success", "PR scanner: PASS (0 finding(s))", "## Verdict\n\n**PASS**\n\n@everyone", ())
    with pytest.raises(ReportRejected):
        publisher(t).publish("owner/repo", forged)
    assert t.calls == []


def test_conclusion_title_mismatch_is_not_sent():
    t = FakeTransport()
    rep = report()
    bad = CheckRunReport(rep.head_sha, "success", rep.title, rep.summary, rep.annotations)
    with pytest.raises(ReportRejected):
        publisher(t).publish("owner/repo", bad)
    assert t.calls == []


@pytest.mark.parametrize("repo", ["owner", "a/b/c", "../x", "o/r\n", "o/r?x=1", "o/r#", "o/ r", "", "o/.."])
def test_bad_repo_is_rejected_before_any_request(repo):
    t = FakeTransport()
    with pytest.raises(ValueError):
        publisher(t).publish(repo, report())
    assert t.calls == []


@pytest.mark.parametrize("token", ["", "has space", "tab\t", "new\nline", "x\x00"])
def test_bad_token_is_rejected_at_construction(token):
    with pytest.raises(ValueError):
        CheckRunPublisher(token, transport=FakeTransport())


def test_base_url_must_be_https():
    with pytest.raises(ValueError):
        CheckRunPublisher(TOKEN, base_url="http://api.github.com", transport=FakeTransport())


def test_repr_hides_the_token():
    assert TOKEN not in repr(publisher(FakeTransport()))


# ---- failures are loud, bounded and free of secrets ----------------------------------------


@pytest.mark.parametrize("status", [200, 202, 204, 301, 302, 400, 401, 403, 404, 422, 500, 502])
def test_anything_but_201_is_an_error(status):
    t = FakeTransport(HttpResponse(status, {"location": "https://evil.example/"}, b'{"message":"nope"}'))
    with pytest.raises(PublishError) as exc:
        publisher(t).publish("owner/repo", report())
    assert exc.value.status == status


def test_redirects_are_not_followed():
    t = FakeTransport(HttpResponse(307, {"location": "https://evil.example/"}, b""))
    with pytest.raises(PublishError):
        publisher(t).publish("owner/repo", report())
    assert len(t.calls) == 1


def test_remote_error_text_is_neutralised_and_capped():
    hostile = json.dumps({"message": "\x1b[31m@everyone\n" + "x" * 5000}).encode()
    with pytest.raises(PublishError) as exc:
        publisher(FakeTransport(HttpResponse(422, {}, hostile))).publish("owner/repo", report())
    text = str(exc.value)
    assert "\x1b" not in text and "\n" not in text and len(text) < 400


def test_network_errors_report_the_type_only_and_are_not_retried():
    t = FakeTransport(error=ConnectionError(f"failed for {TOKEN}"))
    with pytest.raises(PublishError) as exc:
        publisher(t).publish("owner/repo", report())
    assert TOKEN not in str(exc.value) and "ConnectionError" in str(exc.value)
    assert len(t.calls) == 1  # creating a check run is not idempotent: never retry blindly


def test_error_from_the_server_that_echoes_the_token_is_scrubbed():
    body = json.dumps({"message": f"bad credentials {TOKEN}"}).encode()
    with pytest.raises(PublishError) as exc:
        publisher(FakeTransport(HttpResponse(401, {}, body))).publish("owner/repo", report())
    assert TOKEN not in str(exc.value)


def test_a_token_straddling_the_truncation_point_leaves_no_prefix():
    body = json.dumps({"message": "x" * 190 + TOKEN}).encode()
    with pytest.raises(PublishError) as exc:
        publisher(FakeTransport(HttpResponse(401, {}, body))).publish("owner/repo", report())
    assert TOKEN[:8] not in str(exc.value)


def test_oversized_report_is_never_sent_even_if_validation_is_bypassed(monkeypatch):
    # belt and braces: the encoded request body has its own ceiling
    import pr_scanner.publisher as pub

    t = FakeTransport()
    monkeypatch.setattr(pub, "MAX_REQUEST_BYTES", 10)
    with pytest.raises(PublishError):
        publisher(t).publish("owner/repo", report())
    assert t.calls == []


def test_clean_pass_and_incomplete_reports_publish_with_their_conclusions():
    t = FakeTransport()
    publisher(t).publish("owner/repo", report(Outcome.PASS, []))
    publisher(t).publish("owner/repo", report(Outcome.INCOMPLETE))
    assert [json.loads(c[3])["conclusion"] for c in t.calls] == ["success", "action_required"]


def test_fifty_annotations_fit_in_one_request():
    findings = [make_finding(severity=Severity.LOW, line=i + 1, file=f"f{i}.js") for i in range(80)]
    t = FakeTransport()
    publisher(t).publish("owner/repo", report(findings=findings))
    assert len(t.calls) == 1 and len(json.loads(t.calls[0][3])["output"]["annotations"]) == 50
