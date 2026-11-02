"""GitHub API client: token safety, bounded reads, fail-closed errors (NFR-04, NFR-06, NFR-08)."""

from __future__ import annotations

import http.server
import threading

import pytest

from pr_scanner.github_client import (
    FetchError,
    GitHubClient,
    HttpResponse,
    UrllibTransport,
)

TOKEN = "ghs_SECRETTOKENVALUE1234567890"


class FakeTransport:
    """Records requests and replays canned responses (recorded-fixture style)."""

    def __init__(self, *responses: HttpResponse | Exception) -> None:
        self._responses = list(responses)
        self.calls: list[dict] = []

    def __call__(self, method, url, headers, max_bytes):
        self.calls.append({"method": method, "url": url, "headers": dict(headers), "max_bytes": max_bytes})
        item = self._responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def ok(body: bytes = b"{}", **headers: str) -> HttpResponse:
    return HttpResponse(status=200, headers={k.lower(): v for k, v in headers.items()}, body=body)


def client(transport, **kw) -> GitHubClient:
    return GitHubClient(TOKEN, transport=transport, sleep=lambda _s: None, **kw)


# --- request construction -------------------------------------------------------------------

def test_sends_token_accept_and_api_version_headers():
    t = FakeTransport(ok())
    client(t).get("/repos/o/r/pulls/1", accept="application/vnd.github+json")
    h = t.calls[0]["headers"]
    assert h["Authorization"] == f"Bearer {TOKEN}"
    assert h["Accept"] == "application/vnd.github+json"
    assert "X-GitHub-Api-Version" in h
    assert t.calls[0]["url"] == "https://api.github.com/repos/o/r/pulls/1"
    assert t.calls[0]["method"] == "GET"


def test_query_params_are_encoded():
    t = FakeTransport(ok())
    client(t).get("/repos/o/r/contents/a b.yml", params={"ref": "x&y=1"})
    assert t.calls[0]["url"] == "https://api.github.com/repos/o/r/contents/a%20b.yml?ref=x%26y%3D1"


def test_non_https_base_url_is_rejected():
    with pytest.raises(ValueError):
        GitHubClient(TOKEN, base_url="http://api.github.com", transport=FakeTransport())


def test_empty_token_is_rejected():
    with pytest.raises(ValueError):
        GitHubClient("", transport=FakeTransport())


def test_path_must_be_absolute_and_free_of_scheme_tricks():
    c = client(FakeTransport(ok()))
    for bad in ("repos/o/r", "//evil.example/x", "https://evil.example/x", "/a/../b", "/a\r\nX: y"):
        with pytest.raises(ValueError):
            c.get(bad)


def test_token_not_in_repr():
    assert TOKEN not in repr(client(FakeTransport()))
    assert TOKEN not in str(client(FakeTransport()))


# --- error handling -------------------------------------------------------------------------

def test_non_2xx_raises_fetch_error_with_status_and_no_token():
    body = b'{"message": "Bad credentials"}'
    t = FakeTransport(HttpResponse(401, {}, body))
    with pytest.raises(FetchError) as ei:
        client(t).get("/repos/o/r/pulls/1")
    assert ei.value.status == 401
    assert "401" in str(ei.value)
    assert TOKEN not in str(ei.value)


def test_remote_error_message_is_sanitised_and_truncated():
    evil = '{"message": "' + "A" * 5000 + "\\u001b[31m\\nINJECT" + '"}'
    t = FakeTransport(HttpResponse(404, {}, evil.encode()))
    with pytest.raises(FetchError) as ei:
        client(t).get("/x")
    msg = str(ei.value)
    assert len(msg) < 400
    assert "\x1b" not in msg and "\n" not in msg


def test_non_json_error_body_is_handled():
    t = FakeTransport(HttpResponse(500, {}, b"<html>boom</html>"))
    with pytest.raises(FetchError):
        client(t, max_retries=0).get("/x")


def test_transport_exception_becomes_fetch_error_without_leaking_token():
    t = FakeTransport(OSError(f"connection reset while sending {TOKEN}"))
    with pytest.raises(FetchError) as ei:
        client(t, max_retries=0).get("/x")
    assert TOKEN not in str(ei.value)


def test_redirect_status_is_an_error_not_followed():
    t = FakeTransport(HttpResponse(302, {"location": "https://evil.example/"}, b""))
    with pytest.raises(FetchError) as ei:
        client(t).get("/x")
    assert ei.value.status == 302
    assert len(t.calls) == 1


# --- retries and rate limits ----------------------------------------------------------------

def test_retries_5xx_then_succeeds():
    t = FakeTransport(HttpResponse(502, {}, b""), HttpResponse(503, {}, b""), ok(b'{"a":1}'))
    resp = client(t, max_retries=2).get("/x")
    assert resp.body == b'{"a":1}'
    assert len(t.calls) == 3


def test_gives_up_after_max_retries():
    t = FakeTransport(*[HttpResponse(502, {}, b"")] * 3)
    with pytest.raises(FetchError):
        client(t, max_retries=2).get("/x")
    assert len(t.calls) == 3


def test_client_errors_are_not_retried():
    t = FakeTransport(HttpResponse(404, {}, b"{}"))
    with pytest.raises(FetchError):
        client(t, max_retries=3).get("/x")
    assert len(t.calls) == 1


def test_primary_rate_limit_fails_closed_and_reports_reset():
    t = FakeTransport(HttpResponse(403, {"x-ratelimit-remaining": "0", "x-ratelimit-reset": "1700000000"}, b"{}"))
    with pytest.raises(FetchError) as ei:
        client(t).get("/x")
    assert ei.value.rate_limited is True
    assert len(t.calls) == 1  # never sleeps for an hour inside a CI job


def test_secondary_rate_limit_retry_after_is_honoured_once_when_short():
    sleeps: list[float] = []
    t = FakeTransport(HttpResponse(429, {"retry-after": "2"}, b"{}"), ok())
    c = GitHubClient(TOKEN, transport=t, sleep=sleeps.append, max_retries=2)
    c.get("/x")
    assert sleeps == [2.0]


def test_long_retry_after_fails_closed():
    t = FakeTransport(HttpResponse(429, {"retry-after": "3600"}, b"{}"))
    with pytest.raises(FetchError) as ei:
        client(t).get("/x")
    assert ei.value.rate_limited is True


# --- size limits ----------------------------------------------------------------------------

def test_max_bytes_is_passed_to_transport():
    t = FakeTransport(ok())
    client(t).get("/x", max_bytes=1234)
    assert t.calls[0]["max_bytes"] == 1234


def test_oversize_body_from_transport_is_rejected():
    t = FakeTransport(ok(b"x" * 11))
    with pytest.raises(FetchError):
        client(t).get("/x", max_bytes=10)


# --- real transport against a local server --------------------------------------------------

class _Handler(http.server.BaseHTTPRequestHandler):
    seen_auth: list[str | None] = []

    def log_message(self, *a):  # silence
        pass

    def do_GET(self):  # noqa: N802
        _Handler.seen_auth.append(self.headers.get("Authorization"))
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:1/stolen")
            self.end_headers()
        elif self.path == "/big":
            self.send_response(200)
            self.send_header("Content-Length", "5000")
            self.end_headers()
            self.wfile.write(b"a" * 5000)
        else:
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")


@pytest.fixture
def server():
    srv = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def test_urllib_transport_reads_body(server):
    r = UrllibTransport()("GET", server + "/", {"Authorization": "Bearer t"}, 100)
    assert (r.status, r.body) == (200, b"ok")


def test_urllib_transport_does_not_follow_redirects(server):
    r = UrllibTransport()("GET", server + "/redirect", {"Authorization": "Bearer t"}, 100)
    assert r.status == 302
    assert r.headers["location"].endswith("/stolen")
    assert len(_Handler.seen_auth) >= 1  # only the first hop was ever contacted


def test_urllib_transport_stops_reading_past_limit(server):
    with pytest.raises(FetchError):
        UrllibTransport()("GET", server + "/big", {}, 100)
