"""Fetcher: PR metadata, SHA-pinned diff, workflow contents, huge-PR fallback (FR-02, NFR-06)."""

from __future__ import annotations

import json

import pytest

from pr_scanner.fetcher import FetchLimits, fetch_pull_request
from pr_scanner.github_client import FetchError, HttpResponse

BASE = "a" * 40
HEAD = "b" * 40
DIFF_ACCEPT = "application/vnd.github.diff"
RAW_ACCEPT = "application/vnd.github.raw+json"

SIMPLE_DIFF = """\
diff --git a/package.json b/package.json
index 1111111..2222222 100644
--- a/package.json
+++ b/package.json
@@ -1,3 +1,4 @@
 {
   "name": "x",
+  "scripts": {"postinstall": "node i.js"},
   "version": "1.0.0"
"""


def pr_meta(*, head_repo: str | None = "fork/repo", changed_files: int = 1) -> bytes:
    return json.dumps(
        {
            "base": {"sha": BASE, "repo": {"full_name": "owner/repo"}},
            "head": {"sha": HEAD, "repo": {"full_name": head_repo} if head_repo else None},
            "changed_files": changed_files,
        }
    ).encode()


def resp(body: bytes | str, status: int = 200, **headers: str) -> HttpResponse:
    if isinstance(body, str):
        body = body.encode()
    return HttpResponse(status, {k.lower(): v for k, v in headers.items()}, body)


class FakeClient:
    """Routes by (path, accept); records every request. Unrouted requests fail the test."""

    def __init__(self, routes: dict) -> None:
        self.routes = routes
        self.calls: list[tuple[str, str, dict]] = []

    def get(self, path, *, accept="application/vnd.github+json", params=None, max_bytes=0):
        self.calls.append((path, accept, dict(params or {})))
        key = (path, accept)
        if key not in self.routes:
            raise AssertionError(f"unexpected request: {key} params={params}")
        item = self.routes[key]
        if isinstance(item, list):
            item = item.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def routes_for(diff: str = SIMPLE_DIFF, meta: bytes | None = None) -> dict:
    return {
        ("/repos/owner/repo/pulls/7", "application/vnd.github+json"): resp(meta or pr_meta()),
        (f"/repos/owner/repo/compare/{BASE}...{HEAD}", DIFF_ACCEPT): resp(diff),
    }


# --- stage 2: metadata + pinned diff --------------------------------------------------------

def test_fetches_metadata_then_diff_pinned_to_shas():
    client = FakeClient(routes_for())
    result = fetch_pull_request(client, "owner/repo", 7)
    assert result.diff.head_sha == HEAD
    assert result.diff.base_sha == BASE
    assert [f.path for f in result.diff.files] == ["package.json"]
    assert result.incomplete is False
    assert result.notes == ()
    # The diff is requested by immutable SHAs, never by PR number (no TOCTOU on force-push).
    assert client.calls[1][0] == f"/repos/owner/repo/compare/{BASE}...{HEAD}"


def test_all_requests_are_read_only_gets_through_the_client():
    client = FakeClient(routes_for())
    fetch_pull_request(client, "owner/repo", 7)
    assert len(client.calls) == 2


@pytest.mark.parametrize("repo", ["owner", "a/b/c", "../etc/passwd", "o/r;x", "o/ r", "", "o/..", "/r"])
def test_rejects_malformed_repo(repo):
    with pytest.raises(ValueError):
        fetch_pull_request(FakeClient({}), repo, 1)


@pytest.mark.parametrize("number", [0, -1, True])
def test_rejects_bad_pr_number(number):
    with pytest.raises(ValueError):
        fetch_pull_request(FakeClient({}), "o/r", number)


@pytest.mark.parametrize("bad", ["", "xyz", "A" * 40, "b" * 39, "b" * 40 + "/../x", None])
def test_rejects_malformed_sha_in_metadata(bad):
    meta = json.dumps({"base": {"sha": BASE}, "head": {"sha": bad}, "changed_files": 1}).encode()
    client = FakeClient({("/repos/owner/repo/pulls/7", "application/vnd.github+json"): resp(meta)})
    with pytest.raises(FetchError):
        fetch_pull_request(client, "owner/repo", 7)


def test_malformed_metadata_json_is_a_fetch_error():
    client = FakeClient({("/repos/owner/repo/pulls/7", "application/vnd.github+json"): resp(b"not json")})
    with pytest.raises(FetchError):
        fetch_pull_request(client, "owner/repo", 7)


def test_metadata_not_an_object_is_a_fetch_error():
    client = FakeClient({("/repos/owner/repo/pulls/7", "application/vnd.github+json"): resp(b"[1,2]")})
    with pytest.raises(FetchError):
        fetch_pull_request(client, "owner/repo", 7)


def test_unparseable_diff_is_a_fetch_error_not_empty_result():
    client = FakeClient(routes_for(diff="diff --git a/x b/x\n@@ -1 +1 @@\n+a\n"))
    with pytest.raises(FetchError):
        fetch_pull_request(client, "owner/repo", 7)


def test_api_error_propagates():
    client = FakeClient({("/repos/owner/repo/pulls/7", "application/vnd.github+json"): FetchError("x", status=404)})
    with pytest.raises(FetchError):
        fetch_pull_request(client, "owner/repo", 7)


def test_empty_diff_for_nonempty_pr_is_incomplete_not_clean():
    """A PR that claims changed files but yields an empty diff must never read as 'clean'."""
    client = FakeClient(routes_for(diff="", meta=pr_meta(changed_files=3)))
    result = fetch_pull_request(client, "owner/repo", 7)
    assert result.incomplete is True
    assert any("0 file" in n or "mismatch" in n for n in result.notes)


def test_file_count_mismatch_marks_incomplete():
    client = FakeClient(routes_for(meta=pr_meta(changed_files=5)))
    result = fetch_pull_request(client, "owner/repo", 7)
    assert result.incomplete is True


def test_oversize_diff_limit_is_passed_to_client():
    seen = {}

    class Spy(FakeClient):
        def get(self, path, *, accept="", params=None, max_bytes=0):
            seen[path] = max_bytes
            return super().get(path, accept=accept, params=params, max_bytes=max_bytes)

    fetch_pull_request(Spy(routes_for()), "owner/repo", 7, limits=FetchLimits(max_diff_bytes=4321))
    assert seen[f"/repos/owner/repo/compare/{BASE}...{HEAD}"] == 4321


def test_parse_error_message_does_not_carry_control_characters():
    bad = 'diff --git "a/\\x1b[31mevil b/x\n--- a\n'
    client = FakeClient(routes_for(diff=bad))
    with pytest.raises(FetchError) as ei:
        fetch_pull_request(client, "owner/repo", 7)
    msg = str(ei.value)
    assert "\x1b" not in msg and "\n" not in msg and len(msg) < 300
