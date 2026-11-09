"""Fetcher: PR metadata, SHA-pinned diff, workflow contents, huge-PR fallback (FR-02, NFR-06)."""

from __future__ import annotations

import json

import pytest

from pr_scanner.fetcher import FetchLimits, fetch_pull_request
from pr_scanner.github_client import FetchError, HttpResponse

BASE = "a" * 40
HEAD = "b" * 40
_JSON = "application/vnd.github+json"
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


@pytest.mark.parametrize("repo", ["owner", "a/b/c", "../etc/passwd", "o/r;x", "o/ r", "", "o/..", "/r", "o/r\n"])
def test_rejects_malformed_repo(repo):
    with pytest.raises(ValueError):
        fetch_pull_request(FakeClient({}), repo, 1)


@pytest.mark.parametrize("number", [0, -1, True])
def test_rejects_bad_pr_number(number):
    with pytest.raises(ValueError):
        fetch_pull_request(FakeClient({}), "o/r", number)


@pytest.mark.parametrize("bad", ["", "xyz", "A" * 40, "b" * 39, "b" * 40 + "/../x", "b" * 40 + "\n", None])
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


# --- stage 3: new_content for CI workflows --------------------------------------------------

WF_DIFF = """\
diff --git a/.github/workflows/ci.yml b/.github/workflows/ci.yml
index 1111111..2222222 100644
--- a/.github/workflows/ci.yml
+++ b/.github/workflows/ci.yml
@@ -1,2 +1,3 @@
 name: ci
+on: pull_request_target
 jobs: {}
"""
WF_DELETED = """\
diff --git a/.github/workflows/old.yml b/.github/workflows/old.yml
deleted file mode 100644
index 1111111..0000000
--- a/.github/workflows/old.yml
+++ /dev/null
@@ -1,1 +0,0 @@
-name: old
"""
WF_PATH = "/repos/fork/repo/contents/.github/workflows/ci.yml"
WF_TEXT = "name: ci\non: pull_request_target\njobs: {}\n"


def wf_routes(diff: str = WF_DIFF, content: object = None, meta: bytes | None = None) -> dict:
    r = routes_for(diff=diff, meta=meta)
    r[(WF_PATH, RAW_ACCEPT)] = content if content is not None else resp(WF_TEXT)
    return r


def test_workflow_new_content_is_read_from_head_repo_at_head_sha():
    client = FakeClient(wf_routes())
    result = fetch_pull_request(client, "owner/repo", 7)
    (f,) = result.diff.files
    assert f.new_content == WF_TEXT
    assert result.incomplete is False
    path, accept, params = client.calls[-1]
    assert path == WF_PATH and accept == RAW_ACCEPT and params == {"ref": HEAD}


def test_non_workflow_files_are_not_fetched():
    client = FakeClient(routes_for())
    result = fetch_pull_request(client, "owner/repo", 7)
    assert result.diff.files[0].new_content is None
    assert len(client.calls) == 2


def test_removed_workflow_is_not_fetched():
    client = FakeClient(routes_for(diff=WF_DELETED))
    result = fetch_pull_request(client, "owner/repo", 7)
    assert result.diff.files[0].new_content is None
    assert result.incomplete is False


def test_missing_head_repo_marks_incomplete():
    client = FakeClient(routes_for(diff=WF_DIFF, meta=pr_meta(head_repo=None)))
    result = fetch_pull_request(client, "owner/repo", 7)
    assert result.diff.files[0].new_content is None
    assert result.incomplete is True and result.notes


def test_unreadable_workflow_marks_incomplete_without_leaking_path():
    client = FakeClient(wf_routes(content=FetchError("gone", status=404)))
    result = fetch_pull_request(client, "owner/repo", 7)
    assert result.diff.files[0].new_content is None
    assert result.incomplete is True
    assert all("workflows" not in n and "ci.yml" not in n for n in result.notes)


def test_rate_limit_while_reading_content_propagates():
    err = FetchError("limit", status=403, rate_limited=True)
    with pytest.raises(FetchError):
        fetch_pull_request(FakeClient(wf_routes(content=err)), "owner/repo", 7)


def test_oversize_content_limit_is_passed_and_failure_marks_incomplete():
    seen = {}

    class Spy(FakeClient):
        def get(self, path, *, accept="", params=None, max_bytes=0):
            seen[path] = max_bytes
            return super().get(path, accept=accept, params=params, max_bytes=max_bytes)

    c = Spy(wf_routes(content=FetchError("response exceeded 99 bytes")))
    result = fetch_pull_request(c, "owner/repo", 7, limits=FetchLimits(max_content_bytes=99))
    assert seen[WF_PATH] == 99
    assert result.incomplete is True


def test_invalid_utf8_content_is_decoded_leniently():
    client = FakeClient(wf_routes(content=resp(b"name: ci\n\xff\xfe on: x\n")))
    (f,) = fetch_pull_request(client, "owner/repo", 7).diff.files
    assert f.new_content is not None and f.new_content.startswith("name: ci")


def test_workflow_fetch_count_is_capped():
    many = "".join(
        f"diff --git a/.github/workflows/w{i}.yml b/.github/workflows/w{i}.yml\n"
        f"--- a/.github/workflows/w{i}.yml\n+++ b/.github/workflows/w{i}.yml\n@@ -1 +1,2 @@\n a: 1\n+b: 2\n"
        for i in range(5)
    )
    r = routes_for(diff=many, meta=pr_meta(changed_files=5))
    for i in range(2):
        r[(f"/repos/fork/repo/contents/.github/workflows/w{i}.yml", RAW_ACCEPT)] = resp("a: 1\nb: 2\n")
    result = fetch_pull_request(FakeClient(r), "owner/repo", 7, limits=FetchLimits(max_content_files=2))
    got = [f for f in result.diff.files if f.new_content is not None]
    assert len(got) == 2
    assert result.incomplete is True


def test_path_that_the_client_refuses_marks_incomplete_instead_of_crashing():
    class Refusing(FakeClient):
        def get(self, path, **kw):
            if "contents" in path:
                raise ValueError("invalid API path")
            return super().get(path, **kw)

    result = fetch_pull_request(Refusing(wf_routes()), "owner/repo", 7)
    assert result.incomplete is True


# --- stage 4: huge PRs (diff refused or oversize) -------------------------------------------

COMPARE = f"/repos/owner/repo/compare/{BASE}...{HEAD}"


def file_item(name="src/a.py", status="modified", patch="@@ -1 +1,2 @@\n x = 1\n+y = 2", **extra) -> dict:
    item = {"filename": name, "status": status, **extra}
    if patch is not None:
        item["patch"] = patch
    return item


def page(*items: dict) -> HttpResponse:
    return resp(json.dumps({"files": list(items)}))


class PagedClient(FakeClient):
    """Diff endpoint refused; compare JSON pages served by ?page=N."""

    def __init__(self, pages: list[HttpResponse], meta: bytes | None = None, refusal: Exception | None = None):
        super().__init__(
            {
                ("/repos/owner/repo/pulls/7", _JSON): resp(meta or pr_meta()),
                (COMPARE, DIFF_ACCEPT): refusal or FetchError("too large", status=406),
            }
        )
        self.pages = pages

    def get(self, path, *, accept=_JSON, params=None, max_bytes=0):
        if path == COMPARE and accept == _JSON:
            self.calls.append((path, accept, dict(params or {})))
            n = int(params["page"])
            return self.pages[n - 1] if n <= len(self.pages) else page()
        return super().get(path, accept=accept, params=params, max_bytes=max_bytes)



def test_refused_diff_falls_back_to_pinned_paged_file_list():
    c = PagedClient([page(file_item())])
    result = fetch_pull_request(c, "owner/repo", 7)
    (f,) = result.diff.files
    assert f.path == "src/a.py" and f.status == "modified"
    assert f.added_lines == ((2, "y = 2"),)
    assert result.incomplete is False
    assert any(call[0] == COMPARE and call[2].get("per_page") == "100" for call in c.calls)


def test_oversize_diff_also_falls_back():
    c = PagedClient([page(file_item())], refusal=FetchError("response exceeded 5 bytes", status=200))
    assert fetch_pull_request(c, "owner/repo", 7).diff.files


def test_other_diff_errors_do_not_fall_back():
    c = PagedClient([page(file_item())], refusal=FetchError("nope", status=404))
    with pytest.raises(FetchError):
        fetch_pull_request(c, "owner/repo", 7)


def test_rate_limit_on_diff_does_not_fall_back():
    c = PagedClient([page(file_item())], refusal=FetchError("rl", status=403, rate_limited=True))
    with pytest.raises(FetchError):
        fetch_pull_request(c, "owner/repo", 7)


def test_pagination_continues_until_a_short_page():
    full = [file_item(name=f"f{i}.py") for i in range(100)]
    c = PagedClient([page(*full), page(file_item(name="last.py"))], meta=pr_meta(changed_files=101))
    result = fetch_pull_request(c, "owner/repo", 7)
    assert len(result.diff.files) == 101
    assert result.incomplete is False


def test_page_cap_marks_incomplete():
    full = [file_item(name=f"f{i}.py") for i in range(100)]
    c = PagedClient([page(*full)] * 5, meta=pr_meta(changed_files=500))
    result = fetch_pull_request(c, "owner/repo", 7, limits=FetchLimits(max_pages=2))
    assert len(result.diff.files) == 200
    assert result.incomplete is True


def test_file_without_patch_is_incomplete_not_clean():
    c = PagedClient([page(file_item(patch=None))])
    result = fetch_pull_request(c, "owner/repo", 7)
    assert result.incomplete is True
    assert len(result.diff.files) == 1


def test_pure_rename_without_patch_is_complete():
    item = file_item(name="new.py", status="renamed", patch=None, previous_filename="old.py")
    result = fetch_pull_request(PagedClient([page(item)]), "owner/repo", 7)
    (f,) = result.diff.files
    assert (f.status, f.path, f.old_path) == ("renamed", "new.py", "old.py")
    assert result.incomplete is False


def test_hostile_filename_cannot_inject_diff_lines():
    evil = 'a.py\n--- a/x\n+++ b/.github/workflows/ci.yml\n@@ -0,0 +1 @@\n+boom'
    result = fetch_pull_request(PagedClient([page(file_item(name=evil))]), "owner/repo", 7)
    assert [f.path for f in result.diff.files] == [evil]
    assert result.diff.files[0].added_lines == ((2, "y = 2"),)


def test_patch_that_smuggles_a_second_file_marks_incomplete():
    sneaky = "@@ -1 +1 @@\n x\ndiff --git a/evil b/evil\n--- a/evil\n+++ b/evil\n@@ -0,0 +1 @@\n+boom"
    result = fetch_pull_request(PagedClient([page(file_item(patch=sneaky))]), "owner/repo", 7)
    assert result.incomplete is True
    assert len(result.diff.files) == 1


def test_malformed_page_json_is_a_fetch_error():
    c = PagedClient([resp(b"nope")])
    with pytest.raises(FetchError):
        fetch_pull_request(c, "owner/repo", 7)


def test_page_without_files_list_is_a_fetch_error():
    c = PagedClient([resp(b'{"files": 3}')])
    with pytest.raises(FetchError):
        fetch_pull_request(c, "owner/repo", 7)


def test_fallback_files_still_get_workflow_content():
    item = file_item(name=".github/workflows/ci.yml", status="modified", patch="@@ -1,2 +1,3 @@\n name: ci\n+on: x\n jobs: {}")
    c = PagedClient([page(item)])
    c.routes[(WF_PATH, RAW_ACCEPT)] = resp(WF_TEXT)
    (f,) = fetch_pull_request(c, "owner/repo", 7).diff.files
    assert f.new_content == WF_TEXT


def test_status_mapping():
    items = [
        file_item(name="a", status="added", patch="@@ -0,0 +1 @@\n+x"),
        file_item(name="b", status="removed", patch="@@ -1 +0,0 @@\n-x"),
        file_item(name="c", status="copied", patch="@@ -0,0 +1 @@\n+x"),
        file_item(name="d", status="changed", patch="@@ -1 +1 @@\n-x\n+y"),
    ]
    result = fetch_pull_request(PagedClient([page(*items)], meta=pr_meta(changed_files=4)), "owner/repo", 7)
    assert [f.status for f in result.diff.files] == ["added", "removed", "added", "modified"]
