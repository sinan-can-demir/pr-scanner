"""The shipped workflow must keep the properties ADR-0005 depends on.

Text-based on purpose (no YAML dependency, and the scanner treats workflows as inert text).
If someone edits the workflow in a way that breaks the trust model, these tests fail.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

from pr_scanner.engine import Engine
from pr_scanner.models import ChangedFile, Diff
from pr_scanner.policy import Outcome, Policy
from pr_scanner.rules import default_registry

ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "pr-scan.yml"
TEXT = WORKFLOW.read_text(encoding="utf-8") if WORKFLOW.exists() else ""
LINES = TEXT.split("\n")


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _block(header: str, lines: list[str] = LINES) -> list[str]:
    """Lines nested under the first line whose stripped text equals ``header``."""
    for i, line in enumerate(lines):
        if line.strip() == header:
            base, out = _indent(line), []
            for nxt in lines[i + 1 :]:
                if nxt.strip() and _indent(nxt) <= base:
                    break
                out.append(nxt)
            return out
    raise AssertionError(f"{header!r} not found")


def _job(name: str) -> list[str]:
    return _block(f"{name}:", _block("jobs:"))


def _perms(lines: list[str]) -> dict[str, str]:
    out = {}
    for line in _block("permissions:", lines):
        key, _, value = line.strip().partition(":")
        if key:
            out[key] = value.strip()
    return out


def _run_scripts() -> list[str]:
    scripts, i = [], 0
    while i < len(LINES):
        m = re.match(r"^(\s*)(?:- )?run:\s*(.*)$", LINES[i])
        if m:
            indent, rest = len(m.group(1)), m.group(2)
            if rest in ("|", ">", "|-", ">-"):
                body = []
                for nxt in LINES[i + 1 :]:
                    if nxt.strip() and _indent(nxt) <= indent:
                        break
                    body.append(nxt)
                scripts.append("\n".join(body))
            else:
                scripts.append(rest)
        i += 1
    return scripts


def test_workflow_exists():
    assert WORKFLOW.exists()


# ---- trigger and token scope ---------------------------------------------------------------


def test_only_trigger_is_pull_request_target_with_the_three_types():
    triggers = [l.strip() for l in _block("on:") if _indent(l) == 2 and l.strip()]
    assert triggers == ["pull_request_target:"]
    assert "types: [opened, synchronize, reopened]" in TEXT


def test_default_token_permissions_are_empty_at_workflow_level():
    top = [l for l in LINES if l.startswith("permissions:")]
    assert top == ["permissions: {}"]


def test_scan_job_is_read_only():
    assert _perms(_job("scan")) == {"contents": "read", "pull-requests": "read"}


def test_report_job_can_only_write_checks():
    assert _perms(_job("report")) == {"checks": "write"}


def test_report_job_runs_after_scan_even_when_scan_fails_but_not_when_cancelled():
    job = _job("report")
    assert "needs: scan" in [l.strip() for l in job]
    assert "if: ${{ !cancelled() }}" in [l.strip() for l in job]


def test_no_secrets_are_referenced_and_the_token_is_the_built_in_one():
    assert "secrets." not in TEXT
    assert "github.token" in TEXT


# ---- never run or fetch the PR -------------------------------------------------------------


def test_nothing_checks_out_code():
    assert "actions/checkout" not in TEXT
    assert not re.search(r"git\s+(clone|checkout|fetch|pull)", TEXT)


def test_comment_explains_why_pull_request_target_is_safe():
    assert re.search(r"(?i)never check.{0,20}out", TEXT)


def test_every_action_is_pinned_to_a_full_commit_sha_with_a_version_comment():
    uses = [l for l in LINES if re.match(r"^\s*-?\s*uses:", l)]
    assert uses
    for line in uses:
        assert re.search(r"uses:\s*[\w./-]+@[0-9a-f]{40}\s+#\s*v\d", line), line


def test_no_expression_is_interpolated_into_a_shell_script():
    scripts = _run_scripts()
    assert scripts
    for script in scripts:
        assert "${{" not in script, script


def test_event_values_reach_the_scanner_only_through_env():
    for name in ("REPO", "PR_NUMBER", "HEAD_SHA"):
        assert f"{name}: " in TEXT
    assert "${{ github.event.pull_request.head.sha }}" in TEXT
    assert "${{ github.event.pull_request.number }}" in TEXT
    assert "${{ github.repository }}" in TEXT
    assert '--head-sha "$HEAD_SHA"' in TEXT


def test_scanner_is_installed_from_a_pinned_commit_of_this_repo_not_from_the_pr():
    installs = re.findall(r"git\+https://github\.com/sinan-can-demir/pr-scanner@([0-9a-f]{40})", TEXT)
    assert installs and len(set(installs)) == 1
    assert re.search(r"bin/pip\" install", TEXT) and "@main" not in TEXT


def test_pinned_scanner_commit_exists_in_this_repository():
    sha = re.search(r"pr-scanner@([0-9a-f]{40})", TEXT).group(1)
    try:
        shallow = subprocess.run(
            ["git", "rev-parse", "--is-shallow-repository"], cwd=ROOT, capture_output=True, text=True, timeout=30
        ).stdout.strip()
        found = subprocess.run(["git", "cat-file", "-e", f"{sha}^{{commit}}"], cwd=ROOT, capture_output=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        pytest.skip("git not available")
    if shallow == "true" and found.returncode != 0:
        pytest.skip("shallow clone")
    assert found.returncode == 0, "pinned scanner commit not found; was it pushed?"


# ---- robustness ----------------------------------------------------------------------------


def test_jobs_have_timeouts_and_superseded_runs_are_cancelled():
    for name in ("scan", "report"):
        assert any(l.strip().startswith("timeout-minutes:") for l in _job(name))
    assert "cancel-in-progress: true" in TEXT


def test_artifact_is_always_uploaded_briefly_and_missing_artifact_does_not_stop_the_report_job():
    assert "if: always()" in TEXT
    assert "retention-days: 1" in TEXT
    assert "continue-on-error: true" in TEXT  # download: a missing artifact becomes a failing check


def test_report_job_passes_the_event_sha_not_a_value_from_the_artifact():
    report = "\n".join(_job("report"))
    assert 'report --repo "$REPO" --head-sha "$HEAD_SHA"' in report


# ---- the scanner reads its own workflow ----------------------------------------------------


def test_our_own_scanner_does_not_block_our_own_workflow():
    added = tuple((i + 1, line) for i, line in enumerate(LINES))
    changed = ChangedFile(
        path=".github/workflows/pr-scan.yml", status="added", added_lines=added, new_content=TEXT
    )
    result = Engine(default_registry()).scan(Diff("a" * 40, "b" * 40, (changed,)), Policy())
    assert result.verdict.outcome in (Outcome.PASS, Outcome.WARN), [
        (f.rule_id, f.severity.name, f.line, f.evidence) for f in result.findings
    ]
