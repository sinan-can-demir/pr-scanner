"""Fetcher output through the real engine: new_content must change a verdict (FR-05, FR-02)."""

from __future__ import annotations

from pr_scanner.engine import Engine
from pr_scanner.fetcher import fetch_pull_request
from pr_scanner.github_client import FetchError
from pr_scanner.models import Severity
from pr_scanner.policy import Policy
from pr_scanner.rules import default_registry
from tests.test_fetcher import FakeClient, RAW_ACCEPT, pr_meta, resp, routes_for

# The diff adds a head-SHA checkout; the pull_request_target trigger is on an unchanged line.
DIFF = """\
diff --git a/.github/workflows/label.yml b/.github/workflows/label.yml
index 1111111..2222222 100644
--- a/.github/workflows/label.yml
+++ b/.github/workflows/label.yml
@@ -3,3 +3,6 @@
 jobs:
   label:
     steps:
+      - uses: actions/checkout@v4
+        with:
+          ref: ${{ github.event.pull_request.head.sha }}
"""
FULL = (
    "name: label\non: pull_request_target\njobs:\n  label:\n    steps:\n"
    "      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"
)
CONTENT_KEY = ("/repos/fork/repo/contents/.github/workflows/label.yml", RAW_ACCEPT)


def _ci_prt_severity(client) -> Severity:
    diff = fetch_pull_request(client, "owner/repo", 7).diff
    result = Engine(default_registry()).scan(diff, Policy())
    found = [f for f in result.findings if f.rule_id == "CI-PRT"]
    assert found, "CI-PRT should fire"
    return max(f.severity for f in found)


def test_workflow_context_from_fetcher_escalates_ci_prt_to_critical():
    routes = routes_for(diff=DIFF, meta=pr_meta(changed_files=1))
    routes[CONTENT_KEY] = resp(FULL)
    assert _ci_prt_severity(FakeClient(routes)) is Severity.CRITICAL


def test_without_context_ci_prt_is_only_medium():
    routes = routes_for(diff=DIFF, meta=pr_meta(changed_files=1))
    routes[CONTENT_KEY] = FetchError("gone", status=404)
    assert _ci_prt_severity(FakeClient(routes)) is Severity.MEDIUM


def test_incomplete_fetch_cannot_produce_a_pass_through_the_engine():
    """End to end: a fetch that could not read everything must not look like a clean PR."""
    routes = routes_for(diff=DIFF, meta=pr_meta(changed_files=1))
    routes[CONTENT_KEY] = FetchError("gone", status=404)
    fetched = fetch_pull_request(FakeClient(routes), "owner/repo", 7)
    assert fetched.incomplete  # the unreadable workflow is reported by the fetcher
    result = Engine(default_registry()).scan(
        fetched.diff, Policy(block_at=Severity.CRITICAL), input_incomplete=fetched.notes
    )
    assert result.incomplete and result.verdict.outcome.value != "pass"
