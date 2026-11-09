"""Command line entry point: the unprivileged ``scan`` job of ADR-0005.

    GITHUB_TOKEN=<read-only token> python -m pr_scanner scan \\
        --repo OWNER/REPO --pr N --head-sha SHA --out report.json

* The token comes from the environment only; argv is visible to other processes and logs.
* Reads the pull request through the read-only API client. Nothing is checked out, installed,
  imported or executed (ADR-0004, NFR-01).
* Always tries to leave a report for the commit the event named. Any failure becomes an ERROR
  report (never a pass), described by exception *type* or a scrubbed fetch message, never by
  arbitrary exception text that could carry a secret (NFR-08).
* Exit status is 0 whenever a report was written, whatever its verdict: the privileged ``report``
  job decides what GitHub shows, and a failing step would hide the explanation. Exit status 2
  means usage or environment problems and no report was written.
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import Callable, Mapping, Sequence

from .engine import Engine, ScanResult
from .fetcher import _validate_repo, fetch_pull_request
from .github_client import FetchError, GitHubClient
from .policy import Outcome, Policy, compute_verdict
from .report_io import report_to_json
from .reporter import _SHA, CheckRunReport, build_report
from .rules import default_registry
from .rules.registry import Registry

_REDACTED = "[redacted]"


def run_scan(
    client,
    repo: str,
    pr_number: int,
    expected_head_sha: str,
    *,
    registry: Registry | None = None,
    policy: Policy = Policy(),
    redact: Sequence[str] = (),
) -> CheckRunReport:
    """Scan one pull request and return the report for ``expected_head_sha``. Never raises for
    scan-time failures; they become ERROR reports."""
    if not _SHA.match(expected_head_sha):
        raise ValueError("expected_head_sha is not a full lowercase hex commit id")
    try:
        fetched = fetch_pull_request(client, repo, pr_number)
        if fetched.diff.head_sha != expected_head_sha:
            return _error_report(
                expected_head_sha,
                "pull request head changed after the scan was triggered; this commit was not scanned",
            )
        result = Engine(registry or default_registry()).scan(
            fetched.diff, policy, input_incomplete=fetched.notes
        )
        return build_report(result)
    except FetchError as exc:
        return _error_report(expected_head_sha, "fetch failed: " + _scrub(str(exc), redact))
    except Exception as exc:  # anything else: report the type only, the message may hold secrets
        return _error_report(expected_head_sha, f"internal error: {type(exc).__name__}")


def _scrub(text: str, secrets: Sequence[str]) -> str:
    for secret in secrets:
        if secret:
            text = text.replace(secret, _REDACTED)
    return text


def _error_report(head_sha: str, message: str) -> CheckRunReport:
    verdict = compute_verdict(
        [], Policy(), incomplete=True, incomplete_reasons=["the scan did not run to completion"], errors=[message]
    )
    assert verdict.outcome is Outcome.ERROR
    return build_report(
        ScanResult(
            head_sha=head_sha,
            findings=(),
            errors=(message,),
            incomplete=True,
            verdict=verdict,
            rule_versions={},
        )
    )


# ---- argument handling ---------------------------------------------------------------------


class _Quiet(argparse.ArgumentParser):
    """argparse echoes offending arguments in its errors, which would print a mistakenly
    supplied token into the CI log. Say that usage was wrong and nothing more."""

    def error(self, message: str):  # type: ignore[override]
        self.print_usage(sys.stderr)
        sys.stderr.write("error: invalid arguments\n")
        raise SystemExit(2)


def _pr_number(text: str) -> int:
    if not text.isascii() or not text.isdigit() or int(text) < 1:
        raise argparse.ArgumentTypeError("invalid")
    return int(text)


def _head_sha(text: str) -> str:
    if not _SHA.match(text):
        raise argparse.ArgumentTypeError("invalid")
    return text


def _repo(text: str) -> str:
    try:
        _validate_repo(text)
    except ValueError:
        raise argparse.ArgumentTypeError("invalid") from None
    return text


def _parser() -> argparse.ArgumentParser:
    parser = _Quiet(prog="pr_scanner", description="Static scanner for malicious code in pull requests.")
    sub = parser.add_subparsers(dest="command", required=True, parser_class=_Quiet)
    scan = sub.add_parser("scan", help="scan a pull request and write report.json")
    scan.add_argument("--repo", required=True, type=_repo, help="OWNER/REPO")
    scan.add_argument("--pr", required=True, type=_pr_number, help="pull request number")
    scan.add_argument("--head-sha", required=True, type=_head_sha, help="head commit named by the event")
    scan.add_argument("--out", required=True, help="where to write report.json")
    return parser


def main(
    argv: Sequence[str],
    env: Mapping[str, str] | None = None,
    *,
    client_factory: Callable[[str], object] = GitHubClient,
) -> int:
    env = os.environ if env is None else env
    try:
        args = _parser().parse_args(list(argv))
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2

    token = env.get("GITHUB_TOKEN", "")
    try:
        if not token or not token.isascii() or not token.isprintable() or " " in token:
            raise ValueError("bad token")
        client = client_factory(token)
    except ValueError:
        sys.stderr.write("error: GITHUB_TOKEN is missing or malformed\n")
        return 2

    report = run_scan(client, args.repo, args.pr, args.head_sha, redact=(token,))
    try:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(report_to_json(report))
    except OSError:
        sys.stderr.write("error: cannot write the report file\n")
        return 2
    print(f"{report.title} -> {report.conclusion}")
    return 0
