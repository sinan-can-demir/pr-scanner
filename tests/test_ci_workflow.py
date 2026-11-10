"""The CI workflow that runs this repository's own tests must stay low-privilege.

It runs code from the pull request (the tests), so unlike pr-scan.yml it must use the plain
`pull_request` trigger: GitHub then gives fork PRs a read-only token and no secrets.
Text-based on purpose, like test_workflow_file.py.
"""

from __future__ import annotations

import re
from pathlib import Path

from pr_scanner.engine import Engine
from pr_scanner.models import ChangedFile, Diff
from pr_scanner.policy import Outcome, Policy
from pr_scanner.rules import default_registry

ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "tests.yml"
REQUIREMENTS = ROOT / "requirements" / "dev.txt"
TEXT = WORKFLOW.read_text(encoding="utf-8") if WORKFLOW.exists() else ""
LINES = TEXT.split("\n")
# The YAML without comment lines, so explanations in comments cannot satisfy or trip a check.
CODE = "\n".join(l for l in LINES if not l.lstrip().startswith("#"))


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _block(header: str, lines: list[str] = LINES) -> list[str]:
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


def test_workflow_exists():
    assert WORKFLOW.exists()


def test_triggers_are_pull_request_push_to_main_schedule_and_manual():
    on = "\n".join(_block("on:"))
    assert "pull_request_target" not in CODE
    assert re.search(r"^  pull_request:", on, re.M)
    assert re.search(r"^  push:\n    branches: \[main\]", on, re.M)
    assert re.search(r"^  schedule:", on, re.M)
    assert re.search(r"^  workflow_dispatch:", on, re.M)


def test_token_is_read_only():
    assert re.search(r"^permissions: \{\}$", TEXT, re.M)
    for job in ("tests", "perf"):
        assert _perms(_job(job)) == {"contents": "read"}


def test_no_secrets_and_no_expressions_in_shell():
    assert "secrets." not in CODE
    # The only expression allowed is the concurrency group; none may reach a shell script.
    assert re.findall(r"\$\{\{.*", CODE) == ["${{ github.ref }}"]


def test_every_action_is_pinned_to_a_full_commit_sha_with_a_version_comment():
    uses = re.findall(r"uses:\s*(\S+)(.*)", TEXT)
    assert uses
    for ref, comment in uses:
        assert re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", ref), ref
        assert re.match(r"\s+# v\d", comment), ref


def test_checkout_does_not_keep_the_token_on_disk():
    assert TEXT.count("actions/checkout@") == TEXT.count("persist-credentials: false") >= 2


def test_dependencies_come_only_from_hash_pinned_requirements_and_the_package_offline():
    installs = [l.strip() for l in LINES if re.search(r"\bpip install\b", l)]
    deps = [l for l in installs if "requirements/dev.txt" in l]
    local = [l for l in installs if l not in deps]
    assert deps and local
    for line in deps:
        assert "--require-hashes" in line and "--only-binary=:all:" in line, line
    # The package itself: no index, no build isolation, no deps, so nothing is downloaded.
    for line in local:
        for flag in ("--no-index", "--no-build-isolation", "--no-deps"):
            assert flag in line, line


def test_requirements_pin_every_package_by_version_and_sha256():
    entries = [l for l in REQUIREMENTS.read_text().splitlines() if l and not l.startswith("#")]
    names = set()
    for line in entries:
        assert re.fullmatch(r"[a-z0-9-]+==[\w.]+ --hash=sha256:[0-9a-f]{64}", line), line
        names.add(line.split("==")[0])
    assert {"pytest", "hypothesis", "setuptools"} <= names


def test_default_suite_runs_on_every_trigger_and_perf_only_on_schedule_or_manual():
    tests, perf = "\n".join(_job("tests")), "\n".join(_job("perf"))
    assert "if:" not in tests
    assert re.search(r"-m pytest -p no:cacheprovider'$", tests, re.M)
    assert "github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'" in perf
    assert re.search(r"-m pytest -p no:cacheprovider -m perf'$", perf, re.M)


def test_jobs_have_timeouts_and_superseded_runs_are_cancelled():
    for job in ("tests", "perf"):
        assert re.search(r"timeout-minutes: \d+", "\n".join(_job(job)))
    assert "cancel-in-progress: true" in TEXT


def test_our_own_scanner_does_not_block_this_workflow():
    added = tuple((i + 1, line) for i, line in enumerate(LINES))
    changed = ChangedFile(
        path=".github/workflows/tests.yml", status="added", added_lines=added, new_content=TEXT
    )
    result = Engine(default_registry()).scan(Diff("a" * 40, "b" * 40, (changed,)), Policy())
    assert result.verdict.outcome is Outcome.PASS, [
        (f.rule_id, f.severity.name, f.line, f.evidence) for f in result.findings
    ]


def test_checkout_fetches_full_history_so_the_pinned_commit_test_does_not_skip():
    # test_workflow_file.py checks that the scanner pin exists in this repository's history;
    # in a shallow clone it can only skip.
    assert TEXT.count("actions/checkout@") == TEXT.count("fetch-depth: 0") >= 2
