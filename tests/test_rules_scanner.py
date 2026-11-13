"""SCANNER-TAMPER: changes that disable, replace or weaken the scanner itself (T-D12, FR-12).

Found in the rehearsal on 2026-11-09: a PR that rewrote the scan step to write a forged
``report.json`` scanned clean. The base-branch workflow keeps the PR from disabling the scan
*before* merge, but once such a change is merged it becomes the base. So the change itself must
be flagged and held for owner review.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from pr_scanner.diff_parser import parse_unified_diff
from pr_scanner.engine import Engine
from pr_scanner.models import ChangedFile, Diff, Severity
from pr_scanner.policy import Outcome, Policy
from pr_scanner.rules import default_registry
from pr_scanner.rules.scanner import ScannerTamper

ROOT = Path(__file__).resolve().parent.parent
SCAN_WF = ".github/workflows/pr-scan.yml"
SHA_A, SHA_B = "a" * 40, "b" * 40

INVOKE = '"$RUNNER_TEMP/scanner/bin/python" -m pr_scanner scan \\'
REPORT_CMD = '"$RUNNER_TEMP/scanner/bin/python" -m pr_scanner report --repo "$REPO" --head-sha "$HEAD_SHA" \\'
OUT_ARG = '--out "$RUNNER_TEMP/report/report.json"'


def pin(sha: str, owner: str = "sinan-can-demir") -> str:
    return f'"git+https://github.com/{owner}/pr-scanner@{sha}"'


def cf(path=SCAN_WF, added=(), removed=(), status="modified", old_path=None, content=None, binary=False):
    return ChangedFile(
        path=path,
        status=status,
        added_lines=tuple(enumerate(added, 1)),
        removed_lines=tuple(enumerate(removed, 1)),
        old_path=old_path,
        new_content=content,
        is_binary=binary,
    )


def run(*files):
    return list(ScannerTamper().evaluate(Diff("a" * 40, "b" * 40, tuple(files))))


def top(findings):
    return max((f.severity for f in findings), default=None)


# ---- metadata ------------------------------------------------------------------------------


def test_rule_is_registered_with_metadata():
    ids = [r.id for r in default_registry().rules()]
    assert "SCANNER-TAMPER" in ids
    rule = ScannerTamper()
    assert rule.id == "SCANNER-TAMPER" and rule.category == "scanner" and rule.version


# ---- disabling: deletion, removal, rename --------------------------------------------------


def test_deleting_the_scanner_workflow_is_critical():
    f = run(cf(status="removed", removed=[INVOKE, REPORT_CMD]))
    assert top(f) is Severity.CRITICAL


def test_deleting_a_scanner_workflow_by_name_alone_is_critical():
    # the diff may not carry its lines (large file); the name is enough
    assert top(run(cf(status="removed"))) is Severity.CRITICAL


def test_deleting_an_unrelated_workflow_is_not_this_rules_business():
    assert run(cf(path=".github/workflows/ci.yml", status="removed", removed=["run: npm test"])) == []


def test_removing_the_scan_invocation_is_critical():
    f = run(cf(removed=[INVOKE, "  --repo x"], added=["echo skipped"]))
    assert top(f) is Severity.CRITICAL


def test_removing_the_report_step_is_critical():
    assert top(run(cf(removed=[REPORT_CMD]))) is Severity.CRITICAL


def test_replacing_an_invocation_with_another_is_not_removal():
    f = run(cf(removed=[INVOKE], added=[INVOKE + " --extra"]))
    assert top(f) is Severity.MEDIUM  # a modified scanner workflow, but not disabled


def test_renaming_the_scanner_workflow_out_of_workflows_is_critical():
    f = run(cf(path=".github/disabled/pr-scan.yml", old_path=SCAN_WF, status="renamed"))
    assert top(f) is Severity.CRITICAL


def test_renaming_the_scanner_workflow_to_another_workflow_name_is_high():
    f = run(cf(path=".github/workflows/misc.yml", old_path=SCAN_WF, status="renamed", added=[INVOKE]))
    assert top(f) is Severity.HIGH


# ---- replacing: a hand-written report --------------------------------------------------------


@pytest.mark.parametrize(
    "line",
    [
        """echo '{"forged": true}' > "$RUNNER_TEMP/report/report.json\"""",
        'printf "{}" >> report.json',
        "cp ./evil.json $RUNNER_TEMP/report/report.json",
        "mv evil.json report/report.json",
        "cat evil.json | tee report.json",
        'python3 -c "open(\'report.json\', \'w\').write(\'{}\')"',
        "echo ok >report.json",
        "install -m 644 x $RUNNER_TEMP/report/report.json",
        "dd if=evil.json of=report.json",
    ],
)
def test_writing_the_report_by_hand_in_a_scanner_workflow_is_high(line):
    assert top(run(cf(added=[line]))) >= Severity.HIGH


@pytest.mark.parametrize(
    "line",
    [
        OUT_ARG,
        '--report "$RUNNER_TEMP/report/report.json"',
        "path: ${{ runner.temp }}/report/report.json",
        'mkdir -p "$RUNNER_TEMP/report"',
        "name: pr-scan-report",
    ],
)
def test_ordinary_mentions_of_the_report_file_are_not_high(line):
    f = run(cf(added=[line, INVOKE]))
    assert top(f) is None or top(f) < Severity.HIGH


def test_hand_written_report_is_ignored_in_a_workflow_that_is_not_the_scanners():
    assert run(cf(path=".github/workflows/build.yml", added=["echo x > report.json"])) == []


# ---- weakening: pin and source -------------------------------------------------------------


def test_pin_bump_to_another_commit_is_only_medium():
    f = run(cf(removed=[pin(SHA_A)], added=[pin(SHA_B)]))
    assert top(f) is Severity.MEDIUM


@pytest.mark.parametrize("ref", ["main", "master", "v1", "v1.2.3", "HEAD", "abc123", SHA_A[:12], ""])
def test_install_not_pinned_to_a_full_commit_is_high(ref):
    line = f'"git+https://github.com/sinan-can-demir/pr-scanner{"@" + ref if ref else ""}"'
    assert top(run(cf(removed=[pin(SHA_A)], added=[line]))) >= Severity.HIGH


def test_install_from_a_package_index_is_high():
    assert top(run(cf(removed=[pin(SHA_A)], added=['pip install pr-scanner==1.0']))) >= Severity.HIGH


def test_install_from_a_different_repository_is_high():
    f = run(cf(removed=[pin(SHA_A)], added=[pin(SHA_B, owner="someone-else")]))
    assert top(f) >= Severity.HIGH and any("different" in x.rationale.lower() for x in f)


def test_same_repository_with_a_new_commit_is_not_flagged_as_a_different_source():
    f = run(cf(removed=[pin(SHA_A)], added=[pin(SHA_B)]))
    assert not any("different" in x.rationale.lower() for x in f)


def test_url_with_userinfo_or_lookalike_host_is_a_different_source():
    for url in (
        f'"git+https://github.com.evil.example/sinan-can-demir/pr-scanner@{SHA_B}"',
        f'"git+https://user:pw@github.com/sinan-can-demir/pr-scanner@{SHA_B}"',
        f'"git+http://github.com/sinan-can-demir/pr-scanner@{SHA_B}"',
    ):
        assert top(run(cf(removed=[pin(SHA_A)], added=[url]))) >= Severity.HIGH, url


# ---- any other change needs owner review --------------------------------------------------


def test_any_other_edit_to_the_scanner_workflow_is_medium():
    f = run(cf(added=["      - run: echo hello"], removed=[], content=INVOKE + "\n"))
    assert top(f) is Severity.MEDIUM


def test_comment_only_edits_are_ignored():
    assert run(cf(added=["# explain why"], removed=["# old comment"], content=INVOKE)) == []


def test_a_workflow_is_the_scanners_if_it_calls_the_scanner_even_under_another_name():
    f = run(cf(path=".github/workflows/security.yml", added=["      - run: " + INVOKE.strip()]))
    assert top(f) is Severity.MEDIUM


def test_a_mention_only_in_a_comment_does_not_make_a_workflow_the_scanners():
    assert run(cf(path=".github/workflows/ci.yml", added=["# we use pr_scanner elsewhere", "run: npm test"])) == []


def test_blank_lines_never_become_evidence_or_count_as_a_change():
    assert run(cf(added=["", "   ", "\t"], removed=["", " "], content=INVOKE)) == []
    f = run(cf(added=["", "      - run: echo hi"], content=INVOKE))
    assert [x.evidence for x in f] == ["- run: echo hi"]


def test_new_scanner_workflow_is_flagged_for_review_but_not_blocked():
    text = (ROOT / ".github" / "workflows" / "pr-scan.yml").read_text(encoding="utf-8")
    lines = text.split("\n")
    f = run(cf(status="added", added=lines, content=text))
    assert top(f) is Severity.MEDIUM


def test_pr_scanner_tokens_are_matched_case_insensitively_and_with_either_separator():
    for token in ("PR_SCANNER", "Pr-Scanner", "pr_scanner", "pr-scanner"):
        f = run(cf(path=".github/workflows/x.yml", removed=[f"run: python -m {token} scan"]))
        assert top(f) is Severity.CRITICAL, token


def test_paths_are_matched_case_insensitively_and_only_at_the_repository_root():
    assert top(run(cf(path=".GitHub/Workflows/PR-SCAN.YML", status="removed"))) is Severity.CRITICAL
    assert run(cf(path="vendor/.github/workflows/pr-scan.yml", status="removed")) == []


# ---- policy and ownership files ------------------------------------------------------------


@pytest.mark.parametrize("path", [".pr-scanner.yml", ".pr-scanner.yaml", "sub/.pr-scanner.yml"])
def test_scanner_config_changes_are_high(path):
    assert top(run(cf(path=path, added=["block_at: critical"]))) is Severity.HIGH
    assert top(run(cf(path=path, status="removed", removed=["block_at: low"]))) is Severity.HIGH


@pytest.mark.parametrize("path", ["CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS"])
def test_codeowners_edit_is_medium_and_deletion_is_high(path):
    assert top(run(cf(path=path, added=["docs/ @team"]))) is Severity.MEDIUM
    assert top(run(cf(path=path, status="removed", removed=["* @owner"]))) is Severity.HIGH


@pytest.mark.parametrize("path", [
    "vendor/lib/CODEOWNERS", "third_party/x/.github/CODEOWNERS", "src/docs/CODEOWNERS", "sub/CODEOWNERS",
    "node_modules/pkg/CODEOWNERS",
])
def test_codeowners_outside_the_three_locations_github_reads_is_ignored(path):
    # GitHub only reads CODEOWNERS at the root, in .github/ and in docs/ (found as a false positive in buildkit).
    assert run(cf(path=path, added=["* @someone"])) == []
    assert run(cf(path=path, status="removed", removed=["* @owner"])) == []


def test_codeowners_location_match_ignores_case_and_backslashes():
    assert top(run(cf(path=".GITHUB/codeowners", added=["x @y"]))) is Severity.MEDIUM
    assert top(run(cf(path="DOCS/CODEOWNERS", added=["x @y"]))) is Severity.MEDIUM


def test_moving_codeowners_out_of_the_effective_locations_is_high():
    # The file stops being read, so this removes protection just as a deletion does.
    f = run(cf(path="vendor/CODEOWNERS", old_path=".github/CODEOWNERS", status="renamed"))
    assert top(f) is Severity.HIGH
    assert top(run(cf(path="CODEOWNERS", old_path="vendor/CODEOWNERS", status="renamed", added=["x @y"]))) is Severity.MEDIUM
    assert run(cf(path="vendor/b/CODEOWNERS", old_path="vendor/a/CODEOWNERS", status="renamed")) == []


def test_removing_ownership_of_workflows_from_codeowners_is_high():
    f = run(cf(path=".github/CODEOWNERS", removed=["/.github/workflows/ @maintainers"], added=["docs/ @x"]))
    assert top(f) is Severity.HIGH


def test_removing_ownership_of_the_scanner_config_is_high():
    assert top(run(cf(path="CODEOWNERS", removed=[".pr-scanner.yml @maintainers"]))) is Severity.HIGH


# ---- shape of findings ---------------------------------------------------------------------


def test_findings_are_explainable_and_attributed():
    f = run(cf(removed=[INVOKE], added=["echo skipped"]))
    assert f
    for x in f:
        assert x.rule_id == "SCANNER-TAMPER" and x.file == SCAN_WF
        assert x.line >= 1 and x.evidence.strip()
        assert x.rationale and x.remediation
        assert 0 < x.confidence <= 1


def test_deletion_has_usable_evidence_and_line():
    (x,) = [f for f in run(cf(status="removed")) if f.severity is Severity.CRITICAL]
    assert x.line == 1 and "removed" in x.evidence.lower()


def test_finding_count_per_file_is_bounded():
    lines = [f"echo {i} > report.json" for i in range(500)]
    assert len(run(cf(added=lines))) <= 8


def test_binary_files_are_ignored_but_a_deleted_binary_scanner_file_is_not_special():
    assert run(cf(added=["x"], binary=True, content=None)) == []


def test_other_files_are_ignored():
    assert run(cf(path="src/app.py", added=["import os"], removed=["pr_scanner"])) == []


# ---- adversarial input ---------------------------------------------------------------------


def test_long_lines_stay_linear():
    pad = "a" * 300_000
    lines = [pad + " > report.json", pad + "pr_scanner" * 100, "git+https://" + pad + "/pr-scanner@" + pad]
    start = time.perf_counter()
    run(cf(added=lines, removed=lines))
    assert time.perf_counter() - start < 3.0


def test_evasion_by_line_padding_does_not_hide_a_hand_written_report():
    assert top(run(cf(added=["echo x" + " " * 5000 + "> report.json"]))) >= Severity.HIGH


def test_quote_and_escape_splitting_does_not_hide_the_tokens():
    assert top(run(cf(added=['echo x > rep""ort.json']))) >= Severity.HIGH
    assert top(run(cf(removed=['python -m pr""_scanner scan']))) is Severity.CRITICAL


# ---- the real incident ---------------------------------------------------------------------


def _fixture_diff() -> Diff:
    patch = (ROOT / "corpus" / "malicious" / "scanner-workflow-forged-report" / "diff.patch").read_text(encoding="utf-8")
    return parse_unified_diff(patch, head_sha=SHA_A, base_sha=SHA_B)


def test_the_rehearsal_pr_that_forged_the_report_is_critical():
    f = list(ScannerTamper().evaluate(_fixture_diff()))
    assert top(f) is Severity.CRITICAL


def test_the_rehearsal_pr_is_blocked_end_to_end():
    result = Engine(default_registry()).scan(_fixture_diff(), Policy())
    assert result.verdict.outcome is Outcome.BLOCK
    assert "SCANNER-TAMPER" in {f.rule_id for f in result.findings}
