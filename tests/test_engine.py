import pytest

from pr_scanner.engine import Engine, Limits
from pr_scanner.models import ChangedFile, Diff, Severity
from pr_scanner.policy import Outcome, Policy
from pr_scanner.rules.base import Rule
from pr_scanner.rules.registry import DuplicateRuleError, Registry

from tests.test_models import make_finding


def diff(*files):
    return Diff(head_sha="a" * 40, base_sha="b" * 40, files=tuple(files))


def cf(path="a.txt", text="hello"):
    return ChangedFile(path=path, status="added", added_lines=((1, text),))


class FlagWord(Rule):
    """Test rule: flags any added line containing 'evil'."""

    id = "TEST-FLAG"
    version = "1"
    category = "test"
    description = "flags the word evil"

    def evaluate(self, diff):
        return [
            make_finding(rule_id=self.id, file=f.path, line=n, evidence=t)
            for f in diff.files
            for n, t in f.added_lines
            if "evil" in t
        ]


class Crashes(Rule):
    id = "TEST-CRASH"
    version = "1"
    category = "test"
    description = "always raises"

    def evaluate(self, diff):
        raise RuntimeError("boom")


class WrongId(Rule):
    id = "TEST-WRONG"
    version = "1"
    category = "test"
    description = "emits a finding with another rule's id"

    def evaluate(self, diff):
        return [make_finding(rule_id="SOMEONE-ELSE")]


def engine(*rules, limits=None, clock=None):
    reg = Registry()
    for r in rules:
        reg.register(r)
    kwargs = {"limits": limits or Limits()}
    if clock:
        kwargs["clock"] = clock
    return Engine(reg, **kwargs)


def test_registry_rejects_duplicate_ids():
    reg = Registry()
    reg.register(FlagWord())
    with pytest.raises(DuplicateRuleError):
        reg.register(FlagWord())


def test_rule_requires_metadata():
    class Bad(Rule):
        def evaluate(self, diff):
            return []

    with pytest.raises(TypeError):
        Bad()


def test_clean_diff_has_no_findings():
    r = engine(FlagWord()).scan(diff(cf(text="hello")), Policy())
    assert r.findings == () and r.verdict.outcome == Outcome.PASS


def test_finding_is_reported_and_blocks():
    r = engine(FlagWord()).scan(diff(cf(text="so evil")), Policy())
    assert len(r.findings) == 1
    assert r.verdict.outcome == Outcome.BLOCK


def test_crashing_rule_is_an_error_not_a_pass():
    # NFR-08
    r = engine(Crashes()).scan(diff(cf()), Policy())
    assert r.verdict.outcome == Outcome.ERROR
    assert "TEST-CRASH" in r.errors[0]


def test_crashing_rule_does_not_stop_other_rules():
    r = engine(Crashes(), FlagWord()).scan(diff(cf(text="evil")), Policy())
    assert len(r.findings) == 1
    assert r.errors


def test_rule_cannot_emit_findings_under_another_rule_id():
    r = engine(WrongId()).scan(diff(cf()), Policy())
    assert r.findings == ()
    assert r.verdict.outcome == Outcome.ERROR


def test_too_many_files_is_incomplete_not_pass():
    # NFR-06
    files = [cf(path=f"{i}.txt") for i in range(5)]
    r = engine(FlagWord(), limits=Limits(max_files=3)).scan(diff(*files), Policy())
    assert r.incomplete
    assert r.verdict.outcome == Outcome.INCOMPLETE


def test_truncated_files_are_still_scanned_and_can_block():
    files = [cf(path=".evil.txt", text="evil")] + [cf(path=f"{i}.txt") for i in range(5)]
    r = engine(FlagWord(), limits=Limits(max_files=3)).scan(diff(*files), Policy())
    assert r.verdict.outcome == Outcome.BLOCK


def test_oversize_diff_is_incomplete():
    r = engine(FlagWord(), limits=Limits(max_added_bytes=10)).scan(diff(cf(text="x" * 100)), Policy())
    assert r.incomplete and r.verdict.outcome == Outcome.INCOMPLETE


def test_oversized_line_is_incomplete_not_silently_skipped():
    r = engine(FlagWord(), limits=Limits(max_line_chars=1000)).scan(diff(cf(text="evil" + "x" * 5000)), Policy())
    assert r.incomplete
    # the first max_line_chars characters are still scanned
    assert len(r.findings) == 1 and r.verdict.outcome == Outcome.BLOCK


def test_oversized_line_alone_is_incomplete_verdict():
    r = engine(FlagWord(), limits=Limits(max_line_chars=1000)).scan(diff(cf(text="x" * 5000)), Policy())
    assert r.verdict.outcome == Outcome.INCOMPLETE


def test_time_budget_exceeded_is_incomplete():
    ticks = iter([0.0, 0.0, 100.0, 100.0, 100.0, 100.0])
    r = engine(FlagWord(), Crashes(), limits=Limits(max_seconds=5), clock=lambda: next(ticks)).scan(
        diff(cf()), Policy()
    )
    assert r.incomplete


def test_incomplete_input_from_fetcher_is_never_pass():
    # NFR-06/NFR-08: the engine cannot see what the fetcher could not read
    r = engine(FlagWord()).scan(diff(cf()), Policy(), input_incomplete=("diff truncated",))
    assert r.incomplete
    assert r.verdict.outcome == Outcome.INCOMPLETE
    assert any("diff truncated" in reason for reason in r.verdict.reasons)


def test_incomplete_input_does_not_hide_a_block():
    r = engine(FlagWord()).scan(diff(cf(text="evil")), Policy(), input_incomplete=("diff truncated",))
    assert r.incomplete and r.verdict.outcome == Outcome.BLOCK


def test_incomplete_input_does_not_blame_resource_limits():
    r = engine(FlagWord()).scan(diff(cf()), Policy(), input_incomplete=("page cap reached",))
    assert not any("resource limits" in reason for reason in r.verdict.reasons)


def test_no_incomplete_input_still_passes():
    r = engine(FlagWord()).scan(diff(cf()), Policy(), input_incomplete=())
    assert r.verdict.outcome == Outcome.PASS


def test_results_are_deterministic_and_sorted():
    d = diff(cf("b.txt", "evil"), cf("a.txt", "evil"))
    r1 = engine(FlagWord()).scan(d, Policy())
    r2 = engine(FlagWord()).scan(d, Policy())
    assert r1.findings == r2.findings
    assert [f.file for f in r1.findings] == ["a.txt", "b.txt"]


def test_result_records_rule_versions_for_audit():
    # FR-15
    r = engine(FlagWord()).scan(diff(cf()), Policy())
    assert r.rule_versions == {"TEST-FLAG": "1"}


def test_result_is_bound_to_head_sha():
    # T-S13
    r = engine(FlagWord()).scan(diff(cf()), Policy())
    assert r.head_sha == "a" * 40
