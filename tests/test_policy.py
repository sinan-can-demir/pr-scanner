import pytest
from hypothesis import given, strategies as st

from pr_scanner.models import Finding, Severity
from pr_scanner.policy import Outcome, Policy, compute_verdict

from tests.test_models import make_finding


def f(sev):
    return make_finding(severity=sev, line=int(sev))


@pytest.mark.parametrize(
    "sev,expected",
    [
        (Severity.CRITICAL, Outcome.BLOCK),
        (Severity.HIGH, Outcome.BLOCK),
        (Severity.MEDIUM, Outcome.WARN),
        (Severity.LOW, Outcome.PASS),
    ],
)
def test_default_severity_to_outcome(sev, expected):
    assert compute_verdict([f(sev)], Policy()).outcome == expected


def test_no_findings_passes():
    assert compute_verdict([], Policy()).outcome == Outcome.PASS


def test_highest_severity_wins():
    v = compute_verdict([f(Severity.LOW), f(Severity.CRITICAL), f(Severity.MEDIUM)], Policy())
    assert v.outcome == Outcome.BLOCK


def test_high_can_be_downgraded_to_warn_by_policy():
    p = Policy(block_at=Severity.CRITICAL, warn_at=Severity.MEDIUM)
    assert compute_verdict([f(Severity.HIGH)], p).outcome == Outcome.WARN


def test_incomplete_scan_is_never_pass():
    v = compute_verdict([], Policy(), incomplete=True)
    assert v.outcome == Outcome.INCOMPLETE


def test_incomplete_does_not_hide_a_block():
    v = compute_verdict([f(Severity.CRITICAL)], Policy(), incomplete=True)
    assert v.outcome == Outcome.BLOCK


def test_error_is_never_pass_and_is_not_overridable():
    # NFR-08: internal errors never yield success
    v = compute_verdict([], Policy(), errors=["rule X crashed"])
    assert v.outcome == Outcome.ERROR
    assert "rule X crashed" in v.reasons[0]


def test_block_outranks_error_reporting_but_error_outranks_pass():
    v = compute_verdict([f(Severity.CRITICAL)], Policy(), errors=["boom"])
    assert v.outcome in (Outcome.BLOCK, Outcome.ERROR)
    assert v.outcome != Outcome.PASS


def test_invalid_policy_rejected():
    with pytest.raises(ValueError):
        Policy(block_at=Severity.LOW, warn_at=Severity.HIGH)


sev_st = st.sampled_from(list(Severity))


@given(st.lists(sev_st, max_size=8))
def test_verdict_is_deterministic_and_order_independent(sevs):
    findings = [make_finding(severity=s, line=i + 1) for i, s in enumerate(sevs)]
    a = compute_verdict(findings, Policy())
    b = compute_verdict(list(reversed(findings)), Policy())
    assert a.outcome == b.outcome  # NFR-07


@given(st.lists(sev_st, max_size=8), sev_st)
def test_adding_a_finding_never_lowers_the_outcome(sevs, extra):
    order = [Outcome.PASS, Outcome.WARN, Outcome.INCOMPLETE, Outcome.BLOCK, Outcome.ERROR]
    base = [make_finding(severity=s, line=i + 1) for i, s in enumerate(sevs)]
    more = base + [make_finding(severity=extra, line=999)]
    assert order.index(compute_verdict(more, Policy()).outcome) >= order.index(
        compute_verdict(base, Policy()).outcome
    )
