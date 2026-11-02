"""CI gate over the real corpus (NFR-03, FR-16, NFR-07)."""

from pathlib import Path

import pytest

from pr_scanner.corpus import format_report, load_cases, run_corpus
from pr_scanner.engine import Engine
from pr_scanner.policy import Policy
from pr_scanner.rules import default_registry

CORPUS = Path(__file__).resolve().parent.parent / "corpus"
MIN_RECALL = 0.95  # NFR-03


@pytest.fixture(scope="module")
def cases():
    return load_cases(CORPUS)


@pytest.fixture(scope="module")
def report(cases):
    return run_corpus(cases, Engine(default_registry()), Policy())


def test_corpus_is_not_empty(cases):
    assert any(c.label == "malicious" for c in cases)
    assert any(c.label == "benign" for c in cases)


def test_every_case_meets_its_expectation(report):
    assert not report.failures, "\n" + format_report(report)


def test_recall_gate(report):
    assert report.recall is not None and report.recall >= MIN_RECALL, "\n" + format_report(report)


def test_no_benign_pr_is_blocked(report):
    assert report.benign_blocked == 0, "\n" + format_report(report)


def test_every_rule_has_malicious_and_benign_fixtures(cases):
    """FR-16: a rule is only accepted with at least one of each."""
    for rule in default_registry().rules():
        mal = [c for c in cases if c.label == "malicious" and rule.id in c.expect_rules]
        ben = [c for c in cases if c.label == "benign" and rule.id in c.covers_rules]
        assert mal, f"{rule.id} has no malicious fixture"
        assert ben, f"{rule.id} has no benign fixture"


def test_corpus_results_are_deterministic(cases):
    a = run_corpus(cases, Engine(default_registry()), Policy())
    b = run_corpus(cases, Engine(default_registry()), Policy())
    assert [(r.name, r.outcome, r.rules_fired) for r in a.results] == [
        (r.name, r.outcome, r.rules_fired) for r in b.results
    ]


def test_corpus_contains_no_live_indicators(cases):
    """Fixtures must stay defanged: only reserved domains / documentation IP ranges."""
    import re

    allowed_host = re.compile(r"example\.invalid|localhost")
    for c in cases:
        for host in re.findall(r"https?://([^/\s\"'|)]+)", c.patch):
            assert allowed_host.search(host), f"{c.name}: non-defanged host {host}"
        for ip in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", c.patch):
            assert ip.startswith("203.0.113."), f"{c.name}: non-documentation IP {ip}"
