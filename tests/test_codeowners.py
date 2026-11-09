"""CODEOWNERS must cover the files that protect the scanner (T-D12, ADR-0005).

GitHub applies the LAST matching pattern, so a later catch-all with a different owner would
silently remove protection from an earlier line. Keep every rule on the same owner, and keep the
security-critical paths listed explicitly so their protection does not depend on the catch-all.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FILE = ROOT / ".github" / "CODEOWNERS"
RULES = [
    line.split()
    for line in (FILE.read_text(encoding="utf-8").splitlines() if FILE.exists() else [])
    if line.strip() and not line.lstrip().startswith("#")
]

MUST_BE_LISTED = [
    "/.github/",  # workflows, and CODEOWNERS itself
    "/.pr-scanner.yml",
    "/.pr-scanner.yaml",
    "/src/pr_scanner/",  # code that runs in the privileged report job
    "/docs/adr/",
]


def test_file_exists_at_the_location_github_reads():
    assert FILE.exists()


def test_every_rule_has_at_least_one_valid_owner():
    assert RULES
    for pattern, *owners in RULES:
        assert owners, f"{pattern} has no owner"
        for owner in owners:
            assert re.fullmatch(r"@[A-Za-z0-9-]+(/[A-Za-z0-9_-]+)?|[^@\s]+@[^@\s]+\.[^@\s]+", owner), owner


def test_security_critical_paths_are_listed_explicitly():
    patterns = {r[0] for r in RULES}
    for path in MUST_BE_LISTED:
        assert path in patterns, f"{path} must be listed explicitly"


def test_all_rules_share_one_owner_set_so_a_later_line_cannot_dilute_an_earlier_one():
    owner_sets = {tuple(r[1:]) for r in RULES}
    assert len(owner_sets) == 1, owner_sets


def test_the_catch_all_comes_first_so_specific_lines_win():
    assert RULES[0][0] == "*"
