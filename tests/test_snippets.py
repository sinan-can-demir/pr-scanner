from pathlib import Path

from tests.snippets import snippet

TESTS = Path(__file__).resolve().parent


def test_snippets_are_loaded_verbatim_including_leading_punctuation():
    # Compared by shape, not spelled out, so this file stays free of attack-like literals.
    assert snippet("fetch_open").startswith(";") and snippet("fetch_open").endswith("(")
    assert snippet("spawn").startswith("const ") and snippet("spawn").endswith(");")
    assert len(snippet("curl_flag")) == 7 and snippet("curl_flag").endswith(" -s")


def test_unknown_snippet_is_an_error():
    import pytest

    with pytest.raises(KeyError):
        snippet("no-such-snippet")


def test_the_fixture_file_is_not_a_kind_the_dropper_rule_reads():
    from pr_scanner.classify import FileKind, classify

    assert classify("tests/fixtures/snippets.txt") is FileKind.OTHER


# Files that must pass this repository's own scan even when read whole (as if newly added).
# Not yet listed, because they still carry attack-like literals inline (backlog): test_cli.py,
# test_rules_hooks.py, the older half of test_rules_dropper.py, and the rule source
# pr_scanner/rules/dropper.py itself. Edits near those literals will be flagged by our own scan.
SELF_SCAN_CLEAN = ["test_snippets.py", "snippets.py"]


def test_listed_test_files_do_not_trip_our_own_scanner():
    from pr_scanner.engine import Engine
    from pr_scanner.models import ChangedFile, Diff
    from pr_scanner.policy import Outcome, Policy
    from pr_scanner.rules import default_registry

    for name in SELF_SCAN_CLEAN:
        text = (TESTS / name).read_text(encoding="utf-8")
        f = ChangedFile(path=f"tests/{name}", status="added",
                        added_lines=tuple(enumerate(text.split("\n"), 1)), new_content=text)
        result = Engine(default_registry()).scan(Diff("a" * 40, "b" * 40, (f,)), Policy())
        assert result.verdict.outcome is Outcome.PASS, (name, [
            (x.rule_id, x.severity.name, x.line, x.evidence) for x in result.findings])
