"""Real-world runner: sample merged PRs, scan them, summarise (NFR-03 evidence, not rule tuning).

Only references (repo, number, head SHA) and results are stored, never third-party code. Everything
read from a PR is attacker-influenced text, so stored evidence is neutralised and capped.
"""

from __future__ import annotations

import json

import pytest

from pr_scanner import realworld as rw
from pr_scanner.engine import Engine
from pr_scanner.github_client import FetchError
from pr_scanner.rules import default_registry
from tests.test_fetcher import BASE, HEAD, FakeClient, pr_meta, resp, routes_for
from tests.test_cli import BENIGN_DIFF, _hook_diff

_JSON = "application/vnd.github+json"
LIST_KEY = ("/repos/owner/repo/pulls", _JSON)


def item(number, merged=True, sha=None):
    return {"number": number, "merged_at": "2026-11-01T00:00:00Z" if merged else None, "head": {"sha": sha or HEAD}}


def listing(*items):
    return resp(json.dumps(list(items)))


def engine():
    return Engine(default_registry())


# ---- listing -------------------------------------------------------------------------------


def test_only_merged_prs_are_listed_in_order():
    client = FakeClient({LIST_KEY: listing(item(9), item(8, merged=False), item(7))})
    refs = rw.list_merged_prs(client, "owner/repo", 10)
    assert [r.number for r in refs] == [9, 7]
    assert all(r.repo == "owner/repo" and r.head_sha == HEAD for r in refs)


def test_listing_stops_at_the_requested_count():
    client = FakeClient({LIST_KEY: listing(*[item(n) for n in range(100, 0, -1)])})
    assert len(rw.list_merged_prs(client, "owner/repo", 5)) == 5


def test_listing_pages_until_enough_or_exhausted():
    page1 = listing(*[item(n, merged=(n % 2 == 0)) for n in range(200, 100, -1)])  # 50 merged
    page2 = listing(*[item(n) for n in range(100, 0, -1)])
    client = FakeClient({LIST_KEY: [page1, page2]})
    refs = rw.list_merged_prs(client, "owner/repo", 60)
    assert len(refs) == 60
    assert [c[2]["page"] for c in client.calls] == ["1", "2"]


def test_listing_stops_on_a_short_page():
    client = FakeClient({LIST_KEY: [listing(item(3), item(2))]})
    assert len(rw.list_merged_prs(client, "owner/repo", 50)) == 2
    assert len(client.calls) == 1


@pytest.mark.parametrize(
    "bad",
    [
        {"number": "7", "merged_at": "x", "head": {"sha": HEAD}},
        {"number": True, "merged_at": "x", "head": {"sha": HEAD}},
        {"number": 0, "merged_at": "x", "head": {"sha": HEAD}},
        {"number": 5, "merged_at": "x", "head": {"sha": "zzz"}},
        {"number": 5, "merged_at": "x", "head": None},
        {"number": 5, "merged_at": "x"},
        "string",
        None,
    ],
)
def test_malformed_list_entries_are_skipped_not_fatal(bad):
    client = FakeClient({LIST_KEY: listing(bad, item(1))})
    assert [r.number for r in rw.list_merged_prs(client, "owner/repo", 10)] == [1]


def test_non_list_response_is_an_error():
    with pytest.raises(FetchError):
        rw.list_merged_prs(FakeClient({LIST_KEY: resp("{}")}), "owner/repo", 5)


@pytest.mark.parametrize("repo", ["owner", "../x", "o/r\n", ""])
def test_bad_repo_name_is_rejected_before_any_request(repo):
    client = FakeClient({})
    with pytest.raises(ValueError):
        rw.list_merged_prs(client, repo, 5)
    assert client.calls == []


# ---- evaluating one PR ---------------------------------------------------------------------


def ref(number=7, sha=HEAD):
    return rw.PrRef("owner/repo", number, sha)


def test_benign_pr_record():
    rec = rw.evaluate(FakeClient(routes_for(diff=BENIGN_DIFF)), ref(), engine())
    assert rec.outcome == "pass" and rec.findings == () and rec.error is None
    assert rec.files == 1 and not rec.head_changed


def test_malicious_pr_record_has_rule_and_evidence():
    rec = rw.evaluate(FakeClient(routes_for(diff=_hook_diff())), ref(), engine())
    assert rec.outcome in ("block", "warn")
    assert any(f["rule"] == "HOOK-NPM" for f in rec.findings)
    assert all({"rule", "severity", "file", "line", "evidence"} <= set(f) for f in rec.findings)


def test_fetch_failure_is_recorded_not_raised_and_never_a_pass():
    routes = {("/repos/owner/repo/pulls/7", _JSON): FetchError("boom", status=500)}
    rec = rw.evaluate(FakeClient(routes), ref(), engine())
    assert rec.outcome == "error" and rec.error and "boom" in rec.error


def test_unexpected_exception_is_recorded_by_type_only():
    class Exploding(FakeClient):
        def get(self, *a, **k):
            raise RuntimeError("secret detail")

    rec = rw.evaluate(Exploding({}), ref(), engine())
    assert rec.outcome == "error" and "RuntimeError" in rec.error and "secret" not in rec.error


def test_head_moved_since_listing_is_flagged_but_still_scanned():
    rec = rw.evaluate(FakeClient(routes_for(diff=BENIGN_DIFF)), ref(sha="c" * 40), engine())
    assert rec.head_changed and rec.outcome == "pass"


def test_incomplete_fetch_is_recorded_as_incomplete_not_pass():
    routes = routes_for(diff=BENIGN_DIFF, meta=pr_meta(changed_files=5))  # claims more files than the diff has
    rec = rw.evaluate(FakeClient(routes), ref(), engine())
    assert rec.outcome == "incomplete" and rec.notes


def test_stored_evidence_is_neutralised_and_capped():
    diff = _hook_diff().replace("curl -s", "\x1b[31m‮@everyone " + "x" * 5000 + " curl -s")
    rec = rw.evaluate(FakeClient(routes_for(diff=diff)), ref(), engine())
    for f in rec.findings:
        assert "\x1b" not in f["evidence"] and "‮" not in f["evidence"]
        assert len(f["evidence"]) <= 210 and len(f["file"]) <= 210


def test_record_round_trips_through_json():
    rec = rw.evaluate(FakeClient(routes_for(diff=_hook_diff())), ref(), engine())
    assert rw.Record.from_json(json.loads(json.dumps(rec.to_json()))) == rec


def test_only_get_requests_are_made():
    client = FakeClient(routes_for(diff=BENIGN_DIFF))
    rw.evaluate(client, ref(), engine())
    assert client.calls  # FakeClient exposes only .get; nothing else can be called


# ---- summary -------------------------------------------------------------------------------


def rec(outcome, rules=(), error=None, repo="a/b", number=1):
    findings = tuple({"rule": r, "severity": "HIGH", "file": "f", "line": 1, "evidence": "e"} for r in rules)
    return rw.Record(repo, number, HEAD, outcome, False, 1, 10, findings, (), error, False)


def test_summary_counts_outcomes_and_rates():
    s = rw.summarise([rec("pass"), rec("pass"), rec("warn", ["X"]), rec("block", ["X", "Y"]), rec("error", error="e")])
    assert s.total == 5 and s.outcomes == {"pass": 2, "warn": 1, "block": 1, "error": 1}
    assert s.scanned == 4  # errors are not scanned PRs
    assert s.rate("block") == pytest.approx(1 / 4)
    assert s.rate("warn") == pytest.approx(1 / 4)


def test_summary_counts_prs_per_rule_not_findings():
    s = rw.summarise([rec("block", ["X", "X", "Y"]), rec("warn", ["X"])])
    assert s.rules == {"X": 2, "Y": 1}


def test_summary_of_nothing_has_no_rates():
    s = rw.summarise([])
    assert s.total == 0 and s.rate("block") is None


def test_summary_reports_a_confidence_interval_so_small_samples_are_not_over_read():
    lo, hi = rw.summarise([rec("pass")] * 99 + [rec("block", ["X"])]).interval("block")
    assert 0.0 < lo < 0.01 < hi < 0.06
    lo0, hi0 = rw.summarise([rec("pass")] * 50).interval("block")
    assert lo0 == 0.0 and 0.03 < hi0 < 0.1  # zero observed is not zero risk (rule of three)


# ---- CLI -----------------------------------------------------------------------------------


def test_sample_then_run_then_summary_end_to_end(tmp_path, capsys):
    manifest, results = tmp_path / "m.json", tmp_path / "r.json"
    routes = {LIST_KEY: listing(item(7)), **routes_for(diff=BENIGN_DIFF)}
    factory = lambda token: FakeClient(routes)
    env = {"GITHUB_TOKEN": "ghs_abcdefghijklmnop"}
    assert rw.main(["sample", "--repos", "owner/repo", "--per-repo", "1", "--out", str(manifest)], env=env, client_factory=factory) == 0
    assert json.loads(manifest.read_text())["prs"][0]["number"] == 7
    assert rw.main(["run", "--manifest", str(manifest), "--results", str(results)], env=env, client_factory=factory) == 0
    assert rw.main(["summary", "--results", str(results)], env=env) == 0
    assert "pass" in capsys.readouterr().out


def test_run_resumes_and_skips_prs_already_done(tmp_path):
    manifest, results = tmp_path / "m.json", tmp_path / "r.json"
    manifest.write_text(json.dumps({"prs": [{"repo": "owner/repo", "number": 7, "head_sha": HEAD}]}))
    client = FakeClient(routes_for(diff=BENIGN_DIFF))
    env = {"GITHUB_TOKEN": "ghs_abcdefghijklmnop"}
    rw.main(["run", "--manifest", str(manifest), "--results", str(results)], env=env, client_factory=lambda t: client)
    calls = len(client.calls)
    rw.main(["run", "--manifest", str(manifest), "--results", str(results)], env=env, client_factory=lambda t: client)
    assert len(client.calls) == calls


def test_a_rate_limit_stops_the_run_cleanly_and_keeps_progress(tmp_path):
    manifest, results = tmp_path / "m.json", tmp_path / "r.json"
    manifest.write_text(json.dumps({"prs": [
        {"repo": "owner/repo", "number": 7, "head_sha": HEAD},
        {"repo": "owner/repo", "number": 8, "head_sha": HEAD},
    ]}))
    routes = routes_for(diff=BENIGN_DIFF)
    routes[("/repos/owner/repo/pulls/8", _JSON)] = FetchError("limit", status=403, rate_limited=True)
    code = rw.main(["run", "--manifest", str(manifest), "--results", str(results)],
                   env={"GITHUB_TOKEN": "ghs_abcdefghijklmnop"}, client_factory=lambda t: FakeClient(routes))
    assert code == 3  # stopped early, resumable
    assert [r["number"] for r in json.loads(results.read_text())["records"]] == [7]


def test_missing_token_or_bad_args_exit_two(tmp_path):
    assert rw.main(["sample", "--repos", "o/r", "--per-repo", "1", "--out", str(tmp_path / "m")], env={}) == 2
    assert rw.main(["bogus"], env={"GITHUB_TOKEN": "ghs_abc"}) == 2
    assert rw.main(["sample", "--repos", "bad", "--per-repo", "1", "--out", str(tmp_path / "m")], env={"GITHUB_TOKEN": "ghs_abc"}) == 2


def test_python_dash_m_entry_point_runs_main():
    import subprocess
    import sys

    proc = subprocess.run(
        [sys.executable, "-I", "-m", "pr_scanner.realworld"], capture_output=True, text=True, timeout=30
    )
    assert proc.returncode == 2 and "usage" in (proc.stderr + proc.stdout).lower()
