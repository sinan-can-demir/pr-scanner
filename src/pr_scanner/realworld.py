"""Measure the scanner on real pull requests (NFR-03 evidence; docs/rules.md "honest limits").

The in-repo corpus was written together with the rules, so its 100% recall proves little. This tool
samples *real* merged pull requests from public repositories, scans them through the same fetcher
and engine the Action uses, and reports outcome rates with confidence intervals.

* Only references (repo, number, head SHA) and results are stored. No third-party code is copied.
* Read-only: the same GET-only client as the scanner; nothing from a PR is executed.
* Merged PRs from well-known repositories are treated as presumed benign. That is a presumption:
  every block or warn still has to be read and labelled by a person before it counts as a false
  positive, and a clean result says nothing about recall.
* Evidence stored from PRs is attacker-influenced text, so it is neutralised and capped.

    GITHUB_TOKEN=... python -m pr_scanner.realworld sample --repos a/b,c/d --per-repo 30 --out m.json
    GITHUB_TOKEN=... python -m pr_scanner.realworld run --manifest m.json --results r.json
    python -m pr_scanner.realworld summary --results r.json
"""

from __future__ import annotations

import json
import math
import os
import sys
from collections import Counter
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Sequence

from .cli import _Quiet, _repo, _token
from .engine import Engine
from .fetcher import _SHA, _validate_repo, fetch_pull_request
from .github_client import FetchError, GitHubClient
from .policy import Policy
from .reporter import _clean
from .rules import default_registry

_JSON = "application/vnd.github+json"
_PAGE = 100
_MAX_LIST_BYTES = 16 * 1024 * 1024
_EVIDENCE = 200
_Z = 1.96  # 95% Wilson interval


@dataclass(frozen=True)
class PrRef:
    repo: str
    number: int
    head_sha: str


@dataclass(frozen=True)
class Record:
    repo: str
    number: int
    head_sha: str
    outcome: str  # pass | warn | block | incomplete | error
    incomplete: bool
    files: int
    added_bytes: int
    findings: tuple[dict[str, Any], ...]
    notes: tuple[str, ...]
    error: str | None
    head_changed: bool

    def to_json(self) -> dict[str, Any]:
        return {
            "repo": self.repo, "number": self.number, "head_sha": self.head_sha, "outcome": self.outcome,
            "incomplete": self.incomplete, "files": self.files, "added_bytes": self.added_bytes,
            "findings": list(self.findings), "notes": list(self.notes), "error": self.error,
            "head_changed": self.head_changed,
        }

    @staticmethod
    def from_json(d: Mapping[str, Any]) -> "Record":
        return Record(
            d["repo"], d["number"], d["head_sha"], d["outcome"], d["incomplete"], d["files"], d["added_bytes"],
            tuple(d["findings"]), tuple(d["notes"]), d["error"], d["head_changed"],
        )


# ---- sampling ------------------------------------------------------------------------------


def list_merged_prs(client, repo: str, count: int, *, max_pages: int = 5) -> list[PrRef]:
    """The most recently updated merged pull requests of ``repo`` (newest first)."""
    _validate_repo(repo)
    out: list[PrRef] = []
    for page in range(1, max_pages + 1):
        resp = client.get(
            f"/repos/{repo}/pulls",
            accept=_JSON,
            params={"state": "closed", "sort": "updated", "direction": "desc", "per_page": str(_PAGE), "page": str(page)},
            max_bytes=_MAX_LIST_BYTES,
        )
        try:
            items = json.loads(resp.body.decode("utf-8"))
        except ValueError:
            raise FetchError("pull request list is not valid JSON") from None
        if not isinstance(items, list):
            raise FetchError("pull request list is not a JSON array")
        for it in items:
            ref = _ref_from_item(repo, it)
            if ref is not None:
                out.append(ref)
                if len(out) >= count:
                    return out
        if len(items) < _PAGE:
            break
    return out


def _ref_from_item(repo: str, it: Any) -> PrRef | None:
    if not isinstance(it, dict) or not it.get("merged_at"):
        return None
    number, head = it.get("number"), it.get("head")
    sha = head.get("sha") if isinstance(head, dict) else None
    if type(number) is not int or number < 1 or not isinstance(sha, str) or not _SHA.match(sha):
        return None
    return PrRef(repo, number, sha)


# ---- evaluation ----------------------------------------------------------------------------


def evaluate(client, ref: PrRef, engine: Engine, policy: Policy = Policy()) -> Record:
    """Fetch and scan one PR. Failures are recorded, never raised and never a pass; only a rate
    limit propagates so the caller can stop and resume later."""
    try:
        fetched = fetch_pull_request(client, ref.repo, ref.number)
    except FetchError as exc:
        if exc.rate_limited:
            raise
        return _failed(ref, _clean(str(exc), _EVIDENCE))
    except Exception as exc:
        return _failed(ref, f"internal error: {type(exc).__name__}")
    try:
        result = engine.scan(fetched.diff, policy, input_incomplete=fetched.notes)
    except Exception as exc:
        return _failed(ref, f"internal error: {type(exc).__name__}")
    findings = tuple(
        {
            "rule": f.rule_id,
            "severity": f.severity.name,
            "file": _clean(f.file, _EVIDENCE),
            "line": f.line,
            "evidence": _clean(f.evidence, _EVIDENCE),
        }
        for f in result.findings
    )
    return Record(
        ref.repo, ref.number, fetched.diff.head_sha, result.verdict.outcome.value, result.incomplete,
        len(fetched.diff.files), fetched.diff.total_added_bytes, findings,
        tuple(_clean(n, _EVIDENCE) for n in fetched.notes), None, fetched.diff.head_sha != ref.head_sha,
    )


def _failed(ref: PrRef, message: str) -> Record:
    return Record(ref.repo, ref.number, ref.head_sha, "error", False, 0, 0, (), (), message, False)


# ---- summary -------------------------------------------------------------------------------


@dataclass(frozen=True)
class Summary:
    total: int
    scanned: int  # records that were actually scanned (not fetch/internal errors)
    outcomes: dict[str, int]
    rules: dict[str, int]  # number of PRs in which each rule fired

    def rate(self, outcome: str) -> float | None:
        return self.outcomes.get(outcome, 0) / self.scanned if self.scanned else None

    def interval(self, outcome: str) -> tuple[float, float] | None:
        """95% Wilson score interval, which stays meaningful at 0 or 1 observed."""
        if not self.scanned:
            return None
        n, p = self.scanned, self.outcomes.get(outcome, 0) / self.scanned
        denom = 1 + _Z**2 / n
        centre = (p + _Z**2 / (2 * n)) / denom
        half = _Z * math.sqrt(p * (1 - p) / n + _Z**2 / (4 * n**2)) / denom
        return max(0.0, centre - half), min(1.0, centre + half)


def summarise(records: Sequence[Record]) -> Summary:
    outcomes = Counter(r.outcome for r in records)
    scanned = sum(1 for r in records if r.error is None)
    rules: Counter[str] = Counter()
    for r in records:
        rules.update({f["rule"] for f in r.findings})
    return Summary(len(records), scanned, dict(outcomes), dict(rules))


def format_summary(s: Summary) -> str:
    lines = [f"{s.total} pull requests, {s.scanned} scanned, {s.total - s.scanned} errors", ""]
    for outcome in ("pass", "warn", "block", "incomplete", "error"):
        n = s.outcomes.get(outcome, 0)
        r, ci = s.rate(outcome), s.interval(outcome)
        extra = f"  {r:6.1%}  (95% CI {ci[0]:.1%} to {ci[1]:.1%})" if r is not None and ci else ""
        lines.append(f"  {outcome:<11}{n:>5}{extra}")
    if s.rules:
        lines += ["", "PRs in which each rule fired:"]
        lines += [f"  {rule:<18}{n:>5}" for rule, n in sorted(s.rules.items(), key=lambda kv: (-kv[1], kv[0]))]
    return "\n".join(lines)


# ---- command line --------------------------------------------------------------------------


def _repos(text: str) -> list[str]:
    return [_repo(part) for part in text.split(",") if part]


def _positive(text: str) -> int:
    import argparse

    if not text.isascii() or not text.isdigit() or int(text) < 1:
        raise argparse.ArgumentTypeError("invalid")
    return int(text)


def _parser():
    p = _Quiet(prog="pr_scanner.realworld", description="Measure the scanner on real merged pull requests.")
    sub = p.add_subparsers(dest="command", required=True, parser_class=_Quiet)
    s = sub.add_parser("sample")
    s.add_argument("--repos", required=True, type=_repos)
    s.add_argument("--per-repo", required=True, type=_positive)
    s.add_argument("--out", required=True)
    r = sub.add_parser("run")
    r.add_argument("--manifest", required=True)
    r.add_argument("--results", required=True)
    m = sub.add_parser("summary")
    m.add_argument("--results", required=True)
    return p


def _write_json(path: str, data: Any) -> None:
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=1, sort_keys=True)
    os.replace(tmp, path)


def _load(path: str, default: Any) -> Any:
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        return default


def main(
    argv: Sequence[str],
    env: Mapping[str, str] | None = None,
    *,
    client_factory: Callable[[str], Any] = GitHubClient,
) -> int:
    env = os.environ if env is None else env
    try:
        args = _parser().parse_args(list(argv))
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2

    if args.command == "summary":
        records = [Record.from_json(r) for r in _load(args.results, {"records": []})["records"]]
        print(format_summary(summarise(records)))
        return 0

    token = _token(env)
    if token is None:
        sys.stderr.write("error: GITHUB_TOKEN is missing or malformed\n")
        return 2
    client = client_factory(token)

    if args.command == "sample":
        prs: list[dict[str, Any]] = []
        for repo in dict.fromkeys(args.repos):
            try:
                refs = list_merged_prs(client, repo, args.per_repo)
            except FetchError as exc:
                sys.stderr.write(f"skipping {repo}: {_clean(str(exc), 120)}\n")
                continue
            prs += [{"repo": r.repo, "number": r.number, "head_sha": r.head_sha} for r in refs]
        _write_json(args.out, {"prs": prs})
        print(f"{len(prs)} pull requests sampled")
        return 0

    manifest = _load(args.manifest, {"prs": []})["prs"]
    done = _load(args.results, {"records": []})
    records = done["records"]
    seen = {(r["repo"], r["number"], r["head_sha"]) for r in records}
    engine = Engine(default_registry())
    stopped = False
    for item in manifest:
        ref = PrRef(item["repo"], item["number"], item["head_sha"])
        if (ref.repo, ref.number, ref.head_sha) in seen:
            continue
        try:
            records.append(evaluate(client, ref, engine).to_json())
        except FetchError:  # rate limited: keep what we have, resume later
            sys.stderr.write("rate limit reached; stopping (rerun to resume)\n")
            stopped = True
            break
        if len(records) % 10 == 0:
            _write_json(args.results, {"records": records})
    _write_json(args.results, {"records": records})
    print(format_summary(summarise([Record.from_json(r) for r in records])))
    return 3 if stopped else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
