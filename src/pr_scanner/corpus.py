"""Corpus runner: measures recall / false-positive rates (NFR-03, FR-16).

Layout::

    corpus/
      malicious/<case>/diff.patch + meta.json
      benign/<case>/diff.patch    + meta.json

``diff.patch`` files are inert data and are only ever parsed, never executed.
Malicious samples must be defanged (no live payloads, endpoints or secrets).
"""

from __future__ import annotations

import json
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from .diff_parser import DiffParseError, parse_unified_diff
from .engine import Engine
from .policy import Outcome, Policy

LABELS = ("malicious", "benign")
_RANK = {Outcome.PASS: 0, Outcome.WARN: 1, Outcome.BLOCK: 2}
_ALLOWED = {"malicious": {"warn", "block"}, "benign": {"pass", "warn"}}


class CorpusError(ValueError):
    """The corpus is malformed (a corpus bug, not a scanner result)."""


@dataclass(frozen=True)
class Case:
    name: str
    label: str
    patch: str
    description: str
    expect_outcome: str
    threat: str | None = None
    expect_rules: tuple[str, ...] = ()
    covers_rules: tuple[str, ...] = ()  # benign: rules this is a negative example for (FR-16)


@dataclass(frozen=True)
class CaseResult:
    name: str
    label: str
    ok: bool
    outcome: str
    rules_fired: tuple[str, ...]
    detail: str = ""


@dataclass
class RuleStats:
    true_positives: int = 0
    false_positives: int = 0
    unexpected: int = 0  # fired on a malicious case that did not list it

    @property
    def precision(self) -> float | None:
        n = self.true_positives + self.false_positives
        return self.true_positives / n if n else None


@dataclass
class Report:
    results: list[CaseResult] = field(default_factory=list)
    malicious_total: int = 0
    malicious_detected: int = 0
    benign_total: int = 0
    benign_blocked: int = 0
    benign_warned: int = 0
    per_rule: dict[str, RuleStats] = field(default_factory=lambda: defaultdict(RuleStats))

    @property
    def recall(self) -> float | None:
        return self.malicious_detected / self.malicious_total if self.malicious_total else None

    @property
    def block_fp_rate(self) -> float | None:
        return self.benign_blocked / self.benign_total if self.benign_total else None

    @property
    def warn_fp_rate(self) -> float | None:
        return self.benign_warned / self.benign_total if self.benign_total else None

    @property
    def failures(self) -> list[CaseResult]:
        return [r for r in self.results if not r.ok]


def load_cases(root: Path | str) -> list[Case]:
    root = Path(root)
    for child in root.iterdir() if root.exists() else []:
        if child.is_dir() and child.name not in LABELS and not child.name.startswith("."):
            raise CorpusError(f"unknown corpus label directory: {child.name}")

    cases: list[Case] = []
    for label in LABELS:
        base = root / label
        if not base.is_dir():
            continue
        for d in sorted(p for p in base.iterdir() if p.is_dir()):
            patch_file, meta_file = d / "diff.patch", d / "meta.json"
            if not patch_file.is_file() or not meta_file.is_file():
                raise CorpusError(f"{d}: needs diff.patch and meta.json")
            try:
                meta = json.loads(meta_file.read_text(encoding="utf-8"))
            except ValueError as exc:
                raise CorpusError(f"{meta_file}: invalid JSON: {exc}") from exc
            if not isinstance(meta, dict) or not str(meta.get("description", "")).strip():
                raise CorpusError(f"{meta_file}: 'description' is required")
            outcome = meta.get("expect_outcome")
            if outcome not in _ALLOWED[label]:
                raise CorpusError(f"{meta_file}: expect_outcome must be one of {sorted(_ALLOWED[label])}")
            threat, rules = meta.get("threat"), tuple(meta.get("expect_rules", ()))
            if label == "malicious" and (not threat or not rules):
                raise CorpusError(f"{meta_file}: malicious cases need 'threat' and 'expect_rules'")
            cases.append(
                Case(
                    name=d.name,
                    label=label,
                    patch=patch_file.read_text(encoding="utf-8"),
                    description=meta["description"],
                    expect_outcome=outcome,
                    threat=threat,
                    expect_rules=rules,
                    covers_rules=tuple(meta.get("covers_rules", ())),
                )
            )
    return cases


def run_corpus(cases: list[Case], engine: Engine, policy: Policy) -> Report:
    report = Report()
    for c in cases:
        try:
            diff = parse_unified_diff(c.patch, head_sha="a" * 40, base_sha="b" * 40)
        except DiffParseError as exc:
            report.results.append(CaseResult(c.name, c.label, False, "error", (), f"parse failure: {exc}"))
            report.malicious_total += c.label == "malicious"
            report.benign_total += c.label == "benign"
            continue

        result = engine.scan(diff, policy)
        outcome = result.verdict.outcome
        fired = tuple(sorted({f.rule_id for f in result.findings}))

        if c.label == "malicious":
            report.malicious_total += 1
            rank_ok = outcome in _RANK and _RANK[outcome] >= _RANK[Outcome(c.expect_outcome)]
            rules_ok = set(c.expect_rules) <= set(fired)
            ok = rank_ok and rules_ok
            report.malicious_detected += ok
            for r in fired:
                if r in c.expect_rules:
                    report.per_rule[r].true_positives += 1
                else:
                    report.per_rule[r].unexpected += 1
            detail = "" if ok else f"outcome={outcome.value} fired={list(fired)} expected={c.expect_outcome} {list(c.expect_rules)}"
        else:
            report.benign_total += 1
            report.benign_blocked += outcome == Outcome.BLOCK
            report.benign_warned += outcome == Outcome.WARN
            ok = outcome in _RANK and _RANK[outcome] <= _RANK[Outcome(c.expect_outcome)]
            for r in fired:
                report.per_rule[r].false_positives += 1
            detail = "" if ok else f"outcome={outcome.value} fired={list(fired)} expected<={c.expect_outcome}"

        report.results.append(CaseResult(c.name, c.label, ok, outcome.value, fired, detail))
    return report


def format_report(report: Report) -> str:
    def pct(x: float | None) -> str:
        return "n/a" if x is None else f"{x:.1%}"

    lines = [
        f"malicious: {report.malicious_detected}/{report.malicious_total} detected (recall {pct(report.recall)})",
        f"benign:    {report.benign_blocked} blocked ({pct(report.block_fp_rate)}), "
        f"{report.benign_warned} warned ({pct(report.warn_fp_rate)}) of {report.benign_total}",
        "per rule:",
    ]
    for rid in sorted(report.per_rule):
        s = report.per_rule[rid]
        lines.append(f"  {rid:16} TP={s.true_positives} FP={s.false_positives} unexpected={s.unexpected} precision={pct(s.precision)}")
    for r in report.failures:
        lines.append(f"FAIL [{r.label}] {r.name}: {r.detail}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    from .rules import default_registry

    argv = sys.argv[1:] if argv is None else argv
    root = argv[0] if argv else "corpus"
    report = run_corpus(load_cases(root), Engine(default_registry()), Policy())
    print(format_report(report))
    return 1 if report.failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
