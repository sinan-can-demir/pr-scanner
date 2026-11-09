"""Rule engine: runs rules over a diff, fail-safe (NFR-06, NFR-07, NFR-08)."""

from __future__ import annotations

import time
from dataclasses import dataclass, replace
from typing import Callable, Sequence

from .models import Diff, Finding
from .policy import Policy, Verdict, compute_verdict
from .rules.registry import Registry


@dataclass(frozen=True)
class Limits:
    max_files: int = 1000
    max_added_bytes: int = 5 * 1024 * 1024
    max_seconds: float = 60.0
    max_line_chars: int = 1_000_000  # longer lines are truncated and the scan is marked incomplete


@dataclass(frozen=True)
class ScanResult:
    head_sha: str
    findings: tuple[Finding, ...]
    errors: tuple[str, ...]
    incomplete: bool
    verdict: Verdict
    rule_versions: dict[str, str]


class Engine:
    def __init__(
        self,
        registry: Registry,
        limits: Limits = Limits(),
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._registry = registry
        self._limits = limits
        self._clock = clock

    def scan(
        self, diff: Diff, policy: Policy, *, input_incomplete: Sequence[str] = ()
    ) -> ScanResult:
        """Scan ``diff``. ``input_incomplete`` carries the fetcher's reasons it could not read
        everything (``FetchResult.notes``); the engine cannot see what was never given to it,
        so any such reason makes the scan incomplete and can never yield PASS (NFR-06, NFR-08)."""
        incomplete = False

        # Deterministic truncation: stable path order, then cap.
        files = tuple(sorted(diff.files, key=lambda f: f.path))
        if len(files) > self._limits.max_files:
            files = files[: self._limits.max_files]
            incomplete = True
        files, long_line = self._truncate_lines(files)
        incomplete = incomplete or long_line
        scoped = Diff(head_sha=diff.head_sha, base_sha=diff.base_sha, files=files)
        if scoped.total_added_bytes > self._limits.max_added_bytes:
            incomplete = True
            scoped = self._truncate_bytes(scoped)

        findings: list[Finding] = []
        errors: list[str] = []
        versions: dict[str, str] = {}
        start = self._clock()

        for rule in self._registry.rules():
            if self._clock() - start > self._limits.max_seconds:
                incomplete = True
                break
            versions[rule.id] = rule.version
            try:
                produced = list(rule.evaluate(scoped))
            except Exception as exc:  # rule failure must never become a pass
                errors.append(f"{rule.id}: {type(exc).__name__}: {exc}")
                continue
            bad = [f for f in produced if f.rule_id != rule.id]
            if bad:
                errors.append(f"{rule.id}: emitted finding(s) under a different rule id")
                continue
            findings.extend(produced)

        findings.sort(key=lambda f: (f.file, f.line, f.rule_id, f.evidence))
        reasons = [f"input incomplete: {note}" for note in input_incomplete]
        if incomplete:  # at this point only our own limits can have set it
            reasons.append("scan incomplete: resource limits reached")
        incomplete = incomplete or bool(input_incomplete)
        verdict = compute_verdict(
            findings, policy, incomplete=incomplete, incomplete_reasons=reasons, errors=errors
        )
        return ScanResult(
            head_sha=diff.head_sha,
            findings=tuple(findings),
            errors=tuple(errors),
            incomplete=incomplete,
            verdict=verdict,
            rule_versions=versions,
        )

    def _truncate_lines(self, files):
        """Cap very long lines (T-S03) but never silently: report so the verdict is INCOMPLETE."""
        limit, hit, out = self._limits.max_line_chars, False, []
        for f in files:
            if any(len(t) > limit for _, t in f.added_lines):
                hit = True
                f = replace(f, added_lines=tuple((n, t[:limit]) for n, t in f.added_lines))
            out.append(f)
        return tuple(out), hit

    def _truncate_bytes(self, diff: Diff) -> Diff:
        """Keep whole files, in path order, until the byte budget is spent."""
        kept, used = [], 0
        for f in diff.files:
            size = sum(len(t.encode("utf-8")) for _, t in f.added_lines)
            if used + size > self._limits.max_added_bytes:
                continue
            kept.append(f)
            used += size
        return Diff(head_sha=diff.head_sha, base_sha=diff.base_sha, files=tuple(kept))
