"""Verdict computation: a pure function of findings + policy (NFR-07, FR-14)."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable, Sequence

from .models import Finding, Severity


class Outcome(str, Enum):
    PASS = "pass"
    WARN = "warn"
    INCOMPLETE = "incomplete"
    BLOCK = "block"
    ERROR = "error"


@dataclass(frozen=True)
class Policy:
    block_at: Severity = Severity.HIGH
    warn_at: Severity = Severity.MEDIUM

    def __post_init__(self) -> None:
        if self.warn_at > self.block_at:
            raise ValueError("warn_at must not be stricter than block_at")


@dataclass(frozen=True)
class Verdict:
    outcome: Outcome
    reasons: tuple[str, ...] = field(default_factory=tuple)


def compute_verdict(
    findings: Iterable[Finding],
    policy: Policy,
    *,
    incomplete: bool = False,
    errors: Sequence[str] = (),
) -> Verdict:
    """Map findings to a verdict.

    Fail-safe rules (NFR-06, NFR-08): errors and partial scans can never
    produce PASS, and never mask a BLOCK that was found.
    """
    findings = list(findings)
    top = max((f.severity for f in findings), default=None)
    reasons: list[str] = [f"error: {e}" for e in errors]

    if incomplete:
        reasons.append("scan incomplete: resource limits reached")

    if top is not None and top >= policy.block_at:
        reasons.insert(0, f"{sum(f.severity >= policy.block_at for f in findings)} finding(s) at or above block threshold")
        return Verdict(Outcome.BLOCK, tuple(reasons))
    if errors:
        return Verdict(Outcome.ERROR, tuple(reasons))
    if incomplete:
        return Verdict(Outcome.INCOMPLETE, tuple(reasons))
    if top is not None and top >= policy.warn_at:
        reasons.insert(0, f"{sum(f.severity >= policy.warn_at for f in findings)} finding(s) at or above warn threshold")
        return Verdict(Outcome.WARN, tuple(reasons))
    return Verdict(Outcome.PASS, tuple(reasons))
