"""Core domain models (docs/06-domain-model.md).

All PR-derived data here is inert text. Nothing in this module executes,
imports or evaluates it (ADR-0004).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass(frozen=True)
class Finding:
    """An explainable detection result (FR-10)."""

    rule_id: str
    severity: Severity
    file: str
    line: int
    evidence: str
    rationale: str
    remediation: str
    confidence: float = 1.0

    def __post_init__(self) -> None:
        for name in ("rule_id", "file", "evidence", "rationale", "remediation"):
            if not getattr(self, name).strip():
                raise ValueError(f"Finding.{name} must be non-empty")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("Finding.confidence must be within [0, 1]")

    @property
    def fingerprint(self) -> str:
        """Stable content-based identity, used to bind suppressions (FR-11)."""
        raw = "\x1f".join([self.rule_id, self.file, str(self.line), self.evidence])
        return hashlib.sha256(raw.encode("utf-8", "surrogatepass")).hexdigest()


@dataclass(frozen=True)
class ChangedFile:
    path: str
    status: str  # added | modified | removed | renamed
    added_lines: tuple[tuple[int, str], ...] = ()  # (new-file line number, text)
    removed_lines: tuple[tuple[int, str], ...] = ()  # (old-file line number, text)
    old_path: str | None = None  # set for renames
    is_binary: bool = False
    # Full file text at the PR head, supplied by the fetcher (API read only, never executed) for
    # files whose meaning depends on context, e.g. CI workflows. None when unavailable.
    new_content: str | None = None


@dataclass(frozen=True)
class Diff:
    head_sha: str
    base_sha: str
    files: tuple[ChangedFile, ...] = field(default_factory=tuple)

    @property
    def total_added_bytes(self) -> int:
        return sum(len(t.encode("utf-8")) for f in self.files for _, t in f.added_lines)
