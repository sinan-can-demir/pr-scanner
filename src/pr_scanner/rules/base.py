"""Rule interface.

A rule is a pure function over a Diff. It must not perform I/O, execute,
import or evaluate any PR-derived data (ADR-0004, NFR-01).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar, Sequence

from ..models import Diff, Finding


class Rule(ABC):
    id: ClassVar[str]
    version: ClassVar[str]
    category: ClassVar[str]
    description: ClassVar[str]

    def __new__(cls, *args, **kwargs):
        missing = [a for a in ("id", "version", "category", "description") if not getattr(cls, a, None)]
        if missing:
            raise TypeError(f"{cls.__name__} is missing rule metadata: {', '.join(missing)}")
        return super().__new__(cls)

    @abstractmethod
    def evaluate(self, diff: Diff) -> Sequence[Finding]:
        """Return zero or more findings for the diff."""
