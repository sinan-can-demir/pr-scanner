"""Load attack-like code fragments from tests/fixtures/snippets.txt (see the comment there)."""

from __future__ import annotations

from functools import cache
from pathlib import Path

_FILE = Path(__file__).resolve().parent / "fixtures" / "snippets.txt"


@cache
def _all() -> dict[str, str]:
    out: dict[str, str] = {}
    for line in _FILE.read_text(encoding="utf-8").split("\n"):
        if not line or line.startswith("#"):
            continue
        name, sep, text = line.partition(": ")
        if not sep or name in out:
            raise ValueError(f"bad or duplicate snippet line: {line!r}")
        out[name] = text
    return out


def snippet(name: str) -> str:
    return _all()[name]
