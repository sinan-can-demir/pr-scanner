"""Parse a git unified diff (as served by the GitHub API) into a Diff.

Security notes (ADR-0004, T-S01, T-S03):
* The diff is attacker-controlled. It is only ever treated as inert text.
* Lines are split on "\\n" only. ``str.splitlines`` also splits on U+2028,
  \\x0b, \\x0c, \\x85 etc., which would let an attacker shift line numbers
  or hide content from rules.
* Hunk bodies are consumed using the line counts from the hunk header, so an
  added line such as "+++ b/evil" or "+diff --git ..." can never be mistaken
  for a file header.
* Anything malformed raises DiffParseError. Callers must treat that as a scan
  error (never as "nothing found").
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .models import ChangedFile, Diff

DEFAULT_MAX_INPUT_BYTES = 64 * 1024 * 1024


class DiffParseError(ValueError):
    """The diff is malformed, truncated, or too large to parse safely."""


_HUNK = re.compile(r"^@@ -(\d{1,9})(?:,(\d{1,9}))? \+(\d{1,9})(?:,(\d{1,9}))? @@")
_QUOTED = r'"(?:[^"\\]|\\.)*"'
_HEADER_QUOTED = re.compile(rf"^({_QUOTED}|\S+) ({_QUOTED}|\S+)$")
_SIMPLE_ESCAPES = {"a": 7, "b": 8, "f": 12, "n": 10, "r": 13, "t": 9, "v": 11, "\\": 92, '"': 34}
_IGNORED_PREFIXES = (
    "index ", "old mode ", "new mode ", "similarity index ", "dissimilarity index ",
)


def _unquote(token: str) -> str:
    """Decode a git C-style quoted path ("..." with \\t, \\ooo octal escapes)."""
    if not token.startswith('"'):
        return token.split("\t", 1)[0]
    if len(token) < 2 or not token.endswith('"'):
        raise DiffParseError(f"unterminated quoted path: {token!r}")
    inner, out, i = token[1:-1], bytearray(), 0
    while i < len(inner):
        ch = inner[i]
        if ch != "\\":
            out += ch.encode("utf-8")
            i += 1
            continue
        i += 1
        if i >= len(inner):
            raise DiffParseError("dangling escape in quoted path")
        c = inner[i]
        if c in _SIMPLE_ESCAPES:
            out.append(_SIMPLE_ESCAPES[c])
            i += 1
        elif c in "01234567":
            j = i
            while j < len(inner) and j < i + 3 and inner[j] in "01234567":
                j += 1
            value = int(inner[i:j], 8)
            if value > 255:
                raise DiffParseError("octal escape out of range in quoted path")
            out.append(value)
            i = j
        else:
            raise DiffParseError(f"unknown escape \\{c} in quoted path")
    return out.decode("utf-8", errors="replace")


def _strip_prefix(path: str, prefix: str) -> str:
    if not path.startswith(prefix) or len(path) == len(prefix):
        raise DiffParseError(f"expected path starting with {prefix!r}: {path!r}")
    return path[len(prefix):]


@dataclass
class _Builder:
    header: str
    old_hdr: str | None = None  # raw token after "--- "
    new_hdr: str | None = None  # raw token after "+++ "
    rename_from: str | None = None
    rename_to: str | None = None
    is_new: bool = False
    is_deleted: bool = False
    is_binary: bool = False
    added: list[tuple[int, str]] = field(default_factory=list)
    removed: list[tuple[int, str]] = field(default_factory=list)

    def _header_path(self) -> str:
        rest = self.header
        m = _HEADER_QUOTED.match(rest) if rest.startswith('"') or '"' in rest else None
        if m:
            a, b = _unquote(m.group(1)), _unquote(m.group(2))
            a, b = _strip_prefix(a, "a/"), _strip_prefix(b, "b/")
            if a != b:
                raise DiffParseError("ambiguous diff header without rename info")
            return b
        n = len(rest)
        if n >= 5 and (n - 5) % 2 == 0:
            x = rest[2 : 2 + (n - 5) // 2]
            if rest == f"a/{x} b/{x}":
                return x
        raise DiffParseError(f"cannot determine path from header: {rest!r}")

    def build(self) -> ChangedFile:
        old = new = None
        if self.old_hdr is not None and self.old_hdr.split("\t", 1)[0] != "/dev/null":
            old = _strip_prefix(_unquote(self.old_hdr), "a/")
        if self.new_hdr is not None and self.new_hdr.split("\t", 1)[0] != "/dev/null":
            new = _strip_prefix(_unquote(self.new_hdr), "b/")
        dev_null_old = self.old_hdr is not None and old is None
        dev_null_new = self.new_hdr is not None and new is None

        old_path: str | None = None
        if self.rename_from is not None or self.rename_to is not None:
            if self.rename_from is None or self.rename_to is None:
                raise DiffParseError("incomplete rename header")
            status, path, old_path = "renamed", _unquote(self.rename_to), _unquote(self.rename_from)
        elif self.is_new or dev_null_old:
            status, path = "added", new or self._header_path()
        elif self.is_deleted or dev_null_new:
            status, path = "removed", old or self._header_path()
        else:
            status, path = "modified", new or old or self._header_path()

        return ChangedFile(
            path=path,
            status=status,
            added_lines=tuple(self.added),
            removed_lines=tuple(self.removed),
            old_path=old_path,
            is_binary=self.is_binary,
        )


def parse_unified_diff(
    text: str,
    *,
    head_sha: str,
    base_sha: str,
    max_input_bytes: int = DEFAULT_MAX_INPUT_BYTES,
) -> Diff:
    if len(text.encode("utf-8", "surrogatepass")) > max_input_bytes:
        raise DiffParseError("diff exceeds maximum input size")
    if text == "":
        return Diff(head_sha=head_sha, base_sha=base_sha, files=())

    lines = text.split("\n")
    if lines[-1] == "":
        lines.pop()

    files: list[ChangedFile] = []
    cur: _Builder | None = None
    in_binary = False
    i = 0

    def finish() -> None:
        if cur is not None:
            files.append(cur.build())

    while i < len(lines):
        line = lines[i]

        if line.startswith("diff --git "):
            finish()
            cur, in_binary = _Builder(header=line[len("diff --git "):]), False
            i += 1
            continue
        if cur is None:
            raise DiffParseError("content before first 'diff --git' header")
        if in_binary or line.startswith("\\"):
            i += 1
            continue

        if line.startswith("@@"):
            m = _HUNK.match(line)
            if not m:
                raise DiffParseError(f"bad hunk header: {line[:80]!r}")
            old_ln, old_n = int(m.group(1)), int(m.group(2) if m.group(2) is not None else 1)
            new_ln, new_n = int(m.group(3)), int(m.group(4) if m.group(4) is not None else 1)
            i += 1
            while old_n > 0 or new_n > 0:
                if i >= len(lines):
                    raise DiffParseError("truncated hunk")
                body = lines[i]
                if body.startswith("\\"):
                    i += 1
                    continue
                tag = body[:1]
                if tag == " " or body == "":
                    if old_n <= 0 or new_n <= 0:
                        raise DiffParseError("context line beyond hunk counts")
                    old_n, new_n, old_ln, new_ln = old_n - 1, new_n - 1, old_ln + 1, new_ln + 1
                elif tag == "+":
                    if new_n <= 0:
                        raise DiffParseError("added line beyond hunk counts")
                    cur.added.append((new_ln, body[1:]))
                    new_n, new_ln = new_n - 1, new_ln + 1
                elif tag == "-":
                    if old_n <= 0:
                        raise DiffParseError("removed line beyond hunk counts")
                    cur.removed.append((old_ln, body[1:]))
                    old_n, old_ln = old_n - 1, old_ln + 1
                else:
                    raise DiffParseError(f"unexpected line in hunk: {body[:80]!r}")
                i += 1
            continue

        if line.startswith("--- "):
            cur.old_hdr = line[4:]
        elif line.startswith("+++ "):
            cur.new_hdr = line[4:]
        elif line.startswith("new file mode "):
            cur.is_new = True
        elif line.startswith("deleted file mode "):
            cur.is_deleted = True
        elif line.startswith("rename from "):
            cur.rename_from = line[len("rename from "):]
        elif line.startswith("rename to "):
            cur.rename_to = line[len("rename to "):]
        elif line.startswith("Binary files ") or line == "GIT binary patch":
            cur.is_binary = in_binary = True
        elif line.startswith(_IGNORED_PREFIXES):
            pass
        else:
            raise DiffParseError(f"unrecognised line outside hunk: {line[:80]!r}")
        i += 1

    finish()
    if not files:
        raise DiffParseError("no 'diff --git' header found")
    return Diff(head_sha=head_sha, base_sha=base_sha, files=tuple(files))
