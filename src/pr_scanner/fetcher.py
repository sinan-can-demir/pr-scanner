"""Fetch a pull request's diff through the GitHub API (FR-02, NFR-06, NFR-08).

Security notes (ADR-0004, T-S01):
* Read-only API calls. The PR is never checked out, installed, built, imported or executed.
* The diff is requested by the immutable base/head SHAs taken from the PR metadata, never by
  PR number, so a force-push during the scan cannot make rules see one commit and the verdict
  describe another.
* Everything returned is attacker-controlled text and is handled as inert data.
* Anything short of a complete, parseable result is either a :class:`FetchError` or a
  :class:`FetchResult` with ``incomplete=True``. It is never an empty "clean" diff (NFR-08).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, replace
from typing import Any, Protocol

from .classify import FileKind, classify
from .diff_parser import DiffParseError, parse_unified_diff
from .github_client import FetchError, HttpResponse
from .models import Diff

_REPO = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")
_SHA = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_DIFF = "application/vnd.github.diff"
_JSON = "application/vnd.github+json"
_RAW = "application/vnd.github.raw+json"


class _Client(Protocol):
    def get(
        self, path: str, *, accept: str = ..., params: Any = ..., max_bytes: int = ...
    ) -> HttpResponse: ...


@dataclass(frozen=True)
class FetchLimits:
    max_diff_bytes: int = 64 * 1024 * 1024
    max_metadata_bytes: int = 4 * 1024 * 1024
    max_content_bytes: int = 1024 * 1024  # per workflow file read for context
    max_content_files: int = 50


@dataclass(frozen=True)
class FetchResult:
    diff: Diff
    incomplete: bool  # something could not be read; the verdict must not be a clean pass
    notes: tuple[str, ...]  # human-readable reasons, safe to show (no attacker text)


_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def _safe_text(text: str, limit: int = 200) -> str:
    """Parser messages can quote attacker-controlled paths; strip control chars and cap length."""
    return _CONTROL.sub(" ", text)[:limit]


def _validate_repo(repo: str) -> None:
    if not _REPO.match(repo) or any(part in {".", ".."} for part in repo.split("/")):
        raise ValueError(f"invalid repository name: {repo!r}")


def _json_object(resp: HttpResponse, what: str) -> dict[str, Any]:
    try:
        data = json.loads(resp.body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise FetchError(f"{what}: response was not valid JSON") from None
    if not isinstance(data, dict):
        raise FetchError(f"{what}: unexpected response shape")
    return data


def _sha(meta: dict[str, Any], side: str) -> str:
    node = meta.get(side)
    sha = node.get("sha") if isinstance(node, dict) else None
    if not isinstance(sha, str) or not _SHA.match(sha):
        raise FetchError(f"PR metadata has no valid {side} sha")
    return sha


def fetch_pull_request(
    client: _Client,
    repo: str,
    number: int,
    *,
    limits: FetchLimits = FetchLimits(),
) -> FetchResult:
    _validate_repo(repo)
    if isinstance(number, bool) or not isinstance(number, int) or number < 1:
        raise ValueError(f"invalid pull request number: {number!r}")

    meta = _json_object(
        client.get(f"/repos/{repo}/pulls/{number}", accept=_JSON, max_bytes=limits.max_metadata_bytes),
        "pull request metadata",
    )
    base_sha, head_sha = _sha(meta, "base"), _sha(meta, "head")
    expected_files = meta.get("changed_files")

    diff_text = client.get(
        f"/repos/{repo}/compare/{base_sha}...{head_sha}", accept=_DIFF, max_bytes=limits.max_diff_bytes
    ).body.decode("utf-8", "replace")
    try:
        diff = parse_unified_diff(
            diff_text, head_sha=head_sha, base_sha=base_sha, max_input_bytes=limits.max_diff_bytes
        )
    except DiffParseError as exc:
        raise FetchError(f"diff could not be parsed: {_safe_text(str(exc))}") from None

    notes: list[str] = []
    if isinstance(expected_files, int) and not isinstance(expected_files, bool):
        if len(diff.files) != expected_files:
            notes.append(
                f"file count mismatch: GitHub reports {expected_files} changed file(s), "
                f"diff contains {len(diff.files)} file(s)"
            )

    head_repo = _head_repo(meta)
    diff, content_notes = _attach_workflow_contents(client, diff, head_repo, head_sha, limits)
    notes.extend(content_notes)
    return FetchResult(diff=diff, incomplete=bool(notes), notes=tuple(notes))


def _head_repo(meta: dict[str, Any]) -> str | None:
    """Full name of the repository holding the head commit (a fork for fork PRs)."""
    head = meta.get("head")
    repo = head.get("repo") if isinstance(head, dict) else None
    name = repo.get("full_name") if isinstance(repo, dict) else None
    if isinstance(name, str) and _REPO.match(name) and not any(p in {".", ".."} for p in name.split("/")):
        return name
    return None


def _attach_workflow_contents(
    client: _Client, diff: Diff, head_repo: str | None, head_sha: str, limits: FetchLimits
) -> tuple[Diff, list[str]]:
    """Fill ``new_content`` for CI files whose meaning depends on lines the diff does not show.

    Notes deliberately omit file paths: they are attacker-controlled and notes are shown to users.
    """
    wanted = [
        i
        for i, f in enumerate(diff.files)
        if classify(f.path) is FileKind.CI_WORKFLOW and f.status != "removed" and not f.is_binary
    ]
    if not wanted:
        return diff, []
    if head_repo is None:
        return diff, [f"head repository unavailable; context for {len(wanted)} workflow file(s) not read"]

    files = list(diff.files)
    failed = 0
    skipped = max(0, len(wanted) - limits.max_content_files)
    for i in wanted[: limits.max_content_files]:
        try:
            resp = client.get(
                f"/repos/{head_repo}/contents/{files[i].path}",
                accept=_RAW,
                params={"ref": head_sha},
                max_bytes=limits.max_content_bytes,
            )
        except FetchError as exc:
            if exc.rate_limited:
                raise
            failed += 1
            continue
        except ValueError:  # the client refused the path
            failed += 1
            continue
        files[i] = replace(files[i], new_content=resp.body.decode("utf-8", "replace"))

    notes: list[str] = []
    if failed:
        notes.append(f"could not read {failed} workflow file(s) at the head commit")
    if skipped:
        notes.append(f"{skipped} workflow file(s) not read: limit of {limits.max_content_files} reached")
    return Diff(head_sha=diff.head_sha, base_sha=diff.base_sha, files=tuple(files)), notes
