"""Publish a validated report as a GitHub check run: the only write path (ADR-0005, NFR-04).

Design rules:
* Exactly one endpoint, ``POST /repos/{owner}/{repo}/check-runs``, with a body built here from a
  report that has just passed :func:`pr_scanner.report_io.parse_report`. Nothing else can be sent.
* The token is only ever placed in the ``Authorization`` header. It never appears in a URL, repr,
  request body or error message, even if the server echoes it back.
* Redirects are not followed, the response is read with a byte cap, and only HTTP 201 is success.
* No automatic retry: creating a check run is not idempotent, and a blind retry could leave two
  runs under the same name. A failure is raised and the job fails visibly; re-running is safe.
* Used by the privileged ``report`` job, which has ``checks: write`` and nothing else.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Mapping, Protocol

from .fetcher import _validate_repo
from .github_client import API_VERSION, DEFAULT_BASE_URL, HttpResponse, _CONTROL, _NoRedirect, _remote_message
from .report_io import parse_report, report_to_json
from .reporter import CheckRunReport

CHECK_NAME = "PR scanner"
MAX_REQUEST_BYTES = 1024 * 1024
MAX_RESPONSE_BYTES = 1024 * 1024
_NAME = re.compile(r"^[A-Za-z0-9 _.-]{1,64}\Z")
_GITHUB_URL = re.compile(r"^https://github\.com/[\x21-\x7e]{1,300}\Z")
_REDACTED = "[redacted]"


class PublishError(Exception):
    """The check run could not be created. The job must fail; never treat as success."""

    def __init__(self, message: str, *, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


class WriteTransport(Protocol):
    def __call__(
        self, method: str, url: str, headers: Mapping[str, str], body: bytes, max_bytes: int
    ) -> HttpResponse: ...


class UrllibWriteTransport:
    """Real transport. Does not follow redirects and never reads more than ``max_bytes``."""

    def __init__(self, timeout: float = 30.0) -> None:
        self._timeout = timeout
        self._opener = urllib.request.build_opener(_NoRedirect)

    def __call__(
        self, method: str, url: str, headers: Mapping[str, str], body: bytes, max_bytes: int
    ) -> HttpResponse:
        req = urllib.request.Request(url, data=body, method=method, headers=dict(headers))
        try:
            resp = self._opener.open(req, timeout=self._timeout)
        except urllib.error.HTTPError as err:
            resp = err
        try:
            data = resp.read(max_bytes + 1)
            hdrs = {k.lower(): v for k, v in resp.headers.items()}
            status = resp.status if hasattr(resp, "status") else resp.code
        finally:
            resp.close()
        if len(data) > max_bytes:
            raise PublishError(f"response exceeded {max_bytes} bytes", status=status)
        return HttpResponse(status=status, headers=hdrs, body=data)


@dataclass(frozen=True)
class PublishedRun:
    id: int | None
    url: str | None


class CheckRunPublisher:
    def __init__(
        self,
        token: str,
        *,
        base_url: str = DEFAULT_BASE_URL,
        transport: WriteTransport | None = None,
        check_name: str = CHECK_NAME,
    ) -> None:
        if not token or _CONTROL.search(token) or " " in token:
            raise ValueError("a non-empty GitHub token without whitespace is required")
        if not base_url.startswith("https://"):
            raise ValueError("base_url must use https")
        if not _NAME.match(check_name):
            raise ValueError("invalid check run name")
        self._token = token
        self._base = base_url.rstrip("/")
        self._transport: WriteTransport = transport or UrllibWriteTransport()
        self._name = check_name

    def __repr__(self) -> str:
        return f"CheckRunPublisher(base_url={self._base!r}, token=<redacted>)"

    def publish(self, repo: str, report: CheckRunReport) -> PublishedRun:
        _validate_repo(repo)
        # Re-validate here, at the last moment before the privileged write.
        checked = parse_report(report_to_json(report))
        body = json.dumps(
            {
                "name": self._name,
                "head_sha": checked.head_sha,
                "status": "completed",
                "conclusion": checked.conclusion,
                "output": {
                    "title": checked.title,
                    "summary": checked.summary,
                    "annotations": list(checked.annotations),
                },
            },
            separators=(",", ":"),
        ).encode("utf-8")
        if len(body) > MAX_REQUEST_BYTES:
            raise PublishError("report is too large to publish")

        headers = {
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
            "X-GitHub-Api-Version": API_VERSION,
            "User-Agent": "pr-scanner",
        }
        try:
            resp = self._transport("POST", f"{self._base}/repos/{repo}/check-runs", headers, body, MAX_RESPONSE_BYTES)
        except PublishError:
            raise
        except Exception as exc:  # the message can echo request data, so report the type only
            raise PublishError(f"request failed: {type(exc).__name__}") from None

        if resp.status != 201:
            detail = _remote_message(resp.body.replace(self._token.encode(), _REDACTED.encode()))
            raise PublishError(
                f"GitHub returned HTTP {resp.status}" + (f": {detail}" if detail else ""),
                status=resp.status,
            )
        return _parse_created(resp.body)


def _parse_created(body: bytes) -> PublishedRun:
    try:
        data = json.loads(body.decode("utf-8"))
    except ValueError:
        return PublishedRun(None, None)
    if not isinstance(data, dict):
        return PublishedRun(None, None)
    run_id = data.get("id")
    url = data.get("html_url")
    return PublishedRun(
        run_id if type(run_id) is int else None,
        url if isinstance(url, str) and _GITHUB_URL.match(url) else None,
    )
