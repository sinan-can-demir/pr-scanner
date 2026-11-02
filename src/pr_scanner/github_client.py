"""Minimal, read-only GitHub REST client (FR-02, NFR-04, NFR-06, NFR-08).

Design rules:
* Standard library only; the transport is injectable so tests replay recorded responses.
* GET only. There is no code path that writes to GitHub or touches PR code (ADR-0004).
* The token is only ever placed in the ``Authorization`` header. It is never part of a URL, a
  repr, or an error message.
* Redirects are never followed (urllib would forward the Authorization header to the new host).
* Bodies are read with a hard byte cap, so a hostile or huge response cannot exhaust memory.
* Every failure raises :class:`FetchError`. Callers must treat that as a scan error, never as
  "nothing found" (NFR-08).
"""

from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Callable, Mapping, Protocol

DEFAULT_BASE_URL = "https://api.github.com"
API_VERSION = "2022-11-28"
DEFAULT_MAX_BYTES = 64 * 1024 * 1024
MAX_RETRY_AFTER_SECONDS = 30.0
_MAX_REMOTE_MESSAGE = 200
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")


class FetchError(Exception):
    """A GitHub read failed. Never to be interpreted as a clean result."""

    def __init__(self, message: str, *, status: int | None = None, rate_limited: bool = False) -> None:
        super().__init__(message)
        self.status = status
        self.rate_limited = rate_limited


@dataclass(frozen=True)
class HttpResponse:
    status: int
    headers: Mapping[str, str]  # lower-case names
    body: bytes


class Transport(Protocol):
    def __call__(
        self, method: str, url: str, headers: Mapping[str, str], max_bytes: int
    ) -> HttpResponse: ...


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # type: ignore[override]
        return None  # surfaces the 3xx as an HTTPError instead of following it


class UrllibTransport:
    """Real transport. Does not follow redirects and never reads more than ``max_bytes``."""

    def __init__(self, timeout: float = 30.0) -> None:
        self._timeout = timeout
        self._opener = urllib.request.build_opener(_NoRedirect)

    def __call__(
        self, method: str, url: str, headers: Mapping[str, str], max_bytes: int
    ) -> HttpResponse:
        req = urllib.request.Request(url, method=method, headers=dict(headers))
        try:
            resp = self._opener.open(req, timeout=self._timeout)
        except urllib.error.HTTPError as err:  # non-2xx, including un-followed redirects
            resp = err
        try:
            body = resp.read(max_bytes + 1)
            hdrs = {k.lower(): v for k, v in resp.headers.items()}
            status = resp.status if hasattr(resp, "status") else resp.code
        finally:
            resp.close()
        if len(body) > max_bytes:
            raise FetchError(f"response exceeded {max_bytes} bytes", status=status)
        return HttpResponse(status=status, headers=hdrs, body=body)


def _remote_message(body: bytes) -> str:
    """Extract GitHub's error message, neutralised: it is remote text and may be hostile."""
    try:
        data = json.loads(body.decode("utf-8", "replace"))
        msg = data.get("message", "") if isinstance(data, dict) else ""
    except ValueError:
        msg = ""
    msg = _CONTROL.sub(" ", str(msg))[:_MAX_REMOTE_MESSAGE]
    return msg


def _check_path(path: str) -> None:
    if (
        not path.startswith("/")
        or path.startswith("//")
        or "://" in path
        or "\\" in path
        or _CONTROL.search(path)
        or ".." in path.split("/")
    ):
        raise ValueError(f"invalid API path: {path!r}")


class GitHubClient:
    def __init__(
        self,
        token: str,
        *,
        base_url: str = DEFAULT_BASE_URL,
        transport: Transport | None = None,
        sleep: Callable[[float], None] = time.sleep,
        max_retries: int = 2,
    ) -> None:
        if not token or _CONTROL.search(token) or " " in token:
            raise ValueError("a non-empty GitHub token without whitespace is required")
        if not base_url.startswith("https://"):
            raise ValueError("base_url must use https")
        self._token = token
        self._base = base_url.rstrip("/")
        self._transport: Transport = transport or UrllibTransport()
        self._sleep = sleep
        self._max_retries = max_retries

    def __repr__(self) -> str:
        return f"GitHubClient(base_url={self._base!r}, token=<redacted>)"

    def get(
        self,
        path: str,
        *,
        accept: str = "application/vnd.github+json",
        params: Mapping[str, str] | None = None,
        max_bytes: int = DEFAULT_MAX_BYTES,
    ) -> HttpResponse:
        _check_path(path)
        url = self._base + urllib.parse.quote(path, safe="/%")
        if params:
            url += "?" + urllib.parse.urlencode(params, quote_via=urllib.parse.quote)
        headers = {
            "Authorization": f"Bearer {self._token}",
            "Accept": accept,
            "X-GitHub-Api-Version": API_VERSION,
            "User-Agent": "pr-scanner",
        }

        attempt = 0
        while True:
            try:
                resp = self._transport("GET", url, headers, max_bytes)
            except FetchError:
                raise
            except Exception as exc:  # network failure; message may echo request data
                if attempt < self._max_retries:
                    attempt += 1
                    self._sleep(float(attempt))
                    continue
                raise FetchError(f"request failed: {type(exc).__name__}") from None

            if len(resp.body) > max_bytes:
                raise FetchError(f"response exceeded {max_bytes} bytes", status=resp.status)
            if 200 <= resp.status < 300:
                return resp

            retry_after = self._retry_after(resp)
            if resp.status in (403, 429) and (
                resp.headers.get("x-ratelimit-remaining") == "0" or retry_after is not None
            ):
                if retry_after is not None and retry_after <= MAX_RETRY_AFTER_SECONDS and attempt < self._max_retries:
                    attempt += 1
                    self._sleep(retry_after)
                    continue
                raise FetchError(
                    f"GitHub rate limit reached (HTTP {resp.status})", status=resp.status, rate_limited=True
                )
            if resp.status >= 500 and attempt < self._max_retries:
                attempt += 1
                self._sleep(float(attempt))
                continue

            detail = _remote_message(resp.body)
            raise FetchError(
                f"GitHub returned HTTP {resp.status}" + (f": {detail}" if detail else ""),
                status=resp.status,
            )

    @staticmethod
    def _retry_after(resp: HttpResponse) -> float | None:
        raw = resp.headers.get("retry-after")
        if raw is None:
            return None
        try:
            return max(0.0, float(raw))
        except ValueError:
            return None
