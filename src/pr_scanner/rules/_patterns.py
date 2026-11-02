"""Shared, pre-compiled patterns. All are linear-time-ish and applied to
length-capped strings (T-S03). Input is inert text (ADR-0004)."""

from __future__ import annotations

import re

MAX_SCAN_CHARS = 1_000_000  # matches Limits.max_line_chars; the engine truncates longer lines and marks the scan incomplete.
# Do NOT lower this: truncating short lets an attacker hide a payload behind padding.
EVIDENCE_CHARS = 200


def cap(text: str, n: int = MAX_SCAN_CHARS) -> str:
    return text if len(text) <= n else text[:n]


def evidence(line: str) -> str:
    s = line.strip()
    return s if len(s) <= EVIDENCE_CHARS else s[:EVIDENCE_CHARS] + "…"


def normalise_cmd(cmd: str) -> str:
    """Undo cheap shell obfuscation before matching.

    ``c""url``, ``cu\\rl``, ``curl${IFS}x`` all execute curl; strip the
    quoting/escaping so the patterns below see the real command word.
    """
    s = cmd.replace("${IFS}", " ").replace("$IFS", " ")
    return re.sub(r"[\"'\\]", "", s)


_I = re.IGNORECASE

# (compiled pattern, human-readable reason) applied to normalised commands.
SUSPICIOUS_COMMAND: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b(curl|wget|iwr|invoke-webrequest|invoke-expression|iex)\b", _I), "downloads or fetches from the network"),
    # single "|" only: "||" is logical OR, not a pipe
    (re.compile(r"(?<!\|)\|(?!\|)\s*(?:sudo\s+)?(?:(?:ba|z|da|k)?sh|node|python3?|perl|ruby)\b", _I), "pipes data into an interpreter"),
    (re.compile(r"\b(base64|atob|certutil)\b|\bxxd\s+-r\b", _I), "decodes an encoded payload"),
    (re.compile(r"\beval\b", _I), "uses eval"),
    (re.compile(r"\b(?:node|nodejs)\s+(?:-e|-p|--eval|--print)\b|\bpython3?\s+-c\b|\b(?:perl|ruby)\s+-e\b|\b(?:ba|z)?sh\s+-c\b", _I), "runs inline code"),
    (re.compile(r"\b(?:powershell|pwsh)\b|\bcmd(?:\.exe)?\s+/c\b", _I), "invokes PowerShell or cmd"),
    (re.compile(r"(?:https?|ftp)://|\b\d{1,3}(?:\.\d{1,3}){3}\b", _I), "references a remote URL or raw IP"),
    (re.compile(r"/dev/(?:tcp|udp)/|\b(?:nc|ncat|netcat|socat)\b", _I), "opens a network socket"),
    (re.compile(r"\.ssh\b|\.aws\b|\.npmrc\b|\.netrc\b|\b(?:NPM_TOKEN|GITHUB_TOKEN|AWS_[A-Z_]+|SSH_[A-Z_]+)\b|\b(?:printenv|env)\b\s*\|", _I), "touches credentials or environment secrets"),
]


def suspicious_reasons(cmd: str) -> list[str]:
    n = normalise_cmd(cap(cmd))
    return [reason for pat, reason in SUSPICIOUS_COMMAND if pat.search(n)]
