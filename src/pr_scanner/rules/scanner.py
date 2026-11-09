"""FR-12 / T-D12: changes that disable, replace or weaken the scanner itself.

Why this exists: a rehearsal on 2026-11-09 showed that a PR rewriting the scan step to write a
hand-made ``report.json`` scanned clean. The base-branch workflow stops a PR from disabling the
scan *before* it merges, but once a tampering change is merged it becomes the base. So the change
itself must be flagged and held for owner review.

What counts as "the scanner": a workflow under the repository-root ``.github`` whose name contains
``pr-scan`` / ``pr_scan`` or that calls ``pr_scanner`` / ``pr-scanner`` on a non-comment line;
scanner policy files (``.pr-scanner.yml``); and CODEOWNERS (ownership is what protects the rest).

Findings (one per reason per file, so a hostile file cannot flood the report):

* CRITICAL: the workflow is deleted or renamed away; the number of scanner calls goes down.
* HIGH: a hand-written ``report.json``; the scanner installed without a full commit pin, over a
  non-https or non-github.com URL, from a package index, or from a different repository than
  before; policy file changed or deleted; CODEOWNERS deleted or ownership of workflows removed.
* MEDIUM: any other change to the scanner workflow or CODEOWNERS (owner review required).

Line-based and linear on adversarial input, like the other workflow rules (T-S03). Known limits:
removing one of several scanner calls during a legitimate refactor reads as CRITICAL (a human
decides); a hand-written report built through an unusual tool is not seen; changes to the
scanner's own source code in a repository that vendors it are out of scope.
"""

from __future__ import annotations

import posixpath
import re
from typing import Sequence

from ..classify import FileKind, classify
from ..models import ChangedFile, Diff, Finding, Severity
from ._patterns import cap, normalise_cmd
from .base import Rule
from .workflows import _finding, _is_comment, _is_github_workflow, _norm

_REF = re.compile(r"pr[_-]scanner", re.IGNORECASE)
_NAME = re.compile(r"pr[_-]scan", re.IGNORECASE)
_TOKEN = re.compile(r"[^\s|;&]+")
_PIP_WORDS = {"pip", "pip3", "pipx", "uv", "poetry", "easy_install", "conda"}
_REPORT_VERBS = {"cp", "mv", "tee", "dd", "install", "ln", "sed", "sponge", "curl", "wget", "rsync"}
_WRITE_APIS = ("open(", "write_text", "write_bytes", "writefile", "fs.write", "json.dump")
_GIT_URL = re.compile(
    r"git\+([a-z]+)://([^/\s]*)/([^/\s@]+)/([^/\s@#]+?)(?:\.git)?(?:@([^\s#]*))?(?=\s|$|#)",
    re.IGNORECASE,
)
_FULL_SHA = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z", re.IGNORECASE)
_OWNERSHIP_WORDS = re.compile(r"\.github|workflow|pr[_-]scan", re.IGNORECASE)
_MAX_PER_FILE_INSTALLS = 3


def _clean(line: str) -> str:
    """Undo cheap quoting/escaping (``rep""ort``) so tokens are seen as the shell would."""
    return normalise_cmd(cap(line))


def _refs(lines: Sequence[tuple[int, str]]) -> list[tuple[int, str]]:
    return [(n, t) for n, t in lines if not _is_comment(t) and _REF.search(_clean(t))]


def _live(lines: Sequence[tuple[int, str]]) -> list[tuple[int, str]]:
    """Meaningful changed lines: not comments, not blank (a blank line is not usable evidence)."""
    return [(n, t) for n, t in lines if t.strip() and not _is_comment(t)]


def _writes_report(line: str) -> bool:
    """A hand-written report: a redirect or copy/transfer verb targeting ``report.json``, or a
    scripting call that writes. Token based, so linear however the line is padded."""
    norm = _clean(line).lower()
    if "report.json" not in norm:
        return False
    if any(api in norm for api in _WRITE_APIS):
        return True
    prev_redirect = False
    for tok in _TOKEN.findall(norm):
        if posixpath.basename(tok) in _REPORT_VERBS:
            return True
        if "report.json" in tok:
            if prev_redirect or ">" in tok[: tok.index("report.json")]:
                return True
        prev_redirect = tok.endswith(">")
    return False


def _install_sources(lines: Sequence[tuple[int, str]]) -> list[tuple[int, str, re.Match[str]]]:
    out = []
    for n, t in _live(lines):
        for m in _GIT_URL.finditer(_clean(t)):
            if _REF.search(m.group(4) or "") or _REF.search(m.group(3) or ""):
                out.append((n, t, m))
    return out


def _repo_id(m: re.Match[str]) -> str:
    return f"{m.group(3)}/{m.group(4)}".lower()


class ScannerTamper(Rule):
    id = "SCANNER-TAMPER"
    version = "1"
    category = "scanner"
    description = "changes that disable, replace or weaken the scanner workflow, its policy file or CODEOWNERS"

    def evaluate(self, diff: Diff) -> Sequence[Finding]:
        out: list[Finding] = []
        for f in diff.files:
            if f.is_binary and f.status != "removed":
                continue
            kind = classify(f.path)
            base = posixpath.basename(_norm(f.path))
            if kind == FileKind.SCANNER_CONFIG and base.startswith(".pr-scanner"):
                out.extend(self._policy_file(f))
            elif kind == FileKind.SCANNER_CONFIG and base == "codeowners":
                out.extend(self._codeowners(f))
            if f.old_path is not None and f.old_path != f.path:
                out.extend(self._renamed(f))
            if _is_github_workflow(f.path):
                out.extend(self._workflow(f))
        return out

    # ---- the scanner workflow ----------------------------------------------------------

    def _is_scanner_workflow(self, f: ChangedFile) -> bool:
        if _NAME.search(posixpath.basename(_norm(f.path))):
            return True
        if _refs(f.added_lines) or _refs(f.removed_lines):
            return True
        if f.new_content is not None:
            return any(not _is_comment(t) and _REF.search(_clean(t)) for t in f.new_content.split("\n"))
        return False

    def _workflow(self, f: ChangedFile) -> list[Finding]:
        if not self._is_scanner_workflow(f):
            return []
        out: list[Finding] = []

        if f.status == "removed":
            out.append(self._deleted(f, "This workflow runs the scanner and the pull request deletes it. Once merged, "
                                        "pull requests are no longer scanned."))
            return out

        added, removed = _live(f.added_lines), _live(f.removed_lines)
        added_refs, removed_refs = _refs(f.added_lines), _refs(f.removed_lines)

        if removed_refs and len(removed_refs) > len(added_refs):
            n, t = removed_refs[0]
            out.append(_finding(
                self, f, n, t, Severity.CRITICAL,
                "This change removes a call to the scanner from the scanner workflow without replacing it. "
                "Once merged, pull requests are scanned less, or not at all.",
                "Restore the scanner step. If the scanner is being replaced or reorganised on purpose, have the "
                "repository owners review exactly what runs and what it reports.",
                0.9,
            ))

        report = next(((n, t) for n, t in added if _writes_report(t)), None)
        if report:
            out.append(_finding(
                self, f, report[0], report[1], Severity.HIGH,
                "This line writes the scan report by hand. The privileged job publishes that file as the scan "
                "result, so a hand-written report can make any pull request look clean.",
                "Let only the scanner produce report.json. Remove this line.",
                0.85,
            ))

        out.extend(self._install_findings(f, added, removed))

        if not out and (added or removed):
            n, t = (added or removed)[0]
            out.append(_finding(
                self, f, n, t, Severity.MEDIUM,
                "This pull request changes the workflow that runs the scanner. Changes here decide what every "
                "later pull request is checked with.",
                "Have a repository owner review the change (CODEOWNERS on this path), and check that the scanner "
                "is still installed from a pinned commit of the expected repository.",
                0.7,
            ))
        return out

    def _install_findings(self, f: ChangedFile, added, removed) -> list[Finding]:
        out: list[Finding] = []
        before = {_repo_id(m) for _, _, m in _install_sources(removed)}
        for n, t, m in _install_sources(added)[:_MAX_PER_FILE_INSTALLS]:
            scheme, host, ref = m.group(1).lower(), m.group(2).lower(), m.group(5) or ""
            if scheme != "https" or host != "github.com":
                why = ("The scanner is installed over a URL that is not plain https://github.com. A different host, "
                       "embedded credentials or an unencrypted scheme can serve different code.")
                fix = "Install the scanner from https://github.com/<owner>/pr-scanner at a full commit SHA."
            elif before and _repo_id(m) not in before:
                why = ("The scanner is now installed from a different repository than before. That repository's code "
                       "decides every verdict.")
                fix = "Confirm the new repository is the one you intend to trust, or revert."
            elif not _FULL_SHA.match(ref):
                why = ("The scanner is no longer pinned to a full commit SHA. A branch, tag or short id can be moved "
                       "or hijacked, silently changing what runs with the repository's token.")
                fix = "Pin the scanner to a full 40-character commit SHA."
            else:
                continue
            out.append(_finding(self, f, n, t, Severity.HIGH, why, fix, 0.85))
        if not out:
            for n, t in _live(added):
                words = {w.lower() for w in _TOKEN.findall(_clean(t))}
                if _REF.search(_clean(t)) and "git+" not in t.lower() and words & _PIP_WORDS and "install" in words:
                    out.append(_finding(
                        self, f, n, t, Severity.HIGH,
                        "The scanner is installed from a package index or without a commit pin. Anyone who can publish "
                        "under that name controls what runs with the repository's token.",
                        "Install the scanner from this repository at a full 40-character commit SHA.",
                        0.8,
                    ))
                    break
        return out

    # ---- deletion, rename -----------------------------------------------------------------

    def _deleted(self, f: ChangedFile, why: str) -> Finding:
        return _finding(
            self, f, 1, f"file removed: {f.path}", Severity.CRITICAL, why,
            "Do not merge. Restore the file; changes to the scanner need owner review.", 0.95,
        )

    def _renamed(self, f: ChangedFile) -> list[Finding]:
        old = f.old_path or ""
        if not _is_github_workflow(old):
            return []
        was_scanner = bool(_NAME.search(posixpath.basename(_norm(old)))) or bool(_refs(f.removed_lines))
        if not was_scanner:
            return []
        if _is_github_workflow(f.path):
            sev, why = Severity.HIGH, "The scanner workflow is renamed. Check that it still runs and still does the same thing."
        else:
            sev, why = Severity.CRITICAL, "The scanner workflow is moved out of .github/workflows, where GitHub stops running it."
        return [_finding(self, f, 1, f"renamed from {old}", sev, why,
                         "Keep the scanner workflow in place; changes need owner review.", 0.9)]

    # ---- policy file and ownership ----------------------------------------------------------

    def _policy_file(self, f: ChangedFile) -> list[Finding]:
        lines = _live(f.added_lines) or _live(f.removed_lines)
        n, t = lines[0] if lines else (1, f"file {f.status}: {f.path}")
        why = ("This is the scanner's policy file. It sets what is blocked and what is allowed, so a weaker policy "
               "silently lets more through.")
        if f.status == "removed":
            t = f"file removed: {f.path}"
        return [_finding(self, f, n, t, Severity.HIGH, why,
                         "Have a repository owner review the policy change line by line.", 0.85)]

    def _codeowners(self, f: ChangedFile) -> list[Finding]:
        if f.status == "removed":
            return [_finding(self, f, 1, f"file removed: {f.path}", Severity.HIGH,
                             "CODEOWNERS is what forces owner review of the scanner workflow and policy. Deleting it "
                             "removes that protection.", "Restore CODEOWNERS.", 0.9)]
        dropped = next(((n, t) for n, t in _live(f.removed_lines) if _OWNERSHIP_WORDS.search(_clean(t))), None)
        if dropped:
            return [_finding(self, f, dropped[0], dropped[1], Severity.HIGH,
                             "This removes ownership of workflows or the scanner configuration, which is what forces "
                             "owner review of changes to them.", "Keep owners on .github/ and the scanner policy.", 0.85)]
        lines = _live(f.added_lines) or _live(f.removed_lines)
        if not lines:
            return []
        n, t = lines[0]
        return [_finding(self, f, n, t, Severity.MEDIUM,
                         "CODEOWNERS decides who must approve changes, including to the scanner. Check that no "
                         "protection was weakened.", "Have a repository owner review the change.", 0.6)]
