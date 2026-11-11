"""FR-05 / T-D03, T-D08, T-D12: risky CI workflow changes.

Line-based and dependency-free on purpose (no YAML parser to attack, no
alias-bomb risk). Rules report on *added* lines. Where a decision depends on
context outside the diff (is this workflow triggered by pull_request_target?)
they use ``ChangedFile.new_content`` when the fetcher supplied it and fall
back to a weaker, lower-severity answer when it did not.

Every regex is applied once per line with no nested/unbounded repetition
after a repeated token, so adversarial long lines stay linear (T-S03).
"""

from __future__ import annotations

import posixpath
import re
from bisect import bisect_right
from typing import Iterator, Sequence

from ..classify import FileKind, classify
from ..models import ChangedFile, Diff, Finding, Severity
from .base import Rule
from ._patterns import cap, evidence, normalise_cmd


def _norm(path: str) -> str:
    p = posixpath.normpath(path.replace("\\", "/").lower())
    return p[2:] if p.startswith("./") else p


def _is_github_workflow(path: str) -> bool:
    """Only the repository-root .github directory is executed by GitHub."""
    p = _norm(path)
    return (p.startswith(".github/workflows/") and p.endswith((".yml", ".yaml"))) or (
        p.startswith(".github/actions/") and posixpath.basename(p) in {"action.yml", "action.yaml"}
    )


def _is_any_ci(path: str) -> bool:
    return classify(path) == FileKind.CI_WORKFLOW


def _is_comment(line: str) -> bool:
    return line.lstrip().startswith("#")


def _added(f: ChangedFile) -> Iterator[tuple[int, str]]:
    """Added, non-comment lines."""
    for n, t in f.added_lines:
        if not _is_comment(t):
            yield n, t


def _eligible(diff: Diff, pred) -> Iterator[ChangedFile]:
    for f in diff.files:
        if f.status != "removed" and not f.is_binary and pred(f.path):
            yield f


def _finding(rule: Rule, f: ChangedFile, line: int, text: str, sev: Severity, why: str, fix: str, conf: float = 0.8) -> Finding:
    return Finding(
        rule_id=rule.id, severity=sev, file=f.path, line=line, evidence=evidence(text),
        rationale=why, remediation=fix, confidence=conf,
    )


# ============================================================ CI-PRT

_PRT = re.compile(r"\bpull_request_target\b")
_WORKFLOW_RUN = re.compile(r"\bworkflow_run\b")
_PR_HEAD = (
    r"github\.event\.pull_request\.head\.(?:sha|ref|label|repo\.\w+)"
    r"|github\.head_ref"
    r"|refs/pull/"
)
_WR_HEAD = r"github\.event\.workflow_run\.head_(?:sha|branch|repository)"
_REF_KEY = re.compile(r"\b(?:ref|repository)\s*:")
_PR_HEAD_RX = re.compile(_PR_HEAD)
_WR_HEAD_RX = re.compile(_WR_HEAD)
_CHECKOUT_CMD = re.compile(
    r"\bgh\s+pr\s+checkout\b|\bgit\s+(?:fetch|checkout|pull)\b[^#\n]{0,200}?(?:refs/pull/|\bpull/|github\.head_ref|pull_request\.head)"
)


def _key_then_value(s: str, value_rx: re.Pattern[str]) -> bool:
    """True if a ``ref:``/``repository:`` key precedes a value match with no ``#`` comment between.

    Done with bisect over match positions so it is linear however many keys the line
    repeats (a lazy ``key[^#]*?value`` regex is quadratic) and however much padding the
    attacker inserts between key and value.
    """
    keys = [m.start() for m in _REF_KEY.finditer(s)]
    if not keys:
        return False
    hashes = [m.start() for m in re.finditer("#", s)]
    for m in value_rx.finditer(s):
        p = m.start()
        ki = bisect_right(keys, p) - 1
        if ki < 0:
            continue
        hi = bisect_right(hashes, p) - 1
        if hi >= 0 and hashes[hi] > keys[ki]:
            continue
        return True
    return False


class PullRequestTargetCheckout(Rule):
    id = "CI-PRT"
    version = "1"
    category = "ci"
    description = "pull_request_target combined with checking out pull-request code, or the trigger newly added"

    def evaluate(self, diff: Diff) -> Sequence[Finding]:
        out: list[Finding] = []
        for f in _eligible(diff, _is_github_workflow):
            added = [(n, cap(t)) for n, t in _added(f)]
            view = (
                [t for t in f.new_content.split("\n") if not _is_comment(t)]
                if f.new_content is not None
                else [t for _, t in added]
            )
            has_prt = any(_PRT.search(t) for t in view)
            has_wr = any(_WORKFLOW_RUN.search(t) for t in view)

            head = next(((n, t) for n, t in added if _key_then_value(t, _PR_HEAD_RX) or _CHECKOUT_CMD.search(t)), None)
            wr_head = next(((n, t) for n, t in added if _key_then_value(t, _WR_HEAD_RX)), None)
            trig = next(((n, t) for n, t in added if _PRT.search(t)), None)

            if head and has_prt:
                out.append(_finding(
                    self, f, head[0], head[1], Severity.CRITICAL,
                    "This workflow is triggered by pull_request_target, which runs with the base repository's secrets and a "
                    "write-capable token, and it checks out code from the pull request. Anything the PR author put in the "
                    "code (install scripts, tests, build files) then runs with those secrets.",
                    "Never check out or run pull-request code in a pull_request_target workflow. Use the pull_request trigger "
                    "for untrusted code, or split into an unprivileged build job and a separate privileged job that only "
                    "consumes sanitised artifacts.",
                    0.95,
                ))
            elif wr_head and has_wr:
                out.append(_finding(
                    self, f, wr_head[0], wr_head[1], Severity.HIGH,
                    "This workflow_run workflow runs with secrets but checks out the head commit of the workflow that triggered "
                    "it, which can come from a fork pull request.",
                    "Do not check out or execute the triggering run's head. Treat artifacts from it as untrusted data.",
                    0.8,
                ))
            elif head and f.new_content is None:
                out.append(_finding(
                    self, f, head[0], head[1], Severity.MEDIUM,
                    "This line checks out code from a pull request. If the workflow is triggered by pull_request_target "
                    "(not visible from the diff alone) it would run attacker-controlled code with the repository's secrets.",
                    "Confirm which trigger this workflow uses. Do not check out pull-request code under pull_request_target.",
                    0.5,
                ))
            elif trig:
                out.append(_finding(
                    self, f, trig[0], trig[1], Severity.MEDIUM,
                    "The pull_request_target trigger was added. It runs with the base repository's secrets and a write token "
                    "even for pull requests from forks, so it must never execute pull-request code.",
                    "Prefer the pull_request trigger. If pull_request_target is required, keep the workflow to metadata tasks "
                    "(labelling, commenting) and never check out or run the PR's code.",
                    0.6,
                ))
        return out


# ========================================================== CI-UNPINNED

_USES = re.compile(r"""^\s*(?:-\s*)?uses\s*:\s*["']?([^\s"'#]+)""")
_FULL_SHA = re.compile(r"[0-9a-fA-F]{40}(?:[0-9a-fA-F]{24})?")
_BRANCHY = re.compile(r"(?:main|master|trunk|dev|develop|development|head|latest|stable|release[\w./-]*)", re.IGNORECASE)
_FIRST_PARTY = {"actions", "github"}


class ActionPinning(Rule):
    id = "CI-UNPINNED"
    version = "1"
    category = "ci"
    description = "GitHub Actions referenced by a mutable tag or branch instead of a full commit SHA"

    def evaluate(self, diff: Diff) -> Sequence[Finding]:
        out: list[Finding] = []
        for f in _eligible(diff, _is_github_workflow):
            for n, t in _added(f):
                m = _USES.match(cap(t))
                if not m:
                    continue
                ref_full = m.group(1)
                if ref_full.startswith(("./", "../")):
                    continue  # local action: reviewed in the same PR
                if ref_full.startswith("docker://"):
                    if "@sha256:" in ref_full:
                        continue
                    sev, what = Severity.MEDIUM, "a Docker image tag, which can be re-pointed"
                else:
                    name, _, ref = ref_full.rpartition("@")
                    if not name:
                        continue
                    if _FULL_SHA.fullmatch(ref):
                        continue
                    owner = name.split("/", 1)[0].lower()
                    if _BRANCHY.fullmatch(ref):
                        sev, what = Severity.HIGH, f"the mutable branch '{ref}'"
                    elif owner in _FIRST_PARTY:
                        sev, what = Severity.LOW, f"the tag '{ref}' of a first-party action"
                    else:
                        sev, what = Severity.MEDIUM, f"the tag or short reference '{ref}'"
                out.append(_finding(
                    self, f, n, t, sev,
                    f"This step uses {ref_full.split('@')[0]} via {what}. Whoever controls that tag or branch can change what "
                    "runs in your pipeline, with your secrets, without any change to this repository.",
                    "Pin the action to the full 40-character commit SHA (keep the version in a trailing comment) and let "
                    "Dependabot or Renovate update it.",
                    0.9,
                ))
        return out


# ============================================================ CI-PERMS

_WRITE_ALL = re.compile(r"\bpermissions\s*:\s*write-all\b")
_WRITE = re.compile(
    r"\b(contents|actions|id-token|packages|security-events|deployments|issues|pull-requests|checks|statuses|"
    r"discussions|pages|repository-projects)\s*:\s*write\b"
)
_HIGH_WRITE = {"contents", "actions", "id-token", "packages", "security-events", "deployments"}


class PermissionsWidening(Rule):
    id = "CI-PERMS"
    version = "1"
    category = "ci"
    description = "workflow token permissions widened (write-all or write scopes)"

    def evaluate(self, diff: Diff) -> Sequence[Finding]:
        out: list[Finding] = []
        for f in _eligible(diff, _is_github_workflow):
            for n, t in _added(f):
                s = cap(t)
                if _WRITE_ALL.search(s):
                    sev, scope = Severity.HIGH, "write access to every scope"
                else:
                    m = _WRITE.search(s)
                    if not m:
                        continue
                    sev = Severity.MEDIUM if m.group(1) in _HIGH_WRITE else Severity.LOW
                    scope = f"write access to '{m.group(1)}'"
                out.append(_finding(
                    self, f, n, t, sev,
                    f"This grants the workflow token {scope}. A compromised step or action could use it to push code, "
                    "tamper with releases or mint cloud credentials.",
                    "Grant the minimum: set 'permissions: read-all' (or contents: read) at the top level and add write scopes "
                    "only to the specific job that needs them.",
                    0.9 if sev >= Severity.HIGH else 0.7,
                ))
        return out


# ========================================================== CI-SECRETS

_TOJSON_SECRETS = re.compile(r"\$\{\{\s*toJSON\(\s*secrets\s*\)\s*\}\}", re.IGNORECASE)
_SECRET_REF = re.compile(r"\$\{\{\s*secrets\.([A-Za-z0-9_]+)\s*\}\}")
_SECRETS_INHERIT = re.compile(r"^\s*secrets\s*:\s*inherit\b")
_EXFIL = re.compile(
    r"\b(?:curl|wget|nc|ncat|netcat|iwr|Invoke-WebRequest)\b|https?://|\bbase64\b|/dev/tcp/", re.IGNORECASE
)
_ENV_DUMP = re.compile(r"\b(?:printenv|env)\b\s*\|", re.IGNORECASE)

# The one narrow downgrade: the built-in GITHUB_TOKEN sent to api.github.com. It is scoped to this repository and expires
# with the job, and this is how workflows comment, label and assign. Every condition below must hold, on one line:
# only GITHUB_TOKEN is referenced, every URL is https and its host is exactly api.github.com (so no userinfo, no
# lookalike suffix, no second URL), and nothing re-routes or encodes the request.
_URL = re.compile(r"[a-z][a-z0-9+.-]*://[^/\s?#`]*", re.IGNORECASE)
_EXFIL_OTHER = re.compile(
    r"\b(?:nc|ncat|netcat|iwr|Invoke-WebRequest)\b|\bbase64\b|/dev/tcp/|"
    r"--(?:resolve|connect-to|proxy|preproxy|socks\w*|interface|unix-socket)\b|(?-i:\s-x\s)|\bhttps?_proxy\b",
    re.IGNORECASE,
)
_GITHUB_API = re.compile(r"https://api\.github\.com(?::443)?", re.IGNORECASE)


def _is_github_token_to_github_api(refs: list[str], n_s: str) -> bool:
    if not refs or any(r != "GITHUB_TOKEN" for r in refs):
        return False
    urls = _URL.findall(n_s)
    if not urls or not all(_GITHUB_API.fullmatch(u) for u in urls):
        return False
    return not _EXFIL_OTHER.search(n_s)


class SecretExposure(Rule):
    id = "CI-SECRETS"
    version = "1"
    category = "ci"
    description = "secrets dumped, encoded, sent over the network, or newly referenced in a workflow"

    def evaluate(self, diff: Diff) -> Sequence[Finding]:
        out: list[Finding] = []
        for f in _eligible(diff, _is_github_workflow):
            for n, t in _added(f):
                s = cap(t)
                n_s = normalise_cmd(s)
                if _TOJSON_SECRETS.search(s):
                    sev, why = Severity.CRITICAL, "This expression serialises every repository secret into one string."
                elif _ENV_DUMP.search(n_s):
                    sev, why = Severity.HIGH, "This pipes the whole environment (which can include secrets) to another command."
                elif (ref := _SECRET_REF.search(s)) and _EXFIL.search(n_s):
                    sev = Severity.HIGH
                    if _is_github_token_to_github_api([m.group(1) for m in _SECRET_REF.finditer(s)], n_s):
                        sev = Severity.MEDIUM
                    why = (f"The secret '{ref.group(1)}' is used on a line that also encodes it or sends it over the network. "
                           "Encoding is a common trick to get around log masking.")
                elif _SECRETS_INHERIT.match(s):
                    sev, why = Severity.MEDIUM, "'secrets: inherit' hands every secret to the called workflow."
                elif (ref := _SECRET_REF.search(s)) and ref.group(1) != "GITHUB_TOKEN":
                    sev, why = Severity.LOW, f"The secret '{ref.group(1)}' is newly referenced in this workflow."
                else:
                    continue
                out.append(_finding(
                    self, f, n, t, sev, why,
                    "Pass secrets only to the single step that needs them, never print or encode them, and avoid sending them "
                    "to external hosts. Review exactly which action or script receives the value.",
                    0.9 if sev >= Severity.HIGH else 0.5,
                ))
        return out


# ========================================================== CI-PIPE-SH

_DOWNLOADER = re.compile(r"\b(?:curl|wget|iwr|invoke-webrequest)\b", re.IGNORECASE)
_PIPE_TO_INTERP = re.compile(
    r"(?<!\|)\|(?!\|)\s*(?:sudo\s+)?(?:(?:ba|z|da|k)?sh|python3?|node|perl|ruby|pwsh|powershell|iex)\b", re.IGNORECASE
)
_SUBST_SHELL = re.compile(
    r"\b(?:ba|z)?sh\b[^|\n]{0,80}?(?:<\(|\$\()\s*(?:curl|wget)\b|\biex\b[^\n]{0,80}?\b(?:iwr|invoke-webrequest|downloadstring)\b",
    re.IGNORECASE,
)
_RAW_IP = re.compile(r"(?:https?|ftp)://\d{1,3}(?:\.\d{1,3}){3}\b")


class PipeToShell(Rule):
    id = "CI-PIPE-SH"
    version = "1"
    category = "ci"
    description = "download piped straight into a shell or interpreter in a CI file"

    def evaluate(self, diff: Diff) -> Sequence[Finding]:
        out: list[Finding] = []
        for f in _eligible(diff, _is_any_ci):
            for n, t in _added(f):
                s = normalise_cmd(cap(t))
                dl = _DOWNLOADER.search(s)
                hit = bool(dl and _PIPE_TO_INTERP.search(s, dl.end())) or bool(_SUBST_SHELL.search(s))
                if not hit:
                    continue
                sev = Severity.CRITICAL if _RAW_IP.search(s) else Severity.HIGH
                out.append(_finding(
                    self, f, n, t, sev,
                    "A remote script is downloaded and executed immediately, with no review, pinning or checksum. Whoever "
                    "controls that URL (or its DNS or CDN) controls your pipeline and its secrets.",
                    "Download to a file, verify a pinned checksum or signature, then run it. Prefer a pinned, reviewed action "
                    "or a package from your lockfile.",
                    0.9,
                ))
        return out


# ========================================================== CI-INJECT



def _expressions(s: str) -> Iterator[str]:
    """Yield the inside of each ``${{ ... }}`` in one linear pass (str.find, no regex restarts)."""
    i = s.find("${{")
    while i != -1:
        j = s.find("}}", i + 3)
        if j == -1:
            return  # unterminated: nothing later can close either
        yield s[i + 3 : j]
        i = s.find("${{", j + 2)

_UNTRUSTED = re.compile(
    r"github\.head_ref"
    r"|github\.event\.(?:issue|pull_request|comment|review|review_comment|discussion|workflow_run)\.[\w.\[\]*-]{0,120}"
    r"(?:title|body|\bref\b|label|branch|default_branch)"
    r"|github\.event\.(?:head_commit|commits(?:\[[^\]]*\])?|pages(?:\[[^\]]*\])?)\.[\w.\[\]*-]{0,120}"
    r"(?:message|name|email|page_name)"
    r"|github\.event\.pull_request\.head\.(?:ref|label)"
    r"|github\.event\.workflow_run\.head_(?:branch|commit\.message)",
    re.IGNORECASE,
)
# "KEY: ${{ expr }}" (whole value is the expression) is how values are safely passed through env:/with:
_PURE_ASSIGNMENT = re.compile(r"""^\s*(?:-\s*)?([\w.-]+)\s*:\s*["']?\$\{\{[^}]*\}\}["']?\s*$""")
_SCRIPT_KEYS = {"run", "script"}

# Keys whose value GitHub reads as a label and never runs: the group of a concurrency block, an inline
# "concurrency: <group>", and the workflow's run-name. The exemption needs the whole head file, to prove the line
# really is that key and not text inside a script (a "concurrency:" typed into a run block). No proof, no exemption.
_KEY_LINE = re.compile(r"^(\s*)(-\s+)?([A-Za-z0-9_.-]+)\s*:(.*)$")
_BLOCK_SCALAR = re.compile(r"^\s*[|>][+-]?\d*\s*(?:#.*)?$")
_MAX_CTX_LINES = 20000
_LABEL_KEY = re.compile(r"^\s*(?:group|concurrency|run-name)\s*:")


_CLIMB = 200  # how far above a "group:" line its "concurrency:" may be; bounds the work per line


def _is_label_key(lines: list[str] | None, n: int, text: str) -> bool:
    if lines is None or not 1 <= n <= len(lines) or lines[n - 1].strip() != text.strip():
        return False
    m = _KEY_LINE.match(lines[n - 1])
    if not m or m.group(2):
        return False  # not a plain "key: value" line (a list item or continuation text)
    indent, key = len(m.group(1)), m.group(3)
    if key in ("concurrency", "run-name"):
        return indent == 0 or key == "concurrency"  # a job-level concurrency may be inline; run-name is top-level only
    if key != "group" or indent == 0:
        return False
    # "group" must sit directly under "concurrency", and nothing above may open a script (block scalar) or be a list item
    cur, want = indent, "concurrency"
    for i in range(n - 2, max(-1, n - 2 - _CLIMB), -1):
        line = lines[i]
        if not line.strip() or _is_comment(line):
            continue
        mm = _KEY_LINE.match(line)
        ind = len(line) - len(line.lstrip(" "))
        if ind >= cur:
            continue
        if not mm or (mm.group(3) != want and want):
            return False
        if mm.group(2) or _BLOCK_SCALAR.match(mm.group(4)):
            return False
        want, cur = "", ind  # from here up, only reject script blocks
        if ind == 0:
            return True
    return False  # ran out of window without reaching the top: no proof


class ScriptInjection(Rule):
    id = "CI-INJECT"
    version = "1"
    category = "ci"
    description = "attacker-controlled GitHub context (titles, branch names, bodies) expanded directly into a script"

    def evaluate(self, diff: Diff) -> Sequence[Finding]:
        out: list[Finding] = []
        for f in _eligible(diff, _is_github_workflow):
            ctx: list[str] | None | bool = False  # the head file split into lines, built once and only if needed
            for n, t in _added(f):
                s = cap(t)
                bad = next((e.strip() for e in _expressions(s) if _UNTRUSTED.search(e)), None)
                if bad is None:
                    continue
                m = _PURE_ASSIGNMENT.match(s)
                if m and m.group(1) not in _SCRIPT_KEYS:
                    continue  # env:/with: assignment, the recommended mitigation
                if _LABEL_KEY.match(s):
                    if ctx is False:
                        c = f.new_content
                        ctx = None if c is None else c.split("\n", _MAX_CTX_LINES)
                        if ctx is not None and len(ctx) > _MAX_CTX_LINES:
                            ctx = None  # too large to prove anything cheaply
                    if _is_label_key(ctx, n, t):
                        continue  # a concurrency group or run-name: a label, not a script
                out.append(_finding(
                    self, f, n, t, Severity.HIGH,
                    f"'${{{{ {bad[:80]} }}}}' is controlled by whoever opens the pull request or issue and is pasted into a "
                    "script before it runs. A crafted title, branch name or comment can inject shell commands.",
                    "Pass the value through an environment variable (env: NAME: ${{ ... }}) and reference it as \"$NAME\" in "
                    "the script; never interpolate untrusted context directly.",
                    0.85,
                ))
        return out
