"""T-S03 / NFR-06: no rule may go super-linear on adversarial long lines.

Each payload is run through every default rule in a child process with a hard
timeout, because a regex stuck in backtracking cannot be interrupted from
inside the same Python process.
"""

import multiprocessing as mp
import time

import pytest

from pr_scanner.models import ChangedFile, Diff
from pr_scanner.rules import default_registry

PATHS = [
    "package.json",
    "setup.py",
    "pyproject.toml",
    "src/a.py",
    "web/app.js",
    "scripts/a.sh",
    ".github/workflows/x.yml",
    ".gitlab-ci.yml",
]

PAYLOADS = {
    "curl-repeat": "curl " * 40_000,
    "chmod-repeat": "os.chmod(" * 25_000,
    "uses-repeat": "uses: " * 30_000,
    "json-pairs": '"a":"b",' * 30_000,
    "unterminated-expr": "${{ " * 50_000,
    "expr-untrusted-repeat": "${{ github.head_ref " * 10_000,
    "name-at-repeat": "a/b@" * 50_000,
    "backslashes": "\\" * 200_000,
    "quotes": '"' * 200_000,
    "escaped-quotes": '\\"' * 100_000,
    "pipes": "| " * 100_000,
    "double-pipes": "||" * 100_000,
    "sh-repeat": "sh " * 70_000,
    "subst-repeat": "(curl " * 30_000,
    "ref-repeat": "ref: " * 40_000,
    "git-fetch-repeat": "git fetch " * 20_000,
    "exec-repeat": "exec(" * 40_000,
    "subprocess-repeat": "subprocess." * 20_000,
    "class-repeat": "class " * 40_000,
    "curl-then-pipes": "curl " + "| " * 100_000,
    "spaces-then-keyword": " " * 300_000 + "postinstall",
    "ip-like": "1.2.3." * 50_000,
    "pm-spawn-repeat": "spawn('npm run " * 20_000,
    "pm-spawn-unclosed-repeat": "execSync('pnpm " * 17_000,
    "base64-repeat": "base64 " * 30_000,
    "eval-space-repeat": "eval " * 40_000,
    "pipe-sudo-repeat": "| sudo " * 30_000,
    "exec-open-repeat": "exec( open( " * 17_000,
    "decode-flags-repeat": "xz -d " * 35_000,
}

pytestmark = pytest.mark.perf

BUDGET_SECONDS = 20  # ~5 MB of hostile text (the engine's cap) through every rule


def _worker(payload: str, q) -> None:
    files = tuple(
        ChangedFile(path=p, status="modified", added_lines=((1, payload), (2, payload)), new_content=payload)
        for p in PATHS
    )
    diff = Diff("a" * 40, "b" * 40, files)
    t0 = time.perf_counter()
    for rule in default_registry().rules():
        rule.evaluate(diff)
    q.put(time.perf_counter() - t0)


@pytest.mark.parametrize("name", sorted(PAYLOADS))
def test_rules_stay_fast_on_adversarial_lines(name):
    ctx = mp.get_context("fork")
    q = ctx.Queue()
    p = ctx.Process(target=_worker, args=(PAYLOADS[name], q))
    p.start()
    p.join(BUDGET_SECONDS)
    if p.is_alive():
        p.terminate()
        p.join()
        pytest.fail(f"a rule took more than {BUDGET_SECONDS}s on payload {name!r} (super-linear regex?)")
    assert p.exitcode == 0, f"worker crashed on payload {name!r}"
    assert q.get(timeout=1) < BUDGET_SECONDS
