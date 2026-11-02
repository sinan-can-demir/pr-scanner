import pytest
from hypothesis import given, settings, strategies as st

from pr_scanner.diff_parser import DiffParseError, parse_unified_diff

H, B = "a" * 40, "b" * 40


def parse(text, **kw):
    return parse_unified_diff(text, head_sha=H, base_sha=B, **kw)


MODIFIED = """\
diff --git a/package.json b/package.json
index 111..222 100644
--- a/package.json
+++ b/package.json
@@ -1,4 +1,5 @@
 {
   "name": "x",
-  "version": "1.0.0"
+  "version": "1.0.1",
+  "scripts": {"postinstall": "node x.js"}
 }
"""


def test_modified_file_with_line_numbers():
    d = parse(MODIFIED)
    assert d.head_sha == H and d.base_sha == B
    (f,) = d.files
    assert f.path == "package.json" and f.status == "modified"
    assert f.added_lines == ((3, '  "version": "1.0.1",'), (4, '  "scripts": {"postinstall": "node x.js"}'))
    assert f.removed_lines == ((3, '  "version": "1.0.0"'),)


def test_new_file():
    d = parse(
        "diff --git a/n.py b/n.py\nnew file mode 100644\nindex 000..111\n"
        "--- /dev/null\n+++ b/n.py\n@@ -0,0 +1,2 @@\n+a\n+b\n"
    )
    (f,) = d.files
    assert f.status == "added" and f.path == "n.py"
    assert f.added_lines == ((1, "a"), (2, "b"))


def test_deleted_file_uses_old_path():
    d = parse(
        "diff --git a/d.py b/d.py\ndeleted file mode 100644\nindex 111..000\n"
        "--- a/d.py\n+++ /dev/null\n@@ -1,1 +0,0 @@\n-gone\n"
    )
    (f,) = d.files
    assert f.status == "removed" and f.path == "d.py"
    assert f.removed_lines == ((1, "gone"),)


def test_rename_with_edit():
    d = parse(
        "diff --git a/old.py b/new.py\nsimilarity index 80%\nrename from old.py\nrename to new.py\n"
        "index 1..2 100644\n--- a/old.py\n+++ b/new.py\n@@ -1 +1 @@\n-x\n+y\n"
    )
    (f,) = d.files
    assert f.status == "renamed" and f.path == "new.py" and f.old_path == "old.py"
    assert f.added_lines == ((1, "y"),)


def test_pure_rename_without_hunks():
    d = parse("diff --git a/o b/n\nsimilarity index 100%\nrename from o\nrename to n\n")
    (f,) = d.files
    assert (f.status, f.path, f.old_path) == ("renamed", "n", "o")


def test_binary_file_flagged_without_lines():
    d = parse("diff --git a/x.bin b/x.bin\nnew file mode 100755\nindex 0..1\nBinary files /dev/null and b/x.bin differ\n")
    (f,) = d.files
    assert f.is_binary and f.status == "added" and f.added_lines == ()


def test_git_binary_patch_flagged():
    d = parse("diff --git a/x.bin b/x.bin\nindex 1..2 100644\nGIT binary patch\nliteral 3\nKcmZ\n\nliteral 0\nHcmV\n\n")
    assert d.files[0].is_binary


def test_mode_only_change():
    d = parse("diff --git a/run.sh b/run.sh\nold mode 100644\nnew mode 100755\n")
    (f,) = d.files
    assert f.status == "modified" and f.path == "run.sh"


def test_multiple_files_and_hunks():
    text = (
        "diff --git a/a b/a\n--- a/a\n+++ b/a\n@@ -1,2 +1,2 @@\n c\n-x\n+y\n@@ -10,2 +10,3 @@\n c\n+z\n c\n"
        "diff --git a/b b/b\n--- a/b\n+++ b/b\n@@ -1 +1 @@\n-p\n+q\n"
    )
    d = parse(text)
    assert [f.path for f in d.files] == ["a", "b"]
    assert d.files[0].added_lines == ((2, "y"), (11, "z"))


def test_no_newline_marker_ignored():
    d = parse("diff --git a/a b/a\n--- a/a\n+++ b/a\n@@ -1 +1 @@\n-x\n\\ No newline at end of file\n+y\n\\ No newline at end of file\n")
    assert d.files[0].added_lines == ((1, "y"),)


# --- hostile input -------------------------------------------------------


def test_added_line_that_looks_like_a_file_header_is_just_content():
    # content "++ b/evil" is rendered as "+++ b/evil"; must not start a new file
    text = "diff --git a/a b/a\n--- a/a\n+++ b/a\n@@ -1 +1,2 @@\n x\n+++ b/evil.txt\n"
    d = parse(text)
    assert [f.path for f in d.files] == ["a"]
    assert d.files[0].added_lines == ((2, "++ b/evil.txt"),)


def test_added_line_that_looks_like_diff_header_is_just_content():
    text = "diff --git a/a b/a\n--- a/a\n+++ b/a\n@@ -0,0 +1 @@\n+diff --git a/x b/x\n"
    d = parse(text)
    assert len(d.files) == 1 and d.files[0].added_lines == ((1, "diff --git a/x b/x"),)


def test_removed_line_that_looks_like_header_is_just_content():
    text = "diff --git a/a b/a\n--- a/a\n+++ b/a\n@@ -1,2 +1 @@\n--- a/foo\n x\n"
    d = parse(text)
    assert d.files[0].removed_lines == ((1, "-- a/foo"),)


def test_unicode_line_separators_do_not_split_lines():
    payload = "a b\x0bc\x0cd\x85e f"
    d = parse(f"diff --git a/a b/a\n--- /dev/null\n+++ b/a\n@@ -0,0 +1 @@\n+{payload}\n")
    assert d.files[0].added_lines == ((1, payload),)


def test_carriage_returns_in_content_are_preserved():
    d = parse("diff --git a/a b/a\n--- /dev/null\n+++ b/a\n@@ -0,0 +1 @@\n+x\r\n")
    assert d.files[0].added_lines == ((1, "x\r"),)


def test_quoted_path_with_escapes_and_utf8_octal():
    d = parse(
        'diff --git "a/we\\tird \\303\\251.sh" "b/we\\tird \\303\\251.sh"\nnew file mode 100644\n'
        '--- /dev/null\n+++ "b/we\\tird \\303\\251.sh"\n@@ -0,0 +1 @@\n+x\n'
    )
    assert d.files[0].path == "we\tird é.sh"


def test_path_with_spaces():
    d = parse("diff --git a/my file.txt b/my file.txt\n--- a/my file.txt\t\n+++ b/my file.txt\t\n@@ -1 +1 @@\n-a\n+b\n")
    assert d.files[0].path == "my file.txt"


def test_truncated_hunk_fails_closed():
    with pytest.raises(DiffParseError):
        parse("diff --git a/a b/a\n--- a/a\n+++ b/a\n@@ -1,3 +1,3 @@\n x\n")


def test_hunk_with_too_many_lines_fails_closed():
    with pytest.raises(DiffParseError):
        parse("diff --git a/a b/a\n--- a/a\n+++ b/a\n@@ -1 +1 @@\n-x\n+y\n+extra\n")


def test_garbage_input_fails_closed():
    with pytest.raises(DiffParseError):
        parse("this is not a diff\n")


def test_empty_input_is_an_empty_diff():
    assert parse("").files == ()


def test_oversize_input_rejected():
    with pytest.raises(DiffParseError):
        parse("diff --git a/a b/a\n" + "x" * 100, max_input_bytes=50)


@settings(max_examples=300, deadline=None)
@given(st.text())
def test_arbitrary_text_never_raises_unexpected_errors(text):
    try:
        parse(text)
    except DiffParseError:
        pass


@settings(max_examples=100, deadline=None)
@given(st.lists(st.text().filter(lambda s: "\n" not in s), min_size=1, max_size=20))
def test_new_file_round_trip(lines):
    body = "".join(f"+{ln}\n" for ln in lines)
    text = f"diff --git a/f b/f\nnew file mode 100644\n--- /dev/null\n+++ b/f\n@@ -0,0 +1,{len(lines)} @@\n{body}"
    d = parse(text)
    assert [t for _, t in d.files[0].added_lines] == lines
    assert [n for n, _ in d.files[0].added_lines] == list(range(1, len(lines) + 1))
