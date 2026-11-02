import pytest

from pr_scanner.classify import FileKind, classify


@pytest.mark.parametrize(
    "path,kind",
    [
        ("package.json", FileKind.MANIFEST),
        ("sub/dir/package.json", FileKind.MANIFEST),
        ("setup.py", FileKind.MANIFEST),
        ("pyproject.toml", FileKind.MANIFEST),
        ("requirements.txt", FileKind.MANIFEST),
        ("requirements-dev.txt", FileKind.MANIFEST),
        ("package-lock.json", FileKind.LOCKFILE),
        ("yarn.lock", FileKind.LOCKFILE),
        ("pnpm-lock.yaml", FileKind.LOCKFILE),
        ("poetry.lock", FileKind.LOCKFILE),
        ("go.sum", FileKind.LOCKFILE),
        (".github/workflows/ci.yml", FileKind.CI_WORKFLOW),
        (".github/workflows/release.yaml", FileKind.CI_WORKFLOW),
        (".github/actions/foo/action.yml", FileKind.CI_WORKFLOW),
        (".gitlab-ci.yml", FileKind.CI_WORKFLOW),
        ("Dockerfile", FileKind.BUILD_SCRIPT),
        ("docker/Dockerfile.prod", FileKind.BUILD_SCRIPT),
        ("Makefile", FileKind.BUILD_SCRIPT),
        ("scripts/install.sh", FileKind.BUILD_SCRIPT),
        (".pr-scanner.yml", FileKind.SCANNER_CONFIG),
        (".github/CODEOWNERS", FileKind.SCANNER_CONFIG),
        ("src/app.py", FileKind.SOURCE),
        ("web/app.js", FileKind.SOURCE),
        ("README.md", FileKind.OTHER),
        ("logo.png", FileKind.OTHER),
    ],
)
def test_classification(path, kind):
    assert classify(path) == kind


def test_nested_github_dir_is_not_a_real_workflow():
    # only the repository-root .github/workflows is executed by GitHub
    assert classify("vendor/.github/workflows/ci.yml") != FileKind.CI_WORKFLOW


def test_classification_is_case_insensitive_for_names():
    assert classify("PACKAGE.JSON") == FileKind.MANIFEST
    assert classify("dockerfile") == FileKind.BUILD_SCRIPT


def test_path_tricks_do_not_change_kind():
    assert classify("./.github/workflows/ci.yml") == FileKind.CI_WORKFLOW
    assert classify(".github//workflows/ci.yml") == FileKind.CI_WORKFLOW
