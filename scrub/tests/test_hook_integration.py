"""Integration test for the git pre-commit hook.

Stands up a throwaway git repo, installs ``hooks/pre-commit``, stages a file with a
fake AWS key, and asserts the commit is blocked and the report is masked. Skips
cleanly when its prerequisites are absent (no ``git``, or ``scrub`` not on PATH,
which happens when the package hasn't been ``pip install -e .``'d). CI installs the
package first, so it runs there.
"""

import os
import shutil
import subprocess

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # scrub/
REPO_ROOT = os.path.dirname(ROOT)
HOOK_SRC = os.path.join(REPO_ROOT, "hooks", "pre-commit")

FAKE_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"

pytestmark = [
    pytest.mark.skipif(shutil.which("git") is None, reason="git not available"),
    pytest.mark.skipif(
        shutil.which("scrub") is None,
        reason="`scrub` not on PATH (run `pip install -e .`)",
    ),
    pytest.mark.skipif(not os.path.exists(HOOK_SRC), reason="hooks/pre-commit missing"),
]


def _git(repo, *args, **kwargs):
    return subprocess.run(
        ["git", *args],
        cwd=repo,
        capture_output=True,
        text=True,
        **kwargs,
    )


@pytest.fixture
def repo(tmp_path):
    r = tmp_path / "proj"
    r.mkdir()
    _git(r, "init", "-q")
    _git(r, "config", "user.email", "t@example.com")
    _git(r, "config", "user.name", "Test")
    _git(r, "config", "commit.gpgsign", "false")
    # install the hook
    dst = r / ".git" / "hooks" / "pre-commit"
    shutil.copyfile(HOOK_SRC, dst)
    os.chmod(dst, 0o755)
    return r


def test_hook_blocks_commit_with_secret(repo):
    (repo / "config.env").write_text(
        f"AWS_ACCESS_KEY_ID={FAKE_AWS_KEY}\n", encoding="utf-8"
    )
    _git(repo, "add", "config.env")
    res = _git(repo, "commit", "-m", "add config")

    combined = res.stdout + res.stderr
    assert res.returncode != 0, f"commit should have been blocked:\n{combined}"
    # the report must be masked: raw key absent, entity type present
    assert FAKE_AWS_KEY not in combined
    assert "AWS_ACCESS_KEY" in combined
    # commit did not happen
    assert _git(repo, "rev-parse", "--verify", "HEAD").returncode != 0


def test_hook_allows_clean_commit(repo):
    (repo / "notes.txt").write_text("just some harmless prose\n", encoding="utf-8")
    _git(repo, "add", "notes.txt")
    res = _git(repo, "commit", "-m", "add notes")
    assert res.returncode == 0, res.stdout + res.stderr
    assert _git(repo, "rev-parse", "--verify", "HEAD").returncode == 0


def test_no_verify_bypasses_hook(repo):
    (repo / "config.env").write_text(
        f"AWS_ACCESS_KEY_ID={FAKE_AWS_KEY}\n", encoding="utf-8"
    )
    _git(repo, "add", "config.env")
    res = _git(repo, "commit", "--no-verify", "-m", "bypass")
    assert res.returncode == 0, res.stdout + res.stderr
    assert _git(repo, "rev-parse", "--verify", "HEAD").returncode == 0
