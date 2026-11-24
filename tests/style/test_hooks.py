import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
HOOKS = ROOT / ".githooks"
AUTHOR = (HOOKS / "author.txt").read_text().strip()
NAME, EMAIL = AUTHOR.split(" <")[0], AUTHOR.split("<")[1].rstrip(">")

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    def git(*args: str) -> None:
        subprocess.run(["git", *args], cwd=tmp_path, check=True, capture_output=True)

    git("init", "-q", "-b", "throwaway")
    git("config", "user.name", NAME)
    git("config", "user.email", EMAIL)
    git("config", "core.hooksPath", HOOKS.as_posix())
    (tmp_path / "f.txt").write_text("x\n")
    git("add", "f.txt")
    return tmp_path


def commit(repo: Path, message: str, email: str | None = None) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    if email:
        env["GIT_AUTHOR_EMAIL"] = email
    return subprocess.run(
        ["git", "commit", "-q", "-m", message], cwd=repo, env=env, capture_output=True, text=True, check=False
    )


def test_good_commit_passes(repo: Path) -> None:
    result = commit(repo, "Add bucket rule")
    assert result.returncode == 0, result.stderr


def test_trailer_rejected(repo: Path) -> None:
    result = commit(repo, "Add bucket rule\n\nCo-Authored-By: Someone <a@b.c>")
    assert result.returncode != 0
    assert "trailers" in result.stderr


def test_wrong_email_rejected(repo: Path) -> None:
    result = commit(repo, "Add bucket rule", email="wrong@example.com")
    assert result.returncode != 0
    assert "author" in result.stderr


@pytest.mark.parametrize(
    ("title", "reason"),
    [
        ("Added bucket rule", "imperative"),
        ("Add a seamless bucket rule", "banned"),
        ("Add " + "x" * 70, "72"),
        ("Add bucket rule.", "period"),
    ],
)
def test_bad_title_rejected(repo: Path, title: str, reason: str) -> None:
    result = commit(repo, title)
    assert result.returncode != 0
    assert reason in result.stderr
