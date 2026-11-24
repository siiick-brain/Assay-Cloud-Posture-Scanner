import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "check-style.ps1"
FIXTURES = ROOT / "tests" / "style" / "fixtures"
PWSH = shutil.which("pwsh")

pytestmark = pytest.mark.skipif(PWSH is None, reason="pwsh not installed")


def run(*args: str) -> subprocess.CompletedProcess[str]:
    cmd = [str(PWSH), "-NoProfile", "-File", str(SCRIPT), *args]
    return subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT, check=False)


def test_bad_fixture_fails_with_each_rule() -> None:
    result = run("-NoDefaultExcludes", str(FIXTURES / "bad"))
    assert result.returncode == 1
    out = result.stdout
    for expected in ("robust", "leverage", "in order to", "comma before and/or", "em dash", "TODO", "furthermore"):
        assert expected in out, expected


def test_good_fixture_passes() -> None:
    result = run(str(FIXTURES / "good"))
    assert result.returncode == 0, result.stdout


def test_commit_message_check() -> None:
    assert run("-CommitMessage", "Add S3 rules").returncode == 0
    assert run("-CommitMessage", "Utilize a seamless engine").returncode == 1
