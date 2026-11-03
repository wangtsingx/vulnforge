from __future__ import annotations

import subprocess
from pathlib import Path

SAFE_COMMIT_RE = __import__("re").compile(r"^[0-9a-fA-F]{7,64}$")


def run_git(root: Path, args: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
    command = ["git", "-C", str(root), *args]
    try:
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env={"GIT_TERMINAL_PROMPT": "0", "PATH": "/usr/bin:/bin:/usr/local/bin"},
        )
    except FileNotFoundError as exc:
        raise RuntimeError("git executable not found") from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"git command timed out after {timeout} seconds") from exc


def validate_commit(commit: str) -> str:
    if not SAFE_COMMIT_RE.fullmatch(commit):
        raise ValueError("Commit must be a 7-64 character hexadecimal revision")
    return commit
