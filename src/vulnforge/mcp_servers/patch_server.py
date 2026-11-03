from __future__ import annotations

import os
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from vulnforge.config import load_yaml, override_config, project_root
from vulnforge.git_utils import run_git, validate_commit

mcp = FastMCP("vulnforge-patch")
BASE = Path(os.getenv("VULNFORGE_HOME", ".")).resolve()
PROJECTS_CONFIG = Path(os.getenv("VULNFORGE_PROJECTS", BASE / "config/projects.yaml"))
SETTINGS_CONFIG = Path(os.getenv("VULNFORGE_SETTINGS", BASE / "config/settings.yaml"))


def patch_settings() -> dict:
    return load_yaml(SETTINGS_CONFIG).get("patch", {})


def git_result(root: Path, args: list[str]) -> dict:
    cfg = patch_settings()
    timeout = max(5, min(int(cfg.get("timeout_seconds", 60)), 600))
    max_bytes = max(10_000, min(int(cfg.get("max_diff_bytes", 1_000_000)), 10_000_000))
    proc = run_git(root, args, timeout)
    if proc.returncode != 0:
        raise RuntimeError(f"git failed: {(proc.stderr or proc.stdout).strip()[:2000]}")
    return {
        "stdout": proc.stdout[:max_bytes],
        "truncated": len(proc.stdout.encode("utf-8", errors="replace")) > max_bytes,
    }


@mcp.tool()
def patch_show(project: str, commit: str) -> dict:
    """Read one commit patch from a registered Git project."""
    root = project_root(project, override_config(PROJECTS_CONFIG))
    validate_commit(commit)
    info = git_result(root, ["show", "--no-color", "--no-ext-diff", commit])
    return {"project": project, "commit": commit, **info}


@mcp.tool()
def patch_change_list(project: str, commit: str) -> dict:
    """List files changed by one commit."""
    root = project_root(project, override_config(PROJECTS_CONFIG))
    validate_commit(commit)
    result = git_result(root, ["show", "--no-color", "--name-status", "--format=", commit])
    files = [line for line in result["stdout"].splitlines() if line.strip()]
    return {"project": project, "commit": commit, "files": files, "truncated": result["truncated"]}


@mcp.tool()
def patch_history(project: str, path: str, limit: int = 20) -> dict:
    """List commits that changed a repository-relative path."""
    root = project_root(project, override_config(PROJECTS_CONFIG))
    cfg = patch_settings()
    max_commits = max(1, min(int(cfg.get("max_commits", 200)), 1000))
    limit = max(1, min(int(limit), max_commits))
    safe_path = path.lstrip("/")
    if not safe_path or "\x00" in safe_path or safe_path.startswith("-"):
        raise ValueError("Invalid repository path")
    result = git_result(root, ["log", "--no-color", f"-{limit}", "--format=%H%x1f%ad%x1f%s", "--", safe_path])
    commits = []
    for line in result["stdout"].splitlines():
        parts = line.split("\x1f", 2)
        if len(parts) == 3:
            commits.append({"commit": parts[0], "date": parts[1], "subject": parts[2][:300]})
    return {"project": project, "path": safe_path, "commits": commits}


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
