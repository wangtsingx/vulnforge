from __future__ import annotations

import os
import re
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from vulnforge.config import load_yaml, project_root

mcp = FastMCP("vulnforge-source")
BASE = Path(os.getenv("VULNFORGE_HOME", ".")).resolve()
PROJECTS_CONFIG = Path(os.getenv("VULNFORGE_PROJECTS", BASE / "config/projects.yaml"))
SETTINGS_CONFIG = Path(os.getenv("VULNFORGE_SETTINGS", BASE / "config/settings.yaml"))


def settings() -> dict:
    return load_yaml(SETTINGS_CONFIG).get("source", {})


def get_root(project: str) -> Path:
    return project_root(project, PROJECTS_CONFIG)


def safe_file(project: str, relative_path: str) -> Path:
    root = get_root(project)
    candidate = (root / relative_path).resolve(strict=True)
    if not candidate.is_relative_to(root):
        raise ValueError("Path escapes registered project root")
    allowed = set(settings().get("allowed_extensions", [".c", ".h"]))
    if candidate.suffix not in allowed:
        raise ValueError("File extension is not allowed")
    if not candidate.is_file():
        raise ValueError("Not a regular file")
    max_bytes = int(settings().get("max_file_bytes", 2_000_000))
    if candidate.stat().st_size > max_bytes:
        raise ValueError("File exceeds configured size limit")
    return candidate


@mcp.tool()
def project_info(project: str) -> dict:
    """Return registered project path and basic source-tree metadata."""
    root = get_root(project)
    cfg = load_yaml(PROJECTS_CONFIG).get("projects", {}).get(project, {})
    return {
        "project": project,
        "description": cfg.get("description", ""),
        "revision": cfg.get("revision", ""),
        "source_root": str(root),
    }


@mcp.tool()
def list_source_files(project: str, limit: int = 200) -> dict:
    """List registered C/C++ source files. Does not follow symlinks."""
    root = get_root(project)
    allowed = set(settings().get("allowed_extensions", [".c", ".h", ".cc", ".cpp", ".hpp"]))
    limit = max(1, min(int(limit), 1000))
    found: list[str] = []
    for path in root.rglob("*"):
        if path.is_symlink() or not path.is_file() or path.suffix not in allowed:
            continue
        found.append(path.relative_to(root).as_posix())
        if len(found) >= limit:
            break
    return {"project": project, "count": len(found), "files": sorted(found)}


@mcp.tool()
def search_source(project: str, pattern: str, limit: int = 50) -> dict:
    """Search source text using a regular expression; returns file and line evidence."""
    root = get_root(project)
    try:
        regex = re.compile(pattern)
    except re.error as exc:
        raise ValueError(f"Invalid regular expression: {exc}") from exc
    allowed = set(settings().get("allowed_extensions", [".c", ".h", ".cc", ".cpp", ".hpp"]))
    max_bytes = int(settings().get("max_file_bytes", 2_000_000))
    limit = max(1, min(int(limit), int(settings().get("max_search_results", 100))))
    results = []
    for path in root.rglob("*"):
        if path.is_symlink() or not path.is_file() or path.suffix not in allowed:
            continue
        if path.stat().st_size > max_bytes:
            continue
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for line_no, line in enumerate(lines, 1):
            if regex.search(line):
                results.append({
                    "file": path.relative_to(root).as_posix(),
                    "line": line_no,
                    "text": line.strip()[:500],
                })
                if len(results) >= limit:
                    return {"project": project, "results": results, "truncated": True}
    return {"project": project, "results": results, "truncated": False}


@mcp.tool()
def read_source(project: str, relative_path: str, start_line: int, end_line: int) -> dict:
    """Read a bounded source range with stable line-number prefixes."""
    if start_line < 1 or end_line < start_line:
        raise ValueError("Invalid line range")
    max_lines = int(settings().get("max_read_lines", 300))
    if end_line - start_line + 1 > max_lines:
        raise ValueError(f"Requested range exceeds {max_lines} lines")
    path = safe_file(project, relative_path)
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    actual_end = min(end_line, len(lines))
    content = "\n".join(f"{n}: {lines[n - 1]}" for n in range(start_line, actual_end + 1))
    return {
        "project": project,
        "file": relative_path,
        "start_line": start_line,
        "end_line": actual_end,
        "content": content,
    }


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
