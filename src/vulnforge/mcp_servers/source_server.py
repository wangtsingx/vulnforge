from __future__ import annotations

import os
import re
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from vulnforge.config import load_yaml, override_config, project_root

mcp = FastMCP("vulnforge-source")
BASE = Path(os.getenv("VULNFORGE_HOME", ".")).resolve()
PROJECTS_CONFIG = Path(os.getenv("VULNFORGE_PROJECTS", BASE / "config/projects.yaml"))
SETTINGS_CONFIG = Path(os.getenv("VULNFORGE_SETTINGS", BASE / "config/settings.yaml"))
LANGUAGES_CONFIG = Path(os.getenv("VULNFORGE_LANGUAGES", BASE / "config/languages.yaml"))


def settings() -> dict:
    return load_yaml(SETTINGS_CONFIG).get("source", {})


def get_language(project: str) -> str:
    """Return the configured language for a project (default: c)."""
    cfg = load_yaml(override_config(PROJECTS_CONFIG)).get("projects", {}).get(project, {})
    return str(cfg.get("language", "c"))


def get_allowed_extensions(project: str) -> set[str]:
    """Return file extensions for the project's language, falling back to source config."""
    lang = get_language(project)
    languages = load_yaml(LANGUAGES_CONFIG).get("languages", {}) if LANGUAGES_CONFIG.is_file() else {}
    lang_cfg = languages.get(lang, {})
    extensions = lang_cfg.get("extensions")
    if extensions:
        return set(extensions)
    return set(settings().get("allowed_extensions", [".c", ".h"]))


def get_rules_file(project: str) -> str:
    """Return the Semgrep rules file for the project's language."""
    lang = get_language(project)
    languages = load_yaml(LANGUAGES_CONFIG).get("languages", {}) if LANGUAGES_CONFIG.is_file() else {}
    lang_cfg = languages.get(lang, {})
    return str(lang_cfg.get("rules_file", settings().get("rules_file", "rules/c-memory.yml")))


def get_root(project: str) -> Path:
    return project_root(project, override_config(PROJECTS_CONFIG))


def safe_file(project: str, relative_path: str) -> Path:
    root = get_root(project)
    candidate = (root / relative_path).resolve(strict=True)
    if not candidate.is_relative_to(root):
        raise ValueError("Path escapes registered project root")
    allowed = get_allowed_extensions(project)
    if candidate.suffix not in allowed:
        raise ValueError("File extension is not allowed")
    if not candidate.is_file():
        raise ValueError("Not a regular file")
    max_bytes = int(settings().get("max_file_bytes", 2_000_000))
    if candidate.stat().st_size > max_bytes:
        raise ValueError("File exceeds configured size limit")
    return candidate


LANG_SIGNATURES = {
    ".c": "c", ".h": "c", ".cc": "cpp", ".cpp": "cpp", ".hpp": "cpp",
    ".go": "go", ".rs": "rust", ".py": "python",
}


def detect_languages(root: Path) -> list[str]:
    """Scan the source tree and return a sorted list of detected languages."""
    found: set[str] = set()
    for path in root.rglob("*"):
        if any(part in IGNORE_DIRS for part in path.relative_to(root).parts):
            continue
        if path.is_symlink() or not path.is_file():
            continue
        lang = LANG_SIGNATURES.get(path.suffix)
        if lang:
            found.add(lang)
        if len(found) >= len(LANG_SIGNATURES):
            break
    return sorted(found)


@mcp.tool()
def project_info(project: str) -> dict:
    """Return registered project path, language, and detected languages in the source tree."""
    root = get_root(project)
    cfg = load_yaml(override_config(PROJECTS_CONFIG)).get("projects", {}).get(project, {})
    configured_lang = cfg.get("language", "c")
    detected = detect_languages(root)
    return {
        "project": project,
        "description": cfg.get("description", ""),
        "revision": cfg.get("revision", ""),
        "source_root": str(root),
        "configured_language": configured_lang,
        "detected_languages": detected,
    }


@mcp.tool()
def list_source_files(project: str, limit: int = 200) -> dict:
    """List registered C/C++ source files. Does not follow symlinks."""
    root = get_root(project)
    allowed = get_allowed_extensions(project)
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
    allowed = get_allowed_extensions(project)
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


FUNC_DEF_RE = re.compile(
    r"^[ \t]*(?:static\s+|inline\s+|const\s+|unsigned\s+|signed\s+|struct\s+|enum\s+|union\s+)*"
    r"(?:[\w\*]\s*)+?(\w+)\s*\([^;{)]*\)\s*\{",
)

IGNORE_DIRS = {".git", ".svn", "node_modules", "__pycache__", ".venv", "build", "dist"}


def iter_source_files(root: Path, allowed: set[str], max_bytes: int):
    for path in sorted(root.rglob("*")):
        if any(part in IGNORE_DIRS for part in path.relative_to(root).parts):
            continue
        if path.is_symlink() or not path.is_file() or path.suffix not in allowed:
            continue
        if path.stat().st_size > max_bytes:
            continue
        yield path


@mcp.tool()
def function_search(project: str, keyword: str, limit: int = 50) -> dict:
    """Search for C/C++ function definitions matching a keyword in name or body."""
    root = get_root(project)
    allowed = get_allowed_extensions(project)
    max_bytes = int(settings().get("max_file_bytes", 2_000_000))
    limit = max(1, min(int(limit), 500))
    results = []
    for path in iter_source_files(root, allowed, max_bytes):
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for line_no, line in enumerate(lines, 1):
            match = FUNC_DEF_RE.match(line)
            if not match:
                continue
            func_name = match.group(1)
            if keyword.lower() not in func_name.lower():
                continue
            results.append({
                "file": path.relative_to(root).as_posix(),
                "line": line_no,
                "function": func_name,
                "text": line.strip()[:300],
            })
            if len(results) >= limit:
                return {"project": project, "results": results, "truncated": True}
    return {"project": project, "results": results, "truncated": False}


@mcp.tool()
def function_context(project: str, relative_path: str, line: int, context_lines: int = 30) -> dict:
    """Read a function and its surrounding context starting from a line number."""
    get_root(project)
    path = safe_file(project, relative_path)
    max_lines = int(settings().get("max_read_lines", 300))
    context_lines = max(5, min(int(context_lines), max_lines))
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    if line < 1 or line > len(lines):
        raise ValueError(f"Line {line} is out of range (1-{len(lines)})")
    start = max(1, line - context_lines // 2)
    end = min(len(lines), line + context_lines)
    content = "\n".join(f"{n}: {lines[n - 1]}" for n in range(start, end + 1))
    return {
        "project": project,
        "file": relative_path,
        "anchor_line": line,
        "start_line": start,
        "end_line": end,
        "content": content,
    }


@mcp.tool()
def list_functions(project: str, relative_path: str) -> dict:
    """List function definitions found in a single source file."""
    get_root(project)
    path = safe_file(project, relative_path)
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    functions = []
    for line_no, line_text in enumerate(lines, 1):
        match = FUNC_DEF_RE.match(line_text)
        if match:
            functions.append({"function": match.group(1), "line": line_no})
    return {"project": project, "file": relative_path, "functions": functions, "count": len(functions)}
