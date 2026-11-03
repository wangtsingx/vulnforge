from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from vulnforge.config import configured_root, load_yaml, override_config, project_root

mcp = FastMCP("vulnforge-codeql")
BASE = Path(os.getenv("VULNFORGE_HOME", ".")).resolve()
PROJECTS_CONFIG = Path(os.getenv("VULNFORGE_PROJECTS", BASE / "config/projects.yaml"))
SETTINGS_CONFIG = Path(os.getenv("VULNFORGE_SETTINGS", BASE / "config/settings.yaml"))

PROJECT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")


def codeql_settings() -> dict:
    return load_yaml(SETTINGS_CONFIG).get("codeql", {})


def databases_root() -> Path:
    value = codeql_settings().get("databases_dir", "databases")
    return configured_root("VULNFORGE_DATABASES", str(value))


def database_path(project: str) -> Path:
    if not PROJECT_ID_RE.fullmatch(project):
        raise ValueError("Invalid project ID")
    root = databases_root()
    path = (root / project).resolve()
    if path.parent != root:
        raise ValueError("Invalid database path")
    return path


def run_codeql(args: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            args, capture_output=True, text=True, timeout=timeout, check=False,
            env={**os.environ, "NO_COLOR": "1"},
        )
    except FileNotFoundError as exc:
        raise RuntimeError("CodeQL CLI not found; install it first") from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"CodeQL timed out after {timeout} seconds") from exc


@mcp.tool()
def codeql_database_create(project: str, overwrite: bool = False) -> dict:
    """Create a CodeQL database for a registered project using its configured build command."""
    root = project_root(project, override_config(PROJECTS_CONFIG))
    project_cfg = load_yaml(override_config(PROJECTS_CONFIG)).get("projects", {}).get(project, {})
    build_command = str(project_cfg.get("build_command", "")).strip()
    if not build_command:
        raise ValueError("Project must define a build_command in projects.yaml")
    cfg = codeql_settings()
    binary = str(cfg.get("binary", "codeql"))
    language = str(project_cfg.get("language") or cfg.get("language", "cpp"))
    if language not in {"cpp", "c", "java", "python", "go"}:
        raise ValueError("Unsupported CodeQL language")
    timeout = max(60, min(int(cfg.get("create_timeout_seconds", 1800)), 7200))
    db = database_path(project)
    db.parent.mkdir(parents=True, exist_ok=True)
    command = [
        binary, "database", "create", str(db),
        f"--language={language}", f"--source-root={root}",
        f"--command={build_command}",
    ]
    if overwrite:
        command.append("--overwrite")
    proc = run_codeql(command, timeout)
    return {
        "project": project,
        "database": str(db),
        "exit_code": proc.returncode,
        "stderr": (proc.stderr or "")[-4000:],
        "stdout_tail": (proc.stdout or "")[-4000:],
    }


@mcp.tool()
def codeql_analyze(project: str, query_pack: str = "cpp-security-extended") -> dict:
    """Run CodeQL analysis on a project database and return a bounded SARIF summary."""
    cfg = codeql_settings()
    binary = str(cfg.get("binary", "codeql"))
    timeout = max(60, min(int(cfg.get("analyze_timeout_seconds", 3600)), 14400))
    max_output = max(100_000, min(int(cfg.get("max_output_bytes", 5_000_000)), 50_000_000))
    db = database_path(project)
    if not db.is_dir():
        raise ValueError("CodeQL database does not exist; run codeql_database_create first")
    allowed_suites = set(cfg.get("allowed_query_suites", []))
    pack = str(query_pack)
    queries_root = (BASE / "queries").resolve()
    pack_path = (queries_root / pack).resolve() if not pack.startswith("/") else Path(pack).resolve()
    if pack_path.is_relative_to(queries_root) and (pack_path.is_file() or pack_path.is_dir()):
        pack_arg = str(pack_path)
    elif re.fullmatch(r"[a-z0-9-]+", pack) and pack in allowed_suites:
        pack_arg = pack
    else:
        raise ValueError("Query pack must be a path under queries/ or an allowed suite name")
    out_dir = db.parent / f"{db.name}-results"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = (out_dir / "results.sarif").resolve()
    command = [
        binary, "database", "analyze", str(db), pack_arg,
        "--format=sarif-latest", f"--output={out_file}",
    ]
    proc = run_codeql(command, timeout)
    summary: dict = {"project": project, "exit_code": proc.returncode, "stderr": (proc.stderr or "")[-4000:]}
    if proc.returncode == 0 and out_file.is_file():
        raw = out_file.read_text(encoding="utf-8")
        if len(raw.encode("utf-8", errors="replace")) > max_output:
            summary["sarif_path"] = str(out_file)
            summary["note"] = "SARIF output exceeds size limit; read from path."
        else:
            sarif = json.loads(raw)
            runs = sarif.get("runs", [])
            results = [r for run in runs for r in run.get("results", [])]
            summary["result_count"] = len(results)
            summary["results"] = results[:500]
            summary["sarif_path"] = str(out_file)
    return summary


@mcp.tool()
def codeql_list_databases() -> dict:
    """List existing CodeQL databases for registered projects."""
    root = databases_root()
    entries = []
    if root.is_dir():
        for path in sorted(root.iterdir()):
            if path.is_dir() and path.parent == root and PROJECT_ID_RE.fullmatch(path.name):
                entries.append({"project": path.name, "database": str(path)})
    return {"databases": entries}


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
