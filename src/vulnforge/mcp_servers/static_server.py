from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from vulnforge.config import load_yaml, override_config, project_root

mcp = FastMCP("vulnforge-static")
BASE = Path(os.getenv("VULNFORGE_HOME", ".")).resolve()
PROJECTS_CONFIG = Path(os.getenv("VULNFORGE_PROJECTS", BASE / "config/projects.yaml"))
SETTINGS_CONFIG = Path(os.getenv("VULNFORGE_SETTINGS", BASE / "config/settings.yaml"))


@mcp.tool()
def semgrep_scan(project: str, rules_file: str | None = None) -> dict:
    """Run the configured Semgrep rules against a registered local source project.

    The executable and timeout are configuration-controlled. No arbitrary shell is accepted.
    """
    root = project_root(project, override_config(PROJECTS_CONFIG))
    # Revision pinning: refuse to scan if the pinned revision doesn't match HEAD.
    project_cfg = load_yaml(override_config(PROJECTS_CONFIG)).get("projects", {}).get(project, {})
    pinned = str(project_cfg.get("revision", "")).strip()
    if pinned:
        import subprocess as _sp
        try:
            head_proc = _sp.run(
                ["git", "-C", str(root), "rev-parse", "HEAD"],
                capture_output=True, text=True, timeout=10, check=False,
            )
            head = head_proc.stdout.strip()
            if head and head != pinned:
                raise ValueError(
                    f"Source revision mismatch: config pins {pinned[:12]} but HEAD is {head[:12]}. "
                    "Update the revision with 'vulnforge update' before scanning."
                )
        except FileNotFoundError:
            pass  # not a git repo; skip check
    cfg = load_yaml(SETTINGS_CONFIG).get("static", {})
    binary = str(cfg.get("semgrep_binary", "semgrep"))
    from vulnforge.mcp_servers.source_server import get_rules_file
    configured_rules = get_rules_file(project) if rules_file is None else str(cfg.get("rules_file", "rules/c-memory.yml"))
    if not configured_rules:
        raise ValueError("Mixed-language projects require an explicit rules_file parameter")
    rules_arg = Path(rules_file or configured_rules)
    rules = (rules_arg if rules_arg.is_absolute() else BASE / rules_arg).resolve()
    allowed_rules_root = (BASE / "rules").resolve()
    if not rules.is_relative_to(allowed_rules_root) or not rules.is_file():
        raise ValueError("Rules file must be an existing file under the configured rules directory")

    timeout = max(10, min(int(cfg.get("timeout_seconds", 300)), 1800))
    max_output = int(cfg.get("max_output_bytes", 5_000_000))
    command = [
        binary, "scan", "--config", str(rules),
        "--json", "--quiet", "--metrics=off", str(root),
    ]
    try:
        proc = subprocess.run(
            command,
            cwd=str(BASE),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env={**os.environ, "NO_COLOR": "1"},
        )
    except FileNotFoundError as exc:
        raise RuntimeError("Semgrep executable not found; install Semgrep first") from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"Semgrep timed out after {timeout} seconds") from exc

    raw = proc.stdout or ""
    if len(raw.encode("utf-8", errors="replace")) > max_output:
        raise RuntimeError("Semgrep output exceeds configured size limit")
    try:
        result = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError:
        result = {"raw_output": raw[:10000]}

    return {
        "project": project,
        "exit_code": proc.returncode,
        "findings": result.get("results", []),
        "errors": result.get("errors", []),
        "version": result.get("version"),
        "stderr": (proc.stderr or "")[-4000:],
        "note": "Static findings are candidates; they are not confirmed vulnerabilities.",
    }


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
