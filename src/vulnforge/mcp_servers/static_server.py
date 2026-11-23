from __future__ import annotations

import json
import os
import subprocess
import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from vulnforge.config import load_yaml, override_config, project_root

mcp = FastMCP("vulnforge-static")
BASE = Path(os.getenv("VULNFORGE_HOME", ".")).resolve()
PROJECTS_CONFIG = Path(os.getenv("VULNFORGE_PROJECTS", BASE / "config/projects.yaml"))
SETTINGS_CONFIG = Path(os.getenv("VULNFORGE_SETTINGS", BASE / "config/settings.yaml"))

SCAN_ID_RE = __import__("re").compile(r"^scan-[A-Za-z0-9-]{1,128}$")


def _scans_root() -> Path:
    base = Path(os.getenv("VULNFORGE_HOME", ".")).resolve()
    root = Path(os.getenv("VULNFORGE_SCANS", base / "scans")).expanduser()
    if not root.is_absolute():
        root = base / root
    return root.resolve()


def _scan_file(scan_id: str) -> Path:
    if not SCAN_ID_RE.fullmatch(scan_id):
        raise ValueError("Invalid scan ID")
    path = (_scans_root() / f"{scan_id}.json").resolve()
    if path.parent != _scans_root():
        raise ValueError("Invalid scan path")
    return path


def _save_scan(scan: dict[str, Any]) -> None:
    root = _scans_root()
    root.mkdir(parents=True, exist_ok=True)
    path = _scan_file(str(scan["scan_id"]))
    path.write_text(json.dumps(scan, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _load_scan(scan_id: str) -> dict[str, Any]:
    path = _scan_file(scan_id)
    if not path.is_file():
        raise FileNotFoundError(f"Scan not found: {scan_id}")
    return json.loads(path.read_text(encoding="utf-8"))


def _validate_rules(rules_file: str | None, project: str) -> Path:
    from vulnforge.mcp_servers.source_server import get_rules_file

    configured_rules = get_rules_file(project) if rules_file is None else rules_file
    if not configured_rules:
        raise ValueError("Mixed-language projects require an explicit rules_file parameter")
    rules_arg = Path(rules_file or configured_rules)
    repo_root = Path(__file__).resolve().parents[3]
    allowed_rules_root = (repo_root / "rules").resolve()
    if rules_arg.is_absolute():
        rules = rules_arg.resolve()
    elif rules_arg.parts and rules_arg.parts[0] == "rules":
        rules = (repo_root / rules_arg).resolve()
    else:
        rules = (allowed_rules_root / rules_arg).resolve()
    if not rules.is_relative_to(allowed_rules_root) or not rules.is_file():
        raise ValueError("Rules file must be an existing file under the configured rules directory")
    return rules


def _check_revision(project: str) -> None:
    root = project_root(project, override_config(PROJECTS_CONFIG))
    project_cfg = load_yaml(override_config(PROJECTS_CONFIG)).get("projects", {}).get(project, {})
    pinned = str(project_cfg.get("revision", "")).strip()
    if not pinned:
        return
    try:
        head_proc = subprocess.run(
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
        pass


def _run_semgrep(project: str, rules: Path, target: str, timeout: int, max_output: int) -> dict:
    command = [

        str(Path(load_yaml(SETTINGS_CONFIG).get("static", {}).get("semgrep_binary", "semgrep"))),
        "scan", "--config", str(rules),
        "--json", "--quiet", "--metrics=off", target,
    ]
    try:
        proc = subprocess.run(
            command, cwd=str(BASE), capture_output=True, text=True,
            timeout=timeout, check=False, env={**os.environ, "NO_COLOR": "1"},
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
        "exit_code": proc.returncode,
        "findings": result.get("results", []),
        "errors": result.get("errors", []),
        "version": result.get("version"),
        "stderr": (proc.stderr or "")[-4000:],
    }


def _run_background_scan(scan_id: str, project: str, rules: Path, target: str, timeout: int, max_output: int) -> None:
    """Run semgrep in a background thread and persist the result."""
    scan = _load_scan(scan_id)
    scan["status"] = "running"
    _save_scan(scan)
    try:
        result = _run_semgrep(project, rules, target, timeout, max_output)
        scan.update(result)
        scan["status"] = "finished"
        scan["finished_at"] = datetime.now(UTC).isoformat()
    except (RuntimeError, ValueError) as exc:
        scan["status"] = "failed"
        scan["error"] = str(exc)[:2000]
        scan["finished_at"] = datetime.now(UTC).isoformat()
    scan["updated_at"] = datetime.now(UTC).isoformat()
    _save_scan(scan)


@mcp.tool()
def semgrep_scan(project: str, rules_file: str | None = None) -> dict:
    """Run the configured Semgrep rules against a registered local source project.

    The executable and timeout are configuration-controlled. No arbitrary shell is accepted.
    """
    root = project_root(project, override_config(PROJECTS_CONFIG))
    _check_revision(project)
    cfg = load_yaml(SETTINGS_CONFIG).get("static", {})
    rules = _validate_rules(rules_file, project)
    timeout = max(10, min(int(cfg.get("timeout_seconds", 300)), 1800))
    max_output = int(cfg.get("max_output_bytes", 5_000_000))
    result = _run_semgrep(project, rules, str(root), timeout, max_output)
    return {
        "project": project,
        **result,
        "note": "Static findings are candidates; they are not confirmed vulnerabilities.",
    }


@mcp.tool()
def semgrep_scan_files(project: str, files: list[str], rules_file: str | None = None) -> dict:
    """Scan specific source files only (fast, targeted). Returns results immediately."""
    root = project_root(project, override_config(PROJECTS_CONFIG))
    _check_revision(project)
    if not files or not isinstance(files, list) or len(files) > 50:
        raise ValueError("files must be a non-empty list (max 50)")
    validated: list[str] = []
    for f in files:
        resolved = (root / f).resolve()
        if not resolved.is_relative_to(root) or not resolved.is_file():
            raise ValueError(f"File not found under project root: {f}")
        validated.append(str(resolved))
    cfg = load_yaml(SETTINGS_CONFIG).get("static", {})
    rules = _validate_rules(rules_file, project)
    timeout = max(10, min(int(cfg.get("timeout_seconds", 300)), 1800))
    max_output = int(cfg.get("max_output_bytes", 5_000_000))
    result = _run_semgrep(project, rules, " ".join(validated), timeout, max_output)
    return {
        "project": project,
        "files_scanned": len(validated),
        **result,
        "note": "Static findings are candidates; they are not confirmed vulnerabilities.",
    }


@mcp.tool()
def semgrep_scan_async(project: str, rules_file: str | None = None) -> dict:
    """Start a background Semgrep scan. Returns a scan_id immediately (non-blocking)."""
    root = project_root(project, override_config(PROJECTS_CONFIG))
    _check_revision(project)
    cfg = load_yaml(SETTINGS_CONFIG).get("static", {})
    rules = _validate_rules(rules_file, project)
    timeout = max(10, min(int(cfg.get("timeout_seconds", 300)), 1800))
    max_output = int(cfg.get("max_output_bytes", 5_000_000))
    scan_id = f"scan-{uuid.uuid4().hex[:12]}"
    scan = {
        "scan_id": scan_id,
        "project": project,
        "status": "queued",
        "rules": str(rules),
        "target": str(root),
        "created_at": datetime.now(UTC).isoformat(),
    }
    _save_scan(scan)
    thread = threading.Thread(
        target=_run_background_scan,
        args=(scan_id, project, rules, str(root), timeout, max_output),
        daemon=True,
    )
    thread.start()
    return {
        "scan_id": scan_id,
        "project": project,
        "status": "queued",
        "note": "Poll semgrep_scan_status(scan_id) to check progress. Results persist until the next scan.",
    }


@mcp.tool()
def semgrep_scan_status(scan_id: str) -> dict:
    """Check the status and results of a background scan."""
    scan = _load_scan(scan_id)
    # Truncate findings list for status checks to keep response small
    resp = {k: v for k, v in scan.items() if k != "findings"}
    resp["finding_count"] = len(scan.get("findings", []))
    if scan.get("status") == "finished":
        resp["findings"] = scan.get("findings", [])[:100]
        resp["note"] = "Showing first 100 findings; full results in stored JSON."
    return resp


@mcp.tool()
def semgrep_scan_list(project: str | None = None) -> dict:
    """List all stored scans, optionally filtered by project."""
    root = _scans_root()
    scans = []
    if root.is_dir():
        for path in sorted(root.glob("scan-*.json")):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if project and data.get("project") != project:
                continue
            scans.append({
                "scan_id": data.get("scan_id"),
                "project": data.get("project"),
                "status": data.get("status"),
                "finding_count": len(data.get("findings", [])),
                "created_at": data.get("created_at"),
            })
    return {"scans": scans}


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
