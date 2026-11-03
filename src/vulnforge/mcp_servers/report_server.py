from __future__ import annotations

import json
import os
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from vulnforge.config import project_root
from vulnforge.findings import (
    list_findings,
    load_finding,
    save_finding,
)
from vulnforge.paths import reports_root

mcp = FastMCP("vulnforge-report")
BASE = Path(os.getenv("VULNFORGE_HOME", ".")).resolve()
PROJECTS_CONFIG = Path(os.getenv("VULNFORGE_PROJECTS", BASE / "config/projects.yaml"))
SETTINGS_CONFIG = Path(os.getenv("VULNFORGE_SETTINGS", BASE / "config/settings.yaml"))


@mcp.tool()
def create_finding(finding: dict) -> dict:
    """Create or update a schema-validated finding record."""
    return save_finding(finding, SETTINGS_CONFIG)


@mcp.tool()
def get_finding(finding_id: str) -> dict:
    """Load one finding and its evidence references."""
    return load_finding(finding_id, SETTINGS_CONFIG)


@mcp.tool()
def findings_list() -> dict:
    """List validated local findings."""
    return {"findings": list_findings(SETTINGS_CONFIG)}


@mcp.tool()
def generate_report(project: str, title: str = "Security research report") -> dict:
    """Generate a local Markdown report from findings for one registered project."""
    root = project_root(project, PROJECTS_CONFIG)
    records = [r for r in list_findings(SETTINGS_CONFIG) if r["project_id"] == project]
    revision = ""
    try:
        import subprocess

        proc = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if proc.returncode == 0:
            revision = proc.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        pass

    lines = [
        f"# {title}",
        "",
        f"- Project: `{project}`",
        f"- Source root: `{root}`",
        f"- Revision: `{revision or 'unknown'}`",
        "- Finding count: " + str(len(records)),
        "",
        "## Candidate findings",
        "",
    ]
    for record in records:
        full = load_finding(record["finding_id"], SETTINGS_CONFIG)
        lines.extend(
            [
                f"### {record['finding_id']} — {record['title']}",
                "",
                f"- Status: `{record['status']}`",
                f"- Severity: `{record.get('severity', 'unknown')}`",
                f"- Updated: `{record.get('updated_at', 'unknown')}`",
            ]
        )
        location = full.get("location", {})
        if location:
            lines.append(
                f"- Location: `{location.get('file', 'unknown')}"
                f":{location.get('line_start', '?')}-{location.get('line_end', '?')}`"
            )
        evidence = full.get("evidence", [])
        lines.append(f"- Evidence items: {len(evidence)}")
        lines.append("")
        if evidence:
            lines.append("```json")
            lines.append(json.dumps(evidence, ensure_ascii=False, indent=2))
            lines.append("```")
            lines.append("")

    lines.extend(
        [
            "## Interpretation constraints",
            "",
            "- Static-analysis output and crashes are leads, not confirmed vulnerabilities.",
            "- Security impact requires reachable input, data-flow, and verification evidence.",
            "- Human review is required before claiming a confirmed vulnerability.",
            "",
        ]
    )
    reports = reports_root(SETTINGS_CONFIG)
    project_dir = reports / project
    project_dir.mkdir(parents=True, exist_ok=True)
    out = (project_dir / "report.md").resolve()
    if out.parent != project_dir.resolve():
        raise ValueError("Invalid report path")
    out.write_text("\n".join(lines), encoding="utf-8")
    return {"project": project, "finding_count": len(records), "report": str(out)}


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
