from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from vulnforge.config import project_root
from vulnforge.findings import (
    list_findings,
    load_finding,
)
from vulnforge.paths import reports_root

mcp = FastMCP("vulnforge-report")
BASE = Path(os.getenv("VULNFORGE_HOME", ".")).resolve()
PROJECTS_CONFIG = Path(os.getenv("VULNFORGE_PROJECTS", BASE / "config/projects.yaml"))
SETTINGS_CONFIG = Path(os.getenv("VULNFORGE_SETTINGS", BASE / "config/settings.yaml"))

STATUS_BUCKETS = {
    "confirmed": "confirmed",
    "needs_validation": "needs_validation",
    "rejected": "rejected",
    "hypothesis": "candidates",
    "candidate": "candidates",
    "unconfirmed": "candidates",
}


@mcp.tool()
def create_finding(finding: dict) -> dict:
    """Create or update a schema-validated finding record."""
    from vulnforge.findings import save_finding

    return save_finding(finding, SETTINGS_CONFIG)


@mcp.tool()
def get_finding(finding_id: str) -> dict:
    """Load one finding and its evidence references."""
    return load_finding(finding_id, SETTINGS_CONFIG)


@mcp.tool()
def findings_list() -> dict:
    """List validated local findings."""
    return {"findings": list_findings(SETTINGS_CONFIG)}


def _source_revision(root: Path) -> str:
    try:
        proc = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        return proc.stdout.strip() if proc.returncode == 0 else ""
    except (OSError, subprocess.TimeoutExpired):
        return ""


def _finding_section(record: dict, full: dict) -> list[str]:
    location = full.get("location", {})
    lines = [
        f"### {record['finding_id']} — {record['title']}",
        "",
        f"- Status: `{record['status']}`",
        f"- Fingerprint: `{record.get('fingerprint', 'unknown')}`",
        f"- Severity: `{record.get('severity', 'unknown')}`",
        f"- Updated: `{record.get('updated_at', 'unknown')}`",
    ]
    if location:
        lines.append(
            f"- Location: `{location.get('file', 'unknown')}"
            f":{location.get('line_start', '?')}-{location.get('line_end', '?')}`"
        )
    if record.get("coverage_id"):
        lines.append(f"- Coverage: `{record['coverage_id']}`")
    if record.get("blocked_reason"):
        lines.append(f"- Blocked reason: {record['blocked_reason']}")
    analysis = full.get("analysis")
    if analysis:
        lines.extend(
            [
                "",
                "#### Analysis",
                "",
                f"- Overview: {analysis.get('overview', '')}",
                f"- Root cause: {analysis.get('root_cause', '')}",
                f"- Impact scope: {analysis.get('impact_scope', '')}",
            ]
        )
    validation_plan = full.get("validation_plan")
    if validation_plan:
        lines.append("")
        lines.append("#### Reproduction")
        lines.append("")
        if validation_plan.get("steps"):
            lines.append(validation_plan["steps"])
        for key in ("local", "deployment", "required_permission"):
            if validation_plan.get(key):
                lines.append(f"- {key.replace(chr(95), chr(32)).capitalize()}: {validation_plan[key]}")
        if validation_plan.get("expected_result"):
            lines.append(f"- Expected result: {validation_plan['expected_result']}")
        lines.append("")
    evidence = full.get("evidence", [])
    lines.append(f"- Evidence items: {len(evidence)}")
    lines.append("")
    if evidence:
        lines.append("```json")
        lines.append(json.dumps(evidence, ensure_ascii=False, indent=2))
        lines.append("```")
        lines.append("")
    return lines


@mcp.tool()
def generate_report(project: str, title: str = "Security research report") -> dict:
    """Generate a tri-state local Markdown report from findings for one project."""
    root = project_root(project, PROJECTS_CONFIG)
    records = [r for r in list_findings(SETTINGS_CONFIG) if r["project_id"] == project]
    revision = _source_revision(root)
    buckets: dict[str, list[dict]] = {"confirmed": [], "needs_validation": [], "candidates": [], "rejected": []}
    for record in records:
        bucket = STATUS_BUCKETS.get(str(record["status"]), "candidates")
        buckets[bucket].append(record)

    lines = [
        f"# {title}",
        "",
        f"- Project: `{project}`",
        f"- Source root: `{root}`",
        f"- Revision: `{revision or 'unknown'}`",
        f"- Finding count: {len(records)}",
        f"- Confirmed: {len(buckets['confirmed'])}",
        f"- Needs validation: {len(buckets['needs_validation'])}",
        f"- Candidates: {len(buckets['candidates'])}",
        f"- Rejected: {len(buckets['rejected'])}",
        "",
    ]

    section_titles = {
        "confirmed": "Confirmed findings",
        "needs_validation": "Needs validation",
        "candidates": "Candidates and hypotheses",
        "rejected": "Rejected records",
    }
    section_notes = {
        "confirmed": "Each record has reproducible evidence and human review.",
        "needs_validation": (
            "These are source-grounded candidates with specific unresolved blockers. "
            "They have no severity and must not be treated as confirmed vulnerabilities."
        ),
        "candidates": "Static-analysis output and crashes are leads, not confirmed vulnerabilities.",
        "rejected": "These candidates were disproved. Records are retained to avoid repeated work.",
    }
    for bucket in ("confirmed", "needs_validation", "candidates", "rejected"):
        lines.extend([f"## {section_titles[bucket]}", "", section_notes[bucket], ""])
        if not buckets[bucket]:
            lines.extend(["No records.", ""])
            continue
        for record in buckets[bucket]:
            full = load_finding(record["finding_id"], SETTINGS_CONFIG)
            lines.extend(_finding_section(record, full))

    lines.extend(
        [
            "## Interpretation constraints",
            "",
            "- Static-analysis output and crashes are leads, not confirmed vulnerabilities.",
            "- Security impact requires reachable input, data-flow, and verification evidence.",
            "- Human review is required before claiming a confirmed vulnerability.",
            "- `needs_validation` records have no severity and must not be reported as vulnerabilities.",
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
    return {
        "project": project,
        "finding_count": len(records),
        "confirmed": len(buckets["confirmed"]),
        "needs_validation": len(buckets["needs_validation"]),
        "candidates": len(buckets["candidates"]),
        "rejected": len(buckets["rejected"]),
        "report": str(out),
    }


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
