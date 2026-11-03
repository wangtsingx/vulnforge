from __future__ import annotations

import os
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from vulnforge.config import override_config, project_root
from vulnforge.coverage import (
    coverage_id_from_refs,
    coverage_summary,
    load_ledger,
    save_ledger,
)
from vulnforge.tasks import (
    VALID_STATUS,
    list_tasks,
    load_task,
    new_task_id,
    save_task,
    task_coverage_summary,
    transition_task,
)

mcp = FastMCP("vulnforge-tasks")
BASE = Path(os.getenv("VULNFORGE_HOME", ".")).resolve()
PROJECTS_CONFIG = Path(os.getenv("VULNFORGE_PROJECTS", BASE / "config/projects.yaml"))
SETTINGS_CONFIG = Path(os.getenv("VULNFORGE_SETTINGS", BASE / "config/settings.yaml"))


@mcp.tool()
def create_task(project: str, title: str, scope: str = "") -> dict:
    """Create a new research task for a registered project."""
    root = project_root(project, override_config(PROJECTS_CONFIG))
    task_id = new_task_id()
    task = {
        "task_id": task_id,
        "project_id": project,
        "title": title[:500],
        "scope": scope[:2000],
        "status": "created",
        "source_root": str(root),
        "findings": [],
        "notes": [],
        "verification": {"reproducible": False, "human_reviewed": False},
    }
    return save_task(task, SETTINGS_CONFIG)


@mcp.tool()
def get_task(task_id: str) -> dict:
    """Load a research task by ID."""
    return load_task(task_id, SETTINGS_CONFIG)


@mcp.tool()
def tasks_list() -> dict:
    """List all research tasks."""
    return {"tasks": list_tasks(SETTINGS_CONFIG)}


@mcp.tool()
def advance_task(task_id: str, next_status: str) -> dict:
    """Advance a task through the research state machine."""
    if next_status not in VALID_STATUS:
        raise ValueError(f"Invalid status: {next_status}")
    return transition_task(task_id, next_status, SETTINGS_CONFIG)


@mcp.tool()
def add_task_note(task_id: str, note: str) -> dict:
    """Append a note to a research task."""
    task = load_task(task_id, SETTINGS_CONFIG)
    task.setdefault("notes", []).append(note[:3000])
    return save_task(task, SETTINGS_CONFIG)


@mcp.tool()
def link_task_finding(task_id: str, finding_id: str) -> dict:
    """Link a finding to a research task."""
    task = load_task(task_id, SETTINGS_CONFIG)
    if finding_id not in task.get("findings", []):
        task.setdefault("findings", []).append(finding_id)
    return save_task(task, SETTINGS_CONFIG)


@mcp.tool()
def set_task_verification(task_id: str, reproducible: bool, human_reviewed: bool) -> dict:
    """Set verification flags on a task. human_reviewed=true is required for confirmed status."""
    task = load_task(task_id, SETTINGS_CONFIG)
    task["verification"] = {"reproducible": reproducible, "human_reviewed": human_reviewed}
    return save_task(task, SETTINGS_CONFIG)


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()


@mcp.tool()
def create_coverage_unit(
    task_id: str,
    surface_ref: str,
    boundary_ref: str,
    subsystem_ref: str,
    attack_class_ref: str,
    surface: str,
    boundary: str,
    subsystem: str,
    attack_class: str,
    starting_path: str,
    lifecycle_ref: str = "",
) -> dict:
    """Create and append one deterministic coverage unit to a task ledger."""
    load_task(task_id, SETTINGS_CONFIG)
    refs = {
        "surface": surface_ref,
        "boundary": boundary_ref,
        "subsystem": subsystem_ref,
        "attack_class": attack_class_ref,
    }
    if lifecycle_ref:
        refs["lifecycle"] = lifecycle_ref
    unit = {
        "coverage_id": coverage_id_from_refs(refs),
        "canonical_refs": refs,
        "surface": surface[:500],
        "boundary": boundary[:500],
        "subsystem": subsystem[:500],
        "attack_class": attack_class[:500],
        "starting_paths": [starting_path],
        "status": "planned",
        "owner": None,
        "reviewed_paths": [],
        "local_checks": [],
        "result_fingerprints": [],
        "unresolved": [],
    }
    try:
        records = load_ledger(task_id, SETTINGS_CONFIG)
    except FileNotFoundError:
        records = []
    if any(record.get("coverage_id") == unit["coverage_id"] for record in records):
        raise ValueError("Coverage unit already exists")
    records.append(unit)
    save_ledger(records, task_id, SETTINGS_CONFIG)
    return unit


@mcp.tool()
def update_coverage_unit(
    task_id: str,
    coverage_id: str,
    status: str,
    owner: str | None = None,
    reviewed_paths: list[str] | None = None,
    local_checks: list[dict] | None = None,
    result_fingerprints: list[str] | None = None,
    unresolved: list[str] | None = None,
) -> dict:
    """Replace the live state of one coverage unit and validate the whole ledger."""
    records = load_ledger(task_id, SETTINGS_CONFIG)
    for record in records:
        if record.get("coverage_id") == coverage_id:
            record["status"] = status
            record["owner"] = owner
            record["reviewed_paths"] = list(reviewed_paths or [])
            record["local_checks"] = list(local_checks or [])
            record["result_fingerprints"] = list(result_fingerprints or [])
            record["unresolved"] = list(unresolved or [])
            save_ledger(records, task_id, SETTINGS_CONFIG)
            return task_coverage_summary(task_id, SETTINGS_CONFIG)
    raise ValueError(f"Coverage unit not found: {coverage_id}")


@mcp.tool()
def link_finding_to_coverage(
    task_id: str,
    coverage_id: str,
    finding_id: str,
    fingerprint: str | None = None,
) -> dict:
    """Validate a finding and link its fingerprint to a candidate coverage unit.

    Also writes coverage_id back onto the finding so the relationship is bidirectional.
    """
    records = load_ledger(task_id, SETTINGS_CONFIG)
    target = None
    for record in records:
        if record.get("coverage_id") == coverage_id:
            target = record
            break
    if target is None:
        raise ValueError(f"Coverage unit not found: {coverage_id}")
    if target.get("status") != "candidate":
        raise ValueError("Findings can only be linked to candidate coverage units")
    from vulnforge.findings import load_finding, save_finding

    finding = load_finding(finding_id, SETTINGS_CONFIG)
    actual_fingerprint = str(finding.get("fingerprint", ""))
    if fingerprint and fingerprint != actual_fingerprint:
        raise ValueError("Fingerprint does not match the finding")
    fingerprints = set(target.get("result_fingerprints", []))
    fingerprints.add(actual_fingerprint)
    target["result_fingerprints"] = sorted(fingerprints)
    save_ledger(records, task_id, SETTINGS_CONFIG)
    if finding.get("coverage_id") != coverage_id:
        finding["coverage_id"] = coverage_id
        save_finding(finding, SETTINGS_CONFIG)
    return task_coverage_summary(task_id, SETTINGS_CONFIG)


@mcp.tool()
def coverage_orphans(task_id: str) -> dict:
    """Return candidate coverage fingerprints that do not exist in the finding store."""
    records = load_ledger(task_id, SETTINGS_CONFIG)
    from vulnforge.findings import list_findings

    known = {item["fingerprint"] for item in list_findings(SETTINGS_CONFIG) if item.get("fingerprint")}
    result = []
    for record in records:
        if record.get("status") != "candidate":
            continue
        orphan = [fp for fp in record.get("result_fingerprints", []) if fp not in known]
        if orphan:
            result.append({"coverage_id": record["coverage_id"], "orphans": sorted(orphan)})
    return {"task_id": task_id, "orphan_units": result}


@mcp.tool()
def coverage_summary_for_task(task_id: str) -> dict:
    """Return a validated coverage summary and update it onto the research task."""
    task = load_task(task_id, SETTINGS_CONFIG)
    records = load_ledger(task_id, SETTINGS_CONFIG)
    task["coverage_summary"] = coverage_summary(records)
    return {"task_id": task_id, **task_coverage_summary(task_id, SETTINGS_CONFIG)["coverage_summary"]}


@mcp.tool()
def get_coverage_ledger(task_id: str) -> dict:
    """Load and validate one task coverage ledger."""
    return {"task_id": task_id, "units": load_ledger(task_id, SETTINGS_CONFIG)}
