from __future__ import annotations

import os
import re
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
def audit_status(task_id: str) -> dict:
    """Return a one-call snapshot of task status, coverage summary, and finding counts."""
    task = load_task(task_id, SETTINGS_CONFIG)
    from vulnforge.coverage import load_ledger
    from vulnforge.findings import list_findings

    project_id = str(task.get("project_id", ""))
    all_findings = [f for f in list_findings(SETTINGS_CONFIG) if f["project_id"] == project_id]
    linked_finding_ids = set(task.get("findings", []))

    status_counts: dict[str, int] = {}
    for item in all_findings:
        status = str(item.get("status", "unknown"))
        status_counts[status] = status_counts.get(status, 0) + 1

    try:
        ledger = load_ledger(task_id, SETTINGS_CONFIG)
        coverage = coverage_summary(ledger)
    except FileNotFoundError:
        ledger = []
        coverage = {"total": 0, "note": "no coverage ledger yet"}

    orphan_units = 0
    if ledger:
        known_fingerprints = {f["fingerprint"] for f in all_findings if f.get("fingerprint")}
        for unit in ledger:
            if unit.get("status") == "candidate":
                orphans = [fp for fp in unit.get("result_fingerprints", []) if fp not in known_fingerprints]
                if orphans:
                    orphan_units += 1

    return {
        "task_id": task_id,
        "status": task.get("status"),
        "title": task.get("title"),
        "project_id": project_id,
        "coverage_summary": coverage,
        "finding_status_counts": status_counts,
        "total_findings": len(all_findings),
        "findings_linked_to_task": len([f for f in all_findings if f["finding_id"] in linked_finding_ids]),
        "orphan_candidate_units": orphan_units,
    }


@mcp.tool()
def import_scan_results(project: str, task_id: str, scan_output: dict) -> dict:
    """Turn raw Semgrep scan results into hypothesis findings with deduplication.

    Groups results by (path, check_id), generates stable fingerprints, creates
    hypothesis findings and planned coverage units. Existing fingerprints return
    the existing finding_id without creating duplicates.
    """
    load_task(task_id, SETTINGS_CONFIG)
    from vulnforge.coverage import coverage_id_from_refs
    from vulnforge.findings import list_findings, new_finding_id, save_finding

    source_root = str(project_root(project, override_config(PROJECTS_CONFIG)))
    raw_results = scan_output.get("findings", [])
    if not isinstance(raw_results, list):
        raise TypeError("scan_output.findings must be a list")
    from vulnforge.config import load_yaml
    max_import = int(load_yaml(SETTINGS_CONFIG).get("coverage", {}).get("max_scan_import", 500))
    if len(raw_results) > max_import:
        raise ValueError(f"scan_output.findings exceeds max_scan_import limit ({max_import})")

    # Group by (path, check_id)
    groups: dict[tuple[str, str], list[dict]] = {}
    for result in raw_results:
        path = str(result.get("path") or result.get("location", {}).get("path", "unknown"))
        resolved = _resolve_source_path(project, path)
        if resolved is not None:
            path = resolved.relative_to(Path(source_root)).as_posix()
        check_id = str(result.get("check_id") or "unknown")
        groups.setdefault((path, check_id), []).append(result)

    known = {f["finding_id"]: f for f in list_findings(SETTINGS_CONFIG) if f["project_id"] == project}
    known_by_fp = {f["fingerprint"]: f for f in known.values() if f.get("fingerprint")}

    created_findings: list[str] = []
    existing_findings: list[str] = []
    created_units: list[str] = []
    existing_units: list[str] = []
    all_fingerprints: list[str] = []

    try:
        ledger = load_ledger(task_id, SETTINGS_CONFIG)
    except FileNotFoundError:
        ledger = []

    for (path, check_id), items in sorted(groups.items()):
        vuln_class = check_id
        func_names = {str(item.get("extra", {}).get("metavars", {}).get("$FUNC", "")) for item in items}
        func_names.discard("")
        function = next(iter(func_names)) if len(func_names) == 1 else None
        if not function:
            function = _enclosing_function(project, path, items)
        line_start = min(int(item.get("start", {}).get("line", 1)) for item in items)
        line_end = max(int(item.get("end", {}).get("line", line_start)) for item in items)

        from vulnforge.fingerprint import finding_fingerprint

        fingerprint = finding_fingerprint(project, path, vuln_class, function or "")

        # Finding dedup
        if fingerprint in known_by_fp:
            existing_findings.append(known_by_fp[fingerprint]["finding_id"])
            all_fingerprints.append(fingerprint)
        else:
            finding_id = new_finding_id()
            finding = {
                "finding_id": finding_id,
                "project_id": project,
                "status": "hypothesis",
                "title": f"Semgrep: {check_id} in {path}",
                "cwe": check_id,
                "location": {
                    "file": path,
                    "function": function,
                    "line_start": line_start,
                    "line_end": line_end,
                },
                "evidence": [
                    {
                        "kind": "semgrep",
                        "check_id": check_id,
                        "path": path,
                        "line": item.get("start", {}).get("line"),
                        "message": str(item.get("extra", {}).get("message", ""))[:500],
                    }
                    for item in items[:10]
                ],
            }
            save_finding(finding, SETTINGS_CONFIG)
            created_findings.append(finding_id)
            known_by_fp[fingerprint] = {"finding_id": finding_id, "fingerprint": fingerprint}
            all_fingerprints.append(fingerprint)

        # Coverage unit dedup
        subsystem = str(Path(path).parent) if Path(path).parent != Path(".") else "root"
        refs = {
            "surface": f"{path}#{function or 'module'}",
            "boundary": f"static:{check_id}",
            "subsystem": subsystem,
            "attack_class": check_id,
        }
        cid = coverage_id_from_refs(refs)
        unit_exists = any(u.get("coverage_id") == cid for u in ledger)
        if not unit_exists:
            unit = {
                "coverage_id": cid,
                "canonical_refs": refs,
                "surface": f"{path} ({function or 'module'})",
                "boundary": f"static rule {check_id}",
                "subsystem": subsystem,
                "attack_class": check_id,
                "starting_paths": [str(Path(path).parent) if Path(path).parent != Path(".") else "."],
                "status": "planned",
                "owner": None,
                "reviewed_paths": [],
                "local_checks": [],
                "result_fingerprints": [],
                "unresolved": [],
            }
            ledger.append(unit)
            created_units.append(cid)
        else:
            existing_units.append(cid)

    if created_units or existing_units:
        save_ledger(ledger, task_id, SETTINGS_CONFIG)

    return {
        "project": project,
        "task_id": task_id,
        "groups": len(groups),
        "created_findings": created_findings,
        "existing_findings": existing_findings,
        "created_coverage_units": created_units,
        "existing_coverage_units": existing_units,
        "fingerprints": all_fingerprints,
        "note": "All imported findings are hypothesis status; review each before promoting to candidate.",
    }


@mcp.tool()
def _resolve_source_path(project: str, path: str) -> Path | None:
    """Resolve a scan path to an existing source file beneath the project root."""
    try:
        root = project_root(project, override_config(PROJECTS_CONFIG))
    except ValueError:
        return None
    scan_path = Path(path)
    if scan_path.is_absolute():
        candidates = [scan_path]
    else:
        candidates = [root / scan_path]
        candidates.extend(root / Path(*scan_path.parts[index:]) for index in range(1, len(scan_path.parts)))
    for candidate in candidates:
        resolved = candidate.resolve()
        if resolved.is_file() and resolved.is_relative_to(root):
            return resolved
    return None


def _enclosing_function(project: str, path: str, items: list[dict]) -> str | None:
    """Best-effort enclosing-function extraction when Semgrep omits match metadata."""
    source_path = _resolve_source_path(project, path)
    if source_path is None:
        return None
    try:
        text = source_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None

    start = min(int(item.get("start", {}).get("line", 1)) for item in items)
    func_re = re.compile(r"^[A-Za-z_][A-Za-z0-9_ *]*\b([A-Za-z_][A-Za-z0-9_]*)\s*\([^;{}]*\)\s*\{\s*$")
    for line in reversed(text[:max(0, start - 1)]):
        match = func_re.match(line.strip())
        if match:
            return match.group(1)
    return None


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
