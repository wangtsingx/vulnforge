from __future__ import annotations

import os
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from vulnforge.config import override_config, project_root
from vulnforge.tasks import (
    VALID_STATUS,
    list_tasks,
    load_task,
    new_task_id,
    save_task,
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
