from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

TASK_ID_RE = __import__("re").compile(r"^task-[A-Za-z0-9-]{1,128}$")

VALID_STATUS = {
    "created",
    "project_analysis",
    "attack_surface_analysis",
    "static_analysis",
    "candidate_generation",
    "manual_review",
    "dynamic_validation",
    "unconfirmed",
    "confirmed",
    "rejected",
    "report_generated",
}

STATUS_TRANSITIONS: dict[str, set[str]] = {
    "created": {"project_analysis"},
    "project_analysis": {"attack_surface_analysis"},
    "attack_surface_analysis": {"static_analysis"},
    "static_analysis": {"candidate_generation"},
    "candidate_generation": {"manual_review"},
    "manual_review": {"dynamic_validation", "rejected"},
    "dynamic_validation": {"unconfirmed", "confirmed"},
    "unconfirmed": {"dynamic_validation", "report_generated"},
    "confirmed": {"report_generated"},
    "rejected": {"report_generated"},
    "report_generated": set(),
}


def tasks_root(settings_path: str | Path) -> Path:
    import os

    base = Path(os.getenv("VULNFORGE_HOME", ".")).resolve()
    root = Path(os.getenv("VULNFORGE_TASKS", base / "tasks")).expanduser()
    if not root.is_absolute():
        root = base / root
    return root.resolve()


def task_file(root: Path, task_id: str) -> Path:
    if not TASK_ID_RE.fullmatch(task_id):
        raise ValueError("Invalid task ID")
    path = (root / f"{task_id}.json").resolve()
    if path.parent != root:
        raise ValueError("Invalid task path")
    return path


def new_task_id() -> str:
    return f"task-{uuid.uuid4().hex[:12]}"


def save_task(task: dict[str, Any], settings_path: str | Path) -> dict[str, Any]:

    root = tasks_root(settings_path)
    root.mkdir(parents=True, exist_ok=True)
    task_id = str(task.get("task_id", ""))
    path = task_file(root, task_id)
    if not path.exists():
        task["created_at"] = datetime.now(UTC).isoformat()
    task["updated_at"] = datetime.now(UTC).isoformat()
    path.write_text(json.dumps(task, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return task


def load_task(task_id: str, settings_path: str | Path) -> dict[str, Any]:
    root = tasks_root(settings_path)
    path = task_file(root, task_id)
    if not path.is_file():
        raise FileNotFoundError(f"Task not found: {task_id}")
    return json.loads(path.read_text(encoding="utf-8"))


def list_tasks(settings_path: str | Path) -> list[dict[str, Any]]:
    root = tasks_root(settings_path)
    records = []
    if root.is_dir():
        for path in sorted(root.glob("task-*.json")):
            if path.parent != root:
                continue
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            records.append({
                "task_id": data.get("task_id"),
                "project_id": data.get("project_id"),
                "status": data.get("status"),
                "title": data.get("title"),
                "updated_at": data.get("updated_at"),
            })
    return records


def transition_task(task_id: str, new_status: str, settings_path: str | Path) -> dict[str, Any]:
    task = load_task(task_id, settings_path)
    current = str(task.get("status", "created"))
    if new_status not in VALID_STATUS:
        raise ValueError(f"Invalid status: {new_status}")
    if new_status not in STATUS_TRANSITIONS.get(current, set()):
        raise ValueError(f"Invalid transition: {current} -> {new_status}")
    if new_status == "confirmed":
        verification = task.get("verification", {})
        if not verification.get("reproducible") or not verification.get("human_reviewed"):
            raise ValueError("Confirmed status requires reproducible evidence and human_reviewed=true")
    task["status"] = new_status
    return save_task(task, settings_path)
