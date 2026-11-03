from pathlib import Path

import pytest

from vulnforge.tasks import (
    list_tasks,
    load_task,
    new_task_id,
    save_task,
    transition_task,
)


@pytest.fixture()
def task_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("VULNFORGE_HOME", str(tmp_path))
    monkeypatch.setenv("VULNFORGE_TASKS", str(tmp_path / "tasks"))
    settings = tmp_path / "settings.yaml"
    settings.write_text("tasks:\n  tasks_dir: tasks\n")
    return settings


def make_task(settings: Path) -> dict:
    return save_task(
        {
            "task_id": new_task_id(),
            "project_id": "demo",
            "title": "Test task",
            "status": "created",
            "verification": {"reproducible": False, "human_reviewed": False},
        },
        settings,
    )


def test_create_and_load(task_env):
    task = make_task(task_env)
    loaded = load_task(task["task_id"], task_env)
    assert loaded["title"] == "Test task"
    assert loaded["status"] == "created"


def test_valid_transition_chain(task_env):
    task = make_task(task_env)
    chain = [
        "project_analysis",
        "attack_surface_analysis",
        "static_analysis",
        "candidate_generation",
        "manual_review",
        "dynamic_validation",
    ]
    for status in chain:
        task = transition_task(task["task_id"], status, task_env)
    assert task["status"] == "dynamic_validation"


def test_invalid_transition(task_env):
    task = make_task(task_env)
    with pytest.raises(ValueError):
        transition_task(task["task_id"], "confirmed", task_env)


def test_confirm_requires_human_review(task_env):
    task = make_task(task_env)
    for status in ["project_analysis", "attack_surface_analysis", "static_analysis", "candidate_generation", "manual_review", "dynamic_validation"]:
        task = transition_task(task["task_id"], status, task_env)
    with pytest.raises(ValueError):
        transition_task(task["task_id"], "confirmed", task_env)
    task["verification"] = {"reproducible": True, "human_reviewed": True}
    save_task(task, task_env)
    result = transition_task(task["task_id"], "confirmed", task_env)
    assert result["status"] == "confirmed"


def test_list_tasks(task_env):
    make_task(task_env)
    tasks = list_tasks(task_env)
    assert len(tasks) == 1
    assert tasks[0]["project_id"] == "demo"
