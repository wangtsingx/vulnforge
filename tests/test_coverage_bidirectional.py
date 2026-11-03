from pathlib import Path

import pytest

from vulnforge.coverage import load_ledger, save_ledger
from vulnforge.findings import save_finding
from vulnforge.mcp_servers.task_server import (
    coverage_orphans,
    create_coverage_unit,
    link_finding_to_coverage,
    update_coverage_unit,
)


@pytest.fixture()
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("VULNFORGE_HOME", str(tmp_path))
    monkeypatch.setenv("VULNFORGE_TASKS", str(tmp_path / "tasks"))
    monkeypatch.setenv("VULNFORGE_COVERAGE", str(tmp_path / "coverage"))
    monkeypatch.setenv("VULNFORGE_FINDINGS", str(tmp_path / "findings"))
    settings = tmp_path / "settings.yaml"
    settings.write_text(
        f"tasks:\n  tasks_dir: {tmp_path / 'tasks'}\n"
        f"coverage:\n  ledger_dir: {tmp_path / 'coverage'}\n"
        f"report:\n  findings_dir: {tmp_path / 'findings'}\n"
    )
    monkeypatch.setattr("vulnforge.mcp_servers.task_server.SETTINGS_CONFIG", settings)
    from vulnforge.tasks import new_task_id, save_task

    task = save_task(
        {
            "task_id": new_task_id(),
            "project_id": "demo",
            "title": "Bidirectional test",
            "status": "created",
            "verification": {},
        },
        settings,
    )
    return settings, task["task_id"]


def _candidate_finding(settings: Path, finding_id: str, fingerprint: str) -> dict:
    return save_finding(
        {
            "finding_id": finding_id,
            "project_id": "demo",
            "status": "candidate",
            "title": finding_id,
            "fingerprint": fingerprint,
            "location": {"file": "src/a.c", "line_start": 1, "line_end": 2},
            "evidence": [{"kind": "source", "path": "src/a.c", "line": 1}],
        },
        settings,
    )


def test_link_requires_real_finding(env):
    _settings, task_id = env
    unit = create_coverage_unit(
        task_id=task_id,
        surface_ref="src/router.c#handler",
        boundary_ref="src/auth.c#require_auth",
        subsystem_ref="src/http",
        attack_class_ref="ATTACK-CLASSES.md#Access control",
        surface="HTTP handler",
        boundary="authentication",
        subsystem="http",
        attack_class="Access control",
        starting_path="src/http",
    )
    update_coverage_unit(
        task_id=task_id,
        coverage_id=unit["coverage_id"],
        status="candidate",
        owner="hunter",
        reviewed_paths=["src/http/a.c"],
        local_checks=[{"agent_id": "hunter", "reviewed_paths": ["src/http/a.c"]}],
        result_fingerprints=["fp/demo/initial"],
        unresolved=[],
    )
    with pytest.raises(FileNotFoundError):
        link_finding_to_coverage(task_id=task_id, coverage_id=unit["coverage_id"], finding_id="finding-missing")


def test_bidirectional_link_and_orphans(env):
    settings, task_id = env
    finding = _candidate_finding(settings, "finding-link", "fp/demo/link001")
    unit = create_coverage_unit(
        task_id=task_id,
        surface_ref="src/router.c#handler",
        boundary_ref="src/auth.c#require_auth",
        subsystem_ref="src/http",
        attack_class_ref="ATTACK-CLASSES.md#Access control",
        surface="HTTP handler",
        boundary="authentication",
        subsystem="http",
        attack_class="Access control",
        starting_path="src/http",
    )
    update_coverage_unit(
        task_id=task_id,
        coverage_id=unit["coverage_id"],
        status="candidate",
        owner="hunter",
        reviewed_paths=["src/http/a.c"],
        local_checks=[{"agent_id": "hunter", "reviewed_paths": ["src/http/a.c"]}],
        result_fingerprints=[finding["fingerprint"]],
        unresolved=[],
    )
    result = link_finding_to_coverage(
        task_id=task_id,
        coverage_id=unit["coverage_id"],
        finding_id=finding["finding_id"],
    )
    from vulnforge.findings import load_finding

    updated = load_finding(finding["finding_id"], settings)
    assert updated["coverage_id"] == unit["coverage_id"]
    assert result["coverage_summary"]["candidate"] == 1

    ledger = load_ledger(task_id, settings)
    target = next(u for u in ledger if u["coverage_id"] == unit["coverage_id"])
    assert finding["fingerprint"] in target["result_fingerprints"]

    # no orphans when finding exists
    assert coverage_orphans(task_id)["orphan_units"] == []

    # simulate orphan by directly editing ledger
    target["result_fingerprints"].append("fp/demo/ghost")
    save_ledger(ledger, task_id, settings)
    orphan = coverage_orphans(task_id)["orphan_units"]
    assert len(orphan) == 1
    assert "fp/demo/ghost" in orphan[0]["orphans"]


def test_fingerprint_mismatch_rejected(env):
    settings, task_id = env
    finding = _candidate_finding(settings, "finding-mismatch", "fp/demo/match01")
    unit = create_coverage_unit(
        task_id=task_id,
        surface_ref="src/router.c#handler",
        boundary_ref="src/auth.c#require_auth",
        subsystem_ref="src/http",
        attack_class_ref="ATTACK-CLASSES.md#Access control",
        surface="HTTP handler",
        boundary="authentication",
        subsystem="http",
        attack_class="Access control",
        starting_path="src/http",
    )
    update_coverage_unit(
        task_id=task_id,
        coverage_id=unit["coverage_id"],
        status="candidate",
        owner="hunter",
        reviewed_paths=["src/http/a.c"],
        local_checks=[{"agent_id": "hunter", "reviewed_paths": ["src/http/a.c"]}],
        result_fingerprints=[finding["fingerprint"]],
        unresolved=[],
    )
    with pytest.raises(ValueError, match="does not match"):
        link_finding_to_coverage(
            task_id=task_id,
            coverage_id=unit["coverage_id"],
            finding_id=finding["finding_id"],
            fingerprint="fp/demo/wrong1",
        )
