from pathlib import Path

import pytest

from vulnforge.mcp_servers.task_server import (
    audit_status,
    create_task,
    import_scan_results,
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
    projects = tmp_path / "projects.yaml"
    source = tmp_path / "source"
    source.mkdir()
    projects.write_text(f"projects:\n  demo:\n    path: {source}\n")
    monkeypatch.setattr("vulnforge.mcp_servers.task_server.PROJECTS_CONFIG", projects)
    monkeypatch.setattr("vulnforge.mcp_servers.static_server.PROJECTS_CONFIG", projects)
    monkeypatch.setenv("VULNFORGE_PROJECTS", str(projects))
    task = create_task(project="demo", title="Agent smoke test")
    return settings, task["task_id"]


def test_audit_status_empty(env):
    _settings, task_id = env
    status = audit_status(task_id)
    assert status["status"] == "created"
    assert status["total_findings"] == 0
    assert status["coverage_summary"]["total"] == 0
    assert status["orphan_candidate_units"] == 0


def test_import_scan_results_creates_hypotheses(env):
    _settings, task_id = env
    scan_output = {
        "findings": [
            {
                "check_id": "c-memory.unbounded-copy",
                "path": "src/a.c",
                "start": {"line": 10},
                "end": {"line": 15},
                "extra": {"message": "Unbounded copy"},
            },
            {
                "check_id": "c-memory.unbounded-copy",
                "path": "src/a.c",
                "start": {"line": 55},
                "end": {"line": 60},
                "extra": {"message": "Unbounded copy"},
            },
            {
                "check_id": "c-resource.fd-leak",
                "path": "src/io.c",
                "start": {"line": 88},
                "end": {"line": 90},
                "extra": {"message": "FD leak"},
            },
        ]
    }
    result = import_scan_results(project="demo", task_id=task_id, scan_output=scan_output)
    assert result["groups"] == 2
    assert len(result["created_findings"]) == 2
    assert result["existing_findings"] == []
    assert len(result["created_coverage_units"]) == 2

    status = audit_status(task_id)
    assert status["total_findings"] == 2
    assert status["finding_status_counts"]["hypothesis"] == 2
    assert status["coverage_summary"]["total"] == 2
    assert status["coverage_summary"]["planned"] == 2

    # re-import: all dedup
    again = import_scan_results(project="demo", task_id=task_id, scan_output=scan_output)
    assert again["created_findings"] == []
    assert len(again["existing_findings"]) == 2
    assert again["created_coverage_units"] == []
    assert len(again["existing_coverage_units"]) == 2


def test_import_scan_results_rejects_oversized(env):
    _settings, task_id = env
    scan_output = {"findings": [{"check_id": f"rule{i}", "path": "a.c", "start": {"line": 1}} for i in range(501)]}
    with pytest.raises(ValueError, match="max_scan_import"):
        import_scan_results(project="demo", task_id=task_id, scan_output=scan_output)


def test_audit_status_orphan_detection(env):
    _settings, task_id = env
    scan_output = {"findings": [
        {"check_id": "c-memory.test", "path": "src/a.c", "start": {"line": 1}, "end": {"line": 2}},
    ]}
    result = import_scan_results(project="demo", task_id=task_id, scan_output=scan_output)
    fp = result["fingerprints"][0]
    unit_id = result["created_coverage_units"][0]

    # Promote unit to candidate with a ghost fingerprint alongside the real one
    update_coverage_unit(
        task_id=task_id,
        coverage_id=unit_id,
        status="candidate",
        owner="hunter",
        reviewed_paths=["src/a.c"],
        local_checks=[{"agent_id": "hunter", "reviewed_paths": ["src/a.c"]}],
        result_fingerprints=[fp, "fp/demo/ghost"],
        unresolved=[],
    )
    status = audit_status(task_id)
    assert status["orphan_candidate_units"] == 1


def test_revision_mismatch_blocks_scan(env, monkeypatch):
    """If a project pins a revision and HEAD differs, semgrep_scan raises."""
    import subprocess

    from vulnforge.mcp_servers.static_server import semgrep_scan
    _settings, _task_id = env
    tmp_path = env[0].parent
    source = tmp_path / "source"
    # make it a git repo and commit
    subprocess.run(["git", "init", "-q", str(source)], check=True)
    subprocess.run(["git", "-C", str(source), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(source), "config", "user.email", "t@t"], check=True)
    subprocess.run(["git", "-C", str(source), "config", "user.name", "t"], check=True)
    subprocess.run(["git", "-C", str(source), "commit", "-q", "--allow-empty", "-m", "init"], check=True)
    head = subprocess.run(
        ["git", "-C", str(source), "rev-parse", "HEAD"], capture_output=True, text=True, check=True
    ).stdout.strip()

    # pin a different revision
    projects = tmp_path / "projects.yaml"
    projects.write_text(f"projects:\n  demo:\n    path: {source}\n    revision: {'0' * 40}\n")

    with pytest.raises(ValueError, match="revision mismatch"):
        semgrep_scan(project="demo", rules_file="rules/c-memory.yml")

    # now pin the correct revision — scan should proceed past revision check
    # (it will fail later because semgrep isn't installed, but NOT with revision mismatch)
    projects.write_text(f"projects:\n  demo:\n    path: {source}\n    revision: {head}\n")
    try:
        semgrep_scan(project="demo", rules_file="rules/c-memory.yml")
    except (RuntimeError, FileNotFoundError) as exc:
        assert "revision" not in str(exc).lower()
