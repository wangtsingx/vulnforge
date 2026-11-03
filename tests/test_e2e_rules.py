from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
RULES = REPO_ROOT / "rules" / "c-memory.yml"
TARGET = REPO_ROOT / "examples" / "mini-httpd" / "src"


@pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep is not installed")
def test_mini_httpd_seed_rules_and_import_pipeline(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    proc = subprocess.run(
        [
            "semgrep", "scan", "--config", str(RULES), "--json", "--quiet",
            "--metrics=off", str(TARGET),
        ],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
        cwd=REPO_ROOT,
    )
    assert proc.returncode == 0, proc.stderr
    results = json.loads(proc.stdout)["results"]
    def lines_for(suffix: str) -> set[int]:
        return {item["start"]["line"] for item in results if item["check_id"].endswith(suffix)}

    assert lines_for("suspicious-unbounded-copy") == {25, 32, 38, 56}
    assert lines_for("integer-overflow-before-bound") == {53}
    assert lines_for("file-descriptor-leak") == {60}
    assert all(item["path"].endswith("handler.c") for item in results)
    # The deliberately safe format-string sink must not be reported.
    assert all(item["start"]["line"] != 73 for item in results)

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
    projects = tmp_path / "projects.yaml"
    projects.write_text(f"projects:\n  mini-httpd:\n    path: {TARGET}\n")
    monkeypatch.setattr("vulnforge.mcp_servers.task_server.SETTINGS_CONFIG", settings)
    monkeypatch.setattr("vulnforge.mcp_servers.task_server.PROJECTS_CONFIG", projects)
    monkeypatch.setattr("vulnforge.mcp_servers.report_server.SETTINGS_CONFIG", settings)
    monkeypatch.setattr("vulnforge.mcp_servers.report_server.PROJECTS_CONFIG", projects)

    from vulnforge.mcp_servers.task_server import audit_status, create_task, import_scan_results

    task = create_task(project="mini-httpd", title="Golden E2E")
    imported = import_scan_results(
        project="mini-httpd", task_id=task["task_id"], scan_output={"findings": results}
    )
    assert len(imported["created_findings"]) == 3
    assert len(imported["created_coverage_units"]) == 3
    titles = []
    for finding_id in imported["created_findings"]:
        from vulnforge.mcp_servers.report_server import get_finding

        titles.append(get_finding(finding_id)["title"])
    assert sum("file-descriptor-leak" in title for title in titles) == 1
    assert sum("integer-overflow-before-bound" in title for title in titles) == 1
    assert sum("suspicious-unbounded-copy" in title for title in titles) == 1
    status = audit_status(task["task_id"])
    assert status["coverage_summary"]["planned"] == 3
    assert status["finding_status_counts"]["hypothesis"] == 3
