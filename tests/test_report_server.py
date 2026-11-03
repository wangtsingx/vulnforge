from pathlib import Path

import pytest

from vulnforge.mcp_servers import report_server


@pytest.fixture()
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("VULNFORGE_HOME", str(tmp_path))
    monkeypatch.setenv("VULNFORGE_FINDINGS", str(tmp_path / "findings"))
    monkeypatch.setenv("VULNFORGE_REPORTS", str(tmp_path / "reports"))
    settings = tmp_path / "settings.yaml"
    settings.write_text(
        f"report:\n  findings_dir: {tmp_path / 'findings'}\n  reports_dir: {tmp_path / 'reports'}\n"
    )
    monkeypatch.setattr(report_server, "SETTINGS_CONFIG", settings)
    project = tmp_path / "source"
    project.mkdir()
    import subprocess
    subprocess.run(["git", "init", "-q", str(project)], check=True)
    monkeypatch.setattr(report_server, "PROJECTS_CONFIG", tmp_path / "projects.yaml")
    (tmp_path / "projects.yaml").write_text(f"projects:\n  demo:\n    path: {project}\n")
    return tmp_path, settings, project


def make(base: dict, finding_id: str, status: str, **extra) -> dict:
    record = {
        **base,
        "finding_id": finding_id,
        "status": status,
        "location": {"file": "src/a.c", "line_start": 1, "line_end": 2},
        "evidence": [{"kind": "source", "path": "src/a.c", "line": 1}],
        **extra,
    }
    return record


def test_generate_report_tri_state(env):
    _tmp_path, settings, _ = env
    from vulnforge.findings import save_finding

    def make_unique(finding_id: str, status: str, **extra):
        record = {
            "finding_id": finding_id,
            "project_id": "demo",
            "title": finding_id.replace("-", " "),
            "status": status,
            "location": {"file": f"src/{finding_id}.c", "line_start": 1, "line_end": 2},
            "evidence": [{"kind": "source", "path": f"src/{finding_id}.c", "line": 1}],
            **extra,
        }
        return record

    confirmed = make_unique("finding-a", "confirmed", verification={"reproducible": True, "human_reviewed": True})
    blocked = make_unique(
        "finding-b", "needs_validation", blocked_reason="Proxy behavior is not visible in source"
    )
    candidate = make_unique("finding-c", "candidate")
    rejected = make_unique("finding-d", "rejected")
    for record in [confirmed, blocked, candidate, rejected]:
        save_finding(record, settings)

    result = report_server.generate_report("demo")
    report = Path(result["report"]).read_text(encoding="utf-8")
    assert result["confirmed"] == 1
    assert result["needs_validation"] == 1
    assert result["candidates"] == 1
    assert result["rejected"] == 1
    assert "## Confirmed findings" in report
    assert "## Needs validation" in report
    assert "## Candidates and hypotheses" in report
    assert "## Rejected records" in report
    assert "must not be treated as confirmed vulnerabilities" in report
    assert "Proxy behavior is not visible in source" in report
