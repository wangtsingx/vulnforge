from __future__ import annotations

import time
from pathlib import Path

import pytest

from vulnforge.mcp_servers.static_server import (
    semgrep_scan_async,
    semgrep_scan_files,
    semgrep_scan_status,
)


@pytest.fixture()
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("VULNFORGE_HOME", str(tmp_path))
    monkeypatch.setenv("VULNFORGE_SCANS", str(tmp_path / "scans"))
    projects = tmp_path / "projects.yaml"
    source = tmp_path / "source"
    source.mkdir()
    (source / "main.c").write_text('#include <string.h>\nvoid f(char *d, char *s) { strcpy(d, s); }\n')
    projects.write_text(f"projects:\n  demo:\n    path: {source}\n    language: c\n")
    settings = tmp_path / "settings.yaml"
    settings.write_text("static:\n  semgrep_binary: semgrep\n  timeout_seconds: 30\n")
    monkeypatch.setattr("vulnforge.mcp_servers.static_server.PROJECTS_CONFIG", projects)
    monkeypatch.setattr("vulnforge.mcp_servers.static_server.SETTINGS_CONFIG", settings)
    monkeypatch.setenv("VULNFORGE_PROJECTS", str(projects))
    monkeypatch.setenv("VULNFORGE_SETTINGS", str(settings))
    return str(source)


def test_semgrep_scan_files_validates_paths(env):
    with pytest.raises(ValueError, match="non-empty"):
        semgrep_scan_files(project="demo", files=[])
    with pytest.raises(ValueError, match="not found"):
        semgrep_scan_files(project="demo", files=["../etc/passwd"])


def test_semgrep_scan_files_runs(env):
    result = semgrep_scan_files(project="demo", files=["main.c"])
    assert result["files_scanned"] == 1
    assert isinstance(result["findings"], list)


def test_semgrep_scan_async_returns_scan_id(env):
    result = semgrep_scan_async(project="demo")
    assert result["scan_id"].startswith("scan-")
    assert result["status"] == "queued"
    # Wait briefly for background thread
    time.sleep(3)
    status = semgrep_scan_status(result["scan_id"])
    assert status["status"] in ("finished", "failed", "running")
    assert status["finding_count"] >= 0


def test_semgrep_scan_status_not_found():
    with pytest.raises(FileNotFoundError):
        semgrep_scan_status("scan-nonexistent")


def test_semgrep_scan_list(env):
    result = semgrep_scan_async(project="demo")
    time.sleep(2)
    from vulnforge.mcp_servers.static_server import semgrep_scan_list
    scans = semgrep_scan_list(project="demo")
    assert len(scans["scans"]) >= 1
    assert scans["scans"][0]["scan_id"] == result["scan_id"]
