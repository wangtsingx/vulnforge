from pathlib import Path

import pytest

from vulnforge.findings import list_findings, load_finding, save_finding


@pytest.fixture()
def settings(tmp_path: Path) -> Path:
    p = tmp_path / "settings.yaml"
    p.write_text(f"report:\n  findings_dir: {tmp_path / 'findings'}\n")
    return p


def valid_finding() -> dict:
    return {
        "finding_id": "finding-test123",
        "project_id": "nginx",
        "status": "hypothesis",
        "title": "Unbounded copy candidate",
        "evidence": [{"kind": "source", "path": "src/a.c", "line": 10}],
    }


def test_save_and_load_finding(settings: Path):
    record = save_finding(valid_finding(), settings)
    assert record["finding_id"] == "finding-test123"
    loaded = load_finding("finding-test123", settings)
    assert loaded["title"] == "Unbounded copy candidate"


def test_save_finding_rejects_path_escape(settings: Path):
    bad = valid_finding()
    bad["finding_id"] = "../escape"
    with pytest.raises(ValueError):
        save_finding(bad, settings)


def test_list_findings(settings: Path):
    save_finding(valid_finding(), settings)
    assert list_findings(settings)[0]["project_id"] == "nginx"
