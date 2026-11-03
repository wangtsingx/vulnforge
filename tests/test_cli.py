from pathlib import Path

import pytest
import yaml

from vulnforge.cli import cmd_add, cmd_list, cmd_remove, cmd_update


@pytest.fixture()
def project_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    src = tmp_path / "repo"
    src.mkdir()
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("vulnforge.cli.PROJECTS_FILE", config_dir / "projects.yaml")
    return src


class Args:
    def __init__(self, **kwargs):
        self.project = kwargs.get("project", "demo")
        self.path = str(kwargs.get("path", ""))
        self.description = kwargs.get("description", "")
        self.revision = kwargs.get("revision", "")
        self.build_command = kwargs.get("build_command")
        self.language = kwargs.get("language")


def test_add_and_list(project_dir):
    cmd_add(Args(path=project_dir, description="test project"))
    data = yaml.safe_load(Path("config/projects.yaml").read_text())
    assert data["projects"]["demo"]["path"] == str(project_dir)
    cmd_list(Args())


def test_add_duplicate(project_dir, capsys):
    cmd_add(Args(path=project_dir))
    with pytest.raises(SystemExit):
        cmd_add(Args(path=project_dir))


def test_add_invalid_path(project_dir):
    with pytest.raises(SystemExit):
        cmd_add(Args(path="/nonexistent"))


def test_remove(project_dir):
    cmd_add(Args(path=project_dir))
    cmd_remove(Args())
    data = yaml.safe_load(Path("config/projects.yaml").read_text())
    assert "demo" not in data.get("projects", {})


def test_remove_nonexistent(project_dir):
    with pytest.raises(SystemExit):
        cmd_remove(Args())


def test_update(project_dir):
    cmd_add(Args(path=project_dir))
    new_src = project_dir / "sub"
    new_src.mkdir()
    cmd_update(Args(path=new_src, revision="abc123"))
    data = yaml.safe_load(Path("config/projects.yaml").read_text())
    assert data["projects"]["demo"]["path"] == str(new_src)
    assert data["projects"]["demo"]["revision"] == "abc123"
