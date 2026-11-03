from pathlib import Path

import pytest
import yaml

from vulnforge.config import project_root


def test_project_root_rejects_unregistered_project(tmp_path: Path):
    config = tmp_path / "projects.yaml"
    config.write_text(yaml.safe_dump({"projects": {}}))
    with pytest.raises(ValueError):
        project_root("nginx", config)


def test_project_root_resolves_registered_project(tmp_path: Path):
    src = tmp_path / "nginx"
    src.mkdir()
    config = tmp_path / "projects.yaml"
    config.write_text(yaml.safe_dump({"projects": {"nginx": {"path": str(src)}}}))
    assert project_root("nginx", config) == src.resolve()
