from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml


def load_yaml(path: str | Path) -> dict[str, Any]:
    p = Path(path).resolve()
    if not p.is_file():
        raise FileNotFoundError(p)
    data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise TypeError(f"Expected YAML mapping in {p}")
    return data


def project_root(project: str, config_path: str | Path | None = None) -> Path:
    if not project or "/" in project or project in {".", ".."}:
        raise ValueError("Invalid project ID")
    cfg_path = Path(config_path or "config/projects.yaml").resolve()
    cfg = load_yaml(cfg_path)
    projects = cfg.get("projects", {})
    if project not in projects:
        raise ValueError(f"Project is not registered: {project}")
    raw = projects[project].get("path")
    if not raw:
        raise ValueError(f"Project path missing for: {project}")
    root = Path(raw).expanduser().resolve(strict=True)
    if not root.is_dir():
        raise ValueError(f"Project path is not a directory: {root}")
    return root


def configured_root(env_name: str, default: str) -> Path:
    """Resolve a configured storage root, forcing it beneath VULNFORGE_HOME."""
    base = Path(os.getenv("VULNFORGE_HOME", ".")).resolve()
    root = Path(os.getenv(env_name, base / default)).expanduser()
    if not root.is_absolute():
        root = base / root
    return root.resolve()


def override_config(path: Path) -> Path:
    """Allow tests to inject an isolated config path through the environment."""
    override = os.getenv("VULNFORGE_TEST_PROJECTS")
    return Path(override).resolve() if override else path
