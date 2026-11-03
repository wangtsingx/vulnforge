from pathlib import Path
import yaml


def load_yaml(path: str | Path) -> dict:
    p = Path(path).resolve()
    if not p.is_file():
        raise FileNotFoundError(p)
    data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError(f"Expected YAML mapping in {p}")
    return data


def project_root(project: str, config_path: str | Path | None = None) -> Path:
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
