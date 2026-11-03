from __future__ import annotations

from pathlib import Path

from vulnforge.config import configured_root, load_yaml


def findings_root(settings_path: str | Path) -> Path:
    value = load_yaml(settings_path).get("report", {}).get("findings_dir", "findings")
    return configured_root("VULNFORGE_FINDINGS", str(value))


def reports_root(settings_path: str | Path) -> Path:
    value = load_yaml(settings_path).get("report", {}).get("reports_dir", "reports")
    return configured_root("VULNFORGE_REPORTS", str(value))
