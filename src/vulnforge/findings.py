from __future__ import annotations

import json
import re
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import jsonschema

from vulnforge.config import load_yaml
from vulnforge.fingerprint import FINGERPRINT_RE, normalize_finding_fingerprint
from vulnforge.paths import findings_root

FINDING_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
PROJECT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")


def schema_path() -> Path:
    return Path(__file__).resolve().parents[2] / "schemas" / "finding.schema.json"


def validate_finding(finding: dict[str, Any], schema_file: str | Path | None = None) -> None:
    path = Path(schema_file or schema_path())
    schema = json.loads(path.read_text(encoding="utf-8"))
    try:
        jsonschema.Draft202012Validator(schema).validate(finding)
    except jsonschema.ValidationError as exc:
        raise ValueError(f"Finding schema validation failed: {exc.message}") from exc
    if not FINDING_ID_RE.fullmatch(str(finding.get("finding_id", ""))):
        raise ValueError("Invalid finding_id")
    if not PROJECT_ID_RE.fullmatch(str(finding.get("project_id", ""))):
        raise ValueError("Invalid project_id")
    fingerprint = normalize_finding_fingerprint(finding)
    if not FINGERPRINT_RE.fullmatch(fingerprint):
        raise ValueError("Invalid fingerprint")
    if str(finding.get("status", "")) == "needs_validation":
        blocked = str(finding.get("blocked_reason") or "").strip()
        if len(blocked) < 10:
            raise ValueError("needs_validation requires blocked_reason (10-2000 chars)")
        if str(finding.get("severity", "unknown")) != "unknown":
            raise ValueError("needs_validation must not have severity")


def finding_file(root: Path, finding_id: str) -> Path:
    return (root / f"{finding_id}.json").resolve()


def find_duplicate_fingerprint(
    fingerprint: str,
    finding_id: str,
    settings_path: str | Path,
    root: Path | None = None,
) -> str | None:
    """Return the finding_id of a different record using the same fingerprint."""
    root = root or findings_root(settings_path)
    for path in root.glob("*.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        try:
            other = normalize_finding_fingerprint(data)
        except ValueError:
            continue
        if other == fingerprint and data.get("finding_id") != finding_id:
            return str(data.get("finding_id"))
    return None


def save_finding(finding: dict[str, Any], settings_path: str | Path) -> dict[str, Any]:
    validate_finding(finding)
    settings = load_yaml(settings_path).get("report", {})
    root = findings_root(settings_path)
    limit = max(1, int(settings.get("max_findings", 1000)))
    root.mkdir(parents=True, exist_ok=True)
    existing = list(root.glob("*.json"))
    path = finding_file(root, str(finding["finding_id"]))
    if path.parent != root or not path.is_relative_to(root):
        raise ValueError("Invalid finding path")
    if not path.exists() and len(existing) >= limit:
        raise ValueError(f"Finding store is full ({limit})")
    fingerprint = normalize_finding_fingerprint(finding)
    finding = dict(finding)
    finding["fingerprint"] = fingerprint
    duplicate = find_duplicate_fingerprint(fingerprint, str(finding["finding_id"]), settings_path, root)
    if duplicate:
        raise ValueError(f"Duplicate finding fingerprint already exists: {duplicate}")
    if str(finding.get("status", "")) == "confirmed":
        verification = finding.get("verification") or {}
        if not verification.get("reproducible") or not verification.get("human_reviewed"):
            raise ValueError("confirmed requires reproducible and human_reviewed evidence")
    record = dict(finding)
    now = datetime.now(UTC).isoformat()
    if path.exists():
        old = json.loads(path.read_text(encoding="utf-8"))
        record["created_at"] = old.get("created_at", now)
    else:
        record["created_at"] = now
    record["updated_at"] = now
    path.write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return record


def load_finding(finding_id: str, settings_path: str | Path) -> dict[str, Any]:
    if not FINDING_ID_RE.fullmatch(finding_id):
        raise ValueError("Invalid finding_id")
    path = finding_file(findings_root(settings_path), finding_id)
    if not path.is_file():
        raise FileNotFoundError(f"Finding not found: {finding_id}")
    data = json.loads(path.read_text(encoding="utf-8"))
    validate_finding(data)
    return data


def list_findings(settings_path: str | Path) -> list[dict[str, Any]]:
    root = findings_root(settings_path)
    records: list[dict[str, Any]] = []
    for path in sorted(root.glob("*.json")):
        if path.parent != root:
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            validate_finding(data)
        except (OSError, ValueError, json.JSONDecodeError):
            continue
        records.append(
            {
                "finding_id": data["finding_id"],
                "project_id": data["project_id"],
                "status": data["status"],
                "title": data["title"],
                "severity": data.get("severity", "unknown"),
                "fingerprint": data.get("fingerprint"),
                "coverage_id": data.get("coverage_id"),
                "blocked_reason": data.get("blocked_reason"),
                "updated_at": data.get("updated_at"),
            }
        )
    return records


def new_finding_id() -> str:
    return f"finding-{uuid.uuid4().hex[:12]}"
