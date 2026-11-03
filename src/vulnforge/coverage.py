from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import quote

import jsonschema

from vulnforge.tasks import TASK_ID_RE

STATUS_VALUES = {
    "planned",
    "not_applicable",
    "out_of_scope",
    "in_progress",
    "covered",
    "candidate",
    "blocked",
    "deferred",
}

TERMINAL_EMPTY_STATUSES = {"planned", "in_progress", "covered"}


def schema_path() -> Path:
    return Path(__file__).resolve().parents[2] / "schemas" / "coverage.schema.json"


def canonical_ref(value: str) -> str:
    """Encode one stable source-derived reference for use in a coverage ID."""
    text = str(value)
    if not text or len(text) > 300:
        raise ValueError("Canonical reference must contain 1-300 characters")
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in text):
        raise ValueError("Canonical reference contains control characters")
    return quote(text, safe="-._~")


def coverage_id_from_refs(refs: dict[str, str]) -> str:
    """Build a deterministic coverage ID from required canonical references."""
    required = ["surface", "boundary", "subsystem", "attack_class"]
    missing = [name for name in required if not str(refs.get(name, ""))]
    if missing:
        raise ValueError(f"Missing canonical references: {', '.join(missing)}")
    parts = [canonical_ref(str(refs[name])) for name in required]
    lifecycle = str(refs.get("lifecycle", ""))
    if lifecycle:
        parts.append(canonical_ref(lifecycle))
    return "::".join(parts)


def validate_coverage_records(records: list[dict[str, Any]], schema_file: str | Path | None = None) -> None:
    if not isinstance(records, list):
        raise TypeError("Coverage ledger must be a JSON array")
    schema = json.loads(Path(schema_file or schema_path()).read_text(encoding="utf-8"))
    try:
        jsonschema.Draft202012Validator(schema).validate(records)
    except jsonschema.ValidationError as exc:
        raise ValueError(f"Coverage schema validation failed: {exc.message}") from exc

    seen: set[str] = set()
    for index, record in enumerate(records):
        refs = dict(record.get("canonical_refs", {}))
        expected_id = coverage_id_from_refs(refs)
        coverage_id = str(record.get("coverage_id", ""))
        if coverage_id != expected_id:
            raise ValueError(
                f"coverage_id mismatch at record {index}: expected {expected_id!r}, got {coverage_id!r}"
            )
        if coverage_id in seen:
            raise ValueError(f"Duplicate coverage_id: {coverage_id}")
        seen.add(coverage_id)
        _validate_state(record, index)

        checks = record.get("local_checks", [])
        check_paths: set[str] = set()
        for check in checks:
            check_paths.update(check.get("reviewed_paths", []))
        if set(record.get("reviewed_paths", [])) != check_paths:
            raise ValueError(
                f"reviewed_paths must equal the union of local_checks paths: {coverage_id}"
            )


def _validate_state(record: dict[str, Any], index: int) -> None:
    status = str(record.get("status", ""))
    if status not in STATUS_VALUES:
        raise ValueError(f"Invalid coverage status at record {index}: {status}")

    owner = record.get("owner")
    reviewed = record.get("reviewed_paths", [])
    checks = record.get("local_checks", [])
    fingerprints = record.get("result_fingerprints", [])
    unresolved = record.get("unresolved", [])

    def require(condition: bool, message: str) -> None:
        if not condition:
            raise ValueError(f"Invalid coverage state at record {index}: {message}")

    if status in TERMINAL_EMPTY_STATUSES:
        if status == "planned":
            require(owner is None and not reviewed and not checks and not fingerprints and not unresolved,
                    "planned units must have no owner or evidence")
        elif status == "in_progress":
            require(isinstance(owner, str) and not reviewed and not checks and not fingerprints and not unresolved,
                    "in_progress units must have only an owner")
        else:
            require(isinstance(owner, str) and reviewed and checks and not fingerprints and not unresolved,
                    "covered units require owner and review evidence without fingerprints")
    elif status in {"not_applicable", "out_of_scope", "deferred"}:
        require(owner is None and not reviewed and not checks and not fingerprints and unresolved,
                f"{status} units require an unresolved reason and no evidence")
    elif status == "blocked":
        require(
            isinstance(owner, str) and reviewed and checks and not fingerprints and unresolved,
            "blocked units require owner, partial review evidence, and a blocker",
        )
    elif status == "candidate":
        require(
            isinstance(owner, str) and reviewed and checks and fingerprints,
            "candidate units require owner, review evidence, and fingerprints",
        )


def coverage_root(settings_path: str | Path) -> Path:
    from vulnforge.config import configured_root, load_yaml

    value = load_yaml(settings_path).get("coverage", {}).get("ledger_dir", "coverage")
    return configured_root("VULNFORGE_COVERAGE", str(value))


def ledger_file(root: Path, task_id: str) -> Path:
    if not TASK_ID_RE.fullmatch(task_id):
        raise ValueError("Invalid task ID")
    path = (root / f"{task_id}.json").resolve()
    if path.parent != root:
        raise ValueError("Invalid coverage ledger path")
    return path


def save_ledger(records: list[dict[str, Any]], task_id: str, settings_path: str | Path) -> list[dict[str, Any]]:
    validate_coverage_records(records)
    root = coverage_root(settings_path)
    root.mkdir(parents=True, exist_ok=True)
    path = ledger_file(root, task_id)
    path.write_text(json.dumps(records, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return records


def load_ledger(task_id: str, settings_path: str | Path) -> list[dict[str, Any]]:
    path = ledger_file(coverage_root(settings_path), task_id)
    if not path.is_file():
        raise FileNotFoundError(f"Coverage ledger not found: {task_id}")
    records = json.loads(path.read_text(encoding="utf-8"))
    validate_coverage_records(records)
    return records


def list_ledgers(settings_path: str | Path) -> list[dict[str, Any]]:
    root = coverage_root(settings_path)
    records = []
    if root.is_dir():
        for path in sorted(root.glob("task-*.json")):
            if path.parent != root:
                continue
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                validate_coverage_records(data)
            except (OSError, ValueError, json.JSONDecodeError):
                continue
            records.append({"task_id": path.stem, "units": len(data), **coverage_summary(data)})
    return records


def coverage_summary(records: list[dict[str, Any]]) -> dict[str, int]:
    summary = {status: 0 for status in sorted(STATUS_VALUES)}
    for record in records:
        status = str(record.get("status", ""))
        if status in summary:
            summary[status] += 1
    return {"total": len(records), **summary}
