from pathlib import Path

import pytest

from vulnforge.coverage import (
    canonical_ref,
    coverage_id_from_refs,
    coverage_summary,
    ledger_file,
    load_ledger,
    save_ledger,
    validate_coverage_records,
)


@pytest.fixture()
def settings(tmp_path: Path) -> Path:
    p = tmp_path / "settings.yaml"
    p.write_text(f"coverage:\n  ledger_dir: {tmp_path / 'coverage'}\n")
    return p


def unit(status: str = "planned", **overrides) -> dict:
    refs = {
        "surface": "src/router.c#http_handler",
        "boundary": "src/auth.c#check_auth",
        "subsystem": "src/http",
        "attack_class": "ATTACK-CLASSES.md#Access control",
    }
    value = {
        "coverage_id": coverage_id_from_refs(refs),
        "canonical_refs": refs,
        "surface": "HTTP handler",
        "boundary": "authentication",
        "subsystem": "http",
        "attack_class": "Access control",
        "starting_paths": ["src/http"],
        "status": status,
        "owner": None,
        "reviewed_paths": [],
        "local_checks": [],
        "result_fingerprints": [],
        "unresolved": [],
    }
    value.update(overrides)
    return value


def test_canonical_ref_escapes_separator():
    assert canonical_ref("a/b:c") == "a%2Fb%3Ac"


def test_coverage_id_is_deterministic_and_percent_is_distinct():
    first = coverage_id_from_refs({"surface": "a/b", "boundary": "c", "subsystem": "d", "attack_class": "e"})
    second = coverage_id_from_refs({"surface": "a%2Fb", "boundary": "c", "subsystem": "d", "attack_class": "e"})
    assert first == "a%2Fb::c::d::e"
    assert second == "a%252Fb::c::d::e"
    assert first != second


def test_save_load_and_summary(settings: Path):
    records = [unit()]
    save_ledger(records, "task-abc", settings)
    loaded = load_ledger("task-abc", settings)
    assert loaded == records
    assert coverage_summary(loaded)["planned"] == 1
    assert ledger_file(Path(settings.parent) / "coverage", "task-abc").is_file()


def test_rejects_duplicate_and_wrong_id(settings: Path):
    record = unit()
    duplicate = [record, dict(record)]
    with pytest.raises(ValueError, match="Duplicate"):
        validate_coverage_records(duplicate)
    wrong = unit(coverage_id="wrong")
    with pytest.raises(ValueError, match="coverage_id mismatch"):
        validate_coverage_records([wrong])


def test_state_contract(settings: Path):
    with pytest.raises(ValueError, match="planned"):
        validate_coverage_records([unit(owner="hunter")])
    with pytest.raises(ValueError, match="covered"):
        validate_coverage_records([unit("covered", owner="hunter")])
    with pytest.raises(ValueError, match="candidate"):
        validate_coverage_records([unit("candidate", owner="hunter", reviewed_paths=["src"])])


def test_reviewed_paths_must_match_checks(settings: Path):
    record = unit(
        "covered",
        owner="hunter",
        reviewed_paths=["src/http"],
        local_checks=[{"agent_id": "hunter", "reviewed_paths": ["src/other"]}],
    )
    with pytest.raises(ValueError, match="reviewed_paths"):
        validate_coverage_records([record])


def test_invalid_task_path_rejected(settings: Path):
    with pytest.raises(ValueError):
        ledger_file(Path("/tmp"), "../escape")
