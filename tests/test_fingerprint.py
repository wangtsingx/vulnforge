from pathlib import Path

import pytest

from vulnforge.findings import save_finding
from vulnforge.fingerprint import finding_fingerprint, normalize_finding_fingerprint


def test_fingerprint_is_stable_and_pattern_safe():
    a = finding_fingerprint("demo", "src/a.c", "CWE-120", "copy_input", "memcpy")
    b = finding_fingerprint("demo", "src/a.c", "CWE-120", "copy_input", "memcpy")
    assert a == b
    assert a.startswith("fp/demo/")


def test_derived_fingerprint_uses_location():
    finding = {
        "finding_id": "finding-x",
        "project_id": "demo",
        "status": "candidate",
        "title": "Overflow",
        "cwe": "CWE-120",
        "location": {"file": "src/a.c", "function": "parse"},
        "evidence": [],
    }
    assert normalize_finding_fingerprint(finding) == finding_fingerprint("demo", "src/a.c", "CWE-120", "parse")


@pytest.fixture()
def settings(tmp_path: Path) -> Path:
    p = tmp_path / "settings.yaml"
    p.write_text(f"report:\n  findings_dir: {tmp_path / 'findings'}\n")
    return p


def test_duplicate_fingerprint_rejected(settings: Path):
    def finding(finding_id: str):
        return {
            "finding_id": finding_id,
            "project_id": "demo",
            "status": "candidate",
            "title": "Same root cause",
            "cwe": "CWE-120",
            "location": {"file": "src/a.c", "function": "parse"},
            "evidence": [],
        }

    save_finding(finding("finding-one"), settings)
    with pytest.raises(ValueError, match="Duplicate"):
        save_finding(finding("finding-two"), settings)


def test_explicit_fingerprint_allows_update(settings: Path):
    record = {
        "finding_id": "finding-one",
        "project_id": "demo",
        "status": "candidate",
        "title": "Same root cause",
        "fingerprint": "fp/demo/custom",
        "location": {"file": "src/a.c"},
        "evidence": [],
    }
    save_finding(record, settings)
    confirmed_record = {
        **record,
        "status": "confirmed",
        "verification": {"reproducible": True, "human_reviewed": True},
    }
    updated = save_finding(confirmed_record, settings)
    assert updated["fingerprint"] == "fp/demo/custom"
