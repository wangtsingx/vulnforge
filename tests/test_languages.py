from pathlib import Path

import pytest

from vulnforge.mcp_servers.source_server import get_allowed_extensions, get_language, get_rules_file


@pytest.fixture()
def multi_lang_project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    src = tmp_path / "goproj"
    src.mkdir()
    (src / "main.go").write_text("package main\n\nfunc main() {}\n")
    cfg = tmp_path / "projects.yaml"
    cfg.write_text(f"projects:\n  goproj:\n    path: {src}\n    language: go\n")
    monkeypatch.setenv("VULNFORGE_TEST_PROJECTS", str(cfg))
    monkeypatch.chdir(tmp_path)
    return src


def test_get_language(multi_lang_project):
    assert get_language("goproj") == "go"


def test_get_language_default_c(multi_lang_project):
    assert get_language("nonexistent") == "c"


def test_get_allowed_extensions_go(multi_lang_project):
    exts = get_allowed_extensions("goproj")
    assert ".go" in exts
    assert ".c" not in exts


def test_get_rules_file_go(multi_lang_project):
    rules = get_rules_file("goproj")
    assert "go-security" in rules


def test_get_rules_file_default(multi_lang_project):
    rules = get_rules_file("nonexistent")
    assert "c-memory" in rules
