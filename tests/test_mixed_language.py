from pathlib import Path

import pytest

from vulnforge.mcp_servers.source_server import detect_languages, get_allowed_extensions


@pytest.fixture()
def mixed_project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    src = tmp_path / "mixed"
    src.mkdir()
    (src / "main.go").write_text("package main\n")
    (src / "lib.rs").write_text("fn main() {}\n")
    (src / "app.py").write_text("print('hello')\n")
    (src / "core.c").write_text("int main(void) { return 0; }\n")
    cfg = tmp_path / "projects.yaml"
    cfg.write_text(f"projects:\n  mixed:\n    path: {src}\n    language: mixed\n")
    monkeypatch.setenv("VULNFORGE_TEST_PROJECTS", str(cfg))
    monkeypatch.chdir(tmp_path)
    return src


def test_detect_languages(mixed_project):
    langs = detect_languages(mixed_project)
    assert "go" in langs
    assert "rust" in langs
    assert "python" in langs
    assert "c" in langs


def test_mixed_extensions(mixed_project):
    exts = get_allowed_extensions("mixed")
    assert ".go" in exts
    assert ".rs" in exts
    assert ".py" in exts
    assert ".c" in exts


def test_detect_languages_empty(tmp_path: Path):
    empty = tmp_path / "empty"
    empty.mkdir()
    assert detect_languages(empty) == []
