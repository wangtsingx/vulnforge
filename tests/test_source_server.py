from pathlib import Path

import pytest

from vulnforge.mcp_servers.source_server import function_context, function_search, list_functions


@pytest.fixture()
def c_project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    src = tmp_path / "demo"
    src.mkdir()
    (src / "main.c").write_text(
        "#include <stdio.h>\n"
        "\n"
        "int helper(int x) {\n"
        "    return x * 2;\n"
        "}\n"
        "\n"
        "int main(int argc, char **argv) {\n"
        "    return helper(argc);\n"
        "}\n"
    )
    cfg = tmp_path / "projects.yaml"
    cfg.write_text(f"projects:\n  demo:\n    path: {src}\n")
    monkeypatch.setenv("VULNFORGE_TEST_PROJECTS", str(cfg))
    return src


def test_function_search(c_project):
    result = function_search("demo", "helper")
    assert len(result["results"]) == 1
    assert result["results"][0]["function"] == "helper"
    assert result["results"][0]["line"] == 3


def test_list_functions(c_project):
    result = list_functions("demo", "main.c")
    names = [f["function"] for f in result["functions"]]
    assert "helper" in names
    assert "main" in names


def test_function_context(c_project):
    result = function_context("demo", "main.c", 3, 10)
    assert result["start_line"] <= 3 <= result["end_line"]
    assert "helper" in result["content"]
