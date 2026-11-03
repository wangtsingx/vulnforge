from pathlib import Path

import pytest

from vulnforge.mcp_servers.patch_server import patch_change_list, patch_history, patch_show


def git_repo(path: Path):
    import subprocess

    path.mkdir()
    subprocess.run(["git", "init", "-q", str(path)], check=True)
    subprocess.run(["git", "-C", str(path), "config", "user.email", "test@example.com"], check=True)
    subprocess.run(["git", "-C", str(path), "config", "user.name", "Test"], check=True)
    (path / "a.c").write_text("int main(void) { return 0; }\n")
    subprocess.run(["git", "-C", str(path), "add", "a.c"], check=True)
    subprocess.run(["git", "-C", str(path), "commit", "-q", "-m", "initial"], check=True)
    out = subprocess.check_output(["git", "-C", str(path), "rev-parse", "HEAD"], text=True).strip()
    return out


@pytest.fixture()
def registered(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    src = tmp_path / "repo"
    commit = git_repo(src)
    cfg = tmp_path / "projects.yaml"
    cfg.write_text(f"projects:\n  demo:\n    path: {src}\n")
    monkeypatch.setenv("VULNFORGE_TEST_PROJECTS", str(cfg))
    return commit, cfg


def test_patch_tools(registered):
    commit, _cfg = registered
    shown = patch_show("demo", commit)
    assert "a.c" in shown["stdout"]
    files = patch_change_list("demo", commit)
    assert files["files"] == ["A\ta.c"]
    history = patch_history("demo", "a.c", 10)
    assert history["commits"][0]["commit"] == commit


def test_patch_show_rejects_branch_name(registered):
    _, _cfg = registered
    with pytest.raises(ValueError):
        patch_show("demo", "main")
