from pathlib import Path

import pytest

from vulnforge.mcp_servers.fuzz_server import (
    build_target_command,
    fuzzing_root,
    make_limits,
    safe_subdir,
)


@pytest.fixture()
def fuzz_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("VULNFORGE_HOME", str(tmp_path))
    monkeypatch.setenv("VULNFORGE_FUZZING", str(tmp_path / "fuzzing"))
    return tmp_path


def test_fuzzing_root(fuzz_env):
    root = fuzzing_root()
    assert root.name == "fuzzing"


def test_safe_subdir_valid(fuzz_env):
    base = fuzz_env / "fuzzing" / "demo" / "targets"
    base.mkdir(parents=True)
    path = safe_subdir(base, "http-parser")
    assert path.name == "http-parser"


def test_safe_subdir_rejects_traversal(fuzz_env):
    base = fuzz_env / "fuzzing" / "demo" / "targets"
    base.mkdir(parents=True)
    with pytest.raises(ValueError):
        safe_subdir(base, "../escape")


def test_safe_subdir_rejects_invalid_chars(fuzz_env):
    base = fuzz_env / "fuzzing" / "demo" / "targets"
    base.mkdir(parents=True)
    with pytest.raises(ValueError):
        safe_subdir(base, "a/b")


def test_build_target_command(fuzz_env):
    cfg = {"max_duration_seconds": 300, "max_memory_mb": 1024}
    project_cfg = {"fuzz_build_command": "make fuzz"}
    target_cfg = {
        "engine": "libfuzzer",
        "sanitizers": ["address"],
        "harness_path": "./fuzz_parser",
    }
    corpus = fuzz_env / "corpus"
    artifacts = fuzz_env / "artifacts"
    command = build_target_command(project_cfg, target_cfg, corpus, artifacts, cfg)
    assert command[0] == "bash"
    assert "-max_total_time=300" in command[2]
    assert "-rss_limit_mb=1024" in command[2]


def test_build_target_command_rejects_shell_metachars(fuzz_env):
    cfg = {"max_duration_seconds": 300, "max_memory_mb": 1024}
    project_cfg = {"fuzz_build_command": "make fuzz; rm -rf /"}
    target_cfg = {"engine": "libfuzzer", "sanitizers": ["address"], "harness_path": "./fuzz"}
    with pytest.raises(ValueError):
        build_target_command(project_cfg, target_cfg, fuzz_env, fuzz_env, cfg)


def test_build_target_command_rejects_bad_engine(fuzz_env):
    cfg = {"max_duration_seconds": 300, "max_memory_mb": 1024}
    project_cfg = {"fuzz_build_command": "make fuzz"}
    target_cfg = {"engine": "custom", "sanitizers": ["address"], "harness_path": "./fuzz"}
    with pytest.raises(ValueError):
        build_target_command(project_cfg, target_cfg, fuzz_env, fuzz_env, cfg)


def test_make_limits(fuzz_env):

    limit_fn = make_limits({"max_memory_mb": 256, "max_cpu_seconds": 10, "max_file_mb": 64, "max_processes": 16})
    assert callable(limit_fn)
    # Do not call in the main test process: RLIMIT_NPROC is irreversible without privileges.
