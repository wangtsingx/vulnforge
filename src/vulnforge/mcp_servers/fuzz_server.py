from __future__ import annotations

import hashlib
import json
import os
import re
import signal
import subprocess
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from vulnforge.config import configured_root, load_yaml, override_config, project_root

mcp = FastMCP("vulnforge-fuzz")
BASE = Path(os.getenv("VULNFORGE_HOME", ".")).resolve()
PROJECTS_CONFIG = Path(os.getenv("VULNFORGE_PROJECTS", BASE / "config/projects.yaml"))
SETTINGS_CONFIG = Path(os.getenv("VULNFORGE_SETTINGS", BASE / "config/settings.yaml"))

PROJECT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")
TARGET_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
JOB_ID_RE = re.compile(r"^[A-Za-z0-9-]{1,128}$")
ALLOWED_ENGINES = {"libfuzzer", "aflpp"}
ALLOWED_SANITIZERS = {"address", "undefined", "memory", "thread"}


def fuzz_settings() -> dict:
    return load_yaml(SETTINGS_CONFIG).get("fuzzing", {})


def fuzzing_root() -> Path:
    return configured_root("VULNFORGE_FUZZING", "fuzzing")


def project_fuzz_dir(project: str) -> Path:
    if not PROJECT_ID_RE.fullmatch(project):
        raise ValueError("Invalid project ID")
    root = fuzzing_root()
    path = (root / project).resolve()
    if path.parent != root:
        raise ValueError("Invalid fuzzing path")
    return path


def targets_dir(project: str) -> Path:
    return project_fuzz_dir(project) / "targets"


def jobs_dir(project: str) -> Path:
    return project_fuzz_dir(project) / "jobs"


def crashes_dir(project: str) -> Path:
    return project_fuzz_dir(project) / "crashes"


def safe_subdir(base: Path, name: str) -> Path:
    if not TARGET_ID_RE.fullmatch(name):
        raise ValueError("Invalid identifier")
    path = (base / name).resolve()
    if path.parent != base:
        raise ValueError("Path escapes fuzzing directory")
    return path


def job_file(project: str, job_id: str) -> Path:
    if not JOB_ID_RE.fullmatch(job_id):
        raise ValueError("Invalid job ID")
    path = (jobs_dir(project) / f"{job_id}.json").resolve()
    if path.parent != jobs_dir(project).resolve():
        raise ValueError("Invalid job path")
    return path


def load_job(project: str, job_id: str) -> dict[str, Any]:
    path = job_file(project, job_id)
    if not path.is_file():
        raise FileNotFoundError(f"Fuzz job not found: {job_id}")
    return json.loads(path.read_text(encoding="utf-8"))


def save_job(project: str, job: dict[str, Any]) -> None:
    path = job_file(project, str(job["job_id"]))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(job, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def make_limits(cfg: dict) -> callable:
    max_cpu_sec = max(1, int(cfg.get("max_cpu_seconds", 3600)))
    max_mem_mb = max(64, min(int(cfg.get("max_memory_mb", 2048)), 65536))
    max_file_mb = max(10, min(int(cfg.get("max_file_mb", 512)), 4096))
    max_procs = max(8, min(int(cfg.get("max_processes", 64)), 512))

    def _apply() -> None:
        import resource

        mem_bytes = max_mem_mb * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_CPU, (max_cpu_sec, max_cpu_sec))
        resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))
        resource.setrlimit(resource.RLIMIT_FSIZE, (max_file_mb * 1024 * 1024,) * 2)
        resource.setrlimit(resource.RLIMIT_NPROC, (max_procs, max_procs))

    return _apply


def build_target_command(
    project_cfg: dict, target_cfg: dict, corpus_dir: Path, artifacts_dir: Path, cfg: dict
) -> list[str]:
    engine = str(target_cfg.get("engine", "libfuzzer"))
    if engine not in ALLOWED_ENGINES:
        raise ValueError("Engine must be libfuzzer or aflpp")
    sanitizers = set(target_cfg.get("sanitizers", ["address"]))
    if not sanitizers or not sanitizers.issubset(ALLOWED_SANITIZERS):
        raise ValueError(f"Sanitizers must be a subset of {sorted(ALLOWED_SANITIZERS)}")
    build_command = str(project_cfg.get("fuzz_build_command", "")).strip()
    if not build_command:
        raise ValueError("Project must define fuzz_build_command in projects.yaml")
    if ";" in build_command or "|" in build_command or "&" in build_command or "`" in build_command:
        raise ValueError("fuzz_build_command cannot contain shell metacharacters")
    harness_path = str(target_cfg.get("harness_path", "")).strip()
    if not harness_path or harness_path.startswith("-") or ".." in Path(harness_path).parts:
        raise ValueError("Invalid harness_path")
    duration = max(10, min(int(cfg.get("max_duration_seconds", 600)), 86400))
    flags = [
        f"-max_total_time={duration}",
        f"-rss_limit_mb={int(cfg.get('max_memory_mb', 2048))}",
        f"-artifact_prefix={artifacts_dir}/",
        "-print_final_stats=1",
    ]
    return [
        "bash", "-c",
        f"{build_command} && {harness_path} {' '.join(flags)} {corpus_dir}",
    ]


@mcp.tool()
def fuzz_target_create(
    project: str,
    target_id: str,
    engine: str = "libfuzzer",
    sanitizers: list[str] | None = None,
    harness_path: str = "",
) -> dict:
    """Create a fuzz target configuration for a registered project."""
    root = project_root(project, override_config(PROJECTS_CONFIG))
    project_cfg = load_yaml(override_config(PROJECTS_CONFIG)).get("projects", {}).get(project, {})
    target_dir = safe_subdir(targets_dir(project), target_id)
    target_dir.mkdir(parents=True, exist_ok=True)
    target_cfg = {
        "target_id": target_id,
        "engine": engine,
        "sanitizers": sanitizers or ["address"],
        "harness_path": harness_path,
        "project_root": str(root),
        "created_at": datetime.now(UTC).isoformat(),
    }
    config_file = target_dir / "config.json"
    config_file.write_text(json.dumps(target_cfg, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (target_dir / "corpus").mkdir(exist_ok=True)
    (target_dir / "artifacts").mkdir(exist_ok=True)
    return {
        "project": project,
        "target_id": target_id,
        "config": str(config_file),
        "corpus": str(target_dir / "corpus"),
        "artifacts": str(target_dir / "artifacts"),
        "fuzz_build_command_required": bool(project_cfg.get("fuzz_build_command")),
    }


@mcp.tool()
def fuzz_start(project: str, target_id: str, duration_seconds: int = 300) -> dict:
    """Start a background fuzz run with resource limits. Returns a job ID."""
    cfg = fuzz_settings()
    target_dir = safe_subdir(targets_dir(project), target_id)
    config_file = target_dir / "config.json"
    if not config_file.is_file():
        raise ValueError("Fuzz target not found; call fuzz_target_create first")
    target_cfg = json.loads(config_file.read_text(encoding="utf-8"))
    project_cfg = load_yaml(override_config(PROJECTS_CONFIG)).get("projects", {}).get(project, {})
    duration = max(10, min(int(duration_seconds), int(cfg.get("max_duration_seconds", 600))))
    effective_cfg = {**cfg, "max_duration_seconds": duration}
    corpus_dir = target_dir / "corpus"
    artifacts_dir = target_dir / "artifacts"
    command = build_target_command(project_cfg, target_cfg, corpus_dir, artifacts_dir, effective_cfg)
    job_id = f"job-{uuid.uuid4().hex[:12]}"
    log_path = target_dir / f"{job_id}.log"
    log_file = open(log_path, "w")  # noqa: SIM115
    try:
        proc = subprocess.Popen(
            command,
            stdout=log_file,
            stderr=subprocess.STDOUT,
            cwd=str(BASE),
            start_new_session=True,
            preexec_fn=make_limits(effective_cfg),  # noqa: PLW1509 - single-threaded MCP server
        )
    except OSError as exc:
        log_file.close()
        raise RuntimeError(f"Failed to start fuzz job: {exc}") from exc
    finally:
        if not log_file.closed:
            log_file.close()
    job = {
        "job_id": job_id,
        "project": project,
        "target_id": target_id,
        "pid": proc.pid,
        "status": "running",
        "duration_seconds": duration,
        "command": " ".join(command[:2]) + " [build && harness]",
        "log": str(log_path),
        "artifacts": str(artifacts_dir),
        "started_at": datetime.now(UTC).isoformat(),
    }
    save_job(project, job)
    return job


@mcp.tool()
def fuzz_status(project: str, job_id: str) -> dict:
    """Check the status of a fuzz job."""
    job = load_job(project, job_id)
    pid = job.get("pid")
    running = False
    if isinstance(pid, int) and pid > 0:
        try:
            os.kill(pid, 0)
            running = True
        except (OSError, ProcessLookupError):
            running = False
    if job.get("status") == "running" and not running:
        job["status"] = "finished"
        job["finished_at"] = datetime.now(UTC).isoformat()
        save_job(project, job)
    crash_count = 0
    artifacts_dir = Path(job.get("artifacts", ""))
    if artifacts_dir.is_dir():
        crash_count = len(list(artifacts_dir.glob("crash-*"))) + len(list(artifacts_dir.glob("oom-*")))
    return {**job, "process_running": running, "crash_files": crash_count}


@mcp.tool()
def fuzz_stop(project: str, job_id: str) -> dict:
    """Stop a running fuzz job by sending SIGTERM to its process group."""
    job = load_job(project, job_id)
    pid = job.get("pid")
    if not isinstance(pid, int) or pid <= 0:
        raise ValueError("Job has no valid PID")
    if job.get("status") != "running":
        return {**job, "note": "Job is not running"}
    try:
        os.killpg(pid, signal.SIGTERM)
    except OSError as exc:
        raise RuntimeError(f"Failed to stop job: {exc}") from exc
    job["status"] = "stopped"
    job["finished_at"] = datetime.now(UTC).isoformat()
    save_job(project, job)
    return job


@mcp.tool()
def fuzz_result(project: str, job_id: str) -> dict:
    """Return crashes and the log tail for a fuzz job."""
    job = load_job(project, job_id)
    log_path = Path(job.get("log", ""))
    log_tail = ""
    if log_path.is_file():
        lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
        log_tail = "\n".join(lines[-100:])
    crashes = []
    artifacts_dir = Path(job.get("artifacts", ""))
    if artifacts_dir.is_dir():
        for path in sorted(artifacts_dir.iterdir()):
            if path.is_file() and (path.name.startswith("crash-") or path.name.startswith("oom-")):
                data = path.read_bytes()[:65536]
                crashes.append({
                    "file": path.name,
                    "size_bytes": path.stat().st_size,
                    "sha256": hashlib.sha256(data).hexdigest(),
                })
    return {
        "project": project,
        "job_id": job_id,
        "status": job.get("status"),
        "crashes": crashes,
        "log_tail": log_tail,
        "note": "Crashes are leads; they do not prove a security vulnerability without impact analysis.",
    }


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
