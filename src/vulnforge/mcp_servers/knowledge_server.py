from __future__ import annotations

import os
import re
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from vulnforge.config import load_yaml, override_config, project_root

mcp = FastMCP("vulnforge-knowledge")
BASE = Path(os.getenv("VULNFORGE_HOME", ".")).resolve()
PROJECTS_CONFIG = Path(os.getenv("VULNFORGE_PROJECTS", BASE / "config/projects.yaml"))
SETTINGS_CONFIG = Path(os.getenv("VULNFORGE_SETTINGS", BASE / "config/settings.yaml"))

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
CWE_RE = re.compile(r"^CWE-\d{1,4}$")


def knowledge_settings() -> dict:
    return load_yaml(SETTINGS_CONFIG).get("knowledge", {})


def http_get(url: str, timeout: int) -> dict:
    """Fetch a URL with size and timeout limits."""
    import urllib.request

    max_bytes = int(knowledge_settings().get("max_response_bytes", 500_000))
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "vulnforge/0.2"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = resp.read(max_bytes + 1)
    except Exception as exc:
        raise RuntimeError(f"HTTP request failed: {exc}") from exc
    if len(data) > max_bytes:
        raise RuntimeError("Response exceeds size limit")
    import json

    try:
        return json.loads(data)
    except json.JSONDecodeError as exc:
        raise RuntimeError("Invalid JSON response") from exc


def extract_cwe(cve_data: dict) -> list[str]:
    cwes = set()
    for desc in cve_data.get("containers", {}).get("cna", {}).get("affected", []):
        for cwe in desc.get("cwes", []):
            cwe_id = cwe.get("cweId", "")
            if CWE_RE.fullmatch(cwe_id):
                cwes.add(cwe_id)
    return sorted(cwes)


def extract_references(cve_data: dict) -> list[str]:
    refs = []
    for ref in cve_data.get("containers", {}).get("cna", {}).get("references", []):
        url = ref.get("url", "")
        if url.startswith("https://"):
            refs.append(url)
    return refs[:50]


def extract_description(cve_data: dict) -> str:
    cna = cve_data.get("containers", {}).get("cna", {})
    for desc in cna.get("descriptions", []):
        if desc.get("lang") == "en":
            return desc.get("value", "")[:3000]
    return ""


@mcp.tool()
def cve_lookup(cve_id: str) -> dict:
    """Look up a CVE record from the CVE.org API."""
    if not CVE_RE.fullmatch(cve_id):
        raise ValueError("Invalid CVE ID format (expected CVE-YYYY-NNNN)")
    cfg = knowledge_settings()
    timeout = max(10, min(int(cfg.get("http_timeout_seconds", 30)), 120))
    url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
    data = http_get(url, timeout)
    return {
        "cve_id": cve_id,
        "description": extract_description(data),
        "cwes": extract_cwe(data),
        "references": extract_references(data),
        "source": "cve.org",
    }


@mcp.tool()
def cve_search_by_keyword(keyword: str, limit: int = 10) -> dict:
    """Search CVE records by keyword using the NVD API."""
    if not keyword or len(keyword) < 3 or len(keyword) > 200:
        raise ValueError("Keyword must be 3-200 characters")
    limit = max(1, min(int(limit), 50))
    cfg = knowledge_settings()
    timeout = max(10, min(int(cfg.get("http_timeout_seconds", 30)), 120))
    import urllib.parse

    query = urllib.parse.quote(keyword)
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={query}&resultsPerPage={limit}"
    data = http_get(url, timeout)
    results = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")
        desc = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")[:500]
                break
        results.append({"cve_id": cve_id, "description": desc})
    return {"keyword": keyword, "total_results": data.get("totalResults", 0), "results": results}


@mcp.tool()
def patch_pattern_extract(project: str, commit: str) -> dict:
    """Extract a structural patch pattern from a fix commit for variant hunting."""
    root = project_root(project, override_config(PROJECTS_CONFIG))
    from vulnforge.git_utils import run_git, validate_commit

    validate_commit(commit)
    cfg = knowledge_settings()
    timeout = max(10, min(int(cfg.get("git_timeout_seconds", 60)), 300))
    proc = run_git(root, ["show", "--no-color", "--no-ext-diff", "--unified=3", commit], timeout)
    if proc.returncode != 0:
        raise RuntimeError(f"git show failed: {(proc.stderr or '').strip()[:2000]}")
    diff = proc.stdout
    files_changed = []
    hunks = []
    current_file = ""
    for line in diff.splitlines():
        if line.startswith("+++ b/"):
            current_file = line[6:]
            files_changed.append(current_file)
        elif line.startswith("@@") and current_file:
            hunks.append({"file": current_file, "header": line[:200]})
    return {
        "project": project,
        "commit": commit,
        "files_changed": files_changed[:50],
        "hunks": hunks[:200],
        "diff_bytes": len(diff.encode("utf-8", errors="replace")),
        "diff_preview": diff[:5000],
    }


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
