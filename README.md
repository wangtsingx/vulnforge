# VulnForge

MCP-based Linux C/C++ source security research MVP.

## Scope

- Four MCP servers:
  - `vulnforge-source`: read-only source browsing and function-level analysis.
  - `vulnforge-static`: configured Semgrep scanning.
  - `vulnforge-patch`: read-only Git patch and history analysis.
  - `vulnforge-report`: schema-validated finding storage and Markdown reports.
  - `vulnforge-codeql`: CodeQL database creation and analysis.
  - `vulnforge-knowledge`: CVE lookup, NVD search, and patch pattern extraction.
  - `vulnforge-fuzz`: fuzz target management, background runs, and crash collection.
  - `vulnforge-tasks`: research task state machine and finding linkage.
- Research Skills for vulnerability research, source audit, and patch analysis.
- A shared Finding JSON schema and local finding store.
- No automatic exploit generation and no remote-target testing.

## 1. Requirements

- Linux
- [uv](https://docs.astral.sh/uv/)
- Python 3.11+
- `git`
- Semgrep installed separately and available as `semgrep`
- A local source tree that you are authorized to review

## 2. Install with uv

```bash
uv sync --group dev
```

Run checks:

```bash
uv run pytest
uv run ruff check .
```

Install Semgrep separately using its official installation instructions.

## 3. Configure projects

Edit `config/projects.yaml` and set the absolute path to each authorized local source checkout:

```yaml
projects:
  nginx:
    path: /absolute/path/to/nginx
    description: Nginx source tree for authorized local research
    revision: ""
```

Optional environment overrides:

- `VULNFORGE_HOME`
- `VULNFORGE_PROJECTS`
- `VULNFORGE_SETTINGS`
- `VULNFORGE_FINDINGS`
- `VULNFORGE_REPORTS`

Findings and reports are constrained to configured roots under `VULNFORGE_HOME`.

## 4. Agent guide

If you are an AI agent (Codex, Claude, etc.) operating this project, read
`AGENTS.md` first. It defines the authorization boundary, the recommended tool
call order, and the error handling rules.

Check runtime health before starting:

```bash
uv run vulnforge doctor
```

Get a one-call status snapshot for any task:

```
audit_status(task_id=...)
```

Import raw Semgrep results into hypothesis findings with fingerprint
deduplication and auto-created coverage units:

```
import_scan_results(project=..., task_id=..., scan_output=...)
```

All imported findings start as `hypothesis`; review each before promoting to
`candidate`.

## 5. Run MCP servers

Run each server from the repository root:

```bash
uv run vulnforge-source
uv run vulnforge-static
uv run vulnforge-patch
uv run vulnforge-report
uv run vulnforge-codeql
uv run vulnforge-knowledge
uv run vulnforge-fuzz
uv run vulnforge-tasks
```

Register projects via CLI:

```bash
uv run vulnforge add <name> </path/to/source> --description "..."
uv run vulnforge list
uv run vulnforge update <name> --revision <commit>
uv run vulnforge remove <name>
```

All servers use MCP stdio transport and are normally launched by an MCP host/client.

## 5. Example MCP client configuration

```json
{
  "mcpServers": {
    "vulnforge-source": {
      "command": "/absolute/path/to/vulnforge/.venv/bin/vulnforge-source",
      "env": {
        "VULNFORGE_HOME": "/absolute/path/to/vulnforge",
        "VULNFORGE_PROJECTS": "/absolute/path/to/vulnforge/config/projects.yaml",
        "VULNFORGE_SETTINGS": "/absolute/path/to/vulnforge/config/settings.yaml"
      }
    },
    "vulnforge-static": {
      "command": "/absolute/path/to/vulnforge/.venv/bin/vulnforge-static",
      "env": {
        "VULNFORGE_HOME": "/absolute/path/to/vulnforge",
        "VULNFORGE_PROJECTS": "/absolute/path/to/vulnforge/config/projects.yaml",
        "VULNFORGE_SETTINGS": "/absolute/path/to/vulnforge/config/settings.yaml"
      }
    },
    "vulnforge-patch": {
      "command": "/absolute/path/to/vulnforge/.venv/bin/vulnforge-patch",
      "env": {
        "VULNFORGE_HOME": "/absolute/path/to/vulnforge",
        "VULNFORGE_PROJECTS": "/absolute/path/to/vulnforge/config/projects.yaml",
        "VULNFORGE_SETTINGS": "/absolute/path/to/vulnforge/config/settings.yaml"
      }
    },
    "vulnforge-report": {
      "command": "/absolute/path/to/vulnforge/.venv/bin/vulnforge-report",
      "env": {
        "VULNFORGE_HOME": "/absolute/path/to/vulnforge",
        "VULNFORGE_PROJECTS": "/absolute/path/to/vulnforge/config/projects.yaml",
        "VULNFORGE_SETTINGS": "/absolute/path/to/vulnforge/config/settings.yaml"
      }
    }
  }
}
```

## 6. Supported languages

| Language | Extensions | Rules | Skill |
|---|---|---|---|
| C | `.c`, `.h` | `rules/c-memory.yml` | `source-audit` |
| C++ | `.c`, `.h`, `.cc`, `.cpp`, `.hpp` | `rules/c-memory.yml` | `source-audit` |
| Go | `.go` | `rules/go-security.yml` | `go-audit` |
| Rust | `.rs` | `rules/rust-security.yml` | `rust-audit` |
| Python | `.py` | `rules/python-security.yml` | `python-audit` |
| Mixed | all above | explicit per scan | `source-audit` |

Set the `language` field in `config/projects.yaml` to select the language for a project. Use `mixed` for projects containing multiple languages:

```yaml
projects:
  my-go-app:
    path: /path/to/source
    language: go
```

Language definitions are in `config/languages.yaml`.

## 7. Research workflow

1. Register an exact source revision and verify the Git commit.
2. Call `project_info`, `list_source_files`, `search_source`, `function_search`, and `list_functions`.
3. For historical variants, call `patch_history`, `patch_change_list`, and `patch_show`.
4. Inspect relevant code with `read_source` or `function_context`.
5. Run `semgrep_scan` and treat results only as candidate leads.
6. Save evidence-based records with `create_finding`.
7. Call `generate_report` to produce `reports/<project>/report.md`.
8. Use coverage MCP tools to track audited surfaces, boundaries, subsystems, and attack classes.
9. Separate confirmed facts, inferences, and unverified hypotheses.

## 8. Finding model

Finding records are validated against `schemas/finding.schema.json` before storage.

Minimum structure:

```json
{
  "finding_id": "finding-example0001",
  "project_id": "nginx",
  "status": "hypothesis",
  "title": "Length validation candidate",
  "evidence": [
    {
      "kind": "source",
      "path": "src/example.c",
      "line": 120,
      "note": "External length is used before a bounds check."
    }
  ]
}
```

Finding records also carry a stable `fingerprint` derived from the project, source location,
and vulnerability class. Saving a different finding with the same fingerprint is rejected to
prevent duplicate root causes. `needs_validation` is reserved for a source-grounded candidate
with a specific unresolved blocker; it must not receive severity.

## 9. Coverage ledger

Each research task can own a coverage ledger at `coverage/<task_id>.json`. A unit records a
surface, trust boundary, subsystem, attack class, starting paths, owner, reviewed paths,
local checks, result fingerprints, and unresolved reasons. `coverage_id` is derived from
canonical source references, and the ledger validator enforces duplicate IDs and state
invariants.

Coverage statuses:

| Status | Meaning |
|---|---|
| `planned` | Seeded, no owner or evidence |
| `in_progress` | Assigned, evidence not yet recorded |
| `covered` | Reviewed with local/source checks, no candidate |
| `candidate` | Reviewed and linked to one or more finding fingerprints |
| `blocked` | Partial evidence with a specific unresolved blocker |
| `deferred`, `out_of_scope`, `not_applicable` | Explicit gaps, never treated as covered |

`confirmed` status requires reproducible verification evidence and human review.

## 9. Safety and limitations

- Source and patch MCP tools are read-only.
- Git revisions are restricted to hexadecimal commit IDs.
- Static scanning only invokes the configured Semgrep executable and rules under `rules/`.
- No arbitrary shell command is exposed to the model.
- Static findings and crashes are leads, not confirmed vulnerabilities.
- Run untrusted builds and fuzzing in a disposable VM/container with resource limits.
- Pin source revisions and tool versions for reproducibility.

## 10. Tests

```bash
uv run pytest
uv run ruff check .
```
