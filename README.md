# VulnForge

MCP-based Linux C/C++ source security research MVP.

## Scope of this first iteration

- Two MCP servers: read-only source browsing and configured Semgrep scanning.
- Three Skills: research planning, source audit, patch analysis.
- One starter Semgrep ruleset.
- A common Finding JSON schema.
- No automatic exploit generation and no remote-target testing.

## 1. Requirements

- Linux
- Python 3.11+
- Semgrep installed and available as `semgrep`
- A local source tree that you are authorized to review

## 2. Install

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e ".[dev]"
```

Install Semgrep separately using its official installation instructions.

## 3. Configure project

Edit `config/projects.yaml` and set the absolute path to your local source checkout.
The example registers `/opt/vulnforge/source/nginx`.

Set environment variables if the checkout is elsewhere:

```bash
export VULNFORGE_HOME="$PWD"
export VULNFORGE_PROJECTS="$PWD/config/projects.yaml"
export VULNFORGE_SETTINGS="$PWD/config/settings.yaml"
```

## 4. Run MCP servers

Run each server from the repository root:

```bash
vulnforge-source
vulnforge-static
```

Both use MCP stdio transport and should normally be launched by an MCP host/client.

## 5. Example MCP client configuration

Adapt command paths to your machine:

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
    }
  }
}
```

## 6. First research task

Ask the connected Agent to:
1. Call `project_info` and `list_source_files`.
2. Search for `memcpy|memmove|strcpy|strcat|malloc|realloc`.
3. Inspect relevant source ranges with `read_source`.
4. Run `semgrep_scan`.
5. Produce candidate findings with exact revision and source locations.
6. Separate confirmed facts from hypotheses.

## 7. Safety and limitations

- The source MCP exposes read-only source operations.
- The static MCP only invokes the configured Semgrep executable and configured rules under `rules/`.
- No arbitrary shell command is exposed to the model.
- Static findings are leads, not confirmed vulnerabilities.
- Run untrusted builds and fuzzing in a disposable VM/container with resource limits.
- Pin source revisions and tool versions for reproducibility.

## 8. Tests

```bash
pytest
```
