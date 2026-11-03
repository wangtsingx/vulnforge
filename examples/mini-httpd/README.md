# mini-httpd: VulnForge end-to-end test target

A deliberately vulnerable mini HTTP handler (~80 lines of C) for verifying
VulnForge's scan → import → coverage → report pipeline.

## Quick start

```bash
# from the vulnforge repo root
uv run vulnforge add mini-httpd ./examples/mini-httpd/src --language c
uv run vulnforge doctor
```

Then use the MCP tools:

```
create_task(project="mini-httpd", title="E2E test")
semgrep_scan(project="mini-httpd")
import_scan_results(project="mini-httpd", task_id=..., scan_output=...)
audit_status(task_id=...)
generate_report(project="mini-httpd")
```

## What to expect

See `expected-findings.md` for the three seeded vulnerabilities that should
appear as hypothesis findings after import.
