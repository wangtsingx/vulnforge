---
name: python-audit
description: Audit Python source for injection, deserialization, path traversal, and SSRF defects.
---

# Python Source Audit

## Workflow

1. Identify external input entry points:
   - HTTP framework handlers (Flask, Django, FastAPI, Starlette)
   - CLI argument parsing (argparse, click)
   - Environment variables and configuration files
   - File uploads and form data
   - Message queue consumers

2. Trace data flow to sensitive operations:
   - SQL queries (`cursor.execute`, ORM raw queries)
   - Command execution (`os.system`, `subprocess.run`, `os.popen`)
   - File operations (`open`, `os.remove`, `shutil.rmtree`)
   - HTTP requests (`requests.get`, `urllib.request.urlopen`)
   - Deserialization (`pickle.loads`, `yaml.load`, `eval`, `exec`)

3. Check Python-specific patterns:
   - **SQL injection**: Are queries parameterized, or built with f-strings/concatenation?
   - **Command injection**: Is `shell=True` used with user input? Are arguments validated?
   - **Deserialization**: Is `pickle.loads` or `yaml.load` called on untrusted data?
   - **Path traversal**: Is `os.path.join` used with user input without validation?
   - **SSRF**: Is the URL user-controlled? Is there an allowlist?
   - **eval/exec**: Are they called with user-controlled strings?
   - **Template injection**: Is user input passed to Jinja2/Mako template rendering?
   - **ReDoS**: Are user-controlled regex patterns compiled and executed?
   - **Hardcoded secrets**: Are credentials embedded in source code?

4. Check authentication and authorization:
   - Are endpoints protected by authentication decorators?
   - Are authorization checks performed before sensitive operations?
   - Is the admin interface exposed without additional protection?

5. For each candidate, capture:
   - File, function, and line range
   - Input source and data flow
   - Missing validation or invariant
   - Trigger conditions

## Constraints

- Python's dynamic typing makes taint analysis harder than in statically typed languages.
- `eval` and `exec` are almost always security risks with untrusted input.
- `yaml.load` without `Loader=yaml.SafeLoader` can execute arbitrary code.
- Do not assume a framework's built-in protections cover all entry points.
