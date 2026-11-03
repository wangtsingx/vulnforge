---
name: go-audit
description: Audit Go source for SSRF, path traversal, unsafe pointer, injection, and concurrency defects.
---

# Go Source Audit

## Workflow

1. Identify external input entry points:
   - HTTP handlers (`net/http` ServeHTTP, router handlers)
   - gRPC service methods
   - CLI flag and environment variable parsing
   - File and configuration parsers
   - Network listeners (TCP, UDP, Unix sockets)

2. Trace data flow to sensitive operations:
   - HTTP client requests (`http.Get`, `http.NewRequest`, custom clients)
   - File system operations (`os.Open`, `os.ReadFile`, `filepath.Join`)
   - Command execution (`exec.Command`, `exec.CommandContext`)
   - Database queries (`db.Query`, `db.Exec`)
   - Deserialization (`json.Unmarshal`, `yaml.Unmarshal`, `gob.Decode`)

3. Check Go-specific patterns:
   - **SSRF**: Is the URL user-controlled? Is there an allowlist for scheme and host?
   - **Path traversal**: Is `filepath.Clean` applied? Is the result confined to a base directory?
   - **Unsafe pointers**: Is `unsafe.Pointer` used for type confusion or bypassing GC?
   - **Command injection**: Are arguments passed as a slice, or concatenated into a shell string?
   - **SQL injection**: Are queries parameterized, or built with `fmt.Sprintf`?
   - **Deserialization**: Is input validated before `Unmarshal`?
   - **Goroutine leaks**: Are goroutines bounded? Is there a `context` cancellation path?
   - **Race conditions**: Is shared state protected by `sync.Mutex` or channels?
   - **Error swallowing**: Are errors ignored with `_` on security-critical paths?

4. Check context and lifecycle:
   - Are `context.Context` values propagated through request handlers?
   - Are timeouts set on HTTP clients and database queries?
   - Are resources (files, connections, response bodies) closed via `defer`?

5. For each candidate, capture:
   - File, function, and line range
   - Input source and data flow
   - Missing validation or invariant
   - Trigger conditions
   - False-positive conditions

## Constraints

- Go's memory safety eliminates most C-style buffer overflows but not logic or injection flaws.
- Presence of a dangerous API alone does not imply reachability.
- `unsafe` usage requires careful review but is not automatically a vulnerability.
- Race conditions may only manifest under concurrent load.
