# Expected findings for mini-httpd

This project intentionally contains the following vulnerability patterns.
Use it to verify that VulnForge's scan → import → coverage pipeline finds them.

## 1. Unbounded copy in `parse_request` (CWE-120 / buffer overflow)

| Location | Description |
|---|---|
| `src/handler.c` ~line 22 | `strncpy(req->method, raw, method_len)` with no MAX check |
| `src/handler.c` ~line 28 | `memcpy(req->path, path_start, path_len)` with no MAX_PATH_LEN check |
| `src/handler.c` ~line 34 | `strcpy(req->body, body_marker)` with no MAX_BODY_LEN check |

All three should be grouped into one fingerprint (same file, same function,
same vulnerability class) by `import_scan_results`.

## 2. Integer overflow before bounds check in `handle_request` (CWE-190)

| Location | Description |
|---|---|
| `src/handler.c` ~line 52 | `req->body_len + 64` can overflow int; check on `total` is bypassable |

## 3. File descriptor leak in `handle_request` (CWE-404 / resource leak)

| Location | Description |
|---|---|
| `src/handler.c` ~line 61 | `fopen` result `fp` never closed |

## 4. Safe function for contrast

`log_request` uses bounded `snprintf` and should NOT appear as a finding when
the rules are correctly tuned.
