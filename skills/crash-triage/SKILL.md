---
name: crash-triage
description: Analyze crash artifacts from fuzzing, deduplicate them, identify root causes, and assess security impact.
---

# Crash Triage

## Workflow

1. Collect crash artifacts from `fuzz_result` (file name, SHA-256, size).
2. Deduplicate crashes by SHA-256 hash and stack signature.
3. For each unique crash:
   - Reproduce using the same target, sanitizer build, and input file.
   - Capture the sanitizer report (ASan/UBSan/MSan output).
   - Identify the crash type (heap-buffer-overflow, use-after-free, stack-overflow, etc.).
   - Map the stack trace to source files and lines using `function_context`.
4. Determine the root cause:
   - What input sequence triggered the crash?
   - What data flow led to the faulty operation?
   - What invariant was missing or insufficient?
5. Assess security impact:
   - Is the crash reachable from an external input?
   - Does it cause memory corruption, information leak, or denial of service?
   - What are the attack prerequisites?
6. Record findings:
   - Link the crash to a finding_id using `create_finding`.
   - Store the crash artifact SHA-256 in the evidence.
   - Mark status as `candidate` until human review confirms security impact.

## Constraints

- A crash alone does not prove a security vulnerability.
- Do not assign a CWE or severity without understanding the root cause.
- Distinguish sanitizer-detected issues from benign assertion failures.
- Record the exact build flags, sanitizer version, and commit revision.
